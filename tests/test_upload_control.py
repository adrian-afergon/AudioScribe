import json
import stat
import threading
import time
from pathlib import Path

import pytest

from audioscribe.config import Config
from audioscribe.control import ServiceControl, request
from audioscribe.service import InstanceLock
from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.capabilities import ensure_owned_staging
from audioscribe.upload.controller import UploadController, verifier_installed
from audioscribe.upload.http import HttpError, UploadRuntime
from audioscribe.upload.runtime import UploadRuntimeOwner


def validation_stub(valid=True, has_media_frame=True):
    from audioscribe.upload.validator import MediaValidation
    return MediaValidation(valid=valid, has_media_frame=has_media_frame,
                           audio_streams=0, video_streams=1, container_format="mp4",
                           child_peak_rss_kib=0, child_threads_before_seal=0,
                           preloaded_stream_wrappers=0, input_bytes_before_seal=0,
                           input_bytes_after_open=0, parent_peak_rss_kib=0,
                           parent_peak_threads=0)


def control_paths(tmp_path):
    for name in ("in", "out", "brain", "data"):
        (tmp_path / name).mkdir(parents=True, exist_ok=True)
    return [str(tmp_path / name) for name in ("in", "out", "brain", "data")]


def control_config(tmp_path, **overrides):
    paths = control_paths(tmp_path)
    values = dict(upload_origin="https://scribe.example.ts.net")
    values.update(overrides)
    return Config(*paths, stable_seconds=1, poll_seconds=1, **values)


def save_config(config, path):
    config.save(path)
    return path


def test_cli_panel_control_parity(tmp_path):
    config = control_config(tmp_path)
    config_path = save_config(config, tmp_path / "config.toml")
    cli = UploadController(config, config_path)
    panel = UploadController(config, config_path)

    for action in ("enable", "disable", "status", "regenerate_secret"):
        assert callable(getattr(cli, action))
        assert callable(getattr(panel, action))

    status = panel.status()
    assert status.outcome == "acknowledged"
    assert status.status["desired_enabled"] is False
    assert status.status["effective_enabled"] is False
    assert "secret" not in json.dumps(status.status)

    enabled = cli.enable()
    assert enabled.outcome == "acknowledged"
    assert enabled.revision == 1
    assert enabled.secret and len(enabled.secret) == 43

    again = panel.enable()
    assert again.outcome == "rejected"
    assert again.secret is None

    disabled = panel.disable()
    assert disabled.outcome == "acknowledged"
    assert disabled.revision == 2

    final = cli.status()
    assert final.status["desired_enabled"] is False


class ActiveService:
    """Fixture seam: an active service holding the InstanceLock with a live owner."""

    def __init__(self, tmp_path, enabled=False, pump=True, listener_factory=None):
        self.config = control_config(tmp_path, upload_enabled=enabled,
                                     upload_reserve_bytes=0)
        self.config_path = tmp_path / "config.toml"
        self.config.save(self.config_path)
        self.data_dir = tmp_path / "data"
        self.secret = generate_secret_offline(self.data_dir)
        self.lock = InstanceLock(self.data_dir / "service.lock")
        ensure_owned_staging(Path(self.config.input_dir))
        self.runtime = UploadRuntime(self.config)
        self.runtime.start()
        self.runtime.baseline_ready = True
        self.stop_event = threading.Event()
        self.owner = UploadRuntimeOwner(self.config, config_path=self.config_path,
                                        runtime=self.runtime, stop_event=self.stop_event,
                                        listener_factory=listener_factory)
        if pump:
            self.owner.start_pump()

    def close(self):
        self.owner.close()
        self.lock.close()


def test_concurrent_local_config_commands_serialize(tmp_path):
    service = ActiveService(tmp_path, enabled=True)
    try:
        cli = UploadController(service.config, service.config_path)
        panel = UploadController(service.config, service.config_path)
        outcomes = {}

        def submit(name, action):
            outcomes[name] = action()

        threads = [threading.Thread(target=submit, args=("cli", cli.disable)),
                   threading.Thread(target=submit, args=("panel", panel.regenerate_secret))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(15)
        assert set(outcomes) == {"cli", "panel"}
        revisions = sorted(outcome.revision for outcome in outcomes.values())
        assert all(outcome.outcome == "acknowledged" for outcome in outcomes.values())
        assert revisions[1] == revisions[0] + 1
        persisted = service.config.__class__.load(service.config_path)
        assert persisted.upload_enabled is False
        new_verifier = json.loads((service.data_dir / "upload-auth" / "verifier.json").read_text())["sha256"]
        assert service.runtime.verifier == new_verifier
        assert service.runtime.auth_epoch == 1
        assert service.owner.snapshot is None
    finally:
        service.close()


def _publish_request(mailbox, command_id, payload_text):
    import os
    import tempfile
    fd, tmp = tempfile.mkstemp(prefix=".test-cmd-", dir=mailbox)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(payload_text)
    os.replace(tmp, mailbox / f"{command_id}.request.json")


def test_secret_ack_consumed_once(tmp_path):
    service = ActiveService(tmp_path, pump=False)
    try:
        mailbox = service.data_dir / "upload-mailbox"
        command_id = "0" * 32
        payload = {"id": command_id, "action": "status", "expected_revision": None,
                   "force": False, "verifier": None, "created": time.time()}
        _publish_request(mailbox, command_id, json.dumps(payload))
        service.owner.pump_once()
        ack = json.loads((mailbox / f"{command_id}.ack.json").read_text())
        assert ack["outcome"] == "acknowledged"
        _publish_request(mailbox, command_id, json.dumps(payload))
        service.owner.pump_once()
        replay = json.loads((mailbox / f"{command_id}.ack.json").read_text())
        assert replay["outcome"] == "rejected"
        assert "replay" in replay["detail"]
    finally:
        service.close()


def test_no_plaintext_secret_in_mailbox(tmp_path):
    service = ActiveService(tmp_path)
    try:
        controller = UploadController(service.config, service.config_path)
        outcome = controller.regenerate_secret()
        assert outcome.outcome == "acknowledged"
        assert outcome.secret and len(outcome.secret) == 43
        mailbox = service.data_dir / "upload-mailbox"
        assert stat.S_IMODE(mailbox.stat().st_mode) == 0o700
        leaked = []
        for path in service.data_dir.rglob("*"):
            if path.is_file():
                try:
                    if outcome.secret in path.read_text(encoding="utf-8", errors="ignore"):
                        leaked.append(str(path.relative_to(service.data_dir)))
                except OSError:
                    continue
        assert leaked == []
        persisted = json.loads((service.data_dir / "upload-auth" / "verifier.json").read_text())
        assert set(persisted) == {"sha256"}
    finally:
        service.close()


def test_control_dispatch_not_blocked_by_scanner_hash(tmp_path, monkeypatch):
    import hashlib as hashlib_module
    import sys

    from audioscribe import store as store_module

    service = ActiveService(tmp_path)
    modules_before = set(sys.modules)
    try:
        release = threading.Event()
        entered = threading.Event()

        def blocking_digest(path):
            entered.set()
            assert release.wait(10)
            return hashlib_module.sha256(b"blocked").hexdigest()

        monkeypatch.setattr(store_module, "digest", blocking_digest)
        scanner_thread = threading.Thread(
            target=lambda: store_module.digest(Path(service.config.input_dir) / "x.mp3"))
        scanner_thread.start()
        assert entered.wait(5)
        controller = UploadController(service.config, service.config_path)
        outcome = controller.disable(force=True)
        assert outcome.outcome == "acknowledged"
        rotated = UploadController(service.config, service.config_path).regenerate_secret()
        assert rotated.outcome == "acknowledged"
        newly_imported = {name for name in set(sys.modules) - modules_before
                          if name == "uvicorn" or name == "av" or name.startswith(("uvicorn.", "av."))}
        assert newly_imported == set()
    finally:
        release.set()
        scanner_thread.join(10)
        service.close()


def test_active_enable_persists_canonical_config_path(tmp_path):
    service = ActiveService(tmp_path, enabled=False)
    try:
        controller = UploadController(service.config, service.config_path)
        outcome = controller.enable()
        assert outcome.outcome == "acknowledged"
        persisted = service.config.__class__.load(service.config_path)
        assert persisted.upload_enabled is True
        assert outcome.revision >= 1
        # A caller-supplied alternative path cannot redirect the write.
        decoy = tmp_path / "decoy.toml"
        persisted.save(decoy)
        decoy_before = decoy.read_text()
        outcome2 = UploadController(service.config, decoy).disable(force=True)
        assert outcome2.outcome == "acknowledged"
        canonical = service.config.__class__.load(service.config_path)
        assert canonical.upload_enabled is False
        assert decoy.read_text() == decoy_before
    finally:
        service.close()


def test_malformed_request_is_rejected_once_and_consumed(tmp_path):
    service = ActiveService(tmp_path, pump=False)
    try:
        mailbox = service.data_dir / "upload-mailbox"
        command_id = "a" * 32
        _publish_request(mailbox, command_id, '{"id": "not-even-valid"')
        service.owner.pump_once()
        ack = json.loads((mailbox / f"{command_id}.ack.json").read_text())
        assert ack["outcome"] == "rejected"
        assert not (mailbox / f"{command_id}.request.json").exists()
        service.owner.pump_once()
        assert not (mailbox / f"{command_id}.request.json").exists()
    finally:
        service.close()


def test_regenerate_timeout_is_uncertain_and_discards_secret(tmp_path):
    service = ActiveService(tmp_path)
    try:
        # Active lock held, but no owner pump: nobody processes the mailbox.
        service.owner.close()
        controller = UploadController(service.config, service.config_path, ack_timeout=0.3)
        outcome = controller.regenerate_secret()
        assert outcome.outcome == "uncertain"
        assert outcome.secret is None
        assert not (service.data_dir / "upload-auth" / "verifier.json").exists() or \
            json.loads((service.data_dir / "upload-auth" / "verifier.json").read_text())["sha256"] == service.runtime.verifier
    finally:
        service.close()


# -- step 2: atomic disable/stop versus admission, write and publication ------


def make_runtime(tmp_path, **overrides):
    overrides.setdefault("upload_reserve_bytes", 0)
    config = control_config(tmp_path, **overrides)
    generate_secret_offline(Path(config.data_dir))
    ensure_owned_staging(Path(config.input_dir))
    runtime = UploadRuntime(config)
    runtime.start()
    runtime.baseline_ready = True
    owner = UploadRuntimeOwner(config, config_path=tmp_path / "config.toml",
                               runtime=runtime, stop_event=threading.Event())
    return config, runtime, owner


def make_session(runtime):
    import secrets as secrets_module
    from audioscribe.upload.http import Session
    session = Session(lineage=secrets_module.token_hex(16),
                      cookie_verifier=secrets_module.token_hex(16), csrf="csrf",
                      created=runtime.wall_fn())
    session.last_seen = session.created
    runtime.sessions[session.cookie_verifier] = session
    return session


def test_unforced_stop_admission_race_refused(tmp_path):
    _config, runtime, owner = make_runtime(tmp_path)
    try:
        session = make_session(runtime)
        entered = threading.Event()
        release = threading.Event()
        runtime.admission_probe = lambda: (entered.set(), release.wait(10))
        result = {}
        admission = threading.Thread(
            target=lambda: result.setdefault("transfer", runtime.register(session, "a.mp3", 1024)))
        admission.start()
        assert entered.wait(5), "admission probe inside the owner-state guard was never reached"
        decisions = []
        stopper = threading.Thread(target=lambda: decisions.append(owner.evaluate_stop(False)))
        stopper.start()
        time.sleep(0.2)
        release.set()
        admission.join(5)
        stopper.join(5)
        # Registration won the guard: the unforced stop is refused, never both.
        assert "transfer" in result
        assert decisions == [False]
        assert owner.stop_refusals == 1
        assert runtime.active_unpublished_count() == 1
        assert not owner.stop_event.is_set()
    finally:
        owner.close()

    _config2, runtime2, owner2 = make_runtime(tmp_path / "second")
    try:
        session2 = make_session(runtime2)
        assert owner2.evaluate_stop(False) is True
        assert runtime2.admission_closed is True
        with pytest.raises(HttpError) as error:
            runtime2.register(session2, "b.mp3", 10)
        assert error.value.status == 409
        assert runtime2.active_unpublished_count() == 0
    finally:
        owner2.close()


def test_forced_stop_cancels_before_publish(tmp_path):
    _config, runtime, owner = make_runtime(tmp_path)
    try:
        session = make_session(runtime)
        transfer = runtime.register(session, "video.mp4", 64)
        runtime.authorize_body(session, transfer.upload_id, transfer.token)
        runtime.receive_chunk(transfer, b"x" * 64)
        staging = runtime.staging
        assert (staging / f"{transfer.upload_id}.part").exists()
        assert owner.evaluate_stop(force=True) is True
        assert owner.stop_event.is_set()
        assert runtime.admission_closed is True
        assert transfer.state == "cancelled"
        assert not (staging / f"{transfer.upload_id}.part").exists()
        assert not (staging / f"{transfer.upload_id}.manifest.json").exists()
        assert not list(Path(runtime.config.input_dir).glob("*.mp4"))
        with pytest.raises(HttpError) as error:
            runtime.register(session, "next.mp4", 10)
        assert error.value.status == 409
    finally:
        owner.close()


def test_legacy_stop_cannot_bypass_owner(tmp_path):
    stop = threading.Event()
    control = ServiceControl(tmp_path, stop)
    try:
        control.start()
        request(tmp_path, "stop")
        control.stop_gate = lambda force: False
        assert control.checkpoint() is False
        assert control.state["state"] != "stopping"
        control.stop_gate = lambda force: True
        assert control.checkpoint() is True
        assert control.state["state"] == "stopping"
    finally:
        stop.set()
        control.close()


def test_stop_request_force_marker(tmp_path):
    request(tmp_path, "stop")
    from audioscribe.control import stop_request_forced
    assert stop_request_forced(tmp_path) is False
    request(tmp_path, "stop", force=True)
    assert stop_request_forced(tmp_path) is True
    (tmp_path / "stop.request").unlink(missing_ok=True)
    assert stop_request_forced(tmp_path) is False


def test_stop_can_mark_cancel_while_write_pending(tmp_path):
    """A cancel racing a pending write must flag the transfer immediately (the
    writer's exit path sees it) but must not expose the terminal state while
    the write holds the resource guard: the terminal release waits for the
    bounded write and only then the transfer reads as cancelled."""
    _config, runtime, owner = make_runtime(tmp_path)
    try:
        session = make_session(runtime)
        transfer = runtime.register(session, "audio.mp3", 4096)
        runtime.authorize_body(session, transfer.upload_id, transfer.token)
        entered = threading.Event()
        release = threading.Event()

        def blocked_write():
            entered.set()
            assert release.wait(10)
            with open(transfer.part_path, "ab") as stream:
                stream.write(b"x" * 4096)
                return 4096

        def sample_free_space():
            return 1 << 40

        writer = threading.Thread(target=lambda: runtime.reservations.write(
            transfer.upload_id, blocked_write, sample_free_space))
        writer.start()
        assert entered.wait(5), "pending bounded write was never reached"
        cancelled = []
        stopper = threading.Thread(target=lambda: cancelled.append(
            owner.evaluate_stop(force=True)))
        stopper.start()

        def cancelling():
            return transfer.state == "cancelling"

        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not cancelling():
            time.sleep(0.02)
        assert cancelling(), "the cancel must flag the transfer while the write is pending"
        assert transfer.state != "cancelled", \
            "state=cancelled must not be observable while a write is pending"
        assert transfer.upload_id in runtime.reservations._commitments, \
            "the commitment must survive until the write completes"
        release.set()
        writer.join(5)
        stopper.join(5)
        assert cancelled == [True]
        assert transfer.state == "cancelled", "the slot release must precede the terminal state"
        assert runtime.reservations.active == 0
        with pytest.raises(HttpError) as error:
            runtime.receive_chunk(transfer, b"x" * 10)
        assert error.value.code == "cancelled"
        assert transfer.upload_id not in runtime.reservations._commitments
        assert not list(Path(runtime.config.input_dir).glob("*.mp3"))
    finally:
        owner.close()


def test_publish_while_other_transfer_writes_releases_both_reservations(tmp_path):
    """A terminal release must never be skipped when ANOTHER transfer's writer
    holds the resource guard: B passes its publication rechecks, then A's
    bounded write takes the guard, then B publishes and must release — waiting
    for the bounded write, never skipping — so once both transfers complete
    every commitment is gone (no stranded slot, no reserve freeze)."""
    _config, runtime, owner = make_runtime(tmp_path)
    try:
        session = make_session(runtime)
        transfer_a = runtime.register(session, "writer.mp4", 4096)
        runtime.authorize_body(session, transfer_a.upload_id, transfer_a.token)
        transfer_b = runtime.register(session, "publisher.mp4", 32)
        runtime.authorize_body(session, transfer_b.upload_id, transfer_b.token)
        runtime.receive_chunk(transfer_b, b"y" * 32)

        writer_holding = threading.Event()
        release = threading.Event()

        import audioscribe.upload.http as http_module
        original_validate = http_module.validate_staged_media
        original_publish = http_module.publish_atomically
        writer_holder = {}

        def blocked_write():
            writer_holding.set()
            assert release.wait(10)
            with open(transfer_a.part_path, "ab") as stream:
                stream.write(b"x" * 4096)
                return 4096

        def sample_free_space():
            return 1 << 40

        def gated_publish(part_path, root, final_name):
            # B cleared its rechecks; only now may A's writer take the guard,
            # so B reaches its release while the resource guard is held.
            thread = threading.Thread(target=lambda: runtime.reservations.write(
                transfer_a.upload_id, blocked_write, sample_free_space))
            writer_holder["thread"] = thread
            thread.start()
            assert writer_holding.wait(5), "A's writer never took the resource guard"
            return original_publish(part_path, root, final_name)

        http_module.validate_staged_media = lambda path, suffix: validation_stub()
        http_module.publish_atomically = gated_publish
        try:
            publisher = threading.Thread(
                target=lambda: _safe_receipt(runtime, transfer_b))
            publisher.start()
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and transfer_b.state != "published":
                time.sleep(0.02)
            assert transfer_b.state == "published", \
                "B must reach its terminal release while A holds the resource guard"
            release.set()
            publisher.join(10)
            assert not publisher.is_alive(), "B's terminal release must not strand"
            assert transfer_b.state == "published"
            assert transfer_b.upload_id not in runtime.reservations._commitments, \
                "B's commitment must be released even though A held the guard"
        finally:
            http_module.validate_staged_media = original_validate
            http_module.publish_atomically = original_publish

        writer_holder.get("thread", threading.Thread()).join(10)
        assert not writer_holder["thread"].is_alive()
        runtime.cancel_transfer(transfer_a)
        assert transfer_a.upload_id not in runtime.reservations._commitments
        assert runtime.reservations.active == 0, \
            "both commitments must be released once both transfers complete"
    finally:
        owner.close()


def test_cancel_forbids_late_publication(tmp_path, monkeypatch):
    _config, runtime, owner = make_runtime(tmp_path)
    try:
        import audioscribe.upload.http as http_module
        entered = threading.Event()
        release = threading.Event()

        def blocked_validate(path, suffix):
            entered.set()
            assert release.wait(10)
            return validation_stub()

        monkeypatch.setattr(http_module, "validate_staged_media", blocked_validate)
        session = make_session(runtime)
        transfer = runtime.register(session, "late.mp4", 32)
        runtime.authorize_body(session, transfer.upload_id, transfer.token)
        runtime.receive_chunk(transfer, b"x" * 32)
        outcome = {}
        publisher = threading.Thread(
            target=lambda: outcome.setdefault("receipt", _safe_receipt(runtime, transfer)))
        publisher.start()
        assert entered.wait(5), "validation barrier was never reached"
        assert runtime.cancel_transfer(transfer) == "cancelled"
        release.set()
        publisher.join(5)
        assert isinstance(outcome.get("receipt"), HttpError)
        assert outcome["receipt"].code == "cancelled"
        assert transfer.state == "cancelled"
        assert not list(Path(runtime.config.input_dir).glob("*.mp4"))
    finally:
        owner.close()


def _safe_receipt(runtime, transfer):
    try:
        runtime.complete_receipt(transfer)
        return "published"
    except HttpError as error:
        return error


def test_stale_revision_command_is_rejected(tmp_path):
    service = ActiveService(tmp_path, pump=False)
    try:
        mailbox = service.data_dir / "upload-mailbox"
        command_id = "c" * 32
        payload = {"id": command_id, "action": "disable", "expected_revision": 99,
                   "force": True, "verifier": None, "created": time.time()}
        _publish_request(mailbox, command_id, json.dumps(payload))
        service.owner.pump_once()
        ack = json.loads((mailbox / f"{command_id}.ack.json").read_text())
        assert ack["outcome"] == "rejected"
        assert ack["detail"] == "stale_revision"
        assert not (service.data_dir / "upload-enable-snapshot.json").exists()
    finally:
        service.close()


def test_cancel_after_publish_reports_already_published(tmp_path):
    _config, runtime, owner = make_runtime(tmp_path)
    try:
        import audioscribe.upload.http as http_module
        original = http_module.validate_staged_media
        http_module.validate_staged_media = lambda path, suffix: validation_stub()
        try:
            session = make_session(runtime)
            transfer = runtime.register(session, "done.mp4", 16)
            runtime.authorize_body(session, transfer.upload_id, transfer.token)
            runtime.receive_chunk(transfer, b"x" * 16)
            runtime.complete_receipt(transfer)
            assert transfer.state == "published"
            assert (Path(runtime.config.input_dir) / "done.mp4").exists()
            assert runtime.cancel(session, transfer.upload_id) == "already_published"
        finally:
            http_module.validate_staged_media = original
    finally:
        owner.close()


# -- step 5: production lifecycle schedule (inactivity clock, reserve monitor) --


def http_runtime(tmp_path, **overrides):
    """Runtime + secret + HTTP client fixtures sharing one consistent origin."""
    from test_upload_http import ORIGIN, make_upload_app

    overrides.setdefault("upload_reserve_bytes", 0)
    config = control_config(tmp_path, upload_origin=ORIGIN, **overrides)
    secret = generate_secret_offline(Path(config.data_dir))
    ensure_owned_staging(Path(config.input_dir))
    runtime = UploadRuntime(config)
    runtime.start()
    runtime.baseline_ready = True
    from test_upload_http import Client
    client = Client(make_upload_app(runtime))
    client.login(secret)
    return config, runtime, client


def pumping_owner(tmp_path, config, runtime, poll_interval=0.05):
    owner = UploadRuntimeOwner(config, config_path=tmp_path / "config.toml",
                               runtime=runtime, stop_event=threading.Event(),
                               poll_interval=poll_interval)
    owner.start_pump()
    return owner


def public_record(client, upload_id):
    status, _, payload = client.request("GET", f"/api/v1/uploads/{upload_id}")
    assert status == 200, payload
    return payload


def test_production_pump_expires_stalled_transfer(tmp_path):
    """The inactivity clock is enforced by the production owner pump itself —
    never by the transfer_record test seam — and reports the timeout."""
    import asyncio

    from test_upload_http import OpenBodyStream

    config, runtime, client = http_runtime(tmp_path, upload_inactivity_seconds=0.3)
    status, _, registration = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "stalled.mp3", "file_bytes": 64})
    assert status == 201
    upload_id = registration["upload_id"]

    opened = threading.Event()
    release = threading.Event()

    def stalled_body():
        async def scenario():
            async with OpenBodyStream(client, upload_id, registration["transfer_token"]):
                opened.set()
                assert release.wait(15)
        asyncio.run(scenario())

    thread = threading.Thread(target=stalled_body, daemon=True)
    thread.start()
    assert opened.wait(5), "the stalled body request was never opened"

    owner = pumping_owner(tmp_path, config, runtime)
    try:
        deadline = time.monotonic() + 10
        record = {}
        while time.monotonic() < deadline:
            record = public_record(client, upload_id)
            if record["state"] in ("cancelled", "failed"):
                break
            time.sleep(0.05)
        assert record["state"] == "cancelled", record
        assert record["error_code"] == "timed_out", \
            "the browser must see the truthful timeout outcome"
        assert runtime.reservations.active == 0, "the slot must be released"
        staging = Path(config.input_dir) / ".audioscribe-upload-staging"
        assert not list(staging.glob(f"{upload_id}*")), "staging must be cleaned"
    finally:
        owner.close()
        release.set()
        thread.join(5)


def client_request_session(runtime, client):
    import hashlib

    presented = client.cookie.split("=", 1)[-1]
    key = hashlib.sha256(presented.encode("latin-1")).hexdigest()
    return runtime.sessions[key]

def test_production_pump_freezes_on_external_consumption(tmp_path):
    """The reserve monitor runs on the production pump: when an external
    consumer breaches the protected reserve, admission freezes and every
    unpublished transfer is cancelled."""
    config, runtime, client = http_runtime(tmp_path, upload_reserve_bytes=1000)
    status, _, registration = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "victim.mp3", "file_bytes": 100_000})
    assert status == 201
    upload_id = registration["upload_id"]
    original_free = runtime._free_bytes
    runtime._free_bytes = lambda: 0  # external consumer drained the disk
    owner = pumping_owner(tmp_path, config, runtime)
    try:
        deadline = time.monotonic() + 10
        record = {}
        while time.monotonic() < deadline:
            record = public_record(client, upload_id)
            if record["state"] in ("cancelled", "failed"):
                break
            time.sleep(0.05)
        assert record["state"] == "cancelled", record
        assert runtime.frozen is True, "admission must stay frozen after the breach"
        assert runtime.reservations.active == 0
        with pytest.raises(HttpError) as error:
            runtime.register(client_request_session(runtime, client), "next.mp3", 10)
        assert error.value.status == 503
    finally:
        owner.close()
        runtime._free_bytes = original_free


# -- step 6: enable validation before persistence; secret display contract -----


class _StubListener:
    """Listener seam: never binds a socket; records start/stop."""

    def __init__(self, runtime, config):
        self.runtime, self.config = runtime, config
        self.stopped = False

    def stop(self):
        self.stopped = True


def write_ack_file(mailbox, command_id, response):
    (mailbox / f"{command_id}.ack.json").write_text(json.dumps(response), encoding="utf-8")


def test_owner_enable_rejects_shipped_empty_origin_before_persisting(tmp_path):
    """The shipped default upload_origin="" must fail the enable before any
    verifier is installed or enabled=true is persisted: Config.load must
    still succeed afterwards (no bricked service)."""
    config = control_config(tmp_path, upload_origin="")
    config_path = save_config(config, tmp_path / "config.toml")
    controller = UploadController(config, config_path)
    outcome = controller.enable()
    assert outcome.outcome == "rejected", outcome.public()
    assert outcome.secret is None, "a rejected enable must not display a secret"
    assert not verifier_installed(controller.data_dir), \
        "no verifier may be installed by a failed enable"
    persisted = Config.load(config_path)
    assert persisted.upload_enabled is False
    assert not (controller.data_dir / "upload-enable-snapshot.json").exists()


def test_owner_enable_rejects_non_ts_net_origin(tmp_path):
    config = control_config(tmp_path, upload_origin="https://audioscribe.example.com")
    config_path = save_config(config, tmp_path / "config.toml")
    controller = UploadController(config, config_path)
    outcome = controller.enable()
    assert outcome.outcome == "rejected"
    assert not verifier_installed(controller.data_dir)
    assert Config.load(config_path).upload_enabled is False


def test_owner_enable_preflight_failure_leaves_no_partial_verifier(tmp_path, monkeypatch):
    """The verifier is installed only after the whole preflight succeeds;
    a mount-probe failure must not leak a partial credential state."""
    config = control_config(tmp_path)
    config_path = save_config(config, tmp_path / "config.toml")
    controller = UploadController(config, config_path)
    monkeypatch.setattr(controller, "_preflight_mount",
                        lambda _config: (_ for _ in ()).throw(OSError("probe failed")))
    outcome = controller.enable()
    assert outcome.outcome == "rejected"
    assert outcome.secret is None
    assert not verifier_installed(controller.data_dir)
    assert Config.load(config_path).upload_enabled is False


def test_active_enable_rejects_empty_origin_without_persisting(tmp_path):
    service = ActiveService(tmp_path, enabled=False)
    try:
        service.config.upload_origin = ""
        service.config.save(service.config_path)
        controller = UploadController(
            service.config.__class__.load(service.config_path), service.config_path)
        outcome = controller.enable()
        assert outcome.outcome == "rejected", outcome.public()
        assert outcome.secret is None
        assert service.owner.listener is None
        # The fixture pre-installed a verifier; the failed enable must not
        # persist enabled=true, write a snapshot or create an unloadable config.
        assert not (service.data_dir / "upload-enable-snapshot.json").exists()
        persisted = service.config.__class__.load(service.config_path)
        assert persisted.upload_enabled is False
    finally:
        service.close()


def test_active_enable_uses_the_persisted_config_object_it_saves(tmp_path, monkeypatch):
    """F4: the active enable path must load once, validate the enabled
    candidate built from that load, adopt it for the live listener/snapshot
    and persist the same object — the documented disable → edit-origin →
    enable flow must bring the new origin live without a restart."""
    import audioscribe.upload.runtime as runtime_module
    from test_upload_http import Client, make_upload_app

    monkeypatch.setattr(runtime_module, "DEFAULT_LISTENER_FACTORY",
                        _StubListener, raising=False)
    service = ActiveService(tmp_path, enabled=False)
    try:
        controller = UploadController(service.config, service.config_path)
        first = controller.enable()
        assert first.outcome == "acknowledged", first.public()
        disabled = controller.disable(force=True)
        assert disabled.outcome == "acknowledged", disabled.public()

        edited = service.config.__class__.load(service.config_path)
        edited.upload_origin = "https://renamed.example.ts.net"
        edited.upload_enabled = False
        edited.save(service.config_path)

        second = controller.enable()
        assert second.outcome == "acknowledged", second.public()

        persisted = service.config.__class__.load(service.config_path)
        assert persisted.upload_enabled is True
        assert persisted.upload_origin == "https://renamed.example.ts.net"
        assert service.owner.config.upload_origin == "https://renamed.example.ts.net"
        assert service.runtime.config.upload_origin == "https://renamed.example.ts.net", \
            "the live listener must serve the persisted origin, not a stale one"
        assert service.owner.snapshot["origin"] == "https://renamed.example.ts.net"
        assert service.runtime.enable_snapshot["origin"] == "https://renamed.example.ts.net"

        # The live app certifies the new Host and refuses the stale one.
        new_client = Client(make_upload_app(service.runtime),
                            host="renamed.example.ts.net")
        status, _, _ = new_client.request("GET", "/", auth=False, csrf=False, origin=None)
        assert status == 200
        stale_client = Client(make_upload_app(service.runtime),
                              host="scribe.example.ts.net")
        status, _, _ = stale_client.request("GET", "/", auth=False, csrf=False, origin=None)
        assert status == 403

        # End to end: the reopened admission registers under the new origin.
        status, _, challenge = new_client.request(
            "GET", "/api/v1/auth/challenge", auth=False, csrf=False, origin=None)
        assert status == 200
        status, _, payload = new_client.request(
            "POST", "/api/v1/auth/login", auth=False, csrf=False,
            origin="https://renamed.example.ts.net",
            json_body={"secret": service.secret, "csrf": challenge["nonce"]})
        assert status == 200, payload
        new_client.csrf = payload["csrf"]
        status, _, registration = new_client.request(
            "POST", "/api/v1/uploads", origin="https://renamed.example.ts.net",
            json_body={"filename": "nuevo.mp3", "file_bytes": 64})
        assert status == 201, registration
    finally:
        service.close()


def test_active_enable_refuses_invalid_on_disk_origin_without_bricking(tmp_path, monkeypatch):
    """F4 inverse: an invalid origin edited on disk while disabled must be
    refused by the active enable path — it validates the exact object it would
    persist — and Config.load of the rewritten file must still succeed."""
    import audioscribe.upload.runtime as runtime_module

    monkeypatch.setattr(runtime_module, "DEFAULT_LISTENER_FACTORY",
                        _StubListener, raising=False)
    service = ActiveService(tmp_path, enabled=False)
    try:
        edited = service.config.__class__.load(service.config_path)
        edited.upload_origin = ""
        edited.upload_enabled = False
        edited.save(service.config_path)
        controller = UploadController(service.config, service.config_path)
        outcome = controller.enable()
        assert outcome.outcome == "rejected", outcome.public()
        assert outcome.secret is None
        assert service.owner.listener is None
        assert service.runtime.config.upload_origin == "https://scribe.example.ts.net", \
            "an invalid on-disk candidate must never be adopted"
        assert not (service.data_dir / "upload-enable-snapshot.json").exists()
        persisted = service.config.__class__.load(service.config_path)
        assert persisted.upload_enabled is False, \
            "no bricked enabled=true may be persisted"
    finally:
        service.close()


def test_disable_then_enable_rebuilds_derived_state_from_persisted_config(tmp_path, monkeypatch):
    """B1: a disabled edit to upload_reserve_bytes and input_dir must be
    adopted beyond runtime.config on re-enable: the live reservation
    protection, the staging root and every registered .part file must follow
    the persisted/snapshot values, not the previous generation."""
    import audioscribe.upload.runtime as runtime_module
    from test_upload_http import Client, make_upload_app

    origin = "https://scribe.example.ts.net"
    monkeypatch.setattr(runtime_module, "DEFAULT_LISTENER_FACTORY",
                        _StubListener, raising=False)
    service = ActiveService(tmp_path, enabled=False)
    try:
        controller = UploadController(service.config, service.config_path)
        assert controller.enable().outcome == "acknowledged"
        assert controller.disable(force=True).outcome == "acknowledged"

        new_input = tmp_path / "new-input"
        new_input.mkdir()
        edited = service.config.__class__.load(service.config_path)
        edited.input_dir = str(new_input)
        edited.upload_reserve_bytes = 1234
        edited.upload_enabled = False
        edited.save(service.config_path)

        enabled = controller.enable()
        assert enabled.outcome == "acknowledged", enabled.public()

        persisted = service.config.__class__.load(service.config_path)
        assert persisted.upload_reserve_bytes == 1234
        assert persisted.input_dir == str(new_input.resolve())
        new_staging = new_input.resolve() / ".audioscribe-upload-staging"
        assert service.runtime.reservations.reserve_bytes == 1234, \
            "the live reserve protection must follow the persisted limit"
        assert service.runtime.staging == new_staging, \
            "the staging root must follow the persisted input directory"
        for snapshot in (service.owner.snapshot, service.runtime.enable_snapshot):
            assert snapshot["reserve_bytes"] == 1234
            assert snapshot["input_dir"] == str(new_input.resolve())

        # End to end: the reopened admission must stage under the NEW root.
        client = Client(make_upload_app(service.runtime), host="scribe.example.ts.net")
        status, _, challenge = client.request(
            "GET", "/api/v1/auth/challenge", auth=False, csrf=False, origin=None)
        assert status == 200
        status, _, payload = client.request(
            "POST", "/api/v1/auth/login", auth=False, csrf=False, origin=origin,
            json_body={"secret": service.secret, "csrf": challenge["nonce"]})
        assert status == 200, payload
        client.csrf = payload["csrf"]
        status, _, registration = client.request(
            "POST", "/api/v1/uploads", origin=origin,
            json_body={"filename": "nuevo.mp4", "file_bytes": 64})
        assert status == 201, registration
        transfer = next(t for t in service.runtime.transfers.values()
                        if t.state == "reserved")
        assert transfer.part_path is not None and transfer.part_path.exists()
        assert transfer.part_path.is_relative_to(new_staging), \
            "a registered .part must land under the persisted input root"
        assert service.runtime.reservations.active == 1
        service.runtime.cancel_transfer(transfer)
        assert service.runtime.reservations.active == 0
    finally:
        service.close()


def test_active_enable_refuses_data_dir_change_without_adoption(tmp_path, monkeypatch):
    """data_dir anchors the running process identity (InstanceLock, command
    mailbox, verifier, revision): an enable whose candidate moves it must be
    refused fail-closed instead of half-adopting derived upload state — the
    operator's edit is honored by the next service restart."""
    import audioscribe.upload.runtime as runtime_module

    monkeypatch.setattr(runtime_module, "DEFAULT_LISTENER_FACTORY",
                        _StubListener, raising=False)
    service = ActiveService(tmp_path, enabled=False)
    try:
        owner = service.owner
        assert owner._command_disable(True)["outcome"] == "acknowledged"
        edited = service.config.__class__.load(service.config_path)
        edited.data_dir = str(tmp_path / "moved-data")
        edited.upload_enabled = False
        edited.save(service.config_path)

        result = owner._command_enable({})
        assert result["outcome"] == "rejected", result
        assert result["detail"] == "data_dir_changed_restart_required"
        assert owner.data_dir == service.data_dir
        assert owner.mailbox == service.data_dir / "upload-mailbox"
        assert owner.listener is None
        assert Path(owner.config.data_dir) == service.data_dir
        assert Path(owner.runtime.config.data_dir) == service.data_dir
        assert owner.runtime.reservations.reserve_bytes == 0
        assert verifier_installed(service.data_dir)
        assert not (tmp_path / "moved-data" / "upload-mailbox").exists()
        assert not (tmp_path / "moved-data" / "upload-enable-snapshot.json").exists()
        assert not (service.data_dir / "upload-enable-snapshot.json").exists()
        assert Config.load(service.config_path).upload_enabled is False
    finally:
        service.close()


def test_rejected_enable_ack_discards_the_memory_secret(tmp_path):
    """The caller displays its secret only after a matching acknowledged
    enable; a rejected acknowledgement discards it (A2)."""
    service = ActiveService(tmp_path, pump=False)
    try:
        (service.data_dir / "upload-auth" / "verifier.json").unlink(missing_ok=True)
        controller = UploadController(service.config, service.config_path, ack_timeout=5)
        result = {}

        def call():
            result["outcome"] = controller.enable()

        thread = threading.Thread(target=call)
        thread.start()
        mailbox = service.data_dir / "upload-mailbox"
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not list(mailbox.glob("*.request.json")):
            time.sleep(0.02)
        request_path = next(iter(mailbox.glob("*.request.json")))
        command_id = request_path.name[: -len(".request.json")]
        write_ack_file(mailbox, command_id, {"id": command_id, "revision": 0,
                                             "outcome": "rejected",
                                             "detail": "enable failed: OSError"})
        thread.join(10)
        outcome = result["outcome"]
        assert outcome.outcome == "rejected"
        assert outcome.secret is None, "a rejected enable must discard the secret"
    finally:
        service.close()


def test_uncertain_enable_never_carries_a_secret(tmp_path):
    service = ActiveService(tmp_path)
    try:
        service.owner.close()
        (service.data_dir / "upload-auth" / "verifier.json").unlink(missing_ok=True)
        controller = UploadController(service.config, service.config_path, ack_timeout=0.3)
        outcome = controller.enable()
        assert outcome.outcome == "uncertain"
        assert outcome.secret is None
    finally:
        service.close()


def test_panel_enable_displays_the_generated_secret_once(tmp_path, monkeypatch):
    """PLAN-03 parity: the panel enable path must display the generated secret
    exactly like the CLI and the regenerate path."""
    from audioscribe import dashboard as dashboard_module
    from audioscribe.upload.controller import CommandOutcome

    recorded = []
    monkeypatch.setattr(dashboard_module.messagebox, "showinfo",
                        lambda *args, **kwargs: recorded.append(args))
    monkeypatch.setattr(dashboard_module.messagebox, "showerror",
                        lambda *args, **kwargs: recorded.append(args))
    monkeypatch.setattr(dashboard_module.messagebox, "showwarning",
                        lambda *args, **kwargs: recorded.append(args))
    dash = dashboard_module.Dashboard.__new__(dashboard_module.Dashboard)
    dash.root = None

    dash.show_upload_outcome("upload_enable", CommandOutcome("acknowledged", secret="S" * 43))
    assert any("S" * 43 in str(args) for args in recorded), \
        "panel enable must display the generated secret once"

    recorded.clear()
    dash.show_upload_outcome("upload_regenerate", CommandOutcome("acknowledged", secret="R" * 43))
    assert any("R" * 43 in str(args) for args in recorded)

    recorded.clear()
    dash.show_upload_outcome("upload_enable", CommandOutcome("rejected", detail="enable failed"))
    assert all("S" * 43 not in str(args) for args in recorded)


def test_cli_rejected_enable_prints_no_secret(tmp_path, capsys, monkeypatch):
    service = ActiveService(tmp_path, pump=False)
    try:
        (service.data_dir / "upload-auth" / "verifier.json").unlink(missing_ok=True)
        import audioscribe.upload.controller as controller_module
        monkeypatch.setattr(controller_module.UploadController, "enable",
                            lambda self: controller_module.CommandOutcome(
                                "rejected", detail="enable failed: OSError",
                                secret="LEAK" * 11))
        import audioscribe.cli as cli_module
        cli_module.main(["--config", str(service.config_path), "upload", "enable"])
        output = capsys.readouterr().out
        assert "LEAK" not in output, "the CLI must not print a secret for a rejected enable"
    finally:
        service.close()


# -- step 7: atomic disable/close with runtime admission -----------------------


def _safe_disable(owner):
    try:
        return owner._command_disable(True)
    except Exception as error:  # surface thread failures to the assertion
        return error


def test_disable_command_closes_runtime_admission_atomically(tmp_path):
    """_command_disable must route through the runtime admission gate so
    runtime.admission_closed is set under the same guard as the active count;
    a registration racing the disable decision is cancelled by the same
    disable, and any later registration is refused."""
    _config, runtime, owner = make_runtime(tmp_path)
    _config.save(tmp_path / "config.toml")  # the disable persists here
    try:
        session = make_session(runtime)
        entered = threading.Event()
        release = threading.Event()
        runtime.admission_probe = lambda: (entered.set(), release.wait(10))
        admitted = {}
        admission = threading.Thread(
            target=lambda: admitted.setdefault("transfer",
                                               runtime.register(session, "race.mp3", 64)))
        admission.start()
        assert entered.wait(5), "the racing registration never reached the guard"

        outcome = {}
        disabler = threading.Thread(
            target=lambda: outcome.update(disable=_safe_disable(owner)))
        disabler.start()
        time.sleep(0.2)  # the disable decision blocks on the same state guard
        release.set()
        admission.join(5)
        disabler.join(5)
        transfer = admitted.get("transfer")
        assert transfer is not None, "the racing registration never completed"
        disable_result = outcome.get("disable")
        if isinstance(disable_result, Exception):
            raise disable_result
        result = disable_result
        assert result["outcome"] == "acknowledged", result
        assert transfer.state == "cancelled", \
            "a transfer admitted during the decision must be cancelled by the disable"
        assert runtime.admission_closed is True, \
            "disable must close RUNTIME admission under the state guard"
        assert owner.admission_closed is True
        assert runtime.active_unpublished_count() == 0
        with pytest.raises(HttpError) as error:
            runtime.register(session, "late.mp3", 10)
        assert error.value.status == 409
    finally:
        owner.close()


def test_unforced_disable_refusal_leaves_admission_open(tmp_path):
    _config, runtime, owner = make_runtime(tmp_path)
    try:
        session = make_session(runtime)
        transfer = runtime.register(session, "busy.mp3", 64)
        result = owner._command_disable(False)
        assert result["outcome"] == "rejected"
        assert result["detail"] == "active_uploads"
        assert runtime.admission_closed is False, \
            "a refused disable must not close admission"
        assert owner.stop_refusals == 1
        assert transfer.state == "reserved"
    finally:
        owner.close()


def test_owner_close_sets_runtime_admission_closed(tmp_path):
    _config, runtime, owner = make_runtime(tmp_path)
    session = make_session(runtime)
    runtime.register(session, "drain.mp3", 16)
    owner.close()
    assert runtime.admission_closed is True
    assert runtime.active_unpublished_count() == 0


def test_disable_then_enable_reopens_upload_admission(tmp_path, monkeypatch):
    """F1: a successful enable must reopen the admission gate that disable
    closed, so the documented disable → fix → enable flow serves uploads
    again instead of answering 409 forever."""
    import audioscribe.upload.runtime as runtime_module

    _config, runtime, owner = make_runtime(tmp_path)
    _config.save(tmp_path / "config.toml")  # the enable persists here
    try:
        session = make_session(runtime)
        outcome = owner._command_disable(True)
        assert outcome["outcome"] == "acknowledged", outcome
        assert runtime.admission_closed is True
        assert owner.admission_closed is True
        monkeypatch.setattr(runtime_module, "DEFAULT_LISTENER_FACTORY",
                            _StubListener, raising=False)
        enabled = owner._command_enable({})
        assert enabled["outcome"] == "acknowledged", enabled
        assert runtime.admission_closed is False, \
            "a successful enable must reopen runtime admission"
        assert owner.admission_closed is False, \
            "a successful enable must reopen owner admission"
        transfer = runtime.register(session, "again.mp3", 32)  # must not be a 409
        assert transfer.state == "reserved"
        runtime.cancel_transfer(transfer)
        assert runtime.reservations.active == 0
    finally:
        owner.close()
