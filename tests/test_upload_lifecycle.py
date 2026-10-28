"""PLAN-03 step 3: expiry, logout and rotation at publication linearization."""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import threading
import time
from pathlib import Path

import pytest

from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.http import HttpError, UploadRuntime, make_upload_app

from test_upload_http import ORIGIN, Client, OpenBodyStream, make_config
from test_upload_control import validation_stub


class WallClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_lifecycle_runtime(tmp_path, clock, **overrides):
    from audioscribe.upload.capabilities import ensure_owned_staging
    from audioscribe.upload.resources import DiskReservations
    tmp_path = Path(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    overrides.setdefault("upload_reserve_bytes", 0)
    config = make_config(tmp_path, **overrides)
    secret = generate_secret_offline(Path(config.data_dir))
    ensure_owned_staging(Path(config.input_dir))
    runtime = UploadRuntime(config, reservations=DiskReservations(config.upload_reserve_bytes),
                            wall_fn=clock)
    runtime.start()
    runtime.mark_baseline_ready()
    return config, secret, runtime


@pytest.fixture
def stubbed_validation(monkeypatch):
    import audioscribe.upload.http as http_module
    monkeypatch.setattr(http_module, "validate_staged_media",
                        lambda path, suffix: validation_stub())


def register_upload(client, name="clip.mp3", file_bytes=64):
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": name, "file_bytes": file_bytes})
    assert status == 201, payload
    return payload


def login_with(client, secret, proof=None):
    status, _, payload = client.request("GET", "/api/v1/auth/challenge", auth=False, csrf=False)
    assert status == 200
    body = {"secret": secret, "csrf": payload["nonce"]}
    if proof is not None:
        body["continuity_proof"] = proof
    status, _, payload = client.request("POST", "/api/v1/auth/login", auth=False, csrf=False,
                                        json_body=body)
    if status == 200:
        client.csrf = payload["csrf"]
    return status, payload


def run_body_to_completion(client, upload_id, token, chunks, midstream=None):
    async def scenario():
        async with OpenBodyStream(client, upload_id, token) as stream:
            for index, chunk in enumerate(chunks):
                if index == 1 and midstream is not None:
                    midstream()
                await stream.send(chunk)
            return await stream.finish()

    return asyncio.run(scenario())


def response_status(sent):
    return next(m["status"] for m in sent if m["type"] == "http.response.start")


def test_natural_expiry_transfer_only(tmp_path, stubbed_validation):
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    registration = register_upload(client)
    sent = run_body_to_completion(client, registration["upload_id"],
                                  registration["transfer_token"],
                                  [b"x" * 32, b"x" * 32],
                                  midstream=lambda: clock.advance(24 * 3600 + 1))
    assert response_status(sent) == 200
    record = json.loads(next(m["body"] for m in sent if m["type"] == "http.response.body"))
    assert record["state"] == "published"
    assert (Path(config.input_dir) / "clip.mp3").exists()
    # After natural expiry every subsequent browser action requires reauthentication.
    status, _, _ = client.request("GET", "/api/v1/status")
    assert status == 401
    status, _, _ = client.request("POST",
                                  f"/api/v1/uploads/{registration['upload_id']}/cancel",
                                  json_body={})
    assert status == 401
    status, _, _ = client.request("POST", "/api/v1/auth/logout", json_body={})
    assert status == 401
    status, _, _ = client.request("POST", "/api/v1/uploads", json_body={"filename": "n.mp3"})
    assert status == 401
    assert runtime.sessions == {}


def test_poll_does_not_renew_session(tmp_path, stubbed_validation):
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    for _ in range(23):
        clock.advance(3600)
        status, _, _ = client.request("GET", "/api/v1/status")
        assert status == 200
    clock.advance(3600)
    status, _, _ = client.request("GET", "/api/v1/status")
    assert status == 401, "polling must not renew the 24-hour idle window"

    config2, secret2, runtime2 = make_lifecycle_runtime(tmp_path / "renewed", clock)
    client2 = Client(make_upload_app(runtime2))
    client2.login(secret2)
    register_upload(client2)
    clock.advance(23 * 3600)
    status, _, _ = client2.request("GET", "/api/v1/status")
    assert status == 200
    clock.advance(2 * 3600)
    status, _, _ = client2.request("GET", "/api/v1/status")
    assert status == 401

    config3, secret3, runtime3 = make_lifecycle_runtime(tmp_path / "absolute", clock)
    client3 = Client(make_upload_app(runtime3))
    client3.login(secret3)
    created = list(runtime3.sessions.values())[0].created
    absolute_cap = created + 30 * 24 * 3600
    for hour in range(30 * 24 + 1):
        clock.advance(3600)
        if clock.now >= absolute_cap:
            status, _, _ = client3.request("GET", "/api/v1/status")
            assert status == 401, "the 30-day absolute cap must expire despite sliding renewal"
            break
        registration = register_upload(client3, "renew.mp3", file_bytes=8)
        client3.request("POST", f"/api/v1/uploads/{registration['upload_id']}/cancel",
                        json_body={})
        status, _, _ = client3.request("GET", "/api/v1/status")
        assert status == 200
    else:
        raise AssertionError("session outlived the 30-day absolute cap")


def test_logout_only_own_uploads(tmp_path, stubbed_validation):
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    app = make_upload_app(runtime)
    client_a, client_b = Client(app), Client(app)
    client_a.login(secret)
    client_b.login(secret)
    registration_a = register_upload(client_a, "a.mp3")
    registration_b = register_upload(client_b, "b.mp3")
    status, _, _ = client_a.request("POST", "/api/v1/auth/logout", json_body={})
    assert status == 200
    staging = Path(config.input_dir) / ".audioscribe-upload-staging"
    assert not (staging / f"{registration_a['upload_id']}.part").exists()
    status, _, record = client_b.request("GET", f"/api/v1/uploads/{registration_b['upload_id']}")
    assert status == 200 and record["state"] == "reserved"
    sent = run_body_to_completion(client_b, registration_b["upload_id"],
                                  registration_b["transfer_token"], [b"y" * 16])
    assert response_status(sent) == 200
    assert (Path(config.input_dir) / "b.mp3").exists()
    status, _, _ = client_a.request("GET", "/api/v1/status")
    assert status == 401


def test_rotation_revokes_all_before_publish(tmp_path, monkeypatch):
    import audioscribe.upload.http as http_module
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    entered = threading.Event()
    release = threading.Event()

    def blocked_validate(path, suffix):
        entered.set()
        assert release.wait(10)
        return validation_stub()

    monkeypatch.setattr(http_module, "validate_staged_media", blocked_validate)
    app = make_upload_app(runtime)
    client_a, client_b = Client(app), Client(app)
    client_a.login(secret)
    client_b.login(secret)
    registration_a = register_upload(client_a, "a.mp4")
    registration_b = register_upload(client_b, "b.mp4", file_bytes=16)

    async def start_validation():
        async with OpenBodyStream(client_a, registration_a["upload_id"],
                                  registration_a["transfer_token"]) as stream:
            await stream.send(b"x" * 32)
            sent = await stream.finish()
            return sent

    loop = asyncio.new_event_loop()
    publisher = loop.run_until_complete
    sent_holder = {}
    thread = threading.Thread(target=lambda: sent_holder.setdefault(
        "sent", publisher(start_validation())))
    thread.start()
    assert entered.wait(5), "validation barrier was never reached"

    async def start_b_receipt():
        async with OpenBodyStream(client_b, registration_b["upload_id"],
                                  registration_b["transfer_token"]) as stream:
            await stream.send(b"y" * 16)
            return stream

    # Keep B mid-receipt on its own loop.
    b_loop = asyncio.new_event_loop()
    b_stream = b_loop.run_until_complete(_open_stream(client_b, registration_b))

    raw = secrets.token_bytes(32)
    new_secret = bytes_b64(raw)
    new_verifier = hashlib.sha256(raw).hexdigest()
    runtime.rotate_credentials(new_verifier)
    assert runtime.auth_epoch == 1
    staging = Path(config.input_dir) / ".audioscribe-upload-staging"
    assert not (staging / f"{registration_a['upload_id']}.part").exists()
    assert not (staging / f"{registration_b['upload_id']}.part").exists()
    release.set()
    thread.join(5)
    sent = sent_holder["sent"]
    assert response_status(sent) == 409
    assert not list(Path(config.input_dir).glob("*.mp4"))
    status, _, _ = client_a.request("GET", "/api/v1/status")
    assert status == 401
    status, _, _ = client_b.request("GET", "/api/v1/status")
    assert status == 401
    fresh = Client(app)
    status, payload = login_with(fresh, secret)
    assert status == 401, "the old secret must fail after rotation"
    status, _payload = login_with(fresh, new_secret)
    assert status == 200
    b_loop.run_until_complete(b_stream.abort())
    b_loop.close()
    loop.close()


async def _open_stream(client, registration):
    stream = OpenBodyStream(client, registration["upload_id"], registration["transfer_token"])
    return await stream.__aenter__()


def bytes_b64(raw: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_reauth_preserves_transfer_cancel_logout_scope(tmp_path, stubbed_validation):
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    app = make_upload_app(runtime)
    client = Client(app)
    status, payload = login_with(client, secret)
    assert status == 200
    proof = payload.get("continuity_proof")
    assert proof and len(proof) == 43
    registration = register_upload(client, "keep.mp3", file_bytes=16)
    upload_id = registration["upload_id"]
    clock.advance(24 * 3600 + 1)

    fresh = Client(app)
    status, payload2 = login_with(fresh, secret, proof=proof)
    assert status == 200
    new_proof = payload2["continuity_proof"]
    assert new_proof and new_proof != proof
    status, _, outcome = fresh.request("POST", f"/api/v1/uploads/{upload_id}/cancel",
                                       json_body={})
    assert status == 200 and outcome["result"] == "cancelled", \
        "reauthentication must preserve cancel ownership across natural expiry"
    status, _, _ = fresh.request("GET", "/api/v1/status")
    assert status == 200

    # Proof alone authorizes nothing.
    proof_only = Client(app)
    status, _, _ = proof_only.request("GET", "/api/v1/status", auth=False, csrf=False,
                                      headers=[(b"x-continuity-proof", proof.encode())])
    assert status == 401
    status, _ = login_with(proof_only, "", proof=proof)
    assert status == 401

    # Failed reauthentication preserves live session timestamps.
    live = Client(app)
    status, _ = login_with(live, secret)
    assert status == 200
    session = next(iter(runtime.sessions.values()))
    created, last_seen = session.created, session.last_seen
    status, _ = login_with(live, wrong_secret_for(runtime))
    assert status == 401
    assert (session.created, session.last_seen) == (created, last_seen)

    # Logout revokes the lineage and its continuity proofs.
    second = register_upload(fresh, "second.mp3", file_bytes=16)
    status, _, _ = fresh.request("POST", "/api/v1/auth/logout", json_body={})
    assert status == 200
    assert not (Path(config.input_dir) / ".audioscribe-upload-staging" / f"{second['upload_id']}.part").exists()
    after = Client(app)
    status, _ = login_with(after, secret, proof=new_proof)
    assert status == 200, "a revoked proof means no continuity, not loss of secret access"
    status, _, _ = after.request("GET", f"/api/v1/uploads/{second['upload_id']}")
    assert status == 404, "reauthentication with a revoked proof must not restore the old lineage"


def wrong_secret_for(runtime):
    import base64
    raw = secrets.token_bytes(32)
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# -- step 5b: publication failure cleanup and A6 pre-link rechecks -------------


def test_publication_failure_cleans_up_and_records_history(tmp_path, stubbed_validation, monkeypatch):
    """On a publication I/O failure the staging is deleted, the reservation is
    released (with the lock), and a truthful failed outcome is recorded —
    nothing leaks and the dashboard stops counting the transfer."""
    import audioscribe.upload.http as http_module

    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    app = make_upload_app(runtime)
    client = Client(app)
    client.login(secret)
    registration = register_upload(client, "crash.mp3", file_bytes=16)
    upload_id = registration["upload_id"]

    def broken_publish(staging_path, root, final_name):
        raise OSError("injected link failure")

    monkeypatch.setattr(http_module, "publish_atomically", broken_publish)
    sent = run_body_to_completion(client, upload_id, registration["transfer_token"],
                                  [b"x" * 16])
    assert response_status(sent) == 409
    record = json.loads(next(m["body"] for m in sent if m["type"] == "http.response.body"))
    assert record["error"] == "cleanup_failed"
    assert transfer_state(runtime, upload_id) == "failed"
    assert runtime.reservations.active == 0, "the reservation must be released"
    staging = Path(config.input_dir) / ".audioscribe-upload-staging"
    assert not list(staging.glob(f"{upload_id}*")), "staging must be cleaned"
    assert runtime.history, "the failure must be recorded in shared history"
    assert runtime.history[-1]["outcome"] == "failed"
    assert runtime.history[-1]["error_code"] == "cleanup_failed"
    assert runtime.active_unpublished_count() == 0


def transfer_state(runtime, upload_id):
    transfer = runtime.transfers.get(upload_id)
    return transfer.state if transfer is not None else "pruned"


def test_publication_refused_after_root_retarget(tmp_path, stubbed_validation):
    """A6: publication rechecks the enable snapshot's root identity under the
    publication guard; a retargeted root forbids the link."""
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    app = make_upload_app(runtime)
    client = Client(app)
    client.login(secret)
    registration = register_upload(client, "moved.mp3", file_bytes=16)
    upload_id = registration["upload_id"]
    runtime.enable_snapshot = {"format": 1, "root_device": 999, "root_inode": 999,
                               "input_dir": str(Path(config.input_dir))}
    sent = run_body_to_completion(client, upload_id, registration["transfer_token"],
                                  [b"x" * 16])
    assert response_status(sent) == 409
    assert transfer_state(runtime, upload_id) == "cancelled"
    assert not (Path(config.input_dir) / "moved.mp3").exists()
    assert runtime.reservations.active == 0
    staging = Path(config.input_dir) / ".audioscribe-upload-staging"
    assert not list(staging.glob(f"{upload_id}*"))


def test_publication_refused_on_reserve_breach(tmp_path, stubbed_validation, monkeypatch):
    """A6: coherent disk capacity is rechecked immediately before the link;
    a breach freezes admission and cancels instead of publishing."""
    import shutil as shutil_module

    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock,
                                                     upload_reserve_bytes=1000)
    app = make_upload_app(runtime)
    client = Client(app)
    client.login(secret)
    registration = register_upload(client, "breach.mp3", file_bytes=16)
    upload_id = registration["upload_id"]

    real_free = shutil_module.disk_usage(config.input_dir).free
    samples = {"n": 0}

    def breached_at_publication():
        # The register sample precedes this patch; the two per-chunk write
        # samples see a healthy disk, the publication recheck does not.
        samples["n"] += 1
        return real_free if samples["n"] < 3 else 0

    monkeypatch.setattr(runtime, "_free_bytes", breached_at_publication)
    sent = run_body_to_completion(client, upload_id, registration["transfer_token"],
                                  [b"x" * 8, b"x" * 8])
    assert response_status(sent) == 507
    record = json.loads(next(m["body"] for m in sent if m["type"] == "http.response.body"))
    assert record["error"] == "reserve_unavailable"
    assert transfer_state(runtime, upload_id) == "cancelled"
    assert runtime.frozen is True, "a publication-time breach freezes admission"
    assert not (Path(config.input_dir) / "breach.mp3").exists()
    assert runtime.reservations.active == 0


def test_write_time_reserve_breach_reports_reserve_unavailable(tmp_path, stubbed_validation,
                                                               monkeypatch):
    """A write that would breach the protected reserve fails closed with the
    bounded 507 reserve-unavailable outcome instead of crashing the request,
    and the runtime freezes against further admission."""
    from audioscribe.upload.resources import UnsafeCapacityError

    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock,
                                                     upload_reserve_bytes=1 << 20)
    app = make_upload_app(runtime)
    client = Client(app)
    client.login(secret)
    registration = register_upload(client, "tight.mp3", file_bytes=64)
    upload_id = registration["upload_id"]

    def drained():
        return 0

    monkeypatch.setattr(runtime, "_free_bytes", drained)
    sent = run_body_to_completion(client, upload_id, registration["transfer_token"],
                                  [b"x" * 32])
    assert response_status(sent) == 507
    record = json.loads(next(m["body"] for m in sent if m["type"] == "http.response.body"))
    assert record["error"] == "reserve_unavailable"
    assert runtime.frozen is True
    assert runtime.reservations.active == 0
    assert transfer_state(runtime, upload_id) in ("cancelled", "failed")


# -- step 4: startup ordering, configuration safety and A9 persistence --------


def service_config(tmp_path, **overrides):
    from test_upload_control import control_config
    overrides.setdefault("upload_origin", ORIGIN)
    overrides.setdefault("upload_reserve_bytes", 0)
    return control_config(tmp_path, **overrides)


class RecordingListener:
    instances = []

    def __init__(self, runtime, config):
        self.runtime, self.config = runtime, config
        self.stopped = False
        assert runtime.baseline_ready, "listener must start only after baseline readiness"
        RecordingListener.instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []

    def stop(self):
        self.stopped = True


class QuietEngine:
    def __init__(self, config):
        self.config = config

    def process(self, job, report, stopped):
        report("Prueba de persistencia")
        from audioscribe.config import atomic_write
        path = Path(self.config.output_dir) / f"{job['id']}.md"
        atomic_write(path, "**Hablante 1:** texto de prueba")
        return path


def test_transcription_pause_keeps_upload_admission(tmp_path, monkeypatch):
    from audioscribe.config import atomic_write
    from audioscribe.service import run
    from test_upload_control import control_config
    RecordingListener.reset()
    config = service_config(tmp_path, upload_enabled=True)
    config_path = tmp_path / "config.toml"
    config.save(config_path)
    known_secret = fresh_secret_for(config)
    monkeypatch.setattr("audioscribe.upload.runtime.DEFAULT_LISTENER_FACTORY",
                        RecordingListener, raising=False)
    atomic_write(Path(config.data_dir) / "pause.request", "pause\n")
    errors = []

    def target():
        try:
            run(config, engine_factory=QuietEngine, config_path=config_path)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=target)
    thread.start()
    published = None
    try:
        assert wait_until(lambda: bool(RecordingListener.instances))
        listener = RecordingListener.instances[0]
        import audioscribe.upload.http as http_module
        monkeypatch.setattr(http_module, "validate_staged_media",
                            lambda path, suffix: validation_stub())
        client = Client(make_upload_app(listener.runtime))
        status, payload = login_with(client, known_secret)
        assert status == 200
        registration = register_upload(client, "paused.mp3", file_bytes=16)
        sent = run_body_to_completion(client, registration["upload_id"],
                                      registration["transfer_token"], [b"z" * 16])
        assert response_status(sent) == 200
        published = Path(config.input_dir) / "paused.mp3"
        assert published.exists()
        assert wait_until(lambda: _job_count(config) >= 1), \
            "scanning must admit the published upload while transcription is paused"
        time.sleep(1.0)
        from audioscribe.store import Store
        store = Store(config.database)
        try:
            states = [row["state"] for row in store.db.execute("SELECT state FROM jobs")]
        finally:
            store.close()
        assert states == ["pending"], "pause must hold transcription without disabling uploads"
    finally:
        (Path(config.data_dir) / "pause.request").unlink(missing_ok=True)
        from audioscribe.control import request
        request(Path(config.data_dir), "stop", force=True)
        thread.join(15)
    assert not errors and not thread.is_alive()


def fresh_secret_for(config):
    """The generated secret cannot be recovered from the verifier; install a
    fresh known one for the paused-service session."""
    import base64
    import hashlib
    import secrets as secrets_module
    from audioscribe.upload.auth import install_verifier
    raw = secrets_module.token_bytes(32)
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    install_verifier(Path(config.data_dir), hashlib.sha256(raw).hexdigest(), replace=True)
    return encoded


def wait_until(predicate, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def test_enabled_restart_after_baseline(tmp_path, monkeypatch):
    from audioscribe.service import run
    RecordingListener.reset()
    config = service_config(tmp_path, upload_enabled=True)
    config_path = tmp_path / "config.toml"
    config.save(config_path)
    generate_secret_offline(Path(config.data_dir))
    monkeypatch.setattr("audioscribe.upload.runtime.DEFAULT_LISTENER_FACTORY",
                        RecordingListener, raising=False)
    errors = []

    def target():
        try:
            run(config, engine_factory=QuietEngine, config_path=config_path)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=target)
    thread.start()
    try:
        assert wait_until(lambda: bool(RecordingListener.instances)), \
            "enabled service must start its listener after baseline"
        listener = RecordingListener.instances[0]
        assert listener.runtime.baseline_ready is True
        assert (Path(config.input_dir) / ".audioscribe-upload-staging").is_dir()
        status, _, _ = client_request_status(listener)
        assert status == 401
    finally:
        from audioscribe.control import request
        request(Path(config.data_dir), "stop", force=True)
        thread.join(15)
    assert not errors and not thread.is_alive()
    assert RecordingListener.instances[0].stopped


def client_request_status(listener):
    from test_upload_http import Client
    from audioscribe.upload.http import make_upload_app
    client = Client(make_upload_app(listener.runtime), host="audioscribe.example.ts.net")
    return client.request("GET", "/api/v1/status")


def test_once_never_starts_listener(tmp_path, monkeypatch):
    import sys

    from audioscribe.service import run
    RecordingListener.reset()
    config = service_config(tmp_path, upload_enabled=True)
    config_path = tmp_path / "config.toml"
    config.save(config_path)
    generate_secret_offline(Path(config.data_dir))
    monkeypatch.setattr("audioscribe.upload.runtime.DEFAULT_LISTENER_FACTORY",
                        RecordingListener, raising=False)
    modules_before = set(sys.modules)
    run(config, once=True, config_path=config_path)
    source = Path(config.input_dir) / "nuevo.mp3"
    source.write_bytes(b"audio")
    run(config, once=True, config_path=config_path)
    time.sleep(1.2)
    run(config, once=True, config_path=config_path)
    assert RecordingListener.instances == []
    assert not (Path(config.data_dir) / "upload-mailbox").exists()
    from audioscribe.store import Store
    store = Store(config.database)
    try:
        waiting = store.db.execute("SELECT count(*) FROM jobs").fetchone()[0]
    finally:
        store.close()
    assert waiting == 1, "once mode must keep normal scan/enqueue behavior"
    assert not any(name == "uvicorn" or name == "av" for name in set(sys.modules) - modules_before)


def test_enabled_capability_failure_preserves_desired_state(tmp_path, monkeypatch):
    from audioscribe.service import run
    RecordingListener.reset()
    config = service_config(tmp_path, upload_enabled=True)
    config_path = tmp_path / "config.toml"
    config.save(config_path)
    generate_secret_offline(Path(config.data_dir))
    # A preexisting unowned staging directory fails enable without hiding user files.
    staging = Path(config.input_dir) / ".audioscribe-upload-staging"
    staging.mkdir()
    (staging / "user-file.txt").write_text("user data")
    monkeypatch.setattr("audioscribe.upload.runtime.DEFAULT_LISTENER_FACTORY",
                        RecordingListener, raising=False)
    errors = []

    def target():
        try:
            run(config, engine_factory=QuietEngine, config_path=config_path)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=target)
    thread.start()
    try:
        assert wait_until(lambda: config.database.exists())
        time.sleep(1.0)
        assert RecordingListener.instances == [], "capability failure must keep the listener off"
        persisted = config.__class__.load(config_path)
        assert persisted.upload_enabled is True, "desired state must not be silently reset"
        source = Path(config.input_dir) / "normal.mp3"
        source.write_bytes(b"audio")
        assert wait_until(lambda: _job_count(config) >= 1), \
            "ordinary scanner/worker processing must continue"
    finally:
        from audioscribe.control import request
        request(Path(config.data_dir), "stop", force=True)
        thread.join(15)
    assert not errors and not thread.is_alive()


def _job_count(config):
    from audioscribe.store import Store
    if not config.database.exists():
        return 0
    store = Store(config.database)
    try:
        return store.db.execute("SELECT count(*) FROM jobs").fetchone()[0]
    finally:
        store.close()


def test_protected_changes_require_disabled(tmp_path):
    from audioscribe.config import reject_protected_upload_change
    config = service_config(tmp_path, upload_enabled=True)
    retargeted = service_config(tmp_path / "other")
    retargeted.input_dir = str(tmp_path / "other" / "in")
    with pytest.raises(ValueError):
        reject_protected_upload_change(config, retargeted)
    limited = service_config(tmp_path, upload_enabled=True, upload_max_bytes=123)
    with pytest.raises(ValueError):
        reject_protected_upload_change(config, limited)
    unrelated = service_config(tmp_path, upload_enabled=True, model="base")
    reject_protected_upload_change(config, unrelated)
    disabled = service_config(tmp_path, upload_enabled=False)
    reject_protected_upload_change(disabled, retargeted)


def test_direct_toml_reload_rejected(tmp_path, monkeypatch):
    from audioscribe.service import run
    RecordingListener.reset()
    config = service_config(tmp_path, upload_enabled=True)
    config_path = tmp_path / "config.toml"
    config.save(config_path)
    generate_secret_offline(Path(config.data_dir))
    monkeypatch.setattr("audioscribe.upload.runtime.DEFAULT_LISTENER_FACTORY",
                        RecordingListener, raising=False)

    def target():
        run(config, engine_factory=QuietEngine, config_path=config_path)

    thread = threading.Thread(target=target)
    thread.start()
    try:
        assert wait_until(lambda: bool(RecordingListener.instances))
        owner = RecordingListener.instances[0].owner
        assert owner.config_drift is None
        edited = config.__class__.load(config_path)
        edited.input_dir = str(tmp_path / "elsewhere")
        edited.save(config_path)
        assert wait_until(lambda: owner.config_drift == "rejected_protected_change"), \
            "protected live changes must be rejected while enabled"
        assert owner.snapshot["input_dir"] == str(Path(config.input_dir).resolve())
        persisted = config.__class__.load(config_path)
        assert persisted.upload_enabled is True
        assert owner.runtime.staging == Path(config.input_dir) / ".audioscribe-upload-staging"
    finally:
        from audioscribe.control import request
        request(Path(config.data_dir), "stop", force=True)
        thread.join(15)
    assert not thread.is_alive()


def test_missing_config_path_never_claims_persisted_enable(tmp_path):
    from audioscribe.service import run
    from audioscribe.upload.controller import UploadController
    config = service_config(tmp_path)
    config_path = tmp_path / "config.toml"
    config.save(config_path)
    before = config_path.read_bytes()
    errors = []

    def target():
        try:
            run(config, engine_factory=QuietEngine, config_path=None)
        except Exception as error:
            errors.append(error)

    thread = threading.Thread(target=target)
    thread.start()
    try:
        assert wait_until(lambda: (Path(config.data_dir) / "upload-mailbox").is_dir()), \
            "the owner pump must exist even when HTTP is disabled"
        controller = UploadController(config, config_path)
        outcome = controller.enable()
        assert outcome.outcome == "rejected"
        assert outcome.detail == "configuration_path_unavailable"
        assert config_path.read_bytes() == before, "no guessed-path writes are allowed"
        status = controller.status()
        assert status.status["configuration_path_available"] is False
    finally:
        from audioscribe.control import request
        request(Path(config.data_dir), "stop", force=True)
        thread.join(15)
    assert not errors and not thread.is_alive()


def test_schema_migration_is_monotonic(tmp_path):
    import sqlite3

    from audioscribe.store import Store
    db = tmp_path / "queue.sqlite3"
    legacy = sqlite3.connect(db)
    legacy.executescript("""
        CREATE TABLE IF NOT EXISTS roots (path TEXT PRIMARY KEY, created REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY, source TEXT NOT NULL, sha256 TEXT NOT NULL,
            profile TEXT NOT NULL, state TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            retry_at REAL NOT NULL DEFAULT 0, created REAL NOT NULL, updated REAL NOT NULL,
            progress TEXT NOT NULL DEFAULT '', output TEXT, error TEXT, output_sha256 TEXT);
        CREATE TABLE IF NOT EXISTS files (
            root TEXT NOT NULL, path TEXT NOT NULL, signature TEXT NOT NULL,
            stable_since REAL NOT NULL, ignored INTEGER NOT NULL DEFAULT 0,
            present INTEGER NOT NULL DEFAULT 1, job_id INTEGER, PRIMARY KEY(root,path));
        PRAGMA user_version=1;
    """)
    legacy.commit()
    legacy.close()

    store = Store(db)
    version = store.db.execute("PRAGMA user_version").fetchone()[0]
    assert version >= 2
    names = {row[0] for row in store.db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"upload_history", "upload_sessions", "upload_lineage_proofs"} <= names
    store.close()

    store = Store(db)
    assert store.db.execute("PRAGMA user_version").fetchone()[0] == version
    store.close()

    future = sqlite3.connect(db)
    future.execute("PRAGMA user_version=7")
    future.close()
    store = Store(db)
    assert store.db.execute("PRAGMA user_version").fetchone()[0] == 7, \
        "a foreign future schema version must never be downgraded"
    store.close()


def test_upload_history_and_sessions_persist_restart(tmp_path):
    from audioscribe.upload.persistence import UploadStore
    clock = WallClock()
    db_path = tmp_path / "history.sqlite3"
    config, secret, runtime = make_lifecycle_runtime(tmp_path / "one", clock)
    persistor = UploadStore(db_path)
    runtime.persistor = persistor
    app = make_upload_app(runtime)
    client = Client(app)
    status, payload = login_with(client, secret)
    assert status == 200
    registration = register_upload(client, "gone.mp3", file_bytes=8)
    status, _, _ = client.request("POST", f"/api/v1/uploads/{registration['upload_id']}/cancel",
                                  json_body={})
    assert status == 200
    rows = persistor.latest_history(limit=300)
    assert any(row["upload_id"] == registration["upload_id"] and row["outcome"] == "cancelled"
               for row in rows)
    sessions = persistor.load_sessions()
    assert len(sessions) == 1

    # Restart: a fresh runtime restores sessions and shared history.
    config2 = make_config(tmp_path / "one")
    runtime2 = UploadRuntime(config2, wall_fn=clock, persistor=persistor)
    runtime2.restore_persisted_state()
    app2 = make_upload_app(runtime2)
    client2 = Client(app2)
    client2.cookie = client.cookie
    client2.csrf = client.csrf
    status, _, _ = client2.request("GET", "/api/v1/status")
    assert status == 200, "persisted session survives restart with the same cookie"
    assert any(entry.get("outcome") == "cancelled" for entry in runtime2.history)

    for index in range(305):
        persistor.record_history({"upload_id": f"u{index:03d}", "name": "x.mp3",
                                  "state": "published", "outcome": "published"})
    persistor.prune_history(keep=300)
    assert len(persistor.latest_history(limit=1000)) == 300
    persistor.close()


# -- step 8: cookie lineage continuity, persisted renewal, bounded pruning -----


def login_presenting_cookie(client, secret, proof=None):
    """A real browser presents the still-held cookie on the login POST; page
    memory (CSRF, continuity proof) is gone after a refresh."""
    status, _, payload = client.request("GET", "/api/v1/auth/challenge",
                                        auth=False, csrf=False)
    assert status == 200
    body = {"secret": secret, "csrf": payload["nonce"]}
    if proof is not None:
        body["continuity_proof"] = proof
    cookie_header = [(b"cookie", client.cookie.encode())] if client.cookie else []
    status, _, payload = client.request("POST", "/api/v1/auth/login", auth=False,
                                        csrf=False, json_body=body,
                                        headers=cookie_header)
    if status == 200:
        client.csrf = payload["csrf"]
    return status, payload


def test_current_cookie_proves_lineage_continuity_without_proof(tmp_path, stubbed_validation):
    """A4 line 101: on fresh reauthentication a presented current cookie
    proves continuity even when the page-memory proof is lost."""
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    app = make_upload_app(runtime)
    client = Client(app)
    login_with(client, secret)
    registration = register_upload(client, "cookie.mp3", file_bytes=16)
    upload_id = registration["upload_id"]

    refreshed = Client(app)
    refreshed.cookie = client.cookie
    status, _ = login_presenting_cookie(refreshed, secret)
    assert status == 200
    status, _, outcome = refreshed.request(
        "POST", f"/api/v1/uploads/{upload_id}/cancel", json_body={})
    assert status == 200 and outcome["result"] == "cancelled", \
        "cookie continuity must preserve cancel ownership of the transfer"


def test_expired_cookie_still_proves_continuity(tmp_path, stubbed_validation):
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    app = make_upload_app(runtime)
    client = Client(app)
    login_with(client, secret)
    registration = register_upload(client, "late.mp3", file_bytes=16)
    upload_id = registration["upload_id"]
    clock.advance(24 * 3600 + 1)  # idle expiry; cookie still presented

    refreshed = Client(app)
    refreshed.cookie = client.cookie
    status, _ = login_presenting_cookie(refreshed, secret)
    assert status == 200
    status, _, outcome = refreshed.request(
        "POST", f"/api/v1/uploads/{upload_id}/cancel", json_body={})
    assert status == 200 and outcome["result"] == "cancelled", \
        "an expired cookie must still prove lineage continuity (A4)"


def test_unknown_cookie_falls_back_to_proof_then_new_lineage(tmp_path, stubbed_validation):
    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    app = make_upload_app(runtime)
    client = Client(app)
    status, payload = login_with(client, secret)
    proof = payload["continuity_proof"]
    registration = register_upload(client, "keep.mp3", file_bytes=16)
    upload_id = registration["upload_id"]

    # Unknown cookie + valid proof: the proof still carries continuity.
    stranger = Client(app)
    stranger.cookie = "__Host-audioscribe=unknown-cookie-value-aaaaaaaaaaaaaaaaaaaaaaa"
    status, _ = login_presenting_cookie(stranger, secret, proof=proof)
    assert status == 200
    status, _, outcome = stranger.request(
        "POST", f"/api/v1/uploads/{upload_id}/cancel", json_body={})
    assert status == 200 and outcome["result"] == "cancelled"

    # Unknown cookie and no proof: a new lineage, no ownership.
    fresh = Client(app)
    fresh.cookie = "__Host-audioscribe=unknown-cookie-value-aaaaaaaaaaaaaaaaaaaaaaa"
    status, _ = login_presenting_cookie(fresh, secret)
    assert status == 200
    status, _, _ = fresh.request(
        "POST", f"/api/v1/uploads/{upload_id}/cancel", json_body={})
    assert status == 403, "without continuity the login creates a new lineage"


def test_idle_renewal_is_persisted_across_restart(tmp_path, stubbed_validation):
    """A4: idle renewal must be persisted, or a restart expires an actively
    used session at its stale last_seen."""
    from audioscribe.upload.persistence import UploadStore

    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    runtime.persistor = UploadStore(config.database)
    runtime.restore_persisted_state()
    app = make_upload_app(runtime)
    client = Client(app)
    login_with(client, secret)
    login_last_seen = list(runtime.sessions.values())[0].last_seen
    clock.advance(3600)
    register_upload(client, "renewed.mp3", file_bytes=8)
    renewed_last_seen = list(runtime.sessions.values())[0].last_seen
    assert renewed_last_seen > login_last_seen

    restored = UploadRuntime(config, wall_fn=clock,
                             persistor=UploadStore(config.database))
    restored.restore_persisted_state()
    assert len(restored.sessions) == 1
    session = next(iter(restored.sessions.values()))
    assert session.last_seen == renewed_last_seen, \
        "the renewed idle deadline must survive a restart"


def test_expired_persisted_sessions_and_orphan_proofs_are_pruned(tmp_path, stubbed_validation):
    """A4 line 103: persisted session/proof rows are pruned across natural
    expiry; proofs whose lineage has no live session or active work are gone."""
    from audioscribe.upload.persistence import UploadStore

    clock = WallClock()
    config, secret, runtime = make_lifecycle_runtime(tmp_path, clock)
    runtime.persistor = UploadStore(config.database)
    runtime.restore_persisted_state()
    app = make_upload_app(runtime)
    client = Client(app)
    login_with(client, secret)
    orphan_lineage = "ffffffffffffffffffffffffffffffff"
    runtime.persistor.save_lineage_proof(
        hashlib.sha256(b"orphan-proof").hexdigest(), orphan_lineage, 0)
    store = UploadStore(config.database)
    assert len(store.load_sessions()) == 1
    assert len(store.load_lineage_proofs()) == 2

    clock.advance(30 * 24 * 3600 + 1)  # absolute expiry
    runtime._prune_sessions()
    assert store.load_sessions() == [], "expired persisted sessions must be pruned"
    surviving = store.load_lineage_proofs()
    assert all(row["lineage"] != orphan_lineage for row in surviving), \
        "orphaned continuity proofs must be pruned"
