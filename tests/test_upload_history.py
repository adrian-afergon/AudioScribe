"""PLAN-04 slice 1: bounded shared latest-300 history read model.

One behavior per RED -> GREEN -> REFACTOR. The shared history view is fed by
UploadStore, projected to bounded public records (no lineage/root/timestamps)
and served identically to every authenticated session.
"""

from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from audioscribe.service import Scanner
from audioscribe.store import Store
from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.history import latest_public_history
from audioscribe.upload.http import STATUS_HISTORY_LIMIT, make_upload_app
from audioscribe.upload.persistence import UploadStore
from test_upload_http import FIXTURE_ROOT, Client, make_config, make_runtime
from test_upload_validation import publish_through_http

ORIGIN = "https://audioscribe.example.ts.net"


def runtime_with_store(config, **overrides):
    runtime = make_runtime(config, **overrides)
    runtime.persistor = UploadStore(config.database)
    return runtime


def test_public_history_projection_is_bounded(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    store = UploadStore(config.database)
    store.record_history({
        "upload_id": "a" * 32, "lineage": "lineage-internal-1", "name": "x" * 8000 + ".mp3",
        "root": str(config.input_dir), "state": "published",
        "bytes_received": 10, "declared_bytes": 10,
        "published_path": str(config.input_dir) + "/x.mp3",
        "error_code": None, "outcome": "published", "created": 1.0, "updated": 2.0,
    })
    store.close()
    runtime = runtime_with_store(config)
    runtime.restore_persisted_state()
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request("GET", "/api/v1/status")
    assert status == 200, payload
    record = payload["history"][0]
    assert len(json.dumps(record, sort_keys=True)) <= 4096, "status record exceeds 4 KiB"
    for forbidden in ("lineage", "root", "created", "updated", "published_path"):
        assert forbidden not in record, f"shared history leaked internal field {forbidden}"
    assert record["upload_id"] == "a" * 32
    assert record["name"].endswith(".mp3") and len(record["name"].encode()) <= 240
    assert record["outcome"] == "published"

    other = Client(make_upload_app(runtime))
    other.login(secret)
    status, _, other_payload = other.request("GET", "/api/v1/status")
    assert status == 200
    assert other_payload["history"] == payload["history"]


def test_busy_sqlite_returns_stale_without_reauth(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = runtime_with_store(config)
    runtime.restore_persisted_state()
    client = Client(make_upload_app(runtime))
    client.login(secret)
    # Deterministic storage-unavailable simulation: WAL readers are never
    # blocked by ordinary write transactions, so make the database file
    # unreadable for the duration of the failed read.
    config.database.chmod(0o000)
    try:
        status, _, payload = client.request("GET", "/api/v1/status")
        assert status == 503, payload
        assert payload["error"] == "busy" and payload["stale"] is True
    finally:
        config.database.chmod(0o600)
    status, _, payload = client.request("GET", "/api/v1/status")
    assert status == 200, "recovery after SQLite became available must not need reauthentication"


def _fill_history(store: UploadStore, count: int) -> None:
    for index in range(count):
        store.record_history({
            "upload_id": f"{index:032x}", "lineage": f"lin-{index}", "name": f"old-{index}.mp3",
            "root": "/data/in", "state": "published", "bytes_received": 1,
            "declared_bytes": 1, "published_path": None, "error_code": None,
            "outcome": "published", "created": float(index), "updated": float(index),
        })


def test_live_concurrency_above_history_limit(tmp_path):
    config = make_config(tmp_path, upload_concurrency=2)
    secret = generate_secret_offline(Path(config.data_dir))
    store = UploadStore(config.database)
    _fill_history(store, STATUS_HISTORY_LIMIT)
    store.close()
    runtime = runtime_with_store(config)
    runtime.restore_persisted_state()
    client = Client(make_upload_app(runtime))
    client.login(secret)
    first = client.request("POST", "/api/v1/uploads",
                           json_body={"filename": "one.mp3", "file_bytes": 10})
    second = client.request("POST", "/api/v1/uploads",
                            json_body={"filename": "two.mp3", "file_bytes": 10})
    assert first[0] == 201 and second[0] == 201, "live slots must not be capped by history"
    status, _, payload = client.request("GET", "/api/v1/status")
    assert status == 200 and len(payload["history"]) == STATUS_HISTORY_LIMIT
    assert all(record["upload_id"] not in (first[2]["upload_id"], second[2]["upload_id"])
               for record in payload["history"])


def test_active_lookup_outside_latest300(tmp_path):
    config = make_config(tmp_path, upload_concurrency=1)
    secret = generate_secret_offline(Path(config.data_dir))
    store = UploadStore(config.database)
    _fill_history(store, STATUS_HISTORY_LIMIT)
    store.close()
    runtime = runtime_with_store(config)
    runtime.restore_persisted_state()
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "live.mp3", "file_bytes": 10})
    assert status == 201
    upload_id = payload["upload_id"]
    status, _, record = client.request("GET", f"/api/v1/uploads/{upload_id}")
    assert status == 200 and record["upload_id"] == upload_id
    assert record["state"] == "reserved"
    # Another lineage cannot look up someone else's active record.
    other = Client(make_upload_app(runtime))
    other.login(secret)
    status, _, _ = other.request("GET", f"/api/v1/uploads/{upload_id}")
    assert status == 404


def test_terminal_lookup_uses_persisted_history(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = runtime_with_store(config)
    client = Client(make_upload_app(runtime))
    client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads", json_body={"filename": "gone.mp3", "file_bytes": 5})
    upload_id = payload["upload_id"]
    runtime.cancel_transfer(runtime.transfer_record(upload_id))
    status, _, record = client.request("GET", f"/api/v1/uploads/{upload_id}")
    assert status == 200, record
    assert record["upload_id"] == upload_id and record["outcome"] == "cancelled"
    # A pruned terminal id must report unavailability, never an inferred failure.
    status, _, record = client.request("GET", "/api/v1/uploads/" + "f" * 32)
    assert status == 404 and record["error"] == "outcome_unavailable"


def test_metadata_limits_pruning_thread_owned_sqlite(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = runtime_with_store(config)
    store = runtime.persistor
    for index in range(305):
        store.record_history({
            "upload_id": f"{index:032x}", "lineage": f"lin-{index}", "name": f"f{index}.mp3",
            "root": "/data/in", "state": "published", "bytes_received": index,
            "declared_bytes": index, "published_path": None, "error_code": None,
            "outcome": "published", "created": float(index), "updated": float(index),
        })
        store.prune_history(STATUS_HISTORY_LIMIT)
    rows = store.db.execute("SELECT COUNT(*) c, MIN(rowid) m FROM upload_history").fetchone()
    assert rows["c"] == STATUS_HISTORY_LIMIT, "history must be pruned by creation order"
    assert rows["m"] == 6, "oldest records beyond latest-300 are pruned"
    # No secret or raw header data ever lands in persisted metadata.
    for row in store.db.execute("SELECT * FROM upload_history").fetchall():
        blob = json.dumps(dict(row))
        assert secret not in blob
        assert "authorization" not in blob.lower() and "cookie" not in blob.lower()
    # Each owner keeps its own connection: the persistor stays on its owner
    # thread while read snapshots use their own short-lived connections.
    import threading
    errors = []

    def read_snapshot():
        try:
            history = latest_public_history(config.database, STATUS_HISTORY_LIMIT)
            assert len(history) == STATUS_HISTORY_LIMIT
        except Exception as error:  # pragma: no cover - surfaced below
            errors.append(error)

    reader = threading.Thread(target=read_snapshot)
    reader.start()
    store.record_history({
        "upload_id": "e" * 32, "lineage": "lin-new", "name": "new.mp3", "root": "/data/in",
        "state": "published", "bytes_received": 1, "declared_bytes": 1,
        "published_path": None, "error_code": None, "outcome": "published",
        "created": 999.0, "updated": 999.0,
    })
    reader.join(5)
    assert not errors, errors
    assert not reader.is_alive()


def _published_upload(config, secret, media, name="clip.mp3"):
    runtime = runtime_with_store(config)
    runtime.restore_persisted_state()
    store = Store(config.database)
    scanner = Scanner(config, store)
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    status, record = publish_through_http(runtime, client, media, name=name, secret=secret)
    assert status == 200, record
    return runtime, store, scanner, client, record


def _history_record(client, upload_id):
    status, _, payload = client.request("GET", "/api/v1/status")
    assert status == 200, payload
    return next(row for row in payload["history"] if row["upload_id"] == upload_id)


def test_publication_not_processing_completion(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    runtime, store, scanner, client, record = _published_upload(config, secret, media)
    upload_id = record["upload_id"]
    published = Path(record["published_path"])
    assert record["state"] == "published" and published.exists()

    # Publication is not processing completion: before scanner observation the
    # downstream state is awaiting the scanner, never completed.
    row = _history_record(client, upload_id)
    assert row["downstream"] == "awaiting_scanner", row

    scanner.scan()
    time.sleep(0.01)
    scanner.scan(now=time.time() + 10)
    job = store.db.execute("SELECT * FROM jobs WHERE source=?", (str(published),)).fetchone()
    assert job is not None and job["state"] == "pending"
    row = _history_record(client, upload_id)
    assert row["downstream"] == "queued", row

    output = Path(config.output_dir) / "clip.txt"
    output.write_text("**Hablante 1:** audio procesado", encoding="utf-8")
    store.done(job["id"], output)
    row = _history_record(client, upload_id)
    assert row["downstream"] == "completed", row
    assert row["outcome"] == "published", "upload success stays visible independently"


def test_persistence_writes_from_each_owner_thread(tmp_path):
    """A9: each owner thread has its own connection; no write is silently
    dropped because it arrived from the listener/pump/projection thread."""
    import threading

    config = make_config(tmp_path)
    store = UploadStore(config.database)
    errors = []

    def listener_write():
        try:
            store.record_history({
                "upload_id": "b" * 32, "lineage": "lin-listener", "name": "from-listener.mp3",
                "root": "/data/in", "state": "published", "bytes_received": 3,
                "declared_bytes": 3, "published_path": None, "error_code": None,
                "outcome": "published", "created": 5.0, "updated": 5.0,
            })
        except Exception as error:  # pragma: no cover - surfaced below
            errors.append(error)

    thread = threading.Thread(target=listener_write, name="simulated-listener")
    thread.start()
    thread.join(5)
    assert not errors, f"cross-thread persistence writes must not fail: {errors}"
    rows = store.latest_history()
    assert any(row["upload_id"] == "b" * 32 for row in rows), \
        "a write from another owner thread must land"
    store.close()


def test_duplicate_reuse_requires_scanner_profile_valid_output(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    runtime, store, scanner, client, record = _published_upload(config, secret, media)
    first_id = record["upload_id"]
    published = Path(record["published_path"])
    scanner.scan()
    time.sleep(0.01)
    scanner.scan(now=time.time() + 10)
    job = store.db.execute("SELECT * FROM jobs WHERE source=?", (str(published),)).fetchone()
    output = Path(config.output_dir) / "clip.txt"
    output.write_text("**Hablante 1:** audio procesado", encoding="utf-8")
    store.done(job["id"], output)
    assert _history_record(client, first_id)["downstream"] == "completed"

    # An identical duplicate publishes later; the scanner links it to the
    # prior done job, which proves reuse only with a valid output.
    status, duplicate = publish_through_http(runtime, client, media, name="clip.mp3",
                                             secret=secret)
    assert status == 200 and duplicate["upload_id"] != first_id
    duplicate_path = Path(duplicate["published_path"])
    assert duplicate_path != published, "publication must never overwrite"
    scanner.scan()
    time.sleep(0.01)
    scanner.scan(now=time.time() + 10)
    assert _history_record(client, duplicate["upload_id"])["downstream"] == "reused"

    # A modified output invalidates the cached proof: no stale reuse.
    output.write_text("modificado", encoding="utf-8")
    assert _history_record(client, duplicate["upload_id"])["downstream"] == "error"

    # A missing output is equally no proof of a valid prior result.
    output.unlink()
    assert _history_record(client, duplicate["upload_id"])["downstream"] == "error"

    # A linked job that errors and is reprocessed returns to the queue.
    store.fail(job, "simulated downstream failure", 0)
    store.retry(job["id"])
    assert _history_record(client, duplicate["upload_id"])["downstream"] == "queued"

    # A pending duplicate is never reuse proof, even with the same content.
    assert _history_record(client, first_id)["downstream"] == "queued"

    # Reuse also requires the upload's recorded ingestion profile to match
    # the linked job's profile; a mismatch proves nothing.
    output.write_text("**Hablante 1:** audio procesado", encoding="utf-8")
    with store.db:
        store.db.execute("UPDATE upload_history SET profile_snapshot=? WHERE upload_id=?",
                         ('{"engine": "other"}', duplicate["upload_id"]))
    store.done(job["id"], output)
    assert _history_record(client, duplicate["upload_id"])["downstream"] is None


def test_poll_does_not_rehash_all_outputs(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    import audioscribe.upload.status as status_module
    calls = []
    real_digest = status_module.digest

    def counting_digest(path):
        calls.append(str(path))
        return real_digest(path)

    monkeypatch.setattr(status_module, "digest", counting_digest)
    for name, fixture in (("one.mp3", "P2-mp3-libmp3lame.mp3"),
                      ("two.mp4", "P3-audio-bearing-aac.mp4")):
        _, store, scanner, client, record = _published_upload(config, secret,
                                                              (FIXTURE_ROOT / fixture).read_bytes(),
                                                              name=name)
        scanner.scan()
        time.sleep(0.01)
        scanner.scan(now=time.time() + 10)
        job = store.db.execute("SELECT * FROM jobs WHERE source=?",
                               (record["published_path"],)).fetchone()
        output = Path(config.output_dir) / f"{Path(name).stem}.txt"
        output.write_text("**Hablante 1:** audio procesado", encoding="utf-8")
        store.done(job["id"], output)
    assert len(calls) == 0, "registration and completion must not trigger output hashing"
    for _ in range(3):
        status, _, payload = client.request("GET", "/api/v1/status")
        assert status == 200
        assert all(row["downstream"] == "completed" for row in payload["history"]
                   if row["outcome"] == "published")
    assert len(calls) == 2, f"one-second polls must not rehash every output: {calls}"
