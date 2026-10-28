"""PLAN-02 slice 3: validate, publish, and observe normal scanner intake."""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path

from audioscribe.config import Config
from audioscribe.service import Scanner
from audioscribe.store import Store
from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.http import make_upload_app
from test_upload_http import FIXTURE_ROOT, ORIGIN, Client, OpenBodyStream, make_config, make_runtime

import pytest

pytestmark = pytest.mark.skipif(
    not FIXTURE_ROOT.is_dir(),
    reason="LQ04 fixtures are not available; run the qualification bootstrap")


def audio_engine_factory(recorders: list):
    class Engine:
        def __init__(self, config):
            self.config = config

        def process(self, job, report, stopped):
            recorders.append(job["source"])
            source = Path(job["source"])
            if source.suffix.lower() == ".mp4":
                raise RuntimeError("audio stream missing: media has no audio track")
            output = Path(self.config.output_dir) / f"{source.stem}.md"
            output.write_text("**Hablante 1:** audio procesado", encoding="utf-8")
            return output
    return Engine


def full_config(tmp_path: Path, max_attempts: int = 1, **overrides) -> Config:
    overrides.setdefault("stable_seconds", 0)
    overrides.setdefault("max_attempts", max_attempts)
    return make_config(tmp_path, **overrides)


def publish_through_http(runtime, client: Client, media: bytes, name="clip.mp3",
                         declared=None, secret=None):
    if secret:
        client.login(secret)
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": name,
                   "file_bytes": len(media) if declared is None else declared})
    assert status == 201, payload
    upload_id, token = payload["upload_id"], payload["transfer_token"]

    async def scenario():
        async with OpenBodyStream(client, upload_id, token) as stream:
            await stream.send(media)
            sent = await stream.finish()
        return sent

    sent = asyncio.run(scenario())
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body) if body else None


def test_raw_stream_publishes_complete_media(tmp_path):
    config = full_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    store = Store(config.database)
    scanner = Scanner(config, store)
    preexisting = Path(config.input_dir) / "existing.mp3"
    preexisting.write_bytes(b"preexisting audio")
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    status, record = publish_through_http(runtime, client, media, secret=secret)
    assert status == 200, record
    assert record["state"] == "published"
    published = Path(record["published_path"])
    assert published.name == "clip.mp3"
    assert published.read_bytes() == media
    assert not list((Path(config.input_dir) / ".audioscribe-upload-staging").glob("*.part"))
    assert runtime.reservations.active == 0
    scanner.scan()
    time.sleep(0.01)
    scanner.scan(now=time.time() + 10)
    job = store.db.execute(
        "SELECT * FROM jobs WHERE source=?", (str(published),)).fetchone()
    assert job is not None and job["state"] == "pending"
    baseline_row = store.db.execute(
        "SELECT ignored FROM files WHERE path=?", (str(preexisting),)).fetchone()
    assert baseline_row["ignored"] == 1


def test_readable_container_without_audio_publishes_then_processing_errors(tmp_path):
    config = full_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    from audioscribe.upload.persistence import UploadStore
    runtime.persistor = UploadStore(config.database)
    store = Store(config.database)
    scanner = Scanner(config, store)
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "P1-video-only-mpeg4.mp4").read_bytes()
    status, record = publish_through_http(runtime, client, media, name="silent.mp4", secret=secret)
    assert status == 200, record
    published = Path(record["published_path"])
    scanner.scan()
    time.sleep(0.01)
    scanner.scan(now=time.time() + 10)
    job = store.db.execute(
        "SELECT * FROM jobs WHERE source=?", (str(published),)).fetchone()
    assert job is not None, "video-only upload must reach normal queue admission"
    processed = []
    engine_type = audio_engine_factory(processed)
    engine = engine_type(config)
    worker_store = Store(config.database)
    claimed = worker_store.claim()
    assert claimed["id"] == job["id"]
    failure = None
    try:
        engine.process(claimed, lambda message: None, lambda: False)
        raise AssertionError("video-only media must fail downstream with the audio error")
    except RuntimeError as error:
        failure = error
        assert "audio" in str(error)
    worker_store.fail(claimed, str(failure), config.max_attempts)
    final = worker_store.db.execute("SELECT state,attempts,error FROM jobs WHERE id=?",
                                    (job["id"],)).fetchone()
    assert final["state"] == "error" and final["attempts"] >= 1
    assert "audio" in final["error"]
    assert processed == [str(published)]

    # S03.05/S05.04 through status: the upload success stays visible while the
    # downstream audio error is independently projected from the worker result.
    status, _, payload = client.request("GET", "/api/v1/status")
    assert status == 200, payload
    row = next(r for r in payload["history"] if r["upload_id"] == record["upload_id"])
    assert row["outcome"] == "published"
    assert row["downstream"] == "error", row


def test_unsupported_malformed_media_cleanup(tmp_path):
    config = full_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    store = Store(config.database)
    scanner = Scanner(config, store)
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "N1-malformed.mp4").read_bytes()
    status, record = publish_through_http(runtime, client, media, name="broken.mp4", secret=secret)
    assert status == 422 and record["error"] == "invalid_media"
    assert runtime.reservations.active == 0
    leftovers = [p.name for p in
                 (Path(config.input_dir) / ".audioscribe-upload-staging").glob("*")
                 if p.name != "owner.json"]
    assert leftovers == []
    published = Path(config.input_dir) / "broken.mp4"
    assert not published.exists()
    scanner.scan()
    assert store.db.execute("SELECT COUNT(*) c FROM jobs").fetchone()["c"] == 0


def test_empty_media_rejected_before_publication(tmp_path):
    config = full_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    scanner = Scanner(config, Store(config.database))
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    status, record = publish_through_http(runtime, client, b"", name="empty.mp3",
                                          declared=0, secret=secret)
    assert status == 422 and record["error"] == "invalid_media"
    assert not (Path(config.input_dir) / "empty.mp3").exists()
    assert runtime.reservations.active == 0
