"""PLAN-02 slice 4: interruption, cleanup failure, and recovery outcomes."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from audioscribe.store import Store
from audioscribe.upload.auth import generate_secret_offline
from audioscribe.upload.http import make_upload_app
from audioscribe.upload.staging import (create_transfer_file, owned_orphan_entries,
                                        read_manifest, write_manifest)
from test_upload_http import (FIXTURE_ROOT, Client, OpenBodyStream,
                              make_config, make_runtime)
from test_upload_validation import publish_through_http

import pytest

pytestmark = pytest.mark.skipif(
    not FIXTURE_ROOT.is_dir(),
    reason="LQ04 fixtures are not available; run the qualification bootstrap")


def test_disconnect_during_validation_cleans(tmp_path):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    store = Store(config.database)
    from audioscribe.service import Scanner
    scanner = Scanner(config, store)
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    client.login(secret)
    media = (FIXTURE_ROOT / "N1-malformed.mp4").read_bytes()
    status, _, payload = client.request(
        "POST", "/api/v1/uploads",
        json_body={"filename": "disconnect.mp4", "file_bytes": len(media)})
    assert status == 201, payload
    upload_id, token = payload["upload_id"], payload["transfer_token"]

    async def scenario():
        async with OpenBodyStream(client, upload_id, token) as stream:
            await stream.send(media)
            await stream.abort()

    asyncio.run(scenario())
    record = runtime.transfer_record(upload_id)
    assert record.state in ("cancelled", "failed")
    assert runtime.reservations.active == 0
    leftovers = [p.name for p in
                 (Path(config.input_dir) / ".audioscribe-upload-staging").glob("*")
                 if p.name not in ("owner.json",)]
    assert leftovers == []
    assert not (Path(config.input_dir) / "disconnect.mp4").exists()
    assert store.db.execute("SELECT COUNT(*) c FROM jobs").fetchone()["c"] == 0


def test_cleanup_failure_remains_excluded(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    from audioscribe.service import Scanner
    scanner = Scanner(config, Store(config.database))
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    real_unlink = Path.unlink

    def failing_unlink(self, missing_ok=False):
        if self.name.endswith(".part") and self.parent.name == ".audioscribe-upload-staging":
            raise OSError("simulated stuck unlink")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    client.login(secret)
    status, record = publish_through_http(runtime, client, media, secret=secret)
    monkeypatch.undo()
    assert status == 200
    assert record["state"] == "published"
    assert record["error_code"] == "cleanup_failed"
    staging = Path(config.input_dir) / ".audioscribe-upload-staging"
    part = next(p for p in staging.glob("*.part"))
    assert part.exists()
    published = Path(record["published_path"])
    assert published.read_bytes() == media
    discovered = [str(p) for p in scanner.paths()]
    assert str(part) not in discovered
    assert str(published) in discovered
    scanner.scan()
    store = Store(config.database)
    jobs = store.db.execute("SELECT source FROM jobs").fetchall()
    assert all(row["source"] != str(part) for row in jobs)


def test_orphan_recovery_never_publishes(tmp_path):
    config = make_config(tmp_path)
    from audioscribe.upload.capabilities import ensure_owned_staging
    root = Path(config.input_dir)
    staging = ensure_owned_staging(root)
    from audioscribe.upload.staging import recover_owned_orphans

    abandoned = create_transfer_file(staging, "a" * 32)
    abandoned.write_bytes(b"never-published-bytes")
    write_manifest(staging, "a" * 32, {"upload_id": "a" * 32, "state": "receiving",
                                       "final_name": "abandoned.mp3", "lineage": "L"})
    crashed_after_link = create_transfer_file(staging, "b" * 32)
    crashed_after_link.write_bytes(b"already-linked-bytes")
    write_manifest(staging, "b" * 32, {"upload_id": "b" * 32, "state": "publish-intent",
                                       "final_name": "already-there.mp3", "lineage": "L"})
    final = root / "already-there.mp3"
    os.link(crashed_after_link, final)
    collision_target = root / "collision.mp3"
    collision_target.write_bytes(b"precious-user-bytes")
    orphan_alias = create_transfer_file(staging, "c" * 32)
    orphan_alias.write_bytes(b"precious-user-bytes")
    write_manifest(staging, "c" * 32, {"upload_id": "c" * 32, "state": "publish-intent",
                                       "final_name": "collision.mp3", "lineage": "L"})

    summary = recover_owned_orphans(root, staging)

    assert not (root / "abandoned.mp3").exists()
    assert final.read_bytes() == b"already-linked-bytes"
    assert collision_target.read_bytes() == b"precious-user-bytes"
    assert not (staging / ("a" * 32)).exists()
    assert not (staging / ("b" * 32)).exists()
    assert not (staging / ("c" * 32)).exists()
    assert summary["kept_published"] == ["b" * 32]
    scanner_paths_summary = owned_orphan_entries(staging)
    assert scanner_paths_summary == []


def test_link_success_unlink_failure_stays_published(tmp_path, monkeypatch):
    config = make_config(tmp_path)
    secret = generate_secret_offline(Path(config.data_dir))
    runtime = make_runtime(config)
    from audioscribe.service import Scanner
    scanner = Scanner(config, Store(config.database))
    scanner.baseline()
    runtime.mark_baseline_ready()
    client = Client(make_upload_app(runtime))
    media = (FIXTURE_ROOT / "P2-mp3-libmp3lame.mp3").read_bytes()
    real_unlink = Path.unlink

    def failing_unlink(self, missing_ok=False):
        if self.name.endswith(".part") and self.parent.name == ".audioscribe-upload-staging":
            raise OSError("staging unlink failed after link")
        return real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(Path, "unlink", failing_unlink)
    client.login(secret)
    status, record = publish_through_http(runtime, client, media, secret=secret)
    monkeypatch.undo()
    assert status == 200
    assert record["state"] == "published"
    published = Path(record["published_path"])
    assert published.exists() and published.read_bytes() == media
    history = [h for h in runtime.history if h["upload_id"] == record["upload_id"]]
    assert history and history[-1]["outcome"] == "published-with-cleanup-error"
