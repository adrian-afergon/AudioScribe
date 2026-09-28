import json
import time
from pathlib import Path

import pytest

from audioscribe.config import Config, atomic_write
from audioscribe.service import InstanceLock, Scanner
from audioscribe.store import Store, digest, profile


@pytest.fixture
def system(tmp_path):
    for name in ("in", "out", "brain", "data"):
        (tmp_path / name).mkdir()
    config = Config(*(str(tmp_path / name) for name in ("in", "out", "brain", "data")), stable_seconds=2)
    store = Store(config.database)
    scanner = Scanner(config, store)
    yield config, store, scanner
    store.close()


def jobs(store):
    return store.db.execute("SELECT * FROM jobs ORDER BY id").fetchall()


def add(config, scanner, filename="voz.mp3", content=b"audio", now=None):
    now = time.time() if now is None else now
    path = Path(config.input_dir) / filename
    path.write_bytes(content)
    scanner.scan(now)
    scanner.scan(now + 3)
    return path


def test_baseline_excludes_existing_then_processes_new(system):
    config, store, scanner = system
    (Path(config.input_dir) / "existente.mp4").write_bytes(b"existing")
    scanner.baseline()
    scanner.scan(time.time() + 50)
    assert not jobs(store)
    add(config, scanner)
    assert len(jobs(store)) == 1


def test_restart_detects_offline_arrival(system):
    config, store, scanner = system
    scanner.baseline()
    (Path(config.input_dir) / "offline.mp3").write_bytes(b"offline")
    assert scanner.baseline() is False
    scanner.scan(100)
    scanner.scan(103)
    assert len(jobs(store)) == 1


def test_copy_stability_resets_on_change(system):
    config, store, scanner = system
    scanner.baseline()
    path = Path(config.input_dir) / "copiando.mp4"
    path.write_bytes(b"a")
    scanner.scan(100)
    path.write_bytes(b"ab")
    scanner.scan(102)
    scanner.scan(103)
    assert not jobs(store)
    scanner.scan(105)
    assert jobs(store)[0]["sha256"] == digest(path)


def test_rename_duplicate_reuses_done_output(system):
    config, store, scanner = system
    scanner.baseline()
    original = add(config, scanner)
    job = store.claim()
    output = Path(config.output_dir) / "result.md"
    atomic_write(output, "transcripción")
    store.done(job["id"], output)
    add(config, scanner, "otro-nombre.MP4", original.read_bytes())
    assert len(jobs(store)) == 1
    assert store.db.execute("SELECT count(*) FROM files WHERE job_id=?", (job["id"],)).fetchone()[0] == 2


def test_same_name_new_content_creates_version(system):
    config, store, scanner = system
    scanner.baseline()
    add(config, scanner, content=b"v1", now=100)
    add(config, scanner, content=b"v2", now=200)
    assert len(jobs(store)) == 2


def test_baseline_file_removed_and_reintroduced_is_new(system):
    config, store, scanner = system
    path = Path(config.input_dir) / "old.mp3"
    path.write_bytes(b"audio")
    scanner.baseline()
    path.unlink()
    scanner.scan(100)
    add(config, scanner, filename="old.mp3", now=200)
    assert len(jobs(store)) == 1


def test_processing_recovers_without_spending_attempt(system):
    config, store, scanner = system
    scanner.baseline()
    add(config, scanner)
    first = store.claim()
    assert first["attempts"] == 1
    store.recover()
    resumed = store.claim()
    assert resumed["id"] == first["id"]
    assert resumed["attempts"] == 1


def test_failure_backoff_and_retry(system):
    config, store, scanner = system
    scanner.baseline()
    add(config, scanner)
    row = store.claim()
    store.fail(row, "mal formato", 1)
    assert jobs(store)[0]["state"] == "error"
    store.retry(row["id"])
    assert store.claim()["attempts"] == 1


def test_missing_output_detected(system):
    config, store, scanner = system
    scanner.baseline()
    add(config, scanner)
    row = store.claim()
    output = Path(config.output_dir) / "result.md"
    atomic_write(output, "contenido")
    store.done(row["id"], output)
    output.unlink()
    store.recover()
    assert jobs(store)[0]["state"] == "error"


def test_edited_output_is_preserved(system):
    config, store, scanner = system
    scanner.baseline()
    add(config, scanner)
    row = store.claim()
    output = Path(config.output_dir) / "result.md"
    atomic_write(output, "contenido")
    store.done(row["id"], output)
    atomic_write(output, "corrección humana")
    store.recover()
    assert jobs(store)[0]["state"] == "error"
    assert output.read_text(encoding="utf-8") == "corrección humana"


def test_zero_byte_and_unsupported_files_ignored(system):
    config, store, scanner = system
    scanner.baseline()
    add(config, scanner, content=b"")
    add(config, scanner, filename="nota.txt", content=b"not audio")
    assert not jobs(store)


def test_recursive_is_configurable(system):
    config, store, scanner = system
    scanner.baseline()
    folder = Path(config.input_dir) / "sub"
    folder.mkdir()
    (folder / "voz.mp3").write_bytes(b"audio")
    scanner.scan(100)
    scanner.scan(103)
    assert not jobs(store)
    config.recursive = True
    scanner.scan(104)
    scanner.scan(107)
    assert len(jobs(store)) == 1


def test_config_roundtrip_accents_quotes_backslashes(system, tmp_path):
    config, store, scanner = system
    config.output_dir = str(tmp_path / 'grabación " especial')
    path = tmp_path / "config.toml"
    config.save(path)
    restored = Config.load(path)
    assert restored.output_dir == config.output_dir
    assert restored.autostart is True


def test_rejects_nested_input_output(system):
    config, _, _ = system
    config.output_dir = str(Path(config.input_dir) / "output")
    with pytest.raises(ValueError):
        config.validate()


def test_instance_lock_releases(tmp_path):
    path = tmp_path / "lock"
    lock = InstanceLock(path)
    with pytest.raises(RuntimeError):
        InstanceLock(path)
    lock.close()
    InstanceLock(path).close()


def test_missing_input_does_not_mark_all_files_missing(system):
    config, store, scanner = system
    scanner.baseline()
    add(config, scanner)
    config.input_dir = str(Path(config.input_dir) / "unavailable")
    with pytest.raises(FileNotFoundError):
        scanner.scan()
    assert store.db.execute("SELECT present FROM files").fetchone()[0] == 1
