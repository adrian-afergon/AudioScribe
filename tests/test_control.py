import json
import threading
import time
from pathlib import Path

from audioscribe.config import Config, atomic_write
from audioscribe.control import ServiceControl, request, snapshot
from audioscribe.service import InstanceLock, run
from audioscribe.store import Store, digest, profile


def config_at(path):
    for name in ("in", "out", "brain", "data"):
        (path / name).mkdir()
    return Config(*(str(path / name) for name in ("in", "out", "brain", "data")),
                  stable_seconds=1, poll_seconds=1)


def until(predicate, seconds=6):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    assert predicate(), "Timed out"


def test_pause_blocks_then_resume_continues(tmp_path):
    stop = threading.Event()
    control = ServiceControl(tmp_path, stop)
    control.start()
    control.update(job_id=12)
    request(tmp_path, "pause")
    finished = threading.Event()
    thread = threading.Thread(target=lambda: (control.checkpoint(), finished.set()))
    thread.start()
    try:
        until(lambda: control.state["state"] == "paused")
        assert not finished.is_set()
        control.flush()
        assert json.loads((tmp_path / "runtime.json").read_text())["job_id"] == 12
        request(tmp_path, "resume")
        until(finished.is_set)
        assert control.state["state"] == "processing"
    finally:
        stop.set()
        thread.join(2)
        control.close()


def test_stop_works_while_paused(tmp_path):
    control = ServiceControl(tmp_path, threading.Event())
    control.start()
    request(tmp_path, "pause")
    answer = []
    thread = threading.Thread(target=lambda: answer.append(control.checkpoint()))
    thread.start()
    try:
        until(lambda: control.state["state"] == "paused")
        request(tmp_path, "stop")
        thread.join(2)
        assert answer == [True]
    finally:
        control.stop.set()
        thread.join(2)
        control.close()


def test_stale_status_cannot_claim_service_is_alive(tmp_path):
    config = config_at(tmp_path)
    directory = Path(config.data_dir)
    atomic_write(directory / "runtime.json", json.dumps({"state":"processing", "heartbeat":time.time()}))
    assert snapshot(config)["state"] == "stopped"
    lock = InstanceLock(directory / "service.lock")
    try:
        assert snapshot(config)["state"] == "processing"
        request(directory, "pause")
        assert snapshot(config)["state"] == "pausing"
        atomic_write(directory / "runtime.json", json.dumps({"state":"paused", "heartbeat":time.time()}))
        assert snapshot(config)["state"] == "paused"
    finally:
        lock.close()
    assert snapshot(config)["state"] == "stopped"
    assert snapshot(config)["pause_requested"]


def test_service_pause_preserves_job_and_does_not_start_next(tmp_path):
    config = config_at(tmp_path)
    directory = Path(config.data_dir)
    calls = []
    entered = threading.Event()
    allow = threading.Event()
    errors = []
    source = Path(config.input_dir) / "fixture.mp3"
    source.write_bytes(b"test")
    store = Store(config.database)
    with store.db:
        for n in range(2):
            store.db.execute("INSERT INTO jobs(source,sha256,profile,state,created,updated) VALUES (?,?,?,'pending',?,?)",
                             (str(source), digest(source), profile(config), time.time(), time.time()))
    store.close()
    class Engine:
        def __init__(self, config):
            pass
        def process(self, job, report, stopped):
            calls.append(job["id"])
            entered.set()
            assert allow.wait(5)
            if stopped():
                raise InterruptedError()
            path = Path(config.output_dir) / f"{job['id']}.md"
            atomic_write(path, "resultado")
            return path
    def target():
        try:
            run(config, engine_factory=Engine)
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=target)
    thread.start()
    try:
        assert entered.wait(5)
        request(directory, "pause")
        allow.set()
        until(lambda: snapshot(config)["state"] == "paused")
        assert len(calls) == 1
        assert snapshot(config)["counts"] == {"pending":1, "processing":1}
        assert not list(Path(config.output_dir).glob("*.md"))
        request(directory, "resume")
        until(lambda: snapshot(config)["counts"].get("done") == 2)
        assert calls == [1, 2]
    finally:
        allow.set()
        request(directory, "stop")
        thread.join(10)
    assert not errors and not thread.is_alive()
    assert snapshot(config)["state"] == "stopped"
