"""Local service controls and live status. No network or inference dependencies."""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path

from . import __version__
from .config import atomic_write


class ServiceControl:
    def __init__(self, data_dir: Path, stop: threading.Event):
        self.directory = data_dir
        self.stop = stop
        self.pause_file = data_dir / "pause.request"
        self.stop_file = data_dir / "stop.request"
        self.guard = threading.Lock()
        self.state = {"pid": os.getpid(), "version": __version__, "started": time.time(),
                      "state": "starting", "job_id": None, "scanner_error": None,
                      "last_scan": None, "worker_error": None}
        self.finished = threading.Event()
        self.publisher = threading.Thread(target=self._publish, name="heartbeat", daemon=True)

    def start(self):
        self.publisher.start()

    def update(self, **values):
        with self.guard:
            self.state.update(values)

    def flush(self):
        with self.guard:
            value = dict(self.state, heartbeat=time.time())
        atomic_write(self.directory / "runtime.json", json.dumps(value, ensure_ascii=False))

    def _publish(self):
        while not self.finished.is_set():
            self.flush()
            self.finished.wait(1)

    def checkpoint(self) -> bool:
        """Cooperative pause keeps generator, model and in-flight block in memory."""
        if self.stop.is_set() or self.stop_file.exists():
            self.update(state="stopping")
            return True
        while self.pause_file.exists():
            self.update(state="paused")
            if self.stop.wait(.15) or self.stop_file.exists():
                self.update(state="stopping")
                return True
        with self.guard:
            self.state["state"] = "processing" if self.state["job_id"] is not None else "idle"
        return False

    def close(self):
        self.finished.set()
        self.publisher.join()
        self.update(state="stopped", job_id=None)
        self.flush()


def request(data_dir: Path, action: str):
    if action == "pause":
        atomic_write(data_dir / "pause.request", "pause\n")
    elif action == "resume":
        (data_dir / "pause.request").unlink(missing_ok=True)
    elif action == "stop":
        atomic_write(data_dir / "stop.request", "stop\n")
    else:
        raise ValueError("Acción desconocida")


def service_active(data_dir: Path) -> bool:
    # The OS releases this lock on crashes. A stale JSON heartbeat cannot fake a live service.
    from .service import InstanceLock
    if not (data_dir / "service.lock").exists():
        return False
    try:
        lock = InstanceLock(data_dir / "service.lock")
    except RuntimeError:
        return True
    else:
        lock.close()
        return False


def snapshot(config) -> dict:
    directory = Path(config.data_dir)
    try:
        runtime = json.loads((directory / "runtime.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        runtime = {}
    active = service_active(directory)
    pause = (directory / "pause.request").exists()
    if not active:
        state = "stopped"
    elif time.time() - runtime.get("heartbeat", 0) > 6:
        state = "unresponsive" if runtime else "legacy"
    elif (directory / "stop.request").exists():
        state = "stopping"
    elif pause and runtime.get("state") != "paused":
        state = "pausing"
    else:
        state = runtime.get("state", "starting")
    result = {"active": active, "state": state, "pause_requested": pause,
              "runtime": runtime, "jobs": [], "counts": {}, "waiting": 0, "ignored": 0}
    try:
        result["startup_error"] = (directory / "startup-error.txt").read_text(encoding="utf-8")
    except OSError:
        result["startup_error"] = None
    if config.database.exists():
        connection = sqlite3.connect(config.database.as_uri() + "?mode=ro", uri=True, timeout=.25)
        connection.row_factory = sqlite3.Row
        try:
            result["jobs"] = [dict(row) for row in connection.execute(
                "SELECT * FROM jobs ORDER BY CASE WHEN state='processing' THEN 0 ELSE 1 END,id DESC LIMIT 300")]
            result["counts"] = dict(connection.execute("SELECT state,count(*) FROM jobs GROUP BY state"))
            result["waiting"] = connection.execute("SELECT count(*) FROM files WHERE present=1 AND ignored=0 AND job_id IS NULL").fetchone()[0]
            result["ignored"] = connection.execute("SELECT count(*) FROM files WHERE present=1 AND ignored=1").fetchone()[0]
        finally:
            connection.close()
    return result
