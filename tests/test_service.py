import threading
import time
from pathlib import Path

from audioscribe.config import Config, atomic_write
from audioscribe.service import run
from audioscribe.store import Store


def test_background_service_detects_processes_and_stops(tmp_path):
    for name in ("in", "out", "brain", "data"):
        (tmp_path / name).mkdir()
    config = Config(*(str(tmp_path / name) for name in ("in", "out", "brain", "data")), stable_seconds=1, poll_seconds=1)
    errors = []
    class Engine:
        def __init__(self, config):
            self.config = config
        def process(self, job, report, stopped):
            report("Prueba de persistencia")
            path = Path(self.config.output_dir) / "prueba.md"
            atomic_write(path, "**Hablante 1:** texto de prueba")
            return path
    def target():
        try:
            run(config, engine_factory=Engine)
        except Exception as error:
            errors.append(error)
    thread = threading.Thread(target=target)
    thread.start()
    try:
        deadline = time.monotonic() + 10
        ready = False
        while time.monotonic() < deadline:
            if config.database.exists():
                store = Store(config.database)
                try:
                    ready = bool(store.db.execute("SELECT 1 FROM roots").fetchone())
                finally:
                    store.close()
                if ready:
                    break
            time.sleep(.05)
        assert ready and not errors
        (Path(config.input_dir) / "nuevo.mp3").write_bytes(b"audio")
        done = False
        while time.monotonic() < deadline:
            store = Store(config.database)
            try:
                row = store.db.execute("SELECT state,output FROM jobs").fetchone()
                done = bool(row and row["state"] == "done" and Path(row["output"]).exists())
            finally:
                store.close()
            if done:
                break
            time.sleep(.1)
        assert done and not errors
    finally:
        atomic_write(Path(config.data_dir) / "stop.request", "stop")
        thread.join(10)
    assert not thread.is_alive()
