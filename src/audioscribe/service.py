from __future__ import annotations

import logging
import json
import os
import threading
import time
from dataclasses import replace
from pathlib import Path

from .config import Config
from .control import ServiceControl
from .engine import LocalEngine
from .store import Store, digest, profile, signature

LOG = logging.getLogger(__name__)


class InstanceLock:
    """OS lock, automatically released even on an unclean process exit."""
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                self.stream.seek(0)
                if not self.stream.read(1):
                    self.stream.write(b"0")
                    self.stream.flush()
                self.stream.seek(0)
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise RuntimeError("AudioScribe ya se está ejecutando para esta configuración.") from None

    def close(self):
        self.stream.close()


class Scanner:
    def __init__(self, config: Config, store: Store):
        self.config, self.store = config, store

    def paths(self) -> list[Path]:
        root = Path(self.config.input_dir)
        if not root.is_dir():
            raise FileNotFoundError(f"Carpeta de entrada no disponible: {root}")
        iterator = root.rglob("*") if self.config.recursive else root.iterdir()
        return sorted(p for p in iterator if p.is_file() and not p.is_symlink()
                      and p.suffix.lower() in (".mp3", ".mp4"))

    def baseline(self):
        return self.store.baseline(self.config.input_dir, self.paths(), time.time())

    def scan(self, now=None):
        now = time.time() if now is None else now
        root = self.config.input_dir
        self.store.observe(root, self.paths(), now)
        for row in self.store.candidates(root, now - self.config.stable_seconds):
            try:
                path = Path(row["path"])
                if path.stat().st_size == 0:
                    continue
                sha = digest(path)
                if signature(path) != row["signature"]:
                    continue
                self.store.enqueue(row, sha, profile(self.config), now)
            except OSError as error:
                LOG.warning("Archivo aún no disponible: %s", error)


def run(config: Config, once=False, engine_factory=LocalEngine):
    config.validate(probe=False)
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    Path(config.data_dir).mkdir(parents=True, exist_ok=True)
    lock = InstanceLock(Path(config.data_dir) / "service.lock")
    stop = threading.Event()
    wake = threading.Event()
    store = Store(config.database)
    worker = None
    observer = None
    stop_file = Path(config.data_dir) / "stop.request"
    control = ServiceControl(Path(config.data_dir), stop)
    control.start()
    try:
        stop_file.unlink(missing_ok=True)
        store.recover()
        scanner = Scanner(config, store)
        scanner.baseline()

        def work():
            worker_store = Store(config.database)
            try:
                while not stop.is_set():
                    if control.checkpoint():
                        stop.set()
                        break
                    job = worker_store.claim()
                    if not job:
                        stop.wait(1)
                        continue
                    try:
                        control.update(job_id=job["id"], state="processing")
                        settings = json.loads(job["profile"])
                        job_config = replace(config, model=settings["model"], chunk_seconds=settings["chunk_seconds"])
                        engine = engine_factory(job_config)
                        result = engine.process(job,
                            lambda message: worker_store.progress(job["id"], message),
                            control.checkpoint)
                        worker_store.done(job["id"], result)
                    except InterruptedError:
                        # Remains processing until the next startup recovers it.
                        stop.set()
                    except Exception as error:
                        LOG.exception("Error en trabajo %s", job["id"])
                        worker_store.fail(job, str(error), config.max_attempts)
                    finally:
                        control.update(job_id=None)
            except Exception as error:
                LOG.exception("El trabajador se detuvo inesperadamente")
                control.update(worker_error=str(error))
                stop.set()
            finally:
                worker_store.close()

        scanner.scan()
        control.update(last_scan=time.time())
        if once:
            return
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer
            class Events(FileSystemEventHandler):
                def on_any_event(self, event):
                    if event.event_type in ("created", "modified", "moved", "deleted"):
                        wake.set()
            observer = Observer()
            observer.schedule(Events(), config.input_dir, recursive=config.recursive)
            observer.start()
        except (ImportError, OSError):
            LOG.warning("Vigilancia por eventos no disponible; se utilizará revisión periódica.")
        worker = threading.Thread(target=work, name="transcriber")
        worker.start()
        while not stop.is_set():
            if stop_file.exists():
                stop.set()
                break
            try:
                scanner.scan()
                control.update(last_scan=time.time(), scanner_error=None)
            except OSError:
                LOG.exception("No se pudo revisar la carpeta de entrada")
                control.update(scanner_error="No se puede revisar la carpeta de entrada. Consulta el registro.")
            wake.wait(config.poll_seconds)
            wake.clear()
            # Debounce bursts generated by large file copies.
            stop.wait(0.2)
    except KeyboardInterrupt:
        stop.set()
    finally:
        stop.set()
        if observer:
            observer.stop()
            observer.join()
        if worker:
            worker.join()
        control.close()
        store.close()
        lock.close()
