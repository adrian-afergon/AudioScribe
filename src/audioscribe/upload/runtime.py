from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
import threading
import time
from collections import deque
from pathlib import Path

from .controller import (build_snapshot, load_snapshot, read_revision,
                         snapshot_path, verifier_installed, write_revision)
from .http import UploadRuntime

LOG = logging.getLogger(__name__)

MAILBOX_REQUEST_BYTES = 4096
MAILBOX_ACK_BYTES = 8192
MAILBOX_SLOTS = 16
PUMP_BATCH = 4
RESERVE_MONITOR_SECONDS = 0.25
COMMAND_ACTIONS = ("status", "enable", "disable", "regenerate-secret", "stop")
TERMINAL_TRANSFER_STATES = ("published", "cancelled", "failed", "cleanup-failed")
ACTIVE_TRANSFER_STATES = ("reserved", "receiving", "validating", "publish-intent")

# Resolved lazily so a disabled service never pays the Uvicorn/PyAV import.
DEFAULT_LISTENER_FACTORY = None


class MailboxProtocolError(ValueError):
    pass


class UploadRuntimeOwner:
    """Single upload lifecycle owner inside the service process.

    Consumes the bounded local mailbox on a dedicated asyncio thread with a
    100 ms technical poll, even when HTTP is disabled. Serializes configuration
    writes, credential rotation and admission/stop decisions; starts the
    listener only when an immutable enable snapshot says so.
    """

    def __init__(self, config, config_path: Path | None = None, *,
                 data_dir: Path | None = None, runtime: UploadRuntime | None = None,
                 listener_factory=None, stop_event: threading.Event | None = None,
                 persistor=None, wall_fn=time.time, time_fn=time.monotonic,
                 poll_interval: float = 0.1):
        self.config = config
        self.config_path = Path(config_path).resolve() if config_path else None
        self.data_dir = Path(data_dir or config.data_dir)
        self.mailbox = self.data_dir / "upload-mailbox"
        self.runtime = runtime or UploadRuntime(config, wall_fn=wall_fn, time_fn=time_fn)
        self.persistor = persistor
        self.stop_event = stop_event or threading.Event()
        self.wall_fn = wall_fn
        self.time_fn = time_fn
        self.poll_interval = poll_interval
        self.listener_factory = listener_factory
        self.listener = None
        self.revision = read_revision(self.data_dir)
        self.snapshot = load_snapshot(self.data_dir)
        self.desired_enabled = bool(config.upload_enabled)
        self.admission_closed = False
        self.stop_refusals = 0
        self.effective_error: str | None = None
        self.config_drift: str | None = None
        self._completed: deque[str] = deque(maxlen=64)
        self._pump_thread: threading.Thread | None = None
        self._closing = threading.Event()
        self._lifecycle_lock = threading.Lock()
        self._last_reserve_check = 0.0
        self._boot_config_sha256 = self._file_hash(self.config_path)
        self._prepare_mailbox()

    def _prepare_mailbox(self) -> None:
        self.mailbox.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.mailbox.is_symlink() or os.stat(self.mailbox).st_mode & 0o077:
            raise PermissionError("Upload command mailbox is not private.")

    # -- lifecycle -----------------------------------------------------------
    def start_pump(self) -> None:
        self._prepare_mailbox()
        self._pump_thread = threading.Thread(target=self._pump_main,
                                             name="upload-owner", daemon=True)
        self._pump_thread.start()

    def start(self) -> None:
        """Boot-time activation: desired enabled state is activated only after
        the caller has completed baseline initialization; failures keep the
        saved desire and leave the listener off."""
        if not self.desired_enabled:
            return
        try:
            self._activate_from_snapshot()
        except Exception as error:
            self.effective_error = f"enable failed: {type(error).__name__}: {error}"
            LOG.warning("Upload listener stays off: %s", error)

    def _activate_from_snapshot(self) -> None:
        from .capabilities import ensure_owned_staging, root_identity
        from .publication import probe_link_capability
        from .resources import DiskReservations
        staging = ensure_owned_staging(Path(self.config.input_dir))
        probe = probe_link_capability(Path(self.config.input_dir))
        if not probe.get("link_shares_identity") or not probe.get("collision_preserves_original"):
            raise OSError("atomic no-overwrite link semantics unavailable on the destination mount")
        if self.runtime.verifier is None:
            self.runtime.load_verifier()
        if not verifier_installed(self.data_dir):
            raise RuntimeError("upload credential verifier is missing")
        # Bind the derived enforcement state for this activation from the
        # validated config: a re-enable after a disabled edit must serve with
        # the persisted reserve limit and stage under the persisted input
        # root, and the previous generation's reservation object (its limit
        # and any frozen failure state) must not survive into the new
        # listener generation.
        self.runtime.staging = staging
        self.runtime.reservations = DiskReservations(self.config.upload_reserve_bytes)
        if self.persistor is None:
            from .persistence import UploadStore
            self.persistor = UploadStore(Path(self.config.data_dir) / "queue.sqlite3")
        self.runtime.persistor = self.persistor
        self.runtime.restore_persisted_state()
        if self.snapshot is None:
            revision = self.revision + 1
            self.revision = revision
            write_revision(self.data_dir, revision)
            from ..config import atomic_write
            atomic_write(snapshot_path(self.data_dir),
                         json.dumps(build_snapshot(self.config, revision), sort_keys=True) + "\n")
            self.snapshot = load_snapshot(self.data_dir)
        identity = root_identity(Path(self.config.input_dir))
        if (self.snapshot.get("root_device"), self.snapshot.get("root_inode")) != identity:
            raise RuntimeError("input root identity changed since enable")
        self.runtime.enable_snapshot = self.snapshot
        # Reopen admission for the new listener generation: a disable/stop of
        # the previous generation closed it under the state guard; the
        # documented disable → enable flow must serve uploads again.
        with self.runtime.state_guard:
            self.runtime.admission_closed = False
        self.admission_closed = False
        self._start_listener()

    def _start_listener(self) -> None:
        if self.listener is not None:
            return
        factory = self.listener_factory or DEFAULT_LISTENER_FACTORY
        if factory is None:
            from ._listener import start_uvicorn_listener
            factory = start_uvicorn_listener
        self.listener = factory(self.runtime, self.config)
        self.listener.owner = self

    def _stop_listener(self) -> None:
        if self.listener is not None:
            try:
                self.listener.stop()
            except Exception:
                LOG.exception("Upload listener stop failed")
            self.listener = None

    def close(self) -> None:
        self._closing.set()
        # Close runtime admission atomically with the active count before
        # cancelling, so no transfer is admitted during shutdown.
        self.runtime.evaluate_stop(True)
        self.admission_closed = True
        self.runtime.cancel_all_unpublished()
        self._stop_listener()
        if self._pump_thread is not None:
            self._pump_thread.join(self.poll_interval * 20 + 2)

    # -- pump ----------------------------------------------------------------
    def _pump_main(self) -> None:
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)

            async def runner():
                while not self._closing.is_set():
                    try:
                        self.process_mailbox()
                        self.pump_lifecycle()
                    except Exception:
                        LOG.exception("Upload owner pump iteration failed")
                    await asyncio.sleep(self.poll_interval)

            loop.run_until_complete(runner())
        finally:
            asyncio.set_event_loop(None)
            loop.close()

    def pump_lifecycle(self) -> None:
        """Production schedule for the transfer lifecycle (A1/A6): the byte
        inactivity clock and the external-consumption reserve monitor run on
        the owner pump tick, never on a test seam."""
        self.runtime.expire_idle_transfers()
        now = self.time_fn()
        if now - self._last_reserve_check >= RESERVE_MONITOR_SECONDS:
            self._last_reserve_check = now
            self.runtime.check_external_consumption()

    def pump_once(self) -> None:
        """Deterministic test seam: one bounded synchronous pump iteration."""
        self.process_mailbox()

    def process_mailbox(self) -> None:
        if not self.mailbox.is_dir():
            return
        outstanding = 0
        for path in sorted(self.mailbox.glob("*.request.json")):
            outstanding += 1
            if outstanding > PUMP_BATCH:
                return
            try:
                self._process_one(path)
            except Exception:
                LOG.exception("Mailbox command processing failed")

    def _process_one(self, path: Path) -> None:
        command_id = path.name[:-len(".request.json")]
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return
        except OSError as error:
            self._write_ack(path, {"outcome": "rejected", "detail": f"unreadable request: {error}"})
            self._consume(path, command_id)
            return
        try:
            command = self._parse_command(raw)
        except MailboxProtocolError as error:
            self._write_ack(path, {"outcome": "rejected", "detail": str(error)})
            self._consume(path, command_id)
            return
        if command_id in self._completed:
            self._write_ack(path, {"outcome": "rejected", "detail": "replayed_command"})
            self._consume(path, command_id)
            return
        expected = command.get("expected_revision")
        if expected is not None and (type(expected) is not int or expected != self.revision):
            self._write_ack(path, {"outcome": "rejected", "detail": "stale_revision"})
            self._consume(path, command_id)
            return
        try:
            response = self.dispatch(command["action"], command)
        except Exception as error:
            LOG.exception("Upload command %s failed", command["action"])
            response = {"outcome": "rejected", "detail": f"command failed: {type(error).__name__}"}
        self._write_ack(path, response)
        self._consume(path, command_id)

    def _parse_command(self, raw: bytes) -> dict:
        if len(raw) > MAILBOX_REQUEST_BYTES:
            raise MailboxProtocolError("request exceeds 4 KiB")
        try:
            command = json.loads(raw)
        except ValueError as error:
            raise MailboxProtocolError("request is not valid JSON") from error
        if not isinstance(command, dict) or not set(command) <= {"id", "action", "expected_revision", "force", "verifier", "created"}:
            raise MailboxProtocolError("request schema is not flat and bounded")
        command_id = command.get("id")
        action = command.get("action")
        if (not isinstance(command_id, str) or len(command_id) != 32
                or any(character not in "0123456789abcdef" for character in command_id)):
            raise MailboxProtocolError("command id must be 32 hexadecimal characters")
        if action not in COMMAND_ACTIONS:
            raise MailboxProtocolError(f"unknown action {action!r}")
        return command

    def _consume(self, path: Path, command_id: str) -> None:
        try:
            path.unlink()
        except OSError:
            pass
        self._completed.append(command_id)

    def _write_ack(self, request_path: Path, response: dict) -> None:
        ack_path = request_path.with_name(request_path.name.replace(".request.json", ".ack.json"))
        payload = json.dumps({"id": request_path.name[:-len(".request.json")],
                              "revision": self.revision, **response}, sort_keys=True)
        if len(payload) > MAILBOX_ACK_BYTES:
            payload = json.dumps({"id": request_path.name[:-len(".request.json")],
                                  "revision": self.revision, "outcome": "rejected",
                                  "detail": "acknowledgement overflow"})
        fd, tmp = tempfile.mkstemp(prefix=".audioscribe-ack-", dir=self.mailbox)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
            os.chmod(tmp, 0o600)
            os.replace(tmp, ack_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)

    # -- command dispatch ----------------------------------------------------
    def dispatch(self, action: str, command: dict) -> dict:
        if action == "status":
            return {"outcome": "acknowledged", "status": self.status_snapshot()}
        if action == "enable":
            return self._command_enable(command)
        if action == "disable":
            return self._command_disable(bool(command.get("force")))
        if action == "regenerate-secret":
            return self._command_rotate(command.get("verifier"))
        if action == "stop":
            return self._command_stop(bool(command.get("force")))
        raise MailboxProtocolError(f"unknown action {action!r}")

    def status_snapshot(self) -> dict:
        return {"desired_enabled": self.desired_enabled,
                "effective_enabled": self.listener is not None,
                "active_uploads": self.runtime.active_unpublished_count(),
                "revision": self.revision,
                "auth_epoch": self.runtime.auth_epoch,
                "configuration_path_available": self.config_path is not None,
                "verifier_installed": verifier_installed(self.data_dir),
                "admission_closed": self.admission_closed,
                "stop_refusals": self.stop_refusals,
                "effective_error": self.effective_error,
                "config_drift": self.config_drift}

    def _bump_revision(self) -> int:
        self.revision += 1
        write_revision(self.data_dir, self.revision)
        return self.revision

    def _persist_enabled(self, enabled: bool) -> bool:
        if self.config_path is None:
            return False
        from ..config import Config
        config = Config.load(self.config_path)
        config.upload_enabled = enabled
        config.save(self.config_path)
        self._boot_config_sha256 = self._file_hash(self.config_path)
        return True

    def _command_enable(self, command: dict) -> dict:
        from dataclasses import replace as dataclass_replace

        from ..config import Config, atomic_write
        from .auth import install_verifier
        with self._lifecycle_lock:
            if self.desired_enabled and self.listener is not None:
                return {"outcome": "rejected", "detail": "already_enabled"}
            if self.config_path is None:
                return {"outcome": "rejected", "detail": "configuration_path_unavailable"}
            installed_here = False
            try:
                # A2: one load — the enabled candidate built from the on-disk
                # config is the same object that is validated, adopted by the
                # live runtime and persisted, so the listener, snapshot and
                # saved configuration can never diverge.
                candidate = dataclass_replace(Config.load(self.config_path),
                                              upload_enabled=True)
                candidate.validate(probe=False)
                if Path(candidate.data_dir).resolve() != self.data_dir.resolve():
                    # data_dir anchors the running process identity
                    # (InstanceLock, command mailbox, verifier, revision):
                    # derived upload state cannot follow it mid-process, so
                    # the enable is refused fail-closed and the edit is
                    # honored by the next service restart.
                    return {"outcome": "rejected",
                            "detail": "data_dir_changed_restart_required"}
                if command.get("verifier"):
                    if verifier_installed(self.data_dir):
                        return {"outcome": "rejected", "detail": "verifier_already_installed"}
                    install_verifier(self.data_dir, command["verifier"])
                    installed_here = True
                self._adopt_enabled_config(candidate)
                self._activate_from_snapshot()
            except Exception as error:
                if installed_here:
                    self._discard_installed_verifier()
                return {"outcome": "rejected", "detail": f"enable failed: {type(error).__name__}"}
            revision = self._bump_revision()
            self.desired_enabled = True
            self.effective_error = None
            try:
                candidate.save(self.config_path)
            except Exception as error:
                self.effective_error = f"persistence failed: {type(error).__name__}"
                return {"outcome": "rejected", "detail": "configuration_path_unavailable"}
            self._boot_config_sha256 = self._file_hash(self.config_path)
            atomic_write(snapshot_path(self.data_dir),
                         json.dumps(build_snapshot(candidate, revision), sort_keys=True) + "\n")
            self.snapshot = load_snapshot(self.data_dir)
            self.runtime.enable_snapshot = self.snapshot
            return {"outcome": "acknowledged", "status": self.status_snapshot()}

    def _adopt_enabled_config(self, candidate) -> None:
        """Swap the owner and runtime config references to the validated
        enabled candidate before activation, so live checks that read the
        config directly (canonical origin, limits, staging root, publication
        invariants) use the configuration that was validated and is about to
        be persisted. The derived enforcement objects themselves (reservation
        protection, staging root) are rebuilt from the same candidate by
        _activate_from_snapshot."""
        self.config = candidate
        self.runtime.config = candidate

    def _discard_installed_verifier(self) -> None:
        """Roll back a verifier installed by a failed enable command."""
        path = self.data_dir / "upload-auth" / "verifier.json"
        try:
            path.unlink()
        except OSError:
            pass

    def _command_disable(self, force: bool) -> dict:
        with self._lifecycle_lock:
            # Runtime admission gate: runtime.admission_closed is set under
            # the same state guard as the active count, so a registration
            # racing the decision is either admitted-then-cancelled (force)
            # or the refusal leaves admission undisturbed (A2).
            if not self.runtime.evaluate_stop(force):
                self.stop_refusals += 1
                return {"outcome": "rejected", "detail": "active_uploads",
                        "status": self.status_snapshot()}
            self.admission_closed = True
            if force:
                self.runtime.cancel_all_unpublished()
            self._stop_listener()
            persisted = self._persist_enabled(False)
            self.snapshot = None
            self.runtime.enable_snapshot = None
            snapshot_path(self.data_dir).unlink(missing_ok=True)
            self.desired_enabled = False
            self.effective_error = None
            revision = self._bump_revision()
            if not persisted:
                return {"outcome": "rejected", "detail": "configuration_path_unavailable"}
            return {"outcome": "acknowledged", "status": self.status_snapshot()}

    def _command_rotate(self, verifier: str | None) -> dict:
        from .auth import install_verifier
        if not isinstance(verifier, str) or len(verifier) != 64:
            return {"outcome": "rejected", "detail": "verifier is required as SHA-256 hex"}
        with self._lifecycle_lock:
            install_verifier(self.data_dir, verifier, replace=True)
            self.runtime.rotate_credentials(verifier)
            revision = self._bump_revision()
            return {"outcome": "acknowledged", "status": self.status_snapshot()}

    def _command_stop(self, force: bool) -> dict:
        if self.evaluate_stop(force):
            return {"outcome": "acknowledged", "status": self.status_snapshot()}
        return {"outcome": "rejected", "detail": "active_uploads",
                "status": self.status_snapshot()}

    # -- stop/admission guard -------------------------------------------------
    def evaluate_stop(self, force: bool) -> bool:
        """Atomic admission/stop decision. Returns False (refused) when active
        uploads exist and the request is unforced; approval closes admission
        first so no transfer is admitted after the decision."""
        if self.runtime.evaluate_stop(force):
            self.admission_closed = True
            if force:
                self.runtime.cancel_all_unpublished()
            self.stop_event.set()
            return True
        self.stop_refusals += 1
        return False

    # -- configuration drift --------------------------------------------------
    def check_config_drift(self) -> None:
        """Raw TOML edits are not interceptable: compare protected fields and
        reject adoption while enabled; the snapshot is preserved either way."""
        current = self._file_hash(self.config_path)
        if current is None or self._boot_config_sha256 is None:
            return
        if current == self._boot_config_sha256:
            return
        rejected = False
        if self.desired_enabled:
            try:
                from ..config import Config, reject_protected_upload_change
                file_config = Config.load(self.config_path)
                reject_protected_upload_change(self.config, file_config)
            except Exception:
                rejected = True
        self.config_drift = "rejected_protected_change" if rejected else "restart_pending"
        self._boot_config_sha256 = current

    @staticmethod
    def _file_hash(path: Path | None) -> str | None:
        if path is None:
            return None
        try:
            import hashlib
            return hashlib.sha256(Path(path).read_bytes()).hexdigest()
        except OSError:
            return None
