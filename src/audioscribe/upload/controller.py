from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path

from . import auth
from ..config import Config
from ..control import service_active
from ..service import InstanceLock

OWNER_STATE_NAME = "upload-owner.json"
SNAPSHOT_NAME = "upload-enable-snapshot.json"
VERIFIER_DIRECTORY = "upload-auth"
VERIFIER_NAME = "verifier.json"


@dataclass
class CommandOutcome:
    outcome: str
    revision: int | None = None
    detail: str = ""
    status: dict | None = None
    secret: str | None = None

    def public(self) -> dict:
        return {"outcome": self.outcome, "revision": self.revision,
                "detail": self.detail, "status": self.status}


def owner_state_path(data_dir: Path) -> Path:
    return Path(data_dir) / OWNER_STATE_NAME


def snapshot_path(data_dir: Path) -> Path:
    return Path(data_dir) / SNAPSHOT_NAME


def verifier_installed(data_dir: Path) -> bool:
    return (Path(data_dir) / VERIFIER_DIRECTORY / VERIFIER_NAME).is_file()


def read_revision(data_dir: Path) -> int:
    try:
        record = json.loads(owner_state_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return 0
    revision = record.get("revision")
    return revision if type(revision) is int and revision >= 0 else 0


def write_revision(data_dir: Path, revision: int) -> None:
    from ..config import atomic_write
    atomic_write(owner_state_path(data_dir), json.dumps({"revision": revision}) + "\n")


def build_snapshot(config: Config, revision: int) -> dict:
    from .capabilities import root_identity
    identity = root_identity(Path(config.input_dir))
    return {"format": 1, "input_dir": str(Path(config.input_dir).resolve()),
            "origin": config.upload_origin, "port": config.upload_port,
            "max_bytes": config.upload_max_bytes, "concurrency": config.upload_concurrency,
            "reserve_bytes": config.upload_reserve_bytes,
            "inactivity_seconds": config.upload_inactivity_seconds,
            "root_device": identity[0], "root_inode": identity[1],
            "revision": revision}


def load_snapshot(data_dir: Path) -> dict | None:
    try:
        record = json.loads(snapshot_path(data_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and record.get("format") == 1 else None


class UploadController:
    """One local control authority shared by the CLI and the desktop panel.

    Active service: bounded mailbox command with acknowledged/rejected/uncertain
    outcome. Inactive service: the controller takes the InstanceLock and acts as
    the owner before touching configuration or credential state.
    """

    def __init__(self, config: Config, config_path: Path | None,
                 data_dir: Path | None = None, ack_timeout: float = 10.0):
        self.config = config
        self.config_path = Path(config_path).resolve() if config_path else None
        self.data_dir = Path(data_dir or config.data_dir)
        self.ack_timeout = ack_timeout

    # -- shared entry points -------------------------------------------------
    def status(self) -> CommandOutcome:
        return self._status()

    def enable(self) -> CommandOutcome:
        return self._mutate("enable")

    def disable(self, force: bool = False) -> CommandOutcome:
        return self._mutate("disable", force=force)

    def regenerate_secret(self) -> CommandOutcome:
        return self._mutate("regenerate-secret")

    def stop(self, force: bool = False) -> CommandOutcome:
        return self._mutate("stop", force=force)

    def _mutate(self, action: str, force: bool = False) -> CommandOutcome:
        if service_active(self.data_dir):
            return self._mailbox_command(action, force)
        return self._act_as_owner(action, force)

    def _status(self) -> CommandOutcome:
        if service_active(self.data_dir):
            return self._mailbox_command("status")
        return self._status_offline()

    # -- inactive service: controller owns the lock --------------------------
    def _status_offline(self) -> CommandOutcome:
        effective_detail = "disabled" if not self.config.upload_enabled else (
            "credential_missing" if not verifier_installed(self.data_dir) else "not_running")
        return CommandOutcome("acknowledged", revision=read_revision(self.data_dir),
                              status={"desired_enabled": self.config.upload_enabled,
                                      "effective_enabled": False,
                                      "active_uploads": 0,
                                      "verifier_installed": verifier_installed(self.data_dir),
                                      "configuration_path_available": self.config_path is not None,
                                      "effective_detail": effective_detail})

    def _act_as_owner(self, action: str, force: bool) -> CommandOutcome:
        try:
            lock = InstanceLock(self.data_dir / "service.lock")
        except RuntimeError:
            return self._mailbox_command(action, force)
        try:
            if action == "status":
                return self._status_offline()
            if action == "enable":
                return self._owner_enable()
            if action == "disable":
                return self._owner_disable(force)
            if action == "regenerate-secret":
                return self._owner_regenerate()
            if action == "stop":
                return CommandOutcome("rejected", detail="service is not running")
            raise ValueError(f"unknown action {action}")
        finally:
            lock.close()

    def _load_persisted_config(self) -> Config | None:
        if self.config_path is None:
            return None
        return Config.load(self.config_path)

    def _owner_enable(self) -> CommandOutcome:
        secret = None
        if self.config_path is None:
            return CommandOutcome("rejected", detail="configuration_path_unavailable")
        try:
            config = self._load_persisted_config()
            if config.upload_enabled:
                return CommandOutcome("rejected", detail="already_enabled")
            # A2: the whole preflight must succeed before anything is
            # installed or persisted. Validation of the enabled candidate
            # (canonical origin) comes first, then the mount probe; the
            # verifier is generated and installed last, so a failed enable
            # leaves no partial credential or unloadable configuration.
            candidate = replace(config, upload_enabled=True)
            candidate.validate(probe=False)
            self._preflight_mount(config)
            if not verifier_installed(self.data_dir):
                secret, verifier = self._generate_in_memory()
                auth.install_verifier(self.data_dir, verifier)
            config.upload_enabled = True
            config.save(self.config_path)
        except Exception:
            return CommandOutcome("rejected", detail="enable_preflight_failed")
        revision = read_revision(self.data_dir) + 1
        write_revision(self.data_dir, revision)
        from ..config import atomic_write
        atomic_write(snapshot_path(self.data_dir),
                     json.dumps(build_snapshot(config, revision), sort_keys=True) + "\n")
        return CommandOutcome("acknowledged", revision=revision, secret=secret)

    def _preflight_mount(self, config: Config) -> None:
        from .capabilities import ensure_owned_staging
        from .publication import probe_link_capability
        staging = ensure_owned_staging(Path(config.input_dir))
        probe = probe_link_capability(Path(config.input_dir))
        if not probe.get("link_shares_identity") or not probe.get("collision_preserves_original"):
            raise OSError("atomic no-overwrite link semantics unavailable on the destination mount")

    def _owner_disable(self, force: bool) -> CommandOutcome:
        if self.config_path is None:
            return CommandOutcome("rejected", detail="configuration_path_unavailable")
        config = self._load_persisted_config()
        config.upload_enabled = False
        config.save(self.config_path)
        snapshot_path(self.data_dir).unlink(missing_ok=True)
        revision = read_revision(self.data_dir) + 1
        write_revision(self.data_dir, revision)
        return CommandOutcome("acknowledged", revision=revision)

    def _owner_regenerate(self) -> CommandOutcome:
        secret, verifier = self._generate_in_memory()
        auth.install_verifier(self.data_dir, verifier, replace=True)
        revision = read_revision(self.data_dir) + 1
        write_revision(self.data_dir, revision)
        return CommandOutcome("acknowledged", revision=revision, secret=secret)

    # -- active service: bounded mailbox command -----------------------------
    MAILBOX_REQUEST_BYTES = 4096
    MAILBOX_SLOTS = 16
    ACK_POLL_SECONDS = 0.05

    def _mailbox_command(self, action: str, force: bool = False) -> CommandOutcome:
        mailbox = self.data_dir / "upload-mailbox"
        if not mailbox.is_dir():
            return CommandOutcome("rejected", detail="mailbox_unavailable")
        outstanding = sum(1 for _ in mailbox.glob("*.request.json"))
        if outstanding >= self.MAILBOX_SLOTS:
            return CommandOutcome("rejected", detail="mailbox_busy")
        secret = None
        verifier = None
        if action == "regenerate-secret":
            secret, verifier = self._generate_in_memory()
        elif action == "enable" and not verifier_installed(self.data_dir):
            secret, verifier = self._generate_in_memory()
        command_id = secrets.token_hex(16)
        payload = json.dumps({"id": command_id, "action": action,
                              "expected_revision": None, "force": bool(force),
                              "verifier": verifier, "created": time.time()})
        if len(payload) > self.MAILBOX_REQUEST_BYTES:
            return CommandOutcome("rejected", detail="command envelope overflow")
        request_path = mailbox / f"{command_id}.request.json"
        fd, tmp = tempfile.mkstemp(prefix=".audioscribe-cmd-", dir=mailbox)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
            os.chmod(tmp, 0o600)
            os.replace(tmp, request_path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        deadline = time.monotonic() + self.ack_timeout
        ack_path = mailbox / f"{command_id}.ack.json"
        while time.monotonic() < deadline:
            if ack_path.exists():
                try:
                    ack = json.loads(ack_path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    ack = None
                if isinstance(ack, dict):
                    ack_path.unlink(missing_ok=True)
                    if ack.get("outcome") != "acknowledged":
                        secret = None
                    return CommandOutcome(ack.get("outcome", "rejected"),
                                          revision=ack.get("revision"),
                                          detail=str(ack.get("detail", "")),
                                          status=ack.get("status"),
                                          secret=secret)
            time.sleep(self.ACK_POLL_SECONDS)
        return CommandOutcome("uncertain", detail="acknowledgement timeout; outcome unknown; "
                              "query status and regenerate explicitly; nothing was replayed")

    # -- memory-only secret generation --------------------------------------
    def _generate_in_memory(self) -> tuple[str, str]:
        raw = secrets.token_bytes(32)
        encoded = auth._encode(raw)
        return encoded, hashlib.sha256(raw).hexdigest()
