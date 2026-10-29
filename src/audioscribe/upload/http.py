from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import secrets as secret_module
import shutil
import sqlite3
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from .history import (StaleHistory, latest_internal_history,
                      public_history_record, stored_public_record)
from .publication import InvalidFilename, normalize_media_filename, publish_atomically
from .resources import DiskReservations, UnsafeCapacityError
from .staging import (create_transfer_file, cleanup_transfer, read_manifest,
                      require_owned_staging, write_manifest)
from .status import DownstreamProofs, project_downstream
from .validation import validate_staged_media

COOKIE_NAME = "__Host-audioscribe"
SESSION_CACHE_LIMIT = 64
ABSOLUTE_SESSION_SECONDS = 30 * 24 * 3600
IDLE_SESSION_SECONDS = 24 * 3600
CHALLENGE_EXPIRY_SECONDS = 60
MAX_JSON_BYTES = 4096
MAX_JSON_MESSAGES = 128
STATUS_HISTORY_LIMIT = 300
ACTIVE_TRANSFER_STATES = ("reserved", "receiving", "validating", "publish-intent")
CANCELLING_STATE = "cancelling"
LOGIN_RATE_PER_SECOND = 10.0
LOGIN_BURST = 20


class HttpError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


@dataclass
class Session:
    lineage: str
    cookie_verifier: str
    csrf: str
    created: float
    last_seen: float = field(default=0.0)

    def expired(self, now: float) -> bool:
        return now >= self.created + ABSOLUTE_SESSION_SECONDS or now >= self.last_seen + IDLE_SESSION_SECONDS


@dataclass
class Transfer:
    upload_id: str
    final_name: str
    declared_bytes: int | None
    token: str | None
    lineage: str
    part_path: Path | None
    state: str = "reserved"
    bytes_received: int = 0
    last_byte_at: float = 0.0
    published_path: Path | None = None
    error_code: str | None = None
    auth_epoch: int = 0


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _decode43(value: str) -> bytes:
    if not isinstance(value, str) or len(value) != 43:
        raise HttpError(401, "authentication_required", "credential encoding is not canonical")
    try:
        raw = base64.b64decode(value + "=", altchars=b"-_", validate=True)
    except ValueError as error:
        raise HttpError(401, "authentication_required", "credential encoding is not canonical") from error
    if len(raw) != 32 or _b64(raw) != value:
        raise HttpError(401, "authentication_required", "credential encoding is not canonical")
    return raw


class UploadRuntime:
    """Single runtime owner state: sessions, reservations, staging, transfers.

    Local fixture seam for PLAN-02 verification; the production listener stays
    disabled by default and starts only through the service enable path.
    """

    def __init__(self, config, reservations: DiskReservations | None = None,
                 time_fn=time.monotonic, wall_fn=time.time, persistor=None):
        self.config = config
        self.reservations = reservations or DiskReservations(config.upload_reserve_bytes)
        self.time_fn = time_fn
        self.wall_fn = wall_fn
        self.persistor = persistor
        self.sessions: dict[str, Session] = {}
        self.transfers: dict[str, Transfer] = {}
        self.history: list[dict] = []
        self.challenge_key = secret_module.token_bytes(32)
        self.verifier: str | None = None
        self.baseline_ready = False
        self.staging: Path | None = None
        self.frozen = False
        self.enable_snapshot: dict | None = None
        self.state_guard = threading.RLock()
        self.admission_closed = False
        self.auth_epoch = 0
        self.revoked_lineages: set[str] = set()
        self.lineage_proofs: dict[str, str] = {}
        self.downstream_proofs = DownstreamProofs()
        self._login_bucket = {"tokens": float(LOGIN_BURST), "last": self.time_fn()}

    # -- lifecycle ---------------------------------------------------------
    def load_verifier(self) -> None:
        path = Path(self.config.data_dir) / "upload-auth" / "verifier.json"
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as error:
            raise HttpError(503, "busy", "upload credential verifier is not installed") from error
        verifier = record.get("sha256")
        if not isinstance(verifier, str) or len(verifier) != 64:
            raise HttpError(503, "busy", "upload credential verifier is malformed")
        self.verifier = verifier

    def start(self) -> None:
        self.load_verifier()
        self.staging = require_owned_staging(Path(self.config.input_dir))

    def mark_baseline_ready(self) -> None:
        self.baseline_ready = True

    # -- sessions ----------------------------------------------------------
    def expire_session_for_test(self, cookie: str) -> None:
        presented = cookie.split("=", 1)[-1]
        key = hashlib.sha256(presented.encode("latin-1")).hexdigest()
        session = self.sessions.get(key)
        if session is not None:
            session.created -= ABSOLUTE_SESSION_SECONDS + 1
            session.last_seen = session.created

    def _canonical_origin(self) -> str:
        return self.config.upload_origin

    def _check_origin_and_host(self, scope, *, mutation: bool) -> None:
        headers = _header_map(scope)
        _check_forwarding_chain(scope)
        _check_host_and_scheme(scope, headers, self._canonical_origin())
        origin = headers.get("origin")
        if origin == self._canonical_origin():
            return
        # Browsers omit Origin on same-origin GETs; a present-but-foreign
        # Origin is a cross-site request and is always rejected. Mutations
        # require the exact canonical Origin (A4).
        if mutation or origin:
            raise HttpError(403, "forbidden", "origin is not the configured canonical origin")

    def _session(self, scope, *, mutation: bool) -> Session:
        headers = _header_map(scope)
        self._check_origin_and_host(scope, mutation=mutation)
        cookie = headers.get("cookie", "")
        presented = None
        for part in cookie.split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME:
                presented = value
        session = None
        if presented:
            key = hashlib.sha256(presented.encode("latin-1")).hexdigest()
            session = self.sessions.get(key)
        now = self.wall_fn()
        if session is None or session.expired(now):
            if presented:
                self.sessions.pop(hashlib.sha256(presented.encode("latin-1")).hexdigest(), None)
            raise HttpError(401, "authentication_required", "an authenticated session is required")
        if mutation:
            supplied = headers.get("x-csrf-token")
            if not supplied or not hmac.compare_digest(supplied, session.csrf):
                raise HttpError(403, "forbidden", "CSRF token mismatch")
            session.last_seen = now
            self._persist_touch(session)
        return session

    def _persist_touch(self, session: Session) -> None:
        """Persist an idle renewal (best effort; storage failure fails closed
        only for the row, never for the live session)."""
        if self.persistor is None:
            return
        try:
            self.persistor.touch_session(session.cookie_verifier, session.last_seen)
        except sqlite3.Error:
            pass

    def _prune_sessions(self) -> None:
        expired: list[str] = []
        with self.state_guard:
            now = self.wall_fn()
            expired = [verifier for verifier, session in self.sessions.items()
                       if session.expired(now)]
            for verifier in expired:
                del self.sessions[verifier]
            while len(self.sessions) > SESSION_CACHE_LIMIT:
                oldest = min(self.sessions, key=lambda v: self.sessions[v].last_seen)
                del self.sessions[oldest]
            active = {t.lineage for t in self.transfers.values()
                      if t.state in ACTIVE_TRANSFER_STATES}
            live = {s.lineage for s in self.sessions.values()}
            self.lineage_proofs = {key: value for key, value in self.lineage_proofs.items()
                                   if value in active or value in live}
        if self.persistor is not None:
            # A4: persisted session/proof rows follow the same bounded expiry.
            try:
                for verifier in expired:
                    self.persistor.delete_session(verifier)
                self.persistor.prune_lineage_proofs(active | live)
                self.persistor.prune_expired_sessions(now, ABSOLUTE_SESSION_SECONDS,
                                                      IDLE_SESSION_SECONDS)
            except sqlite3.Error:
                pass

    def logout(self, session: Session) -> None:
        """Explicit logout: revoke the session, its lineage proofs and cancel
        only that lineage's unpublished uploads."""
        with self.state_guard:
            self.sessions.pop(session.cookie_verifier, None)
            self.lineage_proofs = {key: value for key, value in self.lineage_proofs.items()
                                   if value != session.lineage}
            targets = [t for t in self.transfers.values()
                       if t.lineage == session.lineage and t.state in ACTIVE_TRANSFER_STATES]
        for transfer in targets:
            self.cancel_transfer(transfer)
        self._forget_lineage_if_idle(session.lineage)
        if self.persistor is not None:
            try:
                self.persistor.delete_session(session.cookie_verifier)
                self.persistor.delete_lineage_proofs(session.lineage)
            except sqlite3.Error:
                pass

    def renew_session_on_bytes(self, session: Session) -> None:
        """Received bytes renew the idle window only while unexpired."""
        now = self.wall_fn()
        if not session.expired(now):
            session.last_seen = now
            self._persist_touch(session)

    # -- challenges and login ---------------------------------------------
    def _admit_login(self) -> None:
        """A4 global login token bucket: 10/s refill, burst 20, bounded
        counters, immediate rejection before any credential work."""
        with self.state_guard:
            now = self.time_fn()
            bucket = self._login_bucket
            bucket["tokens"] = min(float(LOGIN_BURST),
                                   bucket["tokens"] + (now - bucket["last"]) * LOGIN_RATE_PER_SECOND)
            bucket["last"] = now
            if bucket["tokens"] < 1.0:
                raise HttpError(429, "busy", "login attempts are rate limited")
            bucket["tokens"] -= 1.0

    def _cookie_lineage(self, headers: dict[str, str]) -> str | None:
        """A4 line 101: a presented current/expired cookie proves continuity
        if its session (or its persisted verifier row) is known."""
        presented = None
        for part in headers.get("cookie", "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE_NAME:
                presented = value
        if not presented:
            return None
        key = hashlib.sha256(presented.encode("latin-1")).hexdigest()
        with self.state_guard:
            session = self.sessions.get(key)
        if session is not None:
            return session.lineage
        if self.persistor is not None:
            try:
                return self.persistor.session_lineage(key)
            except sqlite3.Error:
                return None
        return None

    def _challenge(self) -> str:
        expires = int(self.wall_fn()) + CHALLENGE_EXPIRY_SECONDS
        nonce = secret_module.token_bytes(16)
        payload = f"{expires}:{_b64(nonce)}"
        signature = hmac.new(self.challenge_key, payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}:{signature}"

    def _verify_challenge(self, nonce: str) -> bool:
        try:
            expires, token, signature = nonce.split(":", 2)
            payload = f"{expires}:{token}"
            expected = hmac.new(self.challenge_key, payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return False
            return int(expires) >= int(self.wall_fn())
        except (ValueError, TypeError):
            return False

    # -- transfers ---------------------------------------------------------
    def _admission_slots_available(self) -> bool:
        active = sum(1 for t in self.transfers.values()
                     if t.state in ("reserved", "receiving", "validating", "publish-intent"))
        return active < self.config.upload_concurrency

    def transfer_record(self, upload_id: str) -> Transfer | None:
        self.expire_idle_transfers()
        return self.transfers.get(upload_id)

    def register(self, session: Session, filename: str, file_bytes: int | None) -> Transfer:
        if not self.baseline_ready:
            raise HttpError(503, "busy", "scanner baseline is not ready; upload admission is closed")
        if self.frozen:
            raise HttpError(503, "busy", "reserve protection is frozen")
        try:
            final_name, _stem = normalize_media_filename(filename)
        except InvalidFilename as error:
            raise HttpError(422, "invalid_media", str(error)) from error
        maximum = self.config.upload_max_bytes
        if file_bytes is not None:
            if type(file_bytes) is not int or file_bytes < 0:
                raise HttpError(422, "invalid_media", "file_bytes must be a nonnegative integer")
            if file_bytes > maximum:
                raise HttpError(413, "too_large", "declared size exceeds the configured maximum")
            commitment = file_bytes
        else:
            commitment = maximum
        free_bytes = self._free_bytes()
        with self.state_guard:
            if self.admission_closed:
                raise HttpError(409, "busy", "upload admission is closed")
            if not self._admission_slots_available():
                raise HttpError(409, "busy", "configured upload concurrency is already admitted")
            probe = getattr(self, "admission_probe", None)
            if probe is not None:
                probe()
            upload_id = secret_module.token_hex(16)
            now = self.time_fn()
            transfer = Transfer(upload_id=upload_id, final_name=final_name,
                                declared_bytes=file_bytes, token=None, lineage=session.lineage,
                                part_path=None, last_byte_at=now)
            self.transfers[upload_id] = transfer
        try:
            if not self.reservations.admit(upload_id, commitment, free_bytes):
                raise HttpError(409, "busy", "no upload slot or reserve capacity is available")
            transfer.part_path = create_transfer_file(self.staging, upload_id)
            write_manifest(self.staging, upload_id, {
                "upload_id": upload_id, "state": "reserved", "final_name": final_name,
                "declared_bytes": file_bytes, "lineage": session.lineage,
            })
        except BaseException:
            with self.state_guard:
                self.transfers.pop(upload_id, None)
            self._release_reservation(upload_id)
            raise
        transfer.token = _b64(secret_module.token_bytes(32))
        self._prune_sessions()
        return transfer

    def authorize_body(self, session: Session, upload_id: str, token: str | None) -> Transfer:
        transfer = self.transfers.get(upload_id)
        if transfer is None or transfer.state not in ("reserved", "receiving"):
            raise HttpError(404, "stale", "no such active upload")
        if transfer.lineage != session.lineage:
            raise HttpError(403, "forbidden", "upload belongs to another lineage")
        if not token or transfer.token is None or not hmac.compare_digest(token, transfer.token):
            raise HttpError(403, "forbidden", "transfer token is missing or already used")
        transfer.token = None
        transfer.auth_epoch = self.auth_epoch
        if transfer.state == "reserved":
            transfer.state = "receiving"
            self._write_manifest(transfer, "receiving")
        return transfer

    def receive_chunk(self, transfer: Transfer, chunk: bytes) -> None:
        with self.state_guard:
            if transfer.state == "cancelled":
                raise HttpError(409, "cancelled", "transfer was cancelled during receipt")
            if transfer.state != "receiving":
                raise HttpError(409, "busy", "transfer is not receiving bytes")
        limit = transfer.declared_bytes
        if limit is None:
            limit = self.config.upload_max_bytes
        if transfer.bytes_received + len(chunk) > limit:
            raise HttpError(413, "too_large", "body exceeds the declared size")
        if not chunk:
            transfer.last_byte_at = self.time_fn()
            return

        def sample_free_space() -> int:
            return self._free_bytes()

        def write_chunk() -> int:
            with open(transfer.part_path, "ab", opener=_private_opener) as stream:
                stream.write(chunk)
                stream.flush()
                return len(chunk)

        try:
            self.reservations.write(transfer.upload_id, write_chunk, sample_free_space)
        except UnsafeCapacityError:
            # Fail closed: freeze admission, cancel every unpublished transfer
            # and report the bounded 507 outcome instead of crashing the request.
            self.check_external_consumption()
            self.cancel_transfer(transfer)
            raise HttpError(507, "reserve_unavailable",
                            "free space breached the protected reserve during receipt")
        cancelled_during_receipt = False
        with self.state_guard:
            if transfer.state != "receiving":
                # A cancellation flagged while this write was pending: the
                # cancel skipped its release on us; complete it outside the
                # state guard so the commitment hand-back never blocks under
                # the lifecycle guard (A6 lock order).
                cancelled_during_receipt = True
        if cancelled_during_receipt:
            self._release_reservation(transfer.upload_id)
            raise HttpError(409, "cancelled", "transfer was cancelled during receipt")
        transfer.bytes_received += len(chunk)
        transfer.last_byte_at = self.time_fn()

    def complete_receipt(self, transfer: Transfer) -> None:
        """Close, fsync, validate, then publish; single bounded pipeline."""
        with self.state_guard:
            if transfer.state != "receiving":
                raise HttpError(409, "cancelled", "transfer is no longer receiving")
            transfer.state = "validating"
        self._write_manifest(transfer, "validating")
        try:
            with open(transfer.part_path, "rb") as stream:
                if stream.read(1) == b"":
                    raise HttpError(422, "invalid_media", "empty media is rejected before publication")
            validation = validate_staged_media(transfer.part_path, Path(transfer.final_name).suffix)
            if not validation.valid or not validation.has_media_frame:
                raise HttpError(422, "invalid_media", "media failed validation")
        except HttpError:
            self._fail_transfer(transfer)
            raise
        except Exception as error:
            self._fail_transfer(transfer)
            raise HttpError(422, "invalid_media", "media failed validation") from error
        self.attempt_publication(transfer)

    def attempt_publication(self, transfer: Transfer) -> None:
        """A6/A7 linearization: cancellation wins over publication atomically.

        The state guard is taken only around flag checks, the A6 invariant
        rechecks and the link syscall, never across awaited writes or
        validation. Failure paths clean staging, release the reservation and
        record a truthful outcome before raising.
        """
        pre_cancel_message: str | None = None
        with self.state_guard:
            if transfer.state not in ("validating", "publish-intent"):
                raise HttpError(409, "cancelled", "transfer was cancelled before publication")
            if self.frozen or transfer.lineage in self.revoked_lineages:
                pre_cancel_message = "transfer was revoked before publication"
            elif transfer.auth_epoch != self.auth_epoch:
                pre_cancel_message = "credentials were rotated before publication"
            else:
                transfer.state = "publish-intent"
        if pre_cancel_message is not None:
            # Cancel outside the state guard: the terminal release below must
            # never wait for the resource guard while a lifecycle guard is
            # held (A6 lock order).
            self.cancel_transfer(transfer)
            raise HttpError(409, "cancelled", pre_cancel_message)
        self._write_manifest(transfer, "publish-intent")
        failure: HttpError | None = None
        freeze_on_failure = False
        with self.state_guard:
            if transfer.state != "publish-intent":
                raise HttpError(409, "cancelled", "transfer was cancelled before publication")
            invariant_error = self._publication_invariant_error(transfer)
            if invariant_error is not None:
                failure = invariant_error
                freeze_on_failure = invariant_error.code == "reserve_unavailable"
            else:
                try:
                    final = publish_atomically(transfer.part_path, Path(self.config.input_dir),
                                               transfer.final_name)
                except OSError as error:
                    transfer.state = "failed"
                    transfer.error_code = "cleanup_failed"
                    failure = HttpError(409, "cleanup_failed",
                                        "publication could not create the final name")
                    failure.__cause__ = error
                else:
                    transfer.published_path = final
                    transfer.state = "published"
        if failure is not None:
            if freeze_on_failure:
                self.freeze_for_external_consumption()
                if transfer.state == "publish-intent":
                    # The freeze cancels reserved/receiving/validating only;
                    # this transfer was already at the publication gate.
                    self.cancel_transfer(transfer)
            elif transfer.state == "failed":
                self._fail_transfer(transfer)
            elif transfer.state == "publish-intent":
                self.cancel_transfer(transfer)
            raise failure
        self._write_manifest(transfer, "published")
        try:
            transfer.part_path.unlink(missing_ok=True)
        except OSError:
            transfer.error_code = "cleanup_failed"
            self._record_history(transfer, "published-with-cleanup-error")
        self._release_reservation(transfer.upload_id)
        if transfer.error_code is None:
            self._record_history(transfer, "published")
        self._prune_terminal_transfers()

    def _publication_invariant_error(self, transfer: Transfer) -> HttpError | None:
        """A6/A7 pre-link rechecks; caller holds the state guard."""
        from .capabilities import root_identity

        if not self.baseline_ready:
            return HttpError(409, "cancelled", "scanner baseline was lost before publication")
        snapshot = self.enable_snapshot
        if snapshot is not None:
            try:
                identity = root_identity(Path(self.config.input_dir))
            except OSError as error:
                return HttpError(409, "cancelled", "input root is unavailable for publication")
            if (snapshot.get("root_device"), snapshot.get("root_inode")) != identity:
                return HttpError(409, "cancelled", "input root changed since enable")
            if snapshot.get("input_dir") and \
                    Path(snapshot["input_dir"]) != Path(self.config.input_dir).resolve():
                return HttpError(409, "cancelled", "input root changed since enable")
        try:
            free_bytes = self._free_bytes()
        except HttpError as error:
            return error
        if not self.reservations.reserve_intact(free_bytes):
            return HttpError(507, "reserve_unavailable",
                             "free space breached the protected reserve before publication")
        return None

    def cleanup_unused_reservation(self, upload_id: str) -> None:
        """A4: expiry before body authorization cleans the unused reservation."""
        transfer = self.transfers.get(upload_id)
        if transfer is not None and transfer.state == "reserved" and transfer.bytes_received == 0:
            self.cancel_transfer(transfer)

    def cancel(self, session: Session, upload_id: str) -> str:
        transfer = self.transfers.get(upload_id)
        if transfer is None:
            raise HttpError(404, "stale", "no such active upload")
        if transfer.lineage != session.lineage:
            raise HttpError(403, "forbidden", "upload belongs to another lineage")
        return self.cancel_transfer(transfer)

    def cancel_transfer(self, transfer: Transfer) -> str:
        with self.state_guard:
            if transfer.state == "published":
                return "already_published"
            if transfer.state == CANCELLING_STATE:
                # A concurrent cancel owns the finalization, including the
                # blocking release on its exit path.
                return "cancelled"
            if transfer.state in ("cancelled", "failed", "cleanup-failed"):
                already_terminal = True
            else:
                already_terminal = False
                # The immediate writer-visible signal: every state check treats
                # anything but "receiving"/"reserved" as out of receipt. On
                # this cancelled path the terminal state itself is exposed
                # only after staging cleanup and the reservation release
                # complete (F3); published/failed record their terminal state
                # under the guard, with the blocking release immediately
                # after on the same exit path.
                transfer.state = CANCELLING_STATE
        if already_terminal:
            self._release_reservation(transfer.upload_id)
            return "cancelled" if transfer.state == "cancelled" else "cleanup_failed"
        self._write_manifest(transfer, "cancelled")
        complete = cleanup_transfer(self.staging, transfer.upload_id)
        self._release_reservation(transfer.upload_id)
        with self.state_guard:
            transfer.state = "cancelled" if complete else "cleanup-failed"
        if not complete:
            self._record_history(transfer, "cleanup_failed")
            self._prune_terminal_transfers()
            return "cleanup_failed"
        self._record_history(transfer, "cancelled")
        self._forget_lineage_if_idle(transfer.lineage)
        self._prune_terminal_transfers()
        return "cancelled"

    def active_unpublished_count(self) -> int:
        with self.state_guard:
            return sum(1 for transfer in self.transfers.values()
                       if transfer.state in ACTIVE_TRANSFER_STATES)

    def cancel_all_unpublished(self) -> None:
        with self.state_guard:
            targets = [transfer for transfer in self.transfers.values()
                       if transfer.state in ACTIVE_TRANSFER_STATES]
        for transfer in targets:
            self.cancel_transfer(transfer)

    def evaluate_stop(self, force: bool) -> bool:
        """Atomic admission/stop gate: True approves (closing admission first)."""
        with self.state_guard:
            if self.active_unpublished_count() and not force:
                return False
            self.admission_closed = True
            return True

    def rotate_credentials(self, verifier: str) -> None:
        with self.state_guard:
            self.verifier = verifier
            self.auth_epoch += 1
            self.sessions.clear()
            self.lineage_proofs.clear()
            self.revoked_lineages = {transfer.lineage for transfer in self.transfers.values()
                                     if transfer.state in ACTIVE_TRANSFER_STATES}
        self.cancel_all_unpublished()
        if self.persistor is not None:
            try:
                self.persistor.clear_sessions()
                self.persistor.clear_lineage_proofs()
            except sqlite3.Error:
                pass

    def _forget_lineage_if_idle(self, lineage: str) -> None:
        with self.state_guard:
            if any(transfer.lineage == lineage and transfer.state in ACTIVE_TRANSFER_STATES
                   for transfer in self.transfers.values()):
                return
            self.revoked_lineages.discard(lineage)

    def expire_idle_transfers(self) -> None:
        now = self.time_fn()
        for transfer in list(self.transfers.values()):
            if transfer.state in ("reserved", "receiving") and \
                    now - transfer.last_byte_at >= self.config.upload_inactivity_seconds:
                transfer.error_code = "timed_out"
                self.cancel_transfer(transfer)

    def check_external_consumption(self) -> bool:
        """A6 monitor tick: freeze admission and cancel unpublished transfers
        when current free space no longer covers the reserve plus commitments.
        Unavailable free-space samples fail closed. Returns True when frozen."""
        breached = True
        try:
            free_bytes = self._free_bytes()
        except HttpError:
            pass
        else:
            breached = not self.reservations.reserve_intact(free_bytes)
        if breached and not self.frozen:
            self.freeze_for_external_consumption()
        return self.frozen

    def freeze_for_external_consumption(self) -> None:
        """Reserve breach: freeze admission and cancel every unpublished transfer."""
        self.frozen = True
        for transfer in list(self.transfers.values()):
            if transfer.state in ("reserved", "receiving", "validating"):
                self.cancel_transfer(transfer)

    def transfer_record_public(self, session: Session, upload_id: str) -> dict:
        transfer = self.transfers.get(upload_id)
        if transfer is not None:
            if transfer.lineage != session.lineage:
                raise HttpError(404, "stale", "no such active upload")
            return self._owning_record(transfer)
        # Terminal lookups use the persisted latest-300 only; absent or pruned
        # records return outcome_unavailable, never an inferred failure.
        if self.persistor is not None and getattr(self.persistor, "path", None):
            try:
                stored = stored_public_record(self.persistor.path, upload_id)
            except StaleHistory as error:
                raise HttpError(503, "busy", "status storage is unavailable") from error
            if stored is not None:
                lineage, record = stored
                if lineage == session.lineage:
                    return record
        raise HttpError(404, "outcome_unavailable", "no stored outcome for this upload")

    def _owning_record(self, transfer: Transfer) -> dict:
        record = public_history_record(self._public_record(transfer))
        if transfer.published_path is not None:
            record["published_path"] = str(transfer.published_path)
        return record

    def status_snapshot(self) -> dict:
        """Shared bounded status read model: latest-300 history plus config.

        Published records carry their downstream processing state projected
        from the normal ingestion linkage; snapshot reads use their own
        short-lived read-only connections and proof digests are cached.
        """
        if self.persistor is not None and getattr(self.persistor, "path", None):
            internal = latest_internal_history(self.persistor.path, STATUS_HISTORY_LIMIT)
        else:
            with self.state_guard:
                internal = list(self.history[-STATUS_HISTORY_LIMIT:])
        observations: list[tuple[str, int]] = []
        try:
            observations = project_downstream(
                Path(self.config.database), internal, str(self.config.input_dir),
                self.downstream_proofs)
        except Exception:
            for record in internal:
                record.setdefault("downstream", None)
        history = [public_history_record(row, row.get("downstream")) for row in internal]
        if self.persistor is not None and observations:
            self._persist_linkage(observations)
        return {"history": history,
                "concurrency": self.config.upload_concurrency,
                "fresh": True}

    def _persist_linkage(self, observations: list[tuple[str, int]]) -> None:
        try:
            for upload_id, job_id in observations:
                self.persistor.record_observed_job(upload_id, job_id)
        except sqlite3.Error:
            pass

    def _public_record(self, transfer: Transfer) -> dict:
        return {"upload_id": transfer.upload_id, "name": transfer.final_name,
                "state": transfer.state, "bytes_received": transfer.bytes_received,
                "declared_bytes": transfer.declared_bytes,
                "published_path": str(transfer.published_path) if transfer.published_path else None,
                "error_code": transfer.error_code}

    def restore_persisted_state(self) -> None:
        """A9 restart recovery: sessions, continuity proofs and shared history."""
        if self.persistor is None:
            return
        with self.state_guard:
            for record in self.persistor.load_sessions():
                session = Session(lineage=record["lineage"],
                                  cookie_verifier=record["verifier"],
                                  csrf="", created=record["created"],
                                  last_seen=record["last_seen"])
                self.sessions[session.cookie_verifier] = session
            for record in self.persistor.load_lineage_proofs():
                self.lineage_proofs[record["proof_verifier"]] = record["lineage"]
            self.history = [public_history_record(row)
                            for row in reversed(self.persistor.latest_history(STATUS_HISTORY_LIMIT))]

    def _persist_login(self, session: Session, continuity_proof: str, old_proof_key: str | None) -> None:
        if self.persistor is None:
            return
        try:
            self.persistor.save_session(session.cookie_verifier, session.lineage,
                                        self.auth_epoch, session.created, session.last_seen)
            if old_proof_key is not None:
                self.persistor.delete_lineage_proof(old_proof_key)
            self.persistor.save_lineage_proof(
                hashlib.sha256(continuity_proof.encode("latin-1")).hexdigest(),
                session.lineage, self.auth_epoch)
        except sqlite3.Error:
            pass

    def _prune_terminal_transfers(self) -> None:
        """Bounded terminal shadow: live state is released after terminal
        cleanup; only a small recent-terminal window stays for deterministic
        already-published/cancelled outcomes. Older lookups use the persisted
        latest-300 history."""
        limit = max(16, 4 * self.config.upload_concurrency)
        terminal = [key for key, transfer in self.transfers.items()
                    if transfer.state not in ACTIVE_TRANSFER_STATES
                    and transfer.state != CANCELLING_STATE]
        for key in terminal[:max(0, len(terminal) - limit)]:
            del self.transfers[key]

    def _record_history(self, transfer: Transfer, outcome: str) -> None:
        public = self._public_record(transfer)
        public["outcome"] = outcome
        record = public_history_record(public)
        with self.state_guard:
            self.history.append(record)
            del self.history[:-STATUS_HISTORY_LIMIT]
        if self.persistor is not None:
            try:
                now = self.wall_fn()
                internal = {**record, "published_path": public["published_path"],
                            "profile_snapshot": self._profile_snapshot()
                            if transfer.published_path is not None else None,
                            "root": str(self.config.input_dir),
                            "lineage": transfer.lineage,
                            "created": now, "updated": now}
                self.persistor.record_history(internal)
                self.persistor.prune_history(STATUS_HISTORY_LIMIT)
            except sqlite3.Error:
                pass

    def _profile_snapshot(self) -> str:
        from ..store import profile
        return profile(self.config)

    def _write_manifest(self, transfer: Transfer, state: str) -> None:
        try:
            write_manifest(self.staging, transfer.upload_id, {
                "upload_id": transfer.upload_id, "state": state,
                "final_name": transfer.final_name,
                "declared_bytes": transfer.declared_bytes, "lineage": transfer.lineage,
            })
        except OSError:
            pass

    def _fail_transfer(self, transfer: Transfer) -> None:
        transfer.state = "failed"
        complete = cleanup_transfer(self.staging, transfer.upload_id)
        if not complete:
            transfer.error_code = "cleanup_failed"
            self._record_history(transfer, "cleanup_failed")
        else:
            self._record_history(transfer, "failed")
        self._release_reservation(transfer.upload_id)
        self._prune_terminal_transfers()

    def _release_reservation(self, upload_id: str) -> None:
        # Blocking terminal release: every call site runs outside the state
        # guard, so waiting here never violates the A6 lock order
        # (resource guard → state guard). A skipped release would strand the
        # commitment forever; the wait is bounded by one pending write.
        self.reservations.release(upload_id, blocking=True)

    def _free_bytes(self) -> int:
        try:
            return shutil.disk_usage(self.config.input_dir).free
        except OSError as error:
            raise HttpError(507, "reserve_unavailable", "destination free space is unavailable") from error


def _private_opener(path, flags):
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return os.open(path, flags, 0o600)


def _header_map(scope) -> dict[str, str]:
    return {name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers", [])}


def _check_forwarding_chain(scope) -> None:
    """Single-hop proxy forwarding is tolerated; chains are rejected.

    The documented deployment is Tailscale Serve proxying on loopback, which
    adds exactly one X-Forwarded-For hop. Forwarding headers are never used as
    identity or authorization; multi-hop chains, empty entries and duplicated
    header lines are unexpected and fail closed.
    """
    entries: dict[str, list[str]] = {}
    for name, value in scope.get("headers", []):
        lower = name.decode("latin-1").lower()
        if lower in ("x-forwarded-for", "x-real-ip"):
            entries.setdefault(lower, []).append(value.decode("latin-1"))
    for name, values in entries.items():
        if len(values) > 1 or "," in values[0] or not values[0].strip():
            raise HttpError(403, "forbidden", "unexpected client forwarding chain")


def _check_host_and_scheme(scope, headers: dict[str, str], canonical_origin: str) -> None:
    """Certified Host and supported scheme on every request (A4).

    The listener terminates plain HTTP on loopback; Serve terminates TLS in
    front of it, so both http (proxied) and https (direct TLS) are supported
    schemes on the ASGI scope.
    """
    if scope.get("scheme") not in ("http", "https"):
        raise HttpError(403, "forbidden", "unsupported request scheme")
    host = headers.get("host", "")
    if host.split(":", 1)[0] != _origin_host(canonical_origin):
        raise HttpError(403, "forbidden", "host does not match the certified hostname")


def _origin_host(origin: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(origin).hostname or ""


PAGE_CSP = (b"default-src 'self'; script-src 'self'; style-src 'self';"
            b" connect-src 'self'; img-src 'self'; frame-ancestors 'none'")

# Fixed same-origin asset allowlist (A4): no framework, no external CDN, and
# never an arbitrary file or media download route.
STATIC_ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
}
_STATIC_CACHE: dict[str, bytes] = {}


def _serve_static(path: str):
    name, content_type = STATIC_ROUTES[path]
    body = _STATIC_CACHE.get(name)
    if body is None:
        body = (Path(__file__).parent / "static" / name).read_bytes()
        _STATIC_CACHE[name] = body
    return 200, body, content_type


def make_upload_app(runtime: UploadRuntime):
    """Minimal raw-ASGI application implementing the A5 route contracts."""

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        method = scope["method"].upper()
        path = scope["path"].rstrip("/") or "/"
        extra_headers: list = []
        try:
            if method == "GET" and path in STATIC_ROUTES:
                # Static routes enforce the same certified-Host/scheme and
                # forwarding policy as every other route (A4).
                static_headers = _header_map(scope)
                _check_forwarding_chain(scope)
                _check_host_and_scheme(scope, static_headers, runtime._canonical_origin())
                status, body, content_type = _serve_static(path)
            else:
                status, payload, extra_headers = await _route(runtime, scope, receive,
                                                              method, path)
                body = json.dumps(payload, sort_keys=True).encode() if payload is not None else b""
                content_type = "application/json"
        except HttpError as error:
            status = error.status
            payload = {"error": error.code, "detail": error.message}
            extra_headers = []
            body = json.dumps(payload, sort_keys=True).encode()
            content_type = "application/json"
        headers = [(b"content-type", content_type.encode()),
                   (b"cache-control", b"no-store"),
                   (b"x-content-type-options", b"nosniff"),
                   (b"content-security-policy",
                    PAGE_CSP if path == "/" else b"default-src 'none'"),
                   (b"frame-ancestors", b"'none'")]
        headers.extend(extra_headers)
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    return app


async def _route(runtime, scope, receive, method, path):
    prefix = "/api/v1"
    if not path.startswith(prefix):
        raise HttpError(404, "stale", "unknown route")
    path = path[len(prefix):]
    headers = _header_map(scope)
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type.startswith("multipart/") or headers.get("content-encoding"):
        raise HttpError(415, "invalid_media", "multipart and encoded bodies are rejected")
    if method == "GET" and path == "/auth/challenge":
        runtime._check_origin_and_host(scope, mutation=False)
        return 200, {"nonce": runtime._challenge(), "expires_in": CHALLENGE_EXPIRY_SECONDS}, []
    if method == "POST" and path == "/auth/login":
        return await _login(runtime, scope, receive)
    if method == "POST" and path.startswith("/uploads/") and path.endswith("/body"):
        upload_id = path[len("/uploads/"):-len("/body")]
        try:
            session = runtime._session(scope, mutation=True)
        except HttpError as error:
            if error.status == 401:
                runtime.cleanup_unused_reservation(upload_id)
            raise
        return await _body(runtime, session, scope, receive, upload_id, headers.get("x-transfer-token"))
    session = runtime._session(scope, mutation=method != "GET")
    if method == "POST" and path == "/auth/logout":
        runtime.logout(session)
        return 200, {"revoked": True}, []
    if method == "POST" and path == "/uploads":
        body = await _bounded_json(receive)
        transfer = runtime.register(session, body.get("filename"), body.get("file_bytes"))
        return 201, {"upload_id": transfer.upload_id, "transfer_token": transfer.token,
                     "name": transfer.final_name}, []
    if method == "POST" and path.startswith("/uploads/") and path.endswith("/cancel"):
        upload_id = path[len("/uploads/"):-len("/cancel")]
        return 200, {"result": runtime.cancel(session, upload_id)}, []
    if method == "GET" and path.startswith("/uploads/"):
        return 200, runtime.transfer_record_public(session, path[len("/uploads/"):]), []
    if method == "GET" and path == "/status":
        runtime._check_origin_and_host(scope, mutation=False)
        try:
            snapshot = await asyncio.to_thread(runtime.status_snapshot)
        except StaleHistory:
            return 503, {"error": "busy", "stale": True}, []
        return 200, snapshot, []
    raise HttpError(404, "stale", "unknown route")


async def _login(runtime, scope, receive):
    runtime._admit_login()
    runtime._check_origin_and_host(scope, mutation=True)
    body = await _bounded_json(receive)
    nonce = body.get("csrf")
    if not isinstance(nonce, str) or not runtime._verify_challenge(nonce):
        raise HttpError(401, "authentication_required", "challenge nonce is missing, stale or invalid")
    raw = _decode43(body.get("secret", ""))
    candidate = hashlib.sha256(raw).hexdigest()
    if runtime.verifier is None or not hmac.compare_digest(candidate, runtime.verifier):
        raise HttpError(401, "authentication_required", "secret verification failed")
    # Continuity (A4): a presented current/expired cookie proves the lineage
    # first; the page-memory proof is the fallback. Neither authorizes
    # anything alone — fresh-secret verification and Origin/CSRF stay mandatory.
    lineage = runtime._cookie_lineage(_header_map(scope))
    old_proof_key = None
    presented_proof = body.get("continuity_proof")
    if lineage is None and presented_proof is not None:
        _decode43(presented_proof)
        old_proof_key = hashlib.sha256(presented_proof.encode("latin-1")).hexdigest()
        with runtime.state_guard:
            lineage = runtime.lineage_proofs.get(old_proof_key)
    cookie_raw = secret_module.token_bytes(32)
    cookie_value = _b64(cookie_raw)
    session = Session(lineage=lineage or secret_module.token_hex(16),
                      cookie_verifier=hashlib.sha256(cookie_value.encode("latin-1")).hexdigest(),
                      csrf=_b64(secret_module.token_bytes(32)),
                      created=runtime.wall_fn())
    session.last_seen = session.created
    continuity_proof = _b64(secret_module.token_bytes(32))
    with runtime.state_guard:
        if old_proof_key is not None:
            runtime.lineage_proofs.pop(old_proof_key, None)
        runtime.lineage_proofs[hashlib.sha256(continuity_proof.encode("latin-1")).hexdigest()] = session.lineage
        runtime.sessions[session.cookie_verifier] = session
    runtime._prune_sessions()
    runtime._persist_login(session, continuity_proof, old_proof_key)
    cookie = (f"{COOKIE_NAME}={cookie_value}; Path=/; Secure; HttpOnly; SameSite=Strict; "
              f"Max-Age={ABSOLUTE_SESSION_SECONDS}")
    return 200, {"csrf": session.csrf, "continuity_proof": continuity_proof}, \
        [(b"set-cookie", cookie.encode("latin-1"))]


async def _bounded_json(receive) -> dict:
    """Bounded JSON body read: disconnect-safe with a capped receive count.

    h11 delivers {"type": "http.disconnect"} immediately on client
    disconnects; continuing past it would spin the listener event loop, so it
    breaks like any other terminal framing event. Zero-byte keepalive
    messages cannot extend the read past MAX_JSON_MESSAGES.
    """
    chunks = []
    total = 0
    for _ in range(MAX_JSON_MESSAGES):
        message = await receive()
        if message["type"] == "http.disconnect":
            raise HttpError(499, "cancelled", "client disconnected during request body receipt")
        if message["type"] != "http.request":
            continue
        chunk = message.get("body", b"")
        total += len(chunk)
        if total > MAX_JSON_BYTES:
            raise HttpError(422, "invalid_media", "JSON body exceeds 4 KiB")
        chunks.append(chunk)
        if not message.get("more_body", False):
            break
    else:
        raise HttpError(422, "invalid_media", "JSON body framing is unbounded")
    try:
        payload = json.loads(b"".join(chunks) or b"{}")
    except ValueError as error:
        raise HttpError(422, "invalid_media", "JSON body is malformed") from error
    if not isinstance(payload, dict):
        raise HttpError(422, "invalid_media", "JSON body must be a flat object")
    return payload


async def _body(runtime, session, scope, receive, upload_id, token):
    transfer = runtime.authorize_body(session, upload_id, token)
    try:
        framing = _declared_framing(_header_map(scope), transfer)
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                raise HttpError(499, "cancelled", "client disconnected during body receipt")
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            if chunk:
                runtime.receive_chunk(transfer, chunk)
                runtime.renew_session_on_bytes(session)
                framing["received"] += len(chunk)
                if framing["expected"] is not None and framing["received"] > framing["expected"]:
                    raise HttpError(413, "too_large", "body exceeds the declared framing size")
            if not message.get("more_body", False):
                break
        if framing["expected"] is not None and framing["received"] != framing["expected"]:
            raise HttpError(422, "invalid_media", "body framing disagrees with the declared size")
    except BaseException:
        if transfer.state in ("receiving", "reserved"):
            runtime.cancel_transfer(transfer)
        raise
    runtime.complete_receipt(transfer)
    record = runtime._public_record(transfer)
    return 200, record, []


def _declared_framing(headers, transfer) -> dict:
    content_length = headers.get("content-length")
    expected = None
    if content_length is not None:
        if not content_length.isdigit():
            raise HttpError(422, "invalid_media", "Content-Length is not a valid integer")
        expected = int(content_length)
        if transfer.declared_bytes is not None and expected != transfer.declared_bytes:
            raise HttpError(422, "invalid_media", "Content-Length disagrees with the declared file size")
    content_type = headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type.startswith("multipart/"):
        raise HttpError(415, "invalid_media", "multipart bodies are rejected")
    if headers.get("content-encoding"):
        raise HttpError(415, "invalid_media", "Content-Encoding is rejected")
    return {"expected": expected, "received": 0}
