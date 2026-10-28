from __future__ import annotations

"""Bounded public read model for shared upload history (A9).

Shared latest-300 status is projected to fixed public fields before any driver
materialization: no lineage, root mapping or timestamps, with byte-bounded
strings so each served record stays within the 4 KiB status-record budget.

Read snapshots use their own short-lived read-only connection with a bounded
busy timeout; failures surface as stale, never as wrong data.
"""

import sqlite3
from pathlib import Path

PUBLIC_RECORD_KEYS = ("upload_id", "name", "state", "bytes_received",
                      "declared_bytes", "error_code", "outcome", "downstream")

_NAME_BYTES = 240
_CODE_BYTES = 64
BUSY_TIMEOUT_MS = 250


class StaleHistory(Exception):
    """The read snapshot could not be taken; served status would be stale."""


def latest_public_history(db_path: Path, limit: int) -> list[dict]:
    """Latest history rows through a dedicated read-only connection."""
    return [public_history_record(row) for row in latest_internal_history(db_path, limit)]


def latest_internal_history(db_path: Path, limit: int) -> list[dict]:
    """Latest raw history rows (internal columns included) for projection."""
    connection = None
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True,
                                     timeout=BUSY_TIMEOUT_MS / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        rows = connection.execute(
            "SELECT * FROM upload_history ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
    except sqlite3.Error as error:
        raise StaleHistory(str(error)) from error
    finally:
        if connection is not None:
            connection.close()
    return [dict(row) for row in reversed(rows)]


def stored_public_record(db_path: Path, upload_id: str) -> tuple[str, dict] | None:
    """One persisted terminal record: (owning lineage, public projection)."""
    connection = None
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True,
                                     timeout=BUSY_TIMEOUT_MS / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        row = connection.execute("SELECT * FROM upload_history WHERE upload_id=?",
                                 (upload_id,)).fetchone()
    except sqlite3.Error as error:
        raise StaleHistory(str(error)) from error
    finally:
        if connection is not None:
            connection.close()
    if row is None:
        return None
    return row["lineage"], public_history_record(dict(row))


def _truncate_utf8(value: str, limit: int) -> str:
    raw = value.encode("utf-8")
    if len(raw) <= limit:
        return value
    return raw[:limit].decode("utf-8", errors="ignore")


def _bounded_name(value: str, limit: int = _NAME_BYTES) -> str:
    raw = value.encode("utf-8")
    if len(raw) <= limit:
        return value
    suffix = ""
    stem = value
    dot = value.rfind(".")
    if dot > 0:
        candidate = value[dot:]
        if len(candidate.encode("utf-8")) < limit:
            suffix, stem = candidate, value[:dot]
    budget = limit - len(suffix.encode("utf-8"))
    return stem.encode("utf-8")[:budget].decode("utf-8", errors="ignore") + suffix


def public_history_record(record: dict, downstream: str | None = None) -> dict:
    """Project one stored/live history record to its shared public shape."""
    name = record.get("name") or record.get("final_name") or ""
    outcome = record.get("outcome")
    if outcome is None:
        outcome = record.get("state")
    projected = {
        "upload_id": record.get("upload_id"),
        "name": _bounded_name(str(name)),
        "state": record.get("state"),
        "bytes_received": record.get("bytes_received"),
        "declared_bytes": record.get("declared_bytes"),
        "error_code": _truncate_utf8(str(record.get("error_code")), _CODE_BYTES)
        if record.get("error_code") else None,
        "outcome": _truncate_utf8(str(outcome), _CODE_BYTES) if outcome else None,
        "downstream": downstream,
    }
    return {key: projected[key] for key in PUBLIC_RECORD_KEYS}
