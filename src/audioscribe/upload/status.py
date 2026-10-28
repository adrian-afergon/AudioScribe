from __future__ import annotations

"""Downstream processing projection for published uploads (A9).

Each published upload's transcription state is resolved through the normal
ingestion linkage — the scanner's own files.job_id row plus a compatible
profile snapshot — never from a content hash alone. Reuse is marked only when
the linked job was already a valid done result when the upload published.

Output proof digests run off the event loop (callers project inside a worker
thread) and are cached by (job, output, output_sha256) so one-second polls do
not rehash every result; the bounded cache invalidates when the signature
changes. Resolution failures make downstream unknown (None), never wrong.
"""

import sqlite3
from pathlib import Path

from ..store import digest

BUSY_TIMEOUT_MS = 250
PROOF_CACHE_LIMIT = 256


class DownstreamProofs:
    """Bounded digest-proof cache: one hash per unchanged job output."""

    def __init__(self, limit: int = PROOF_CACHE_LIMIT):
        self._entries: dict[tuple, bool] = {}
        self._order: list[tuple] = []
        self._limit = limit

    def valid_output(self, job_id: int, output: str | None, expected_sha: str | None) -> bool:
        try:
            stat = Path(output).stat() if output else None
        except OSError:
            return False
        signature = None if stat is None else (stat.st_size, stat.st_mtime_ns, stat.st_ino)
        key = (job_id, str(output), expected_sha, signature)
        if key in self._entries:
            return self._entries[key]
        try:
            valid = bool(output and expected_sha) and digest(Path(output)) == expected_sha
        except OSError:
            valid = False
        self._entries[key] = valid
        self._order.append(key)
        while len(self._order) > self._limit:
            self._entries.pop(self._order.pop(0), None)
        return valid


def project_downstream(db_path: Path, records: list[dict], input_root: str,
                       proofs: DownstreamProofs) -> list[tuple[str, int]]:
    """Fill each published record's downstream field in place.

    Non-published outcomes keep downstream None: awaiting scanner observation
    is not a queue position and cancelled/failed uploads have none. Returns
    the newly observed (upload_id, job_id) linkages so the caller can persist
    them on its own owner thread.
    """
    connection = None
    observations: list[tuple[str, int]] = []
    try:
        connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True,
                                     timeout=BUSY_TIMEOUT_MS / 1000)
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout={BUSY_TIMEOUT_MS}")
        for record in records:
            try:
                downstream, job_id = _resolve(connection, record, input_root, proofs)
                record["downstream"] = downstream
                if job_id is not None and record.get("job_id") != job_id:
                    observations.append((record["upload_id"], job_id))
            except sqlite3.Error:
                record["downstream"] = None
    except sqlite3.Error:
        for record in records:
            record["downstream"] = None
    finally:
        if connection is not None:
            connection.close()
    return observations


def _resolve(connection, record: dict, input_root: str, proofs: DownstreamProofs):
    if record.get("outcome") not in ("published", "published-with-cleanup-error"):
        return None, None
    path = record.get("published_path")
    if not path:
        return None, None
    row = connection.execute(
        "SELECT job_id FROM files WHERE root=? AND path=?", (input_root, path)).fetchone()
    if row is None or row["job_id"] is None:
        return "awaiting_scanner", None
    job = connection.execute(
        "SELECT id, profile, state, created, updated, output, output_sha256"
        " FROM jobs WHERE id=?", (row["job_id"],)).fetchone()
    if job is None:
        return "awaiting_scanner", None
    profile_snapshot = record.get("profile_snapshot")
    if profile_snapshot and job["profile"] != profile_snapshot:
        return None, None
    if job["state"] == "pending":
        return "queued", job["id"]
    if job["state"] == "processing":
        return "processing", job["id"]
    if job["state"] == "error":
        return "error", job["id"]
    if job["state"] == "done":
        if not proofs.valid_output(job["id"], job["output"], job["output_sha256"]):
            return "error", job["id"]
        published_at = record.get("created") or 0.0
        state = "reused" if job["updated"] <= published_at else "completed"
        return state, job["id"]
    return None, job["id"]