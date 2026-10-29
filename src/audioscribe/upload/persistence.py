from __future__ import annotations

"""A9 upload persistence: latest-300 history and authentication/session
metadata, on a dedicated connection with short WAL transactions."""

import sqlite3
import threading
from pathlib import Path

from ..store import UPLOAD_SCHEMA, ensure_upload_history_columns

SESSION_HISTORY_LIMIT = 300


class UploadStore:
    """Upload persistence with one SQLite connection per owner thread (A9).

    History and session writes arrive from the event loop, the runtime-owner
    pump and status projection workers; each gets its own short-lived WAL
    connection with a bounded busy timeout. Connections are never shared
    across threads and never held open across controller waits.
    """

    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._local = threading.local()
        self.db.executescript(UPLOAD_SCHEMA)
        ensure_upload_history_columns(self.db)
        self.db.commit()

    @property
    def db(self):
        """This thread's own connection, created on first use."""
        connection = getattr(self._local, "db", None)
        if connection is None:
            connection = sqlite3.connect(self.path, timeout=0.25)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=250")
            self._local.db = connection
        return connection

    def close(self):
        connection = getattr(self._local, "db", None)
        if connection is not None:
            connection.close()
            self._local.db = None

    # -- latest-300 history ---------------------------------------------------
    def record_history(self, record: dict) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO upload_history(upload_id, lineage, final_name, root,"
                " state, bytes_received, declared_bytes, published_path, error_code, outcome,"
                " profile_snapshot, job_id, created, updated)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record.get("upload_id"), record.get("lineage"), record.get("name"),
                 record.get("root"), record.get("state"), record.get("bytes_received"),
                 record.get("declared_bytes"), record.get("published_path"),
                 record.get("error_code"), record.get("outcome"),
                 record.get("profile_snapshot"), record.get("job_id"),
                 record.get("created"), record.get("updated")))

    def prune_history(self, keep: int = SESSION_HISTORY_LIMIT) -> None:
        with self.db:
            self.db.execute(
                "DELETE FROM upload_history WHERE rowid NOT IN "
                "(SELECT rowid FROM upload_history ORDER BY rowid DESC LIMIT ?)", (keep,))

    def latest_history(self, limit: int = SESSION_HISTORY_LIMIT) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM upload_history ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def record_observed_job(self, upload_id: str, job_id: int) -> None:
        """Persist the scanner-observed linkage for a published upload."""
        with self.db:
            self.db.execute(
                "UPDATE upload_history SET job_id=? WHERE upload_id=?"
                " AND (job_id IS NULL OR job_id<>?)", (job_id, upload_id, job_id))

    # -- sessions and continuity proofs ---------------------------------------
    def save_session(self, verifier: str, lineage: str, auth_epoch: int,
                     created: float, last_seen: float) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO upload_sessions(verifier, lineage, auth_epoch,"
                " created, last_seen) VALUES (?,?,?,?,?)",
                (verifier, lineage, auth_epoch, created, last_seen))

    def touch_session(self, verifier: str, last_seen: float) -> None:
        """Persist an idle renewal so a restart does not expire an actively
        used session at its stale last_seen (A4)."""
        with self.db:
            self.db.execute("UPDATE upload_sessions SET last_seen=? WHERE verifier=?",
                            (last_seen, verifier))

    def session_lineage(self, verifier: str) -> str | None:
        row = self.db.execute("SELECT lineage FROM upload_sessions WHERE verifier=?",
                              (verifier,)).fetchone()
        return row["lineage"] if row is not None else None

    def prune_expired_sessions(self, now: float, absolute_seconds: float,
                               idle_seconds: float) -> None:
        with self.db:
            self.db.execute(
                "DELETE FROM upload_sessions WHERE ? >= created + ? OR ? >= last_seen + ?",
                (now, absolute_seconds, now, idle_seconds))

    def prune_lineage_proofs(self, keep_lineages: set[str]) -> None:
        """Drop proofs whose lineage owns no live session or active upload."""
        with self.db:
            self.db.execute(
                "DELETE FROM upload_lineage_proofs WHERE lineage NOT IN (%s)"
                % ",".join("?" * len(keep_lineages)) if keep_lineages
                else "DELETE FROM upload_lineage_proofs",
                tuple(keep_lineages))

    def delete_session(self, verifier: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM upload_sessions WHERE verifier=?", (verifier,))

    def delete_lineage_sessions(self, lineage: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM upload_sessions WHERE lineage=?", (lineage,))

    def clear_sessions(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM upload_sessions")

    def load_sessions(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM upload_sessions").fetchall()
        return [dict(row) for row in rows]

    def save_lineage_proof(self, proof_verifier: str, lineage: str, auth_epoch: int) -> None:
        with self.db:
            self.db.execute(
                "INSERT OR REPLACE INTO upload_lineage_proofs(proof_verifier, lineage,"
                " auth_epoch) VALUES (?,?,?)", (proof_verifier, lineage, auth_epoch))

    def delete_lineage_proof(self, proof_verifier: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM upload_lineage_proofs WHERE proof_verifier=?",
                            (proof_verifier,))

    def delete_lineage_proofs(self, lineage: str) -> None:
        with self.db:
            self.db.execute("DELETE FROM upload_lineage_proofs WHERE lineage=?", (lineage,))

    def clear_lineage_proofs(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM upload_lineage_proofs")

    def load_lineage_proofs(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM upload_lineage_proofs").fetchall()
        return [dict(row) for row in rows]
