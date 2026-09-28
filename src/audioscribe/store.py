from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path


def signature(path: Path) -> str:
    stat = path.stat()
    return f"{stat.st_size}:{stat.st_mtime_ns}:{stat.st_ino}"


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, timeout=30)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS roots (path TEXT PRIMARY KEY, created REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY, source TEXT NOT NULL, sha256 TEXT NOT NULL,
                profile TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN
                    ('pending','processing','done','error')),
                attempts INTEGER NOT NULL DEFAULT 0, retry_at REAL NOT NULL DEFAULT 0,
                created REAL NOT NULL, updated REAL NOT NULL,
                progress TEXT NOT NULL DEFAULT '', output TEXT, error TEXT,
                output_sha256 TEXT
            );
            CREATE INDEX IF NOT EXISTS jobs_queue ON jobs(state, retry_at);
            CREATE INDEX IF NOT EXISTS jobs_content ON jobs(sha256, profile);
            CREATE TABLE IF NOT EXISTS files (
                root TEXT NOT NULL, path TEXT NOT NULL, signature TEXT NOT NULL,
                stable_since REAL NOT NULL, ignored INTEGER NOT NULL DEFAULT 0,
                present INTEGER NOT NULL DEFAULT 1,
                job_id INTEGER REFERENCES jobs(id), PRIMARY KEY(root,path)
            );
            PRAGMA user_version=1;
        """)

    def close(self):
        self.db.close()

    def baseline(self, root: str, paths: list[Path], now: float) -> bool:
        if self.db.execute("SELECT 1 FROM roots WHERE path=?", (root,)).fetchone():
            return False
        with self.db:
            for path in paths:
                try:
                    sig = signature(path)
                except OSError:
                    continue
                self.db.execute("INSERT OR IGNORE INTO files(root,path,signature,stable_since,ignored) VALUES (?,?,?,?,1)",
                                (root, str(path), sig, now))
            self.db.execute("INSERT INTO roots VALUES (?,?)", (root, now))
        return True

    def observe(self, root: str, paths: list[Path], now: float):
        with self.db:
            seen = set()
            for path in paths:
                try:
                    sig = signature(path)
                except OSError:
                    continue
                p = str(path)
                seen.add(p)
                row = self.db.execute("SELECT * FROM files WHERE root=? AND path=?", (root, p)).fetchone()
                if row is None:
                    self.db.execute("INSERT INTO files(root,path,signature,stable_since) VALUES (?,?,?,?)", (root, p, sig, now))
                elif row["signature"] != sig or not row["present"]:
                    self.db.execute("UPDATE files SET signature=?, stable_since=?, ignored=0, present=1, job_id=NULL WHERE root=? AND path=?", (sig, now, root, p))
            for row in self.db.execute("SELECT path FROM files WHERE root=? AND present=1", (root,)).fetchall():
                if row["path"] not in seen:
                    self.db.execute("UPDATE files SET present=0 WHERE root=? AND path=?", (root, row["path"]))

    def candidates(self, root: str, stable_before: float):
        return self.db.execute("SELECT * FROM files WHERE root=? AND present=1 AND ignored=0 AND job_id IS NULL AND stable_since<=?", (root, stable_before)).fetchall()

    def enqueue(self, file, sha: str, profile: str, now: float) -> int:
        with self.db:
            match = self.db.execute("SELECT * FROM jobs WHERE sha256=? AND profile=? ORDER BY id DESC LIMIT 1", (sha, profile)).fetchone()
            if match and match["state"] == "done" and not self.valid_output(match):
                match = None
            if match is None:
                cursor = self.db.execute("INSERT INTO jobs(source,sha256,profile,state,created,updated) VALUES (?,?,?,'pending',?,?)", (file["path"], sha, profile, now, now))
                job_id = cursor.lastrowid
            else:
                job_id = match["id"]
                if match["state"] in ("pending", "error"):
                    self.db.execute("UPDATE jobs SET source=? WHERE id=?", (file["path"], job_id))
            self.db.execute("UPDATE files SET job_id=? WHERE root=? AND path=?", (job_id, file["root"], file["path"]))
            return job_id

    @staticmethod
    def valid_output(row) -> bool:
        try:
            return bool(row["output"] and row["output_sha256"] and digest(Path(row["output"])) == row["output_sha256"])
        except OSError:
            return False

    def recover(self):
        with self.db:
            self.db.execute("UPDATE jobs SET state='pending', attempts=MAX(0,attempts-1), progress='Recuperado tras interrupción' WHERE state='processing'")
            for row in self.db.execute("SELECT * FROM jobs WHERE state='done'").fetchall():
                if not self.valid_output(row):
                    self.db.execute("UPDATE jobs SET state='error', error='El resultado falta o fue modificado; usa reprocess para regenerar sin sobrescribirlo.' WHERE id=?", (row["id"],))

    def claim(self):
        with self.db:
            row = self.db.execute("SELECT * FROM jobs WHERE state='pending' AND retry_at<=? ORDER BY id LIMIT 1", (time.time(),)).fetchone()
            if row:
                self.db.execute("UPDATE jobs SET state='processing', attempts=attempts+1, updated=? WHERE id=?", (time.time(), row["id"]))
                return self.db.execute("SELECT * FROM jobs WHERE id=?", (row["id"],)).fetchone()

    def progress(self, job_id: int, value: str):
        with self.db:
            self.db.execute("UPDATE jobs SET progress=?,updated=? WHERE id=?", (value, time.time(), job_id))

    def done(self, job_id: int, output: Path):
        checksum = digest(output)
        with self.db:
            self.db.execute("UPDATE jobs SET state='done',output=?,output_sha256=?,updated=?,error=NULL,progress='Completado' WHERE id=?", (str(output), checksum, time.time(), job_id))

    def fail(self, row, error: str, max_attempts: int):
        retry = row["attempts"] < max_attempts
        with self.db:
            self.db.execute("UPDATE jobs SET state=?,error=?,retry_at=?,updated=? WHERE id=?", ("pending" if retry else "error", error, time.time() + 60 * 2 ** row["attempts"], time.time(), row["id"]))

    def retry(self, job_id: int):
        with self.db:
            result = self.db.execute("UPDATE jobs SET state='pending',attempts=0,retry_at=0,error=NULL WHERE id=? AND state='error'", (job_id,))
            if result.rowcount != 1:
                raise ValueError("Solo se puede reintentar un trabajo con error.")


def profile(config) -> str:
    return json.dumps({"engine": "faster-whisper", "model": config.model,
                       "diarization": "community-1", "language": "es",
                       "chunk_seconds": config.chunk_seconds, "format": 1}, sort_keys=True)
