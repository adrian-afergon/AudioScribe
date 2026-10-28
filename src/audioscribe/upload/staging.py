from __future__ import annotations

import json
import os
from pathlib import Path

from .capabilities import owned_staging_path


class StagingUnavailable(PermissionError):
    pass


TRANSFER_STATES = ("reserved", "receiving", "validating", "publish-intent",
                   "published", "cleanup-failed", "cancelled", "failed")


def require_owned_staging(root: Path) -> Path:
    staging = owned_staging_path(Path(root))
    if staging is None:
        raise StagingUnavailable(
            "Upload staging is unavailable: the input root has no validated "
            "AudioScribe-owned staging namespace.")
    return staging


def create_transfer_file(staging: Path, upload_id: str) -> Path:
    path = staging / f"{upload_id}.part"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    return path


def write_manifest(staging: Path, upload_id: str, record: dict) -> Path:
    path = staging / f"{upload_id}.manifest.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def read_manifest(staging: Path, upload_id: str) -> dict | None:
    path = staging / f"{upload_id}.manifest.json"
    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and record.get("upload_id") == upload_id else None


def cleanup_transfer(staging: Path, upload_id: str) -> bool:
    """Remove one owned transfer's staging entries. Returns False when files remain."""
    complete = True
    for suffix in (".part", ".manifest.json"):
        path = staging / f"{upload_id}{suffix}"
        try:
            if path.exists() and not path.is_symlink():
                path.unlink()
        except OSError:
            complete = False
    return complete


def _is_transfer_id(value: str) -> bool:
    return len(value) == 32 and all(character in "0123456789abcdef" for character in value)


def owned_orphan_entries(staging: Path) -> list[Path]:
    """Owned UUID staging entries only; never follows links or touches foreign names."""
    entries = []
    for path in staging.iterdir():
        name = path.name
        if path.is_symlink() or not path.is_file():
            continue
        if name.endswith(".part") and _is_transfer_id(name[:-len(".part")]):
            entries.append(path)
        elif (name.endswith(".manifest.json")
              and _is_transfer_id(name[:-len(".manifest.json")])):
            entries.append(path)
    return sorted(entries)


def recover_owned_orphans(root: Path, staging: Path) -> dict:
    """A7 startup recovery: never publish an orphan, keep proven complete links.

    For each owned UUID entry: a publish-intent orphan whose final name already
    exists with identical bytes is a proven complete link (crash between link
    and manifest completion) — the final file is kept and the staging alias is
    removed. Everything else is a proven owned abandoned entry and is deleted.
    Foreign names, links and colliding final paths are never touched.
    """
    summary = {"removed": [], "kept_published": [], "untouched": []}
    root = Path(root)
    seen: set[str] = set()
    for path in owned_orphan_entries(staging):
        if path.name.endswith(".manifest.json"):
            continue
        upload_id = path.name[:-len(".part")]
        if upload_id in seen:
            continue
        seen.add(upload_id)
        manifest = read_manifest(staging, upload_id)
        part = staging / f"{upload_id}.part"
        final_name = (manifest or {}).get("final_name")
        final = root / str(final_name) if isinstance(final_name, str) and final_name else None
        if (manifest is not None and manifest.get("state") == "publish-intent"
                and final is not None and final.exists() and not final.is_symlink()
                and _shares_link_identity(part, final)):
            if cleanup_transfer(staging, upload_id):
                summary["kept_published"].append(upload_id)
            else:
                summary["untouched"].append(upload_id)
            continue
        if cleanup_transfer(staging, upload_id):
            summary["removed"].append(upload_id)
        else:
            summary["untouched"].append(upload_id)
    return summary


def _shares_link_identity(part: Path, final: Path) -> bool:
    """A real os.link crash proof: staging alias and final share one inode.

    Content equality alone proves nothing — an unrelated file with identical
    bytes must never count as a completed publication.
    """
    try:
        part_stat, final_stat = part.stat(), final.stat()
    except OSError:
        return False
    if (part_stat.st_dev, part_stat.st_ino) != (final_stat.st_dev, final_stat.st_ino):
        return False
    return part_stat.st_size == final_stat.st_size
