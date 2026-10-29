from __future__ import annotations

import json
import os
import stat
from pathlib import Path


STAGING_NAME = ".audioscribe-upload-staging"
OWNER_MARKER = "owner.json"


class UnownedStagingArea(PermissionError):
    pass


def owned_staging_path(root: Path) -> Path | None:
    staging = root / STAGING_NAME
    if _is_reparse_or_symlink(root) or _is_reparse_or_symlink(staging) or not staging.is_dir():
        return None
    if os.name == "nt":
        return None
    root_stat = root.stat()
    staging_stat = staging.stat()
    marker = staging / OWNER_MARKER
    try:
        if _is_reparse_or_symlink(marker) or not marker.is_file():
            return None
        marker_stat = marker.stat()
        if stat.S_IMODE(staging_stat.st_mode) & 0o077 or stat.S_IMODE(marker_stat.st_mode) & 0o077:
            return None
        if marker_stat.st_size > 4096:
            return None
        record = json.loads(marker.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        return None
    expected = {
        "format": 1,
        "root_device": root_stat.st_dev,
        "root_inode": root_stat.st_ino,
        "staging_device": staging_stat.st_dev,
        "staging_inode": staging_stat.st_ino,
    }
    return staging if record == expected else None


def ensure_owned_staging(root: Path) -> Path:
    root = root.resolve(strict=True)
    if os.name == "nt":
        raise PermissionError("Restrictive Windows ACL support is required for upload staging.")
    staging = root / STAGING_NAME
    try:
        staging.mkdir(mode=0o700)
    except FileExistsError:
        if owned_staging_path(root) is None:
            raise UnownedStagingArea("The staging path exists without a valid AudioScribe ownership marker.")
        return staging
    root_stat, staging_stat = root.stat(), staging.stat()
    record = {
        "format": 1,
        "root_device": root_stat.st_dev,
        "root_inode": root_stat.st_ino,
        "staging_device": staging_stat.st_dev,
        "staging_inode": staging_stat.st_ino,
    }
    marker = staging / OWNER_MARKER
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            marker.unlink(missing_ok=True)
            staging.rmdir()
        except OSError:
            pass
        raise
    if owned_staging_path(root) is None:
        raise PermissionError("Created staging ownership marker failed validation.")
    return staging


def root_identity(root: Path) -> tuple[int, int]:
    stat = Path(root).stat()
    return stat.st_dev, stat.st_ino


def _is_reparse_or_symlink(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)
