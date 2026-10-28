from __future__ import annotations

import hashlib
import os
import re
import secrets
import unicodedata
from pathlib import Path

MAX_NAME_BYTES = 240
ALLOWED_SUFFIXES = (".mp3", ".mp4")
_WINDOWS_RESERVED = re.compile(
    r"^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$", re.IGNORECASE)


class InvalidFilename(ValueError):
    pass


def normalize_media_filename(raw: str) -> tuple[str, str]:
    """Return (final_name, stem) after NFC normalization and the A7 policy.

    Raises InvalidFilename for any rejected name.
    """
    if not isinstance(raw, str) or not raw:
        raise InvalidFilename("filename is required")
    name = unicodedata.normalize("NFC", raw)
    if any(character in name for character in ("/", "\\", "\x00")):
        raise InvalidFilename("filename must not contain path separators")
    if name in (".", "..") or name.startswith(".") or any(part in (".", "..") for part in name.split("/")):
        raise InvalidFilename("dot path components are rejected")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in name):
        raise InvalidFilename("control characters are rejected")
    if ":" in name:
        raise InvalidFilename("colon/ADS syntax is rejected")
    if name != name.strip(" ") or name.endswith("."):
        raise InvalidFilename("trailing dots or spaces are rejected")
    suffix = Path(name).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise InvalidFilename("only .mp3 and .mp4 files are accepted")
    stem = Path(name).stem
    if not stem or _WINDOWS_RESERVED.fullmatch(stem):
        raise InvalidFilename("reserved device names are rejected")
    stem = stem.lower()
    budget = MAX_NAME_BYTES - len(suffix.encode("utf-8"))
    while len(stem.encode("utf-8")) > budget:
        stem = stem[:-1]
    return stem + suffix, stem


def publish_atomically(staging_path: Path, root: Path, final_name: str) -> Path:
    """Hard-link staging into root atomically without overwriting anything.

    Never uses exists-plus-rename or os.replace. On EEXIST retries with
    numeric suffixes (including case-insensitive collisions). Returns the
    final path; raises OSError when no free name is found or linking fails.
    """
    root = Path(root)
    stem, suffix = Path(final_name).stem, Path(final_name).suffix
    candidate = root / final_name
    counter = 1
    while True:
        try:
            os.link(staging_path, candidate, follow_symlinks=False)
            _fsync_directory(root)
            return candidate
        except FileExistsError:
            counter += 1
            if counter > 1000:
                raise
            candidate = root / f"{stem}-{counter}{suffix}"
        except OSError:
            raise


def _fsync_directory(root: Path) -> None:
    """Best-effort POSIX directory durability; separate from link atomicity."""
    if os.name == "nt":
        return
    try:
        fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def probe_link_capability(directory: Path) -> dict:
    """Q03 probe on the actual destination mount: atomic no-overwrite link proof.

    Exclusively creates three private uniquely-named nonmedia probe files
    (O_CREAT|O_EXCL|O_NOFOLLOW, mode 0600) on that same filesystem: link one
    to a fresh name proving shared identity, prove collision EEXIST preserves
    the original bytes, and clean up only its own files. Fixed operator-visible
    names are never unlinked or written; a planted symlink at any name causes
    an O_EXCL retry with a new private name, never a follow. Raises OSError on
    any unsupported semantics (rename/replace fallbacks are never used).
    """
    directory.mkdir(parents=True, exist_ok=True)
    payload_a = os.urandom(4096)
    payload_b = os.urandom(4096)
    source = _create_private_probe_file(directory, payload_a)
    try:
        collision_target = _create_private_probe_file(directory, payload_b)
        try:
            # Collision proof first: the target exists, so the link must fail
            # with EEXIST and leave the original bytes untouched.
            try:
                os.link(source, collision_target, follow_symlinks=False)
            except FileExistsError:
                if collision_target.read_bytes() != payload_b:
                    raise OSError("Collision overwrote the original file bytes.")
                preserves = True
            else:
                raise OSError("Collision did not fail with EEXIST; non-overwrite unproven.")

            # Identity proof: link the source to a fresh unused name.
            shares_identity = False
            for _ in range(16):
                identity_target = directory / f".audioscribe-probe-{secrets.token_hex(8)}"
                if os.path.lexists(identity_target):
                    continue
                try:
                    os.link(source, identity_target, follow_symlinks=False)
                except FileExistsError:
                    continue
                try:
                    if (identity_target.read_bytes() != payload_a
                            or source.read_bytes() != payload_a):
                        raise OSError("Linked file does not share the source identity.")
                    if not os.path.samestat(source.stat(), identity_target.stat()):
                        raise OSError("Linked probe files are not the same inode.")
                finally:
                    _unlink_quietly(identity_target)
                shares_identity = True
                break
            if not shares_identity:
                raise OSError("atomic no-overwrite link proof failed on the destination mount")
        finally:
            _unlink_quietly(collision_target)
    finally:
        _unlink_quietly(source)
    return {"link_shares_identity": shares_identity, "collision_preserves_original": preserves}


def _create_private_probe_file(directory: Path, payload: bytes) -> Path:
    for _ in range(16):
        candidate = directory / f".audioscribe-probe-{secrets.token_hex(8)}"
        try:
            fd = os.open(candidate, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return candidate
    raise OSError("could not create a private probe file on the destination mount")


def _unlink_quietly(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
