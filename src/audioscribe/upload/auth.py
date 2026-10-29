from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path


_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")
_VERIFIER_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


def generate_secret() -> tuple[str, str]:
    raw = secrets.token_bytes(32)
    return _encode(raw), hashlib.sha256(raw).hexdigest()


def verify_secret(encoded: str, verifier: str) -> bool:
    if (not isinstance(encoded, str) or not _SECRET_PATTERN.fullmatch(encoded)
            or not isinstance(verifier, str) or not _VERIFIER_PATTERN.fullmatch(verifier)):
        return False
    try:
        raw = base64.b64decode(encoded + "=", altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        return False
    if len(raw) != 32 or _encode(raw) != encoded:
        return False
    return hmac.compare_digest(hashlib.sha256(raw).hexdigest(), verifier)


def generate_secret_offline(data_dir: Path) -> str:
    from audioscribe.service import InstanceLock

    with _instance_lock(data_dir, InstanceLock):
        secret, verifier = generate_secret()
        directory = data_dir / "upload-auth"
        if _is_windows():
            _create_private_windows_directory(directory)
        else:
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) & 0o077:
                raise PermissionError("Upload credential directory is not private.")
        path = directory / "verifier.json"
        payload = json.dumps({"sha256": verifier}) + "\n"
        if _is_windows():
            _write_private_windows_file(path, payload)
            return secret
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return secret


@contextmanager
def _instance_lock(data_dir: Path, lock_type):
    lock = lock_type(data_dir / "service.lock")
    try:
        yield lock
    finally:
        lock.close()


def install_verifier(data_dir: Path, verifier: str, replace: bool = False) -> None:
    """Persist only the verifier; never any plaintext secret. Fails closed."""
    if not isinstance(verifier, str) or not _VERIFIER_PATTERN.fullmatch(verifier):
        raise ValueError("verifier must be a SHA-256 hex digest")
    directory = data_dir / "upload-auth"
    path = directory / "verifier.json"
    payload = json.dumps({"sha256": verifier}) + "\n"
    if path.exists() and not replace:
        raise FileExistsError("an upload verifier is already installed")
    if _is_windows():
        _create_private_windows_directory(directory)
        _write_private_windows_file(path, payload)
        return
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if directory.is_symlink() or stat.S_IMODE(directory.stat().st_mode) & 0o077:
        raise PermissionError("Upload credential directory is not private.")
    if replace:
        fd, tmp = tempfile.mkstemp(prefix=".audioscribe-verifier-", dir=directory)
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    else:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _is_windows() -> bool:
    return os.name == "nt"


def _windows_security_attributes(directory: bool):
    if not _is_windows():
        raise OSError("Windows ACL creation requested on a non-Windows host")
    from ctypes import wintypes

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor = wintypes.LPVOID()
    acl = "D:P(A;OICI;FA;;;OW)" if directory else "D:P(A;;FA;;;OW)"
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    if not convert(acl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    return SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor, False), descriptor


def _create_private_windows_directory(path: Path) -> None:
    from ctypes import wintypes

    attributes, descriptor = _windows_security_attributes(directory=True)
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateDirectoryW
        create.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(type(attributes))]
        create.restype = wintypes.BOOL
        if not create(str(path), ctypes.byref(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        local_free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
        local_free.argtypes = [wintypes.HLOCAL]
        local_free.restype = wintypes.HLOCAL
        local_free(descriptor)


def _write_private_windows_file(path: Path, payload: str) -> None:
    from ctypes import wintypes

    import msvcrt

    attributes, descriptor = _windows_security_attributes(directory=False)
    handle = wintypes.HANDLE(-1).value
    created = False
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        create = kernel.CreateFileW
        create.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                           ctypes.POINTER(type(attributes)), wintypes.DWORD, wintypes.DWORD,
                           wintypes.HANDLE]
        create.restype = wintypes.HANDLE
        handle = create(str(path), 0x40000000, 0, ctypes.byref(attributes), 1, 0x80, None)
        if handle == wintypes.HANDLE(-1).value:
            raise ctypes.WinError(ctypes.get_last_error())
        created = True
        fd = msvcrt.open_osfhandle(handle, os.O_WRONLY)
        handle = wintypes.HANDLE(-1).value
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        if created and path.exists():
            path.unlink()
        raise
    finally:
        if handle != wintypes.HANDLE(-1).value:
            ctypes.WinDLL("kernel32", use_last_error=True).CloseHandle(handle)
        local_free = ctypes.WinDLL("kernel32", use_last_error=True).LocalFree
        local_free.argtypes = [wintypes.HLOCAL]
        local_free.restype = wintypes.HLOCAL
        local_free(descriptor)
