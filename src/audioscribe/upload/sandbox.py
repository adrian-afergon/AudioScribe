from __future__ import annotations

import ctypes
import ctypes.util
import errno
import sys


_DENIED_SYSCALLS = (
    "open", "openat", "openat2", "open_by_handle_at", "name_to_handle_at",
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "execve", "execveat",
    "fork", "vfork", "clone", "clone3", "io_uring_setup", "io_uring_enter",
    "io_uring_register",
)


def restrict_local_io() -> None:
    if sys.platform != "linux":
        raise OSError("Linux seccomp is unavailable on this target")
    library_name = ctypes.util.find_library("seccomp")
    if not library_name:
        raise OSError("libseccomp is unavailable; validator must remain disabled")
    seccomp = ctypes.CDLL(library_name, use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                         ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None

    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    context = seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise OSError("seccomp_init failed; validator must remain disabled")
    try:
        denied = 0x00050000 | errno.EPERM  # SCMP_ACT_ERRNO(EPERM)
        for name in _DENIED_SYSCALLS:
            number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                continue
            result = seccomp.seccomp_rule_add(context, denied, number, 0)
            if result != 0:
                raise OSError(-result, f"seccomp rule installation failed for {name}")
        result = seccomp.seccomp_load(context)
        if result != 0:
            raise OSError(-result, "seccomp filter load failed")
    finally:
        seccomp.seccomp_release(context)
