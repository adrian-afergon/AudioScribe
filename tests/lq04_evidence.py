# Deprecated as qualification infrastructure; superseded by the plain qualification contract (PLAN-01). Retained as history.
from __future__ import annotations

import json
import ast
import math
import ctypes
import contextlib
import contextvars
import errno
import hashlib
import inspect
import os
import re
import resource
import selectors
import signal
import stat
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

import pytest

_EVIDENCE_KINDS = {
    "native-observed",
    "native-control",
    "unit-simulated",
    "unit-injected",
    "declared",
    "parent-observed",
}
_STATUSES = {"OBSERVED", "DECLARED", "NA", "MISSING"}
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECORD_BYTES = 16 * 1024
_RECORD_TYPES = {
    "identity",
    "fixture",
    "child-sample",
    "unit-fixture",
    "run-event",
    "case-event",
    "source-load",
    "fd-event",
    "syscall-event",
    "resource-sample",
    "output-event",
    "termination",
    "syscall-counts",
    "preflight",
    "manifest",
    "collection",
    "parent-import",
    "parent-module",
}
_INTEGER_VALUES = {
    "rss_bytes", "vmhwm_bytes", "vmsize_bytes", "vmdata_bytes", "as_limit_bytes",
    "data_limit_bytes", "stdout_bytes_observed", "stderr_bytes_observed", "thread_count",
    "stream_count", "input_bytes_before_seal", "input_bytes_after_open", "errno",
    "syscall_number", "wait_status", "as_soft_bytes", "as_hard_bytes", "data_soft_bytes",
    "data_hard_bytes", "cpu_soft_seconds", "cpu_hard_seconds",
}
_NUMBER_VALUES = {"wall_seconds", "cpu_user_seconds", "cpu_system_seconds"}
_ACTIVE_CAPTURE = contextvars.ContextVar("lq04_active_evidence_capture", default=None)
_PTRACE_TRACEME = 0
_PTRACE_PEEKDATA = 2
_PTRACE_CONT = 7
_PTRACE_SYSCALL = 24
_PTRACE_SETOPTIONS = 0x4200
_PTRACE_GETEVENTMSG = 0x4201
_PTRACE_GETSIGINFO = 0x4202
_PTRACE_GET_SYSCALL_INFO = 0x420E
_PTRACE_O_TRACESYSGOOD = 0x00000001
_PTRACE_O_TRACEFORK = 0x00000002
_PTRACE_O_TRACEVFORK = 0x00000004
_PTRACE_O_TRACECLONE = 0x00000008
_PTRACE_O_TRACEEXEC = 0x00000010
_PTRACE_O_TRACEEXIT = 0x00000040
_PTRACE_O_EXITKILL = 0x00100000
_PTRACE_EVENT_FORK = 1
_PTRACE_EVENT_VFORK = 2
_PTRACE_EVENT_CLONE = 3
_PTRACE_EVENT_EXEC = 4
_PTRACE_EVENT_EXIT = 6
_PTRACE_EVENT_STOP = 128
_WAIT_WALL = 0x40000000
_SIGTRAP_SYSCALL = signal.SIGTRAP | 0x80
_AUDIT_ARCH_X86_64 = 0xC000003E
_SYSCALL_NUMBERS = {
    "read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
    "lstat": 6, "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
    "brk": 12, "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
    "ioctl": 16, "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
    "access": 21, "pipe": 22, "select": 23, "sched_yield": 24, "mremap": 25,
    "msync": 26, "mincore": 27, "madvise": 28, "shmget": 29, "shmat": 30,
    "shmctl": 31, "dup": 32, "dup2": 33, "pause": 34, "nanosleep": 35,
    "getitimer": 36, "alarm": 37, "setitimer": 38, "getpid": 39, "sendfile": 40,
    "socket": 41, "connect": 42, "accept": 43, "sendto": 44, "recvfrom": 45,
    "sendmsg": 46, "recvmsg": 47, "shutdown": 48, "bind": 49, "listen": 50,
    "getsockname": 51, "getpeername": 52, "socketpair": 53, "setsockopt": 54,
    "getsockopt": 55, "clone": 56, "fork": 57, "vfork": 58, "execve": 59,
    "exit": 60, "wait4": 61, "kill": 62, "uname": 63, "fcntl": 72,
    "getdents": 78, "getcwd": 79, "chdir": 80, "fchdir": 81, "rename": 82, "mkdir": 83,
    "rmdir": 84, "creat": 85, "link": 86, "unlink": 87, "symlink": 88,
    "readlink": 89, "chmod": 90, "fchmod": 91, "chown": 92, "fchown": 93,
    "umask": 95, "gettimeofday": 96, "getrlimit": 97, "getrusage": 98,
    "sysinfo": 99, "times": 100, "getuid": 102, "getgid": 104, "geteuid": 107,
    "getegid": 108, "getppid": 110, "getpgrp": 111, "getgroups": 115,
    "getdents64": 217, "gettid": 186, "futex": 202, "sched_getaffinity": 204,
    "set_tid_address": 218,
    "clock_gettime": 228, "clock_nanosleep": 230, "exit_group": 231, "epoll_wait": 232, "epoll_ctl": 233,
    "tgkill": 234, "openat": 257, "newfstatat": 262, "unlinkat": 263,
    "renameat": 264, "linkat": 265, "symlinkat": 266,
    "readlinkat": 267, "fchmodat": 268, "faccessat": 269, "pselect6": 270,
    "ppoll": 271, "unshare": 272, "set_robust_list": 273, "get_robust_list": 274,
    "splice": 275, "tee": 276, "sync_file_range": 277, "vmsplice": 278,
    "utimensat": 280, "epoll_pwait": 281, "signalfd": 282, "timerfd_create": 283,
    "eventfd": 284, "fallocate": 285, "timerfd_settime": 286, "timerfd_gettime": 287,
    "accept4": 288, "signalfd4": 289, "eventfd2": 290, "epoll_create1": 291,
    "dup3": 292, "pipe2": 293, "inotify_init1": 294, "preadv": 295, "pwritev": 296,
    "recvmmsg": 299, "fanotify_init": 300, "fanotify_mark": 301, "prlimit64": 302,
    "name_to_handle_at": 303, "open_by_handle_at": 304, "syncfs": 306, "sendmmsg": 307,
    "setns": 308, "getcpu": 309, "process_vm_readv": 310, "process_vm_writev": 311,
    "kcmp": 312, "finit_module": 313, "sched_setattr": 314, "sched_getattr": 315,
    "renameat2": 316, "seccomp": 317, "getrandom": 318, "memfd_create": 319,
    "execveat": 322, "userfaultfd": 323, "membarrier": 324, "mlock2": 325,
    "copy_file_range": 326, "preadv2": 327, "pwritev2": 328, "pkey_mprotect": 329,
    "statx": 332, "rseq": 334, "io_uring_setup": 425, "io_uring_enter": 426,
    "io_uring_register": 427, "open_tree": 428, "move_mount": 429, "fsopen": 430,
    "fsconfig": 431, "fsmount": 432, "fspick": 433, "pidfd_open": 434,
    "clone3": 435, "close_range": 436, "openat2": 437, "pidfd_getfd": 438,
    "faccessat2": 439, "process_madvise": 440, "epoll_pwait2": 441,
    "arch_prctl": 158, "prctl": 157,
}
_SYSCALL_NAMES = {number: name for name, number in _SYSCALL_NUMBERS.items()}
_DETAIL_SYSCALL_NAMES = {
    "read", "write", "open", "close", "stat", "fstat", "lstat", "lseek", "mmap",
    "mprotect", "munmap", "readv", "pread64", "preadv", "preadv2", "mremap", "dup",
    "dup2", "dup3", "fcntl", "pipe", "pipe2", "openat", "openat2", "open_by_handle_at", "name_to_handle_at",
    "newfstatat", "statx", "readlink", "readlinkat", "execve", "execveat", "fork", "vfork",
    "clone", "clone3", "close_range", "socket", "socketpair", "connect", "bind", "listen",
    "accept", "accept4", "sendto", "recvfrom", "sendmsg", "recvmsg", "io_uring_setup",
    "io_uring_enter", "io_uring_register", "prctl", "seccomp", "wait4", "kill", "getdents",
    "getdents64", "sendfile", "splice", "tee", "vmsplice", "copy_file_range", "process_vm_readv",
    "process_vm_writev", "memfd_create", "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount",
    "fspick", "pidfd_getfd", "faccessat", "faccessat2",
}
_EXPECTED_CASES = {
    "test_formal_p1_original_video_only_mp4": "valid first media frame; audio=0; video=1",
    "test_formal_p2_genuine_mp3": "valid genuine MP3 through first media frame",
    "test_formal_p3_audio_bearing_mp4": "valid audio-bearing MP4 through first media frame",
    "test_formal_p4_h264_mp4": "valid H.264 MP4 through first media frame",
    "test_formal_n1_empty_malformed_brand_and_extension_mismatch": "four named safe rejections",
    "test_formal_n2_secondary_file_denied_readonly_descriptor_preserved": "approved read-only FD succeeds; secondary opens and writes are denied",
    "test_formal_n3_network_socket_families_denied_without_traffic": "IPv4 and Unix sockets denied without traffic",
    "test_formal_n4_exec_clone_and_io_uring_denied": "fork/thread/exec/clone3/io_uring outcomes match unchanged policy",
    "test_formal_n5_only_expected_readonly_input_descriptor_inherited": "stdio plus one identity-matched read-only input FD",
    "test_formal_n6_missing_bootstrap_fails_before_media_read_and_late_import_is_denied": "missing bootstrap before input and late import denied",
    "test_formal_n7_closed_pipes_live_child_is_killed_and_reaped": "whole startup-through-reap wall deadline and closed-pipe cleanup",
    "test_formal_n7_cpu_limit_terminates_child": "CPU30 kernel-attributed termination observed within outer45, no media parsing",
    "test_formal_n8_resource_record_and_output_limits_fail_closed": "distinct native AS/DATA/RSS/stdout/stderr controls plus UNIT schema faults",
}
_SECCOMP_DENIAL_NAMES = {
    "open", "openat", "openat2", "open_by_handle_at", "name_to_handle_at",
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "recvfrom", "sendmsg", "recvmsg", "execve", "execveat", "fork",
    "vfork", "clone", "clone3", "io_uring_setup", "io_uring_enter", "io_uring_register",
}
_MAX_TRACE_PIDS = 16
_MAX_TRACE_FDS = 256
_MAX_TRACE_ARTIFACTS = 4096
_MAX_RECORD_BYTES = 16 * 1024
_MAX_CASE_BYTES = 4 * 1024 * 1024

# E-LQ04-FIT-01 F1: declared resource-sample emission policy. Sampling still
# happens at every pump opportunity (read errors still invalidate); only the
# EMISSION is decimated: first sample, at most one sample per 20 ms window,
# and the final measured sample, with the six constant GET-limit fields
# (DECLARED caps) emitted once on the first-of-kind sample only.
_RESOURCE_SAMPLE_WINDOW_SECONDS = 0.020
_RESOURCE_SAMPLE_POLICY_NAME = "first-last-one-per-20ms-window-limit-fields-once"
_RESOURCE_SAMPLE_LIMIT_FIELDS = frozenset({
    "as_soft_bytes", "as_hard_bytes", "data_soft_bytes", "data_hard_bytes",
    "cpu_soft_seconds", "cpu_hard_seconds",
})
_RESOURCE_SAMPLE_CORE_FIELDS = frozenset({
    "rss_bytes", "vmhwm_bytes", "vmsize_bytes", "vmdata_bytes", "thread_count",
})

# E-LQ04-FIT-01 F5 contingency (pre-specified): per-slice batching of compact
# frames. Implemented always; ACTIVATES only when the measured headroom of the
# most recent REAL distribution (budget-fit simulation) lands below 25%.
_COMPACT_FRAME_BATCH_MAX = 40
F5_HEADROOM_THRESHOLD = 0.25
F5_MINIMUM_HEADROOM = 0.20

# Frozen bootstrap basis: the REAL RESULT-21 sidecar per-class distribution
# (6,307 records / 4,132,051 B, COMPACT-01 live). Recorded in the manifest as
# `budget_fit_basis` and consumed by ONE simulation with two consumers
# (UNIT W5 attestation + freeze-time preflight check).
BUDGET_FIT_BASIS = {
    "basis": "E-LQ04-SNAPSHOT-01 real traced P1 stream (RESULT-21 attempt 01, COMPACT-01 live)",
    "run_identity": "E-LQ04-SNAPSHOT-01-1792497482909207811",
    "sidecar_sha256": "d411840fedaed0f57cce8348515a83a54f40d2757f6792cecd8a7d088bd043c1",
    "sidecar_bytes": 4_132_051,
    "sidecar_records": 6_307,
    "child_lifetime_seconds": 3.49,
    "classes": {
        "syscall_full": {"count": 712, "mean_line_bytes": 874},
        "syscall_compact": {"count": 3022, "mean_values_bytes": 59},
        "resource_sample": {"count": 922, "mean_line_bytes": 684, "mean_limit_block_bytes": 153},
        "source_load_mapping_with_file": {"count": 428, "distinct_artifacts": 83, "mean_line_bytes": 1516},
        "source_load_mapping_no_file": {"count": 113, "mean_line_bytes": 714},
        "source_load_mapping_operation": {"count": 114, "mean_line_bytes": 762},
        "source_load_munmap": {"count": 71, "mean_line_bytes": 512},
        "source_load_complete_span": {"count": 45, "mean_line_bytes": 819},
        "source_load_declared": {"count": 7, "mean_line_bytes": 601},
        "child_sample": {"count": 594, "mean_line_bytes": 479},
        "fd_event": {"count": 275, "mean_line_bytes": 894},
        "run_event": {"count": 4, "mean_line_bytes": 1304},
        "case_event": {"count": 3, "mean_line_bytes": 1035},
        "termination": {"count": 2, "mean_line_bytes": 619},
        "identity": {"count": 1, "mean_line_bytes": 964},
        "fixture": {"count": 1, "mean_line_bytes": 496},
    },
}

_BUDGET_FIT_REQUIRED_CLASSES = frozenset({
    "syscall_full", "resource_sample", "source_load_mapping_with_file",
})
_BUDGET_FIT_SAMPLE_COMPACT_VALUES = {"name": "mmap", "phase": "exit", "result": 4096,
                                     "errno": 0, "compact": True}
_BUDGET_FIT_SAMPLE_REFERENCE_VALUES = {
    "artifact_ref": "artifact-4095", "operation": "initial-exec-map",
    "offset": 1234567890123, "length": 1953792, "span_sha256": "0" * 64,
}


def _budget_fit_record_bytes(values, *, record_type: str = "syscall-event",
                             start_ticks: bool = True) -> float:
    """Live-measured canonical line size for a representative native record."""
    fixed = {"schema_v": 1, "evidence_kind": "native-observed", "status": "OBSERVED",
             "run_id": "R", "node_id": "N", "identity_ref": "case", "record_sha256": "0" * 64,
             "subcase": "S", "fixture_sha256": "0" * 64, "pid": 1234567}
    record = {**fixed, "record_type": record_type, "values": values}
    if start_ticks:
        record["start_ticks"] = 163634411
    return len(canonical_record(record)) + 1


def _validated_budget_fit_basis(basis) -> dict[str, dict[str, int]]:
    if not isinstance(basis, Mapping):
        raise ValueError("budget-fit basis must be an object")
    for field in ("sidecar_sha256", "sidecar_bytes", "sidecar_records", "child_lifetime_seconds"):
        if field not in basis:
            raise ValueError(f"budget-fit basis is missing {field}")
    if not isinstance(basis["sidecar_sha256"], str) or not _SHA256.fullmatch(basis["sidecar_sha256"]):
        raise ValueError("budget-fit basis sidecar hash is invalid")
    if type(basis["sidecar_bytes"]) is not int or basis["sidecar_bytes"] <= 0 \
            or type(basis["sidecar_records"]) is not int or basis["sidecar_records"] <= 0 \
            or type(basis["child_lifetime_seconds"]) not in {int, float} \
            or basis["child_lifetime_seconds"] <= 0:
        raise ValueError("budget-fit basis volume/lifetime fields are invalid")
    classes = basis.get("classes")
    if not isinstance(classes, Mapping):
        raise ValueError("budget-fit basis lacks the per-class distribution")
    for name in _BUDGET_FIT_REQUIRED_CLASSES:
        entry = classes.get(name)
        if not isinstance(entry, Mapping) or type(entry.get("count")) is not int \
                or entry["count"] < 0 or type(entry.get("mean_line_bytes")) not in {int, float} \
                or entry["mean_line_bytes"] <= 0:
            raise ValueError(f"budget-fit basis class {name} is missing or malformed")
    compact = classes.get("syscall_compact")
    if not isinstance(compact, Mapping) or type(compact.get("count")) is not int \
            or compact["count"] < 0 or type(compact.get("mean_values_bytes")) not in {int, float} \
            or compact["mean_values_bytes"] <= 0:
        raise ValueError("budget-fit basis class syscall_compact is missing or malformed")
    return classes


def evaluate_budget_fit(basis, *, compact_frame_batching: bool) -> dict[str, object]:
    """ONE deterministic budget-fit simulation, two consumers (UNIT W5 + preflight).

    Projects the frozen REAL per-class distribution through the CURRENT
    compaction policy. Record envelopes are measured live from the current
    schema code; class sizes come from the frozen basis; every modeled term is
    conservative (overestimates the emitted stream).
    """
    classes = _validated_budget_fit_basis(basis)
    projected = float(basis["sidecar_bytes"])
    # F1: first/last/one-per-20ms-window emission; GET-limit fields once.
    rs = classes["resource_sample"]
    windows = max(1, math.ceil(float(basis["child_lifetime_seconds"]) / _RESOURCE_SAMPLE_WINDOW_SECONDS))
    emitted = min(rs["count"], windows + 2)
    decimated = rs["count"] - emitted
    projected -= decimated * float(rs["mean_line_bytes"])
    projected -= (emitted - 1) * float(rs["mean_limit_block_bytes"])
    projected += len(canonical_record(ResourceSamplePolicy().summary())) + 64
    # F2: first artifact occurrence full; repeats are static references.
    mf = classes["source_load_mapping_with_file"]
    distinct = mf.get("distinct_artifacts")
    if type(distinct) is not int or not 0 < distinct <= mf["count"]:
        raise ValueError("budget-fit basis artifact census is invalid")
    repeats = mf["count"] - distinct
    reference_line = _budget_fit_record_bytes(
        _BUDGET_FIT_SAMPLE_REFERENCE_VALUES, record_type="source-load")
    projected -= repeats * max(0.0, float(mf["mean_line_bytes"]) - reference_line)
    projected += distinct * len('"artifact_ref":"artifact-4095",')
    # F3: compact frames replace the per-frame start_ticks with the tracee reference.
    sc = classes["syscall_compact"]
    compact_line = _budget_fit_record_bytes(_BUDGET_FIT_SAMPLE_COMPACT_VALUES)
    start_ticks_delta = compact_line - _budget_fit_record_bytes(
        _BUDGET_FIT_SAMPLE_COMPACT_VALUES, start_ticks=False)
    projected -= sc["count"] * start_ticks_delta
    # F5: per-slice batching, envelope amortized across the measured interleave.
    if compact_frame_batching:
        batch_size = max(1, min(_COMPACT_FRAME_BATCH_MAX,
                                sc["count"] // max(1, classes["syscall_full"]["count"])))
        batch_line = _budget_fit_record_bytes(
            {"batch": [dict(_BUDGET_FIT_SAMPLE_COMPACT_VALUES)] * batch_size})
        projected -= sc["count"] * max(0.0, compact_line - batch_line / batch_size)
    guard = _MAX_CASE_BYTES - 64 * 1024
    return {
        "projected_bytes": int(round(projected)),
        "guard_bytes": guard,
        "headroom": (guard - projected) / guard,
        "batching": bool(compact_frame_batching),
        "basis_sidecar_sha256": basis["sidecar_sha256"],
    }


def declared_budget_fit_policy(basis) -> dict[str, object]:
    """Freeze-time policy decision shared by the manifest and the preflight check."""
    without = evaluate_budget_fit(basis, compact_frame_batching=False)
    with_batching = evaluate_budget_fit(basis, compact_frame_batching=True)
    batching = without["headroom"] < F5_HEADROOM_THRESHOLD
    active = with_batching if batching else without
    if active["headroom"] < F5_MINIMUM_HEADROOM:
        raise ValueError(
            "budget-fit attestation below the declared 20% headroom minimum "
            f"(projected {active['projected_bytes']} B vs guard {active['guard_bytes']} B)")
    return {
        "policy": "E-LQ04-FIT-01 declared compaction policy (F1 sampling, F2 references, "
                  "F3 compact frames, F4 reserve routing, F5 batching on measured <25%)",
        "compact_frame_batching": batching,
        "f5_headroom_threshold": F5_HEADROOM_THRESHOLD,
        "minimum_headroom": F5_MINIMUM_HEADROOM,
        "measured_headroom": active["headroom"],
        "headroom_without_batching": without["headroom"],
        "projected_case_bytes": active["projected_bytes"],
        "case_guard_bytes": active["guard_bytes"],
        "basis_sidecar_sha256": basis["sidecar_sha256"],
        "resource_sample_policy": _RESOURCE_SAMPLE_POLICY_NAME,
        "resource_sample_window_ms": int(_RESOURCE_SAMPLE_WINDOW_SECONDS * 1000),
        "source_load_reference_scheme": "first-full-repeats-artifact-ref-span-sha256-verbatim",
        "compact_frame_shape": "name-phase-result-errno-compact; start_ticks via tracee reference",
        "teardown_reserve_routing": "all containment/teardown emissions use reserve=True",
    }


class ResourceSamplePolicy:
    """F1 emission decimation with a bounded one-slot pending 'last' sample."""

    def __init__(self, window_seconds: float = _RESOURCE_SAMPLE_WINDOW_SECONDS) -> None:
        if type(window_seconds) is not float or not math.isfinite(window_seconds) or window_seconds <= 0:
            raise ValueError("resource sample window must be a positive finite number of seconds")
        self.window_seconds = window_seconds
        self.window_until: float | None = None
        self.first_emitted = False
        self.emitted = 0
        self.decimated = 0
        self.sampled = 0
        self.pending_last: dict[str, object] | None = None

    def admit(self, now: float, values: Mapping[str, object], pid: int,
              start_ticks: int) -> tuple[bool, bool]:
        """Return (emit_now, include_limits); decimated samples refresh the last-slot."""
        self.sampled += 1
        if not self.first_emitted or self.window_until is None or now >= self.window_until:
            include_limits = not self.first_emitted
            self.first_emitted = True
            self.window_until = now + self.window_seconds
            self.emitted += 1
            self.pending_last = None
            return True, include_limits
        self.decimated += 1
        self.pending_last = {
            "pid": pid,
            "start_ticks": start_ticks,
            "values": {name: value for name, value in values.items()
                       if name not in _RESOURCE_SAMPLE_LIMIT_FIELDS},
        }
        return False, False

    def take_pending(self) -> dict[str, object] | None:
        pending, self.pending_last = self.pending_last, None
        if pending is not None:
            self.emitted += 1
            self.decimated -= 1
        return pending

    def summary(self) -> dict[str, object]:
        return {
            "resource_sample_policy": _RESOURCE_SAMPLE_POLICY_NAME,
            "resource_sample_window_ms": int(self.window_seconds * 1000),
            "resource_samples_emitted": self.emitted,
            "resource_samples_decimated": self.decimated,
            "resource_samples_total": self.sampled,
        }


_FD_TRANSITION_SYSCALLS = frozenset({
    "open", "openat", "openat2", "close", "close_range", "dup", "dup2", "dup3",
    "fcntl", "pipe", "pipe2", "execve", "execveat",
})
_SIGNAL_DELIVERY_SYSCALLS = frozenset({"kill", "tkill", "tgkill", "rt_sigreturn"})


def is_boundary_syscall_event(values: Mapping[str, object], *, first_of_kind: bool = False,
                              capture_deferred_completion: bool = False) -> bool:
    """EVIDENCE-LQ04 §9 / E-LQ04-COMPACT-01 classification; fail-safe verbosity."""
    if first_of_kind or capture_deferred_completion:
        return True
    name = values.get("name")
    if not isinstance(name, str) or not name:
        return True
    if values.get("phase") == "initial-exec-return":
        return True
    if values.get("is_error") is True or values.get("errno", 0) != 0:
        return True
    if name in _FD_TRANSITION_SYSCALLS:
        return True
    if values.get("signal") is not None or name in _SIGNAL_DELIVERY_SYSCALLS:
        return True
    return False


def validate_record(
    record: Mapping[str, object], *, authority: _NativeCollectorAuthority | None = None
) -> dict[str, object]:
    """Validate one finite evidence record without upgrading its evidence kind."""
    if not isinstance(record, Mapping):
        raise ValueError("record must be an object")

    required = {
        "schema_v",
        "record_type",
        "evidence_kind",
        "status",
        "run_id",
        "node_id",
        "values",
    }
    allowed = required | {
        "subcase",
        "source_sha256",
        "policy_sha256",
        "collector_sha256",
        "manifest_sha256",
        "fixture_sha256",
        "origin",
        "collector_id",
        "pid",
        "start_ticks",
        "reason",
        "record_sha256",
    }
    missing = required - record.keys()
    extra = record.keys() - allowed
    if missing:
        raise ValueError(f"missing required fields: {', '.join(sorted(missing))}")
    if extra:
        raise ValueError(f"unexpected fields: {', '.join(sorted(extra))}")
    if type(record["schema_v"]) is not int or record["schema_v"] != 1:
        raise ValueError("schema_v must be integer 1")
    if not isinstance(record["record_type"], str) or record["record_type"] not in _RECORD_TYPES:
        raise ValueError("unknown record_type")
    if not isinstance(record["evidence_kind"], str) or record["evidence_kind"] not in _EVIDENCE_KINDS:
        raise ValueError("unknown evidence_kind")
    if not isinstance(record["status"], str) or record["status"] not in _STATUSES:
        raise ValueError("unknown status")
    for field in ("run_id", "node_id"):
        if not isinstance(record[field], str) or not record[field]:
            raise ValueError(f"{field} must be a nonempty string")
    if not isinstance(record["values"], Mapping):
        raise ValueError("values must be an object")
    for field, value in record["values"].items():
        if not isinstance(field, str):
            raise ValueError("evidence value names must be strings")
        if field in _INTEGER_VALUES and type(value) is not int:
            raise ValueError(f"{field} must be an integer, not bool or another type")
        if field in _INTEGER_VALUES and value < 0:
            raise ValueError(f"{field} must be nonnegative")
        if field in _NUMBER_VALUES and (
            type(value) not in {int, float}
            or (type(value) is float and not math.isfinite(value))
            or value < 0
        ):
            raise ValueError(f"{field} must be a finite nonnegative number")
    if "fixture_sha256" in record and (
        not isinstance(record["fixture_sha256"], str)
        or not _SHA256.fullmatch(record["fixture_sha256"])
    ):
        raise ValueError("fixture_sha256 must be a lowercase SHA-256")
    if record["status"] in {"NA", "MISSING"}:
        reason = record.get("reason")
        if not isinstance(reason, str) or not reason:
            raise ValueError("reason must be nonempty text for NA/MISSING records")

    if record["evidence_kind"] in {"native-observed", "native-control"}:
        _validate_native_provenance(record)
        if record["record_type"] == "resource-sample" and record["status"] == "OBSERVED":
            present_limits = _RESOURCE_SAMPLE_LIMIT_FIELDS & record["values"].keys()
            if not _RESOURCE_SAMPLE_CORE_FIELDS.issubset(record["values"]) or (
                    present_limits and present_limits != _RESOURCE_SAMPLE_LIMIT_FIELDS):
                raise ValueError("required native resource fields are missing")
        if not isinstance(authority, _NativeCollectorAuthority) or not authority.active:
            raise ValueError("no live native collector is registered; native promotion is disabled")
    if record['status'] == 'OBSERVED' and record['evidence_kind'] in {
            'native-observed', 'native-control', 'unit-simulated'}:
        _validate_observed_values(record['record_type'], record['values'])

    normalized = dict(record)
    try:
        encoded = json.dumps(
            normalized,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError(f"record is not canonical JSON: {error}") from error
    if len(encoded) > _MAX_RECORD_BYTES:
        raise ValueError("record exceeds 16 KiB")
    return normalized


def _validate_observed_values(kind, values):
    """Finite v1 syscall/output/termination envelopes; units are in field names."""
    def required(names):
        if not set(names).issubset(values):
            raise ValueError(f'required {kind} fields missing: {sorted(set(names)-values.keys())}')
    def integer(name, minimum=0):
        if type(values.get(name)) is not int or (minimum is not None and values[name] < minimum):
            raise ValueError(f'required {name} must be an integer in its declared range')
    if kind == 'resource-sample':
        required(_RESOURCE_SAMPLE_CORE_FIELDS)
        present_limits = _RESOURCE_SAMPLE_LIMIT_FIELDS & set(values)
        if present_limits and present_limits != _RESOURCE_SAMPLE_LIMIT_FIELDS:
            raise ValueError('required native resource fields are missing')
        for name in _RESOURCE_SAMPLE_CORE_FIELDS | present_limits:
            integer(name)
        if values['thread_count'] < 1:
            raise ValueError('required live thread count must be positive')
    elif kind == 'syscall-event':
        batch = values.get('batch')
        if batch is not None:
            if set(values) != {'batch'} or not isinstance(batch, list) \
                    or not 1 <= len(batch) <= _COMPACT_FRAME_BATCH_MAX:
                raise ValueError('required syscall batch frame count/shape is invalid')
            for frame in batch:
                if (not isinstance(frame, Mapping) or not isinstance(frame.get('name'), str)
                        or not frame['name'] or frame.get('phase') not in {'entry', 'exit'}
                        or frame.get('compact') is not True):
                    raise ValueError('required compact batch frame identity is invalid')
                if set(frame) - {'name', 'phase', 'result', 'errno', 'compact'}:
                    raise ValueError('required compact batch frame carries unexpected fields')
                if frame['phase'] == 'exit':
                    if (type(frame.get('result')) is not int or frame['result'] < 0
                            or type(frame.get('errno')) is not int or frame['errno'] != 0):
                        raise ValueError('required compact batch frame retains success evidence only')
                elif {'result', 'errno'} & set(frame):
                    raise ValueError('required compact batch entry carries no exit evidence')
            return
        if values.get('compact') is True:
            name = values.get('name')
            phase = values.get('phase')
            if not isinstance(name, str) or not name or phase not in {'entry', 'exit'}:
                raise ValueError('required compact syscall frame identity is invalid')
            if set(values) - {'name', 'phase', 'result', 'errno', 'compact'}:
                raise ValueError('required compact syscall frame carries unexpected fields')
            if phase == 'exit':
                integer('result', None)
                integer('errno')
                if values['result'] < 0 or values['errno'] != 0:
                    raise ValueError('required compact syscall frame retains success evidence only')
            elif {'result', 'errno'} & set(values):
                raise ValueError('required compact syscall entry carries no exit evidence')
            return
        phase = values.get('phase')
        integer('syscall_number')
        if phase in {'entry', 'exit'}:
            required(('arguments', 'name'))
            arguments = values['arguments']
            if (not isinstance(arguments, (tuple, list)) or len(arguments) != 6
                    or any(type(arg) is not int or not 0 <= arg < 2**64 for arg in arguments)):
                raise ValueError('required six unsigned syscall arguments are invalid')
            if _SYSCALL_NAMES.get(values['syscall_number']) != values['name']:
                raise ValueError('required syscall name/number binding is invalid')
        if phase in {'exit', 'initial-exec-return'}:
            integer('result', None)
            if type(values.get('is_error')) is not bool:
                raise ValueError('required syscall is_error must be boolean')
            if phase == 'exit':
                integer('errno')
                if values['errno'] != (-values['result'] if values['is_error'] else 0):
                    raise ValueError('required kernel errno/result binding is invalid')
            elif (values.get('entry_status') != 'DECLARED' or not values.get('entry_basis')
                  or values['syscall_number'] not in {59, 322} or values['result'] != 0 or values['is_error']):
                raise ValueError('required initial exec declaration/result is invalid')
        elif phase != 'entry':
            raise ValueError('required syscall phase is unknown')
    elif kind == 'syscall-counts':
        if not values or not all(isinstance(key, str) and key for key in values):
            raise ValueError('required syscall-counts names are invalid')
        for buckets in values.values():
            if (not isinstance(buckets, Mapping) or set(buckets) != {'entry', 'exit', 'errors'}
                    or any(type(buckets[slot]) is not int or buckets[slot] < 0
                           for slot in ('entry', 'exit', 'errors'))):
                raise ValueError('required syscall-counts buckets are invalid')
    elif kind == 'output-event':
        if values.get('stream') not in {'stdout', 'stderr'}:
            raise ValueError('required output stream is invalid')
        if type(values.get('eof')) is not bool:
            raise ValueError('required output eof must be boolean')
        if 'observed_chunk_length' in values:
            integer('observed_chunk_length'); integer('total_observed_length')
            if values['total_observed_length'] < values['observed_chunk_length']:
                raise ValueError('required consumed output count is inconsistent')
        else:
            required(('observed_length', 'retained_prefix_length', 'retained_prefix_sha256',
                      'retained_prefix_path', 'truncated', 'coverage', 'terminal_reap_observed'))
            integer('observed_length'); integer('retained_prefix_length')
            cap = 65536 if values['stream'] == 'stdout' else 16384
            if not 0 <= values['retained_prefix_length'] <= min(cap, values['observed_length']):
                raise ValueError('required output prefix exceeds consumed bytes/cap')
            if (type(values['truncated']) is not bool or type(values['terminal_reap_observed']) is not bool
                    or values['truncated'] != (values['observed_length'] > values['retained_prefix_length'])
                    or values['coverage'] != 'consumed-by-parent-only'
                    or not (values['eof'] or values['terminal_reap_observed'])):
                raise ValueError('required output coverage/closure flags are invalid')
            if not isinstance(values['retained_prefix_sha256'], str) or not _SHA256.fullmatch(values['retained_prefix_sha256']):
                raise ValueError('required output prefix hash is invalid')
            path = values['retained_prefix_path']
            if not isinstance(path, str) or not path or Path(path).name != path:
                raise ValueError('required output prefix path must be a basename')
    elif kind == 'termination':
        stage = values.get('stage')
        if stage == 'popen-reap':
            required(('returncode', 'wait_status', 'terminal_delivered', 'terminal_reap_observed', 'monotonic_end_ns',
                      'terminal_reap_ns', 'terminal_wait_delivery_ns', 'finalization_ns'))
            integer('returncode', None); integer('wait_status')
            for name in ('monotonic_end_ns', 'terminal_reap_ns', 'terminal_wait_delivery_ns', 'finalization_ns'):
                integer(name)
            if (values['terminal_delivered'] is not True or values['terminal_reap_observed'] is not True
                    or not (os.WIFEXITED(values['wait_status']) or os.WIFSIGNALED(values['wait_status']))
                    or os.waitstatus_to_exitcode(values['wait_status']) != values['returncode']):
                raise ValueError('required Popen terminal/reap binding is invalid')
        else:
            integer('monotonic_ns')
            if stage == '_drain_child-exception':
                required(('exception_type', 'exception_message', 'deadline'))
                if (not isinstance(values['exception_type'], str) or not values['exception_type']
                        or not isinstance(values['exception_message'], str)
                        or type(values['deadline']) not in {float, int} or not math.isfinite(values['deadline'])):
                    raise ValueError('required source exception/deadline identity is invalid')
            elif stage in {'_kill_child-entry', 'controlled-cancellation-request'}:
                if not isinstance(values.get('actor'), str) or not values['actor']:
                    raise ValueError('required termination actor is missing')
            elif values.get('actor') in {'parent-os.kill', 'parent-os.killpg'}:
                integer('signal', 1); integer('result', None); integer('errno')
            else:
                raise ValueError('required termination stage/actor is unknown')
    elif kind == 'source-load':
        if 'artifact_ref' in values:
            ref = values['artifact_ref']
            if not isinstance(ref, str) or not _ARTIFACT_REF.fullmatch(ref):
                raise ValueError('required source-load artifact reference is invalid')
            if 'mapping' not in values:
                if set(values) != {'artifact_ref', 'operation', 'offset', 'length', 'span_sha256'}:
                    raise ValueError('required source-load reference carries unexpected fields')
                if not isinstance(values['operation'], str) or not values['operation']:
                    raise ValueError('required source-load reference operation is invalid')
                for name in ('offset', 'length'):
                    integer(name)
                if not isinstance(values['span_sha256'], str) or not _SHA256.fullmatch(values['span_sha256']):
                    raise ValueError('required source-load span hash is invalid')
                return
        if 'coverage' in values:
            required(('path', 'device', 'inode', 'offset', 'length', 'consumed_span_sha256', 'expected_file_sha256'))
            for name in ('device', 'inode', 'offset', 'length'):
                integer(name)
            if values['coverage'] != 'complete-span' or not isinstance(values['path'], str) or not Path(values['path']).is_absolute():
                raise ValueError('required consumed source span/path is invalid')
            for name in ('consumed_span_sha256', 'expected_file_sha256'):
                if not isinstance(values[name], str) or not _SHA256.fullmatch(values[name]):
                    raise ValueError('required consumed source span hash is invalid')
    elif kind == 'run-event' and values.get('event') == 'terminal':
        integer('wait_status'); integer('monotonic_ns')
        if not (os.WIFEXITED(values['wait_status']) or os.WIFSIGNALED(values['wait_status'])):
            raise ValueError('required terminal status is a stop')
        usage = values.get('rusage')
        if not isinstance(usage, Mapping) or not {'user_seconds', 'system_seconds', 'max_rss_kib'}.issubset(usage):
            raise ValueError('required raw wait4 rusage is missing')
        for name in ('user_seconds', 'system_seconds'):
            if type(usage[name]) not in {int, float} or not math.isfinite(usage[name]) or usage[name] < 0:
                raise ValueError('required wait4 CPU units/types are invalid')
        if type(usage['max_rss_kib']) is not int or usage['max_rss_kib'] < 0:
            raise ValueError('required wait4 HWM type is invalid')


def reconcile_case_evidence(node_id, records, *, authority=None):
    """Bounded structural acceptance of this fixed matrix, never native qualification."""
    from lq04_runner import EXPECTED_NODE_IDS
    if node_id not in EXPECTED_NODE_IDS:
        raise ValueError('unknown fixed evidence node')
    index = EXPECTED_NODE_IDS.index(node_id)
    labels = {
        4: ('N1-empty.mp3', 'N1-malformed.mp4', 'N1-quicktime-brand.mp4', 'N1-extension-mismatch.mp3'),
        7: ('N4-native-denials',), 9: ('N6-missing-bootstrap', 'N6-late-import'),
        10: ('N7-closed-pipes', 'N7-controlled-cancellation'), 11: ('N7-CPU30-outer45',),
        12: ('N8-AS', 'N8-DATA', 'N8-RSS', 'N8-stdout', 'N8-stderr', 'strict-records'),
    }.get(index, (safe_name(node_id),))
    seen, processes, rejections, stages, schema_cases = set(), {}, {}, set(), set()
    kinds, identity = set(), None
    missing_rss = False
    control_returns = {}
    fixtures, sentinels = {}, {}
    clock_ticks = None
    for record in records:
        validate_record(record, authority=authority)
        if record['node_id'] != node_id:
            raise ValueError('misattributed case record')
        kind, status, values = record['evidence_kind'], record['status'], record['values']
        kinds.add(kind)
        label = record.get('subcase')
        if label in labels:
            seen.add(label)
        stage = values.get('stage')
        if stage:
            stages.add(stage)
        if stage == 'capture-start':
            clock_ticks = values.get('cpu_clock_ticks_per_second')
        if stage == 'control-return':
            child = processes.get(values.get('child_pid'))
            if child is None or label != child['label'] or status != 'OBSERVED':
                raise ValueError('misattributed control return')
            control_returns[values.get('child_pid')] = values.get('control_record')
        if record['record_type'] == 'fixture':
            fixtures[values.get('relative_path')] = {**values, 'sha256': record.get('fixture_sha256')}
        if stage in {'N2-sentinel-before', 'N2-sentinel-after'}:
            if stage in sentinels or status != 'OBSERVED':
                raise ValueError('required sentinel observation is duplicate or unobserved')
            sentinels[stage] = values
        if kind in {'native-observed', 'native-control'}:
            binding = tuple(record[field] for field in ('run_id', 'source_sha256', 'policy_sha256',
                                                       'collector_sha256', 'manifest_sha256', 'origin', 'collector_id'))
            if identity is not None and identity != binding:
                raise ValueError('native case provenance drift')
            identity = binding
        if status == 'MISSING' and kind != 'unit-injected':
            raise ValueError('required evidence is MISSING')
        if values.get('unit_assertion') == 'strict-child-record-rejected':
            case_index = values.get('case_index')
            if kind != 'unit-injected' or type(case_index) is not int:
                raise ValueError('required schema subrecord is not UNIT-injected')
            schema_cases.add(case_index)
        if values.get('unit_assertion') == 'missing-rss-fails-closed':
            missing_rss = kind == 'unit-injected' and status == 'MISSING' and bool(record.get('reason'))
        if stage == 'N1-rejection':
            metadata = values.get('child_metadata', {})
            if values.get('fixture_path') != label or values.get('exception_type') != 'InvalidMediaError':
                raise ValueError('required named N1 rejection identity missing')
            if values.get('phase') == 'before-child':
                before, after = values.get('popen_registrations_before'), values.get('popen_registrations_after')
                if (metadata.get('status') != 'NA' or not metadata.get('reason')
                        or type(before) is not int or type(after) is not int or before < 0 or before != after):
                    raise ValueError('required before-child NA justification missing')
                rejections[label] = metadata
            else:
                if metadata.get('status') != 'OBSERVED' or not metadata.get('pids'):
                    raise ValueError('required after-child rejection envelope missing')
                rejections[label] = metadata
        pid = record.get('pid')
        if stage == 'fork-exec-return':
            if type(pid) is not int or pid <= 0 or type(record.get('start_ticks')) is not int or record['start_ticks'] <= 0:
                raise ValueError('required child PID identity missing')
            if pid in processes or len(processes) >= 16:
                raise ValueError('duplicate or excessive child registration')
            start, deadline = values.get('popen_started_ns'), values.get('caller_wall_deadline_ns')
            budget = 45 if index == 11 else 30
            if (values.get('pgid') != pid or type(start) is not int or type(deadline) is not int
                    or not 0 < deadline-start <= budget*1_000_000_000):
                raise ValueError('required original child timing/PGID binding missing')
            processes[pid] = {'label': label, 'ticks': record['start_ticks'], 'resources': False,
                              'terminal': False, 'reap': False, 'seal': False, 'outputs': set(),
                              'loads': False, 'denials': set(), 'cancel': False, 'pid': pid,
                              'start_ns': start, 'deadline_ns': deadline, 'output_lengths': {},
                              'calls': set(), 'rss_overrange': False, 'kill': False, 'cpu': None,
                              'input_fds': values.get('popen_options', {}).get('pass_fds'),
                              'inherited_fds': {}, 'seal_inventory': None, 'zero_offsets': set(), 'late_import': False,
                              'input_read': False, 'secondary_denials': set()}
        state = processes.get(pid)
        if state is None:
            continue  # Parent records and own resolver descendants are not root Popen envelopes.
        if record.get('start_ticks') != state['ticks']:
            raise ValueError('child PID/start-tick identity drift')
        if label != state['label']:
            raise ValueError('child subcase identity drift')
        if record['record_type'] == 'resource-sample' and status == 'OBSERVED':
            _validate_observed_values('resource-sample', values)
            if any(values[field] != cap for field, cap in (
                ('as_soft_bytes', 256*1024*1024), ('as_hard_bytes', 256*1024*1024),
                ('data_soft_bytes', 128*1024*1024), ('data_hard_bytes', 128*1024*1024),
                ('cpu_soft_seconds', 30), ('cpu_hard_seconds', 30))):
                raise ValueError('required observed limits differ from unchanged policy')
            if index < 4 and values['rss_bytes'] <= 0:
                raise ValueError('positive media requires positive measured RSS')
            state['resources'] = True
            state['rss_overrange'] |= values['rss_bytes'] > 128*1024*1024
        if values.get('event') == 'terminal':
            if state['terminal']:
                raise ValueError('duplicate terminal record')
            _validate_observed_values('run-event', values)
            state['terminal'] = True
            state['terminal_status'] = values['wait_status']
            state['terminal_reap_ns'] = values['monotonic_ns']
            state['terminal_input_before'] = values.get('input_bytes_before_seal')
            state['terminal_input_after'] = values.get('input_bytes_after_seal')
            state['cpu'] = values['rusage']['user_seconds'] + values['rusage']['system_seconds']
        if stage == 'popen-reap':
            _validate_observed_values('termination', values)
            if (state['reap'] or not state['terminal'] or values['wait_status'] != state['terminal_status']
                    or values['terminal_reap_ns'] != state['terminal_reap_ns']
                    or not state['start_ns'] <= values['terminal_reap_ns'] <= values['terminal_wait_delivery_ns']
                           <= values['monotonic_end_ns'] <= state['deadline_ns']
                    or values['finalization_ns'] < values['monotonic_end_ns']):
                raise ValueError('required matching-PID terminal/delivery timeline is invalid or late')
            state['reap'] = True
        if stage == 'seccomp-seal':
            state['seal'] = True
            state['seal_inventory'] = values.get('fd_inventory')
        if record['record_type'] == 'fd-event' and values.get('operation') == 'inherited':
            fd = values.get('fd')
            if type(fd) is not int or fd in state['inherited_fds'] or len(state['inherited_fds']) >= 256:
                raise ValueError('required inherited FD identity is invalid')
            state['inherited_fds'][fd] = values
        if record['record_type'] == 'fd-event' and values.get('media_input') is True and state['seal']:
            state['input_read'] |= (values.get('fd') in (state['input_fds'] or [])
                                    and type(values.get('length')) is int and values['length'] > 0
                                    and type(values.get('input_bytes_before_seal')) is int
                                    and values['input_bytes_before_seal'] == 0)
        if record['record_type'] == 'source-load' and values.get('coverage') == 'complete-span':
            state['loads'] = True
        if record['record_type'] == 'output-event' and 'retained_prefix_sha256' in values:
            _validate_observed_values('output-event', values)
            state['outputs'].add(values['stream'])
            state['output_lengths'][values['stream']] = values['observed_length']
        if stage == 'controlled-cancellation-request':
            state['cancel'] = True
        if record['record_type'] == 'syscall-event' and values.get('phase') == 'exit' and values.get('errno'):
            state['denials'].add((values['name'], values['errno'], bool(values.get('clone_flags', 0)&0x10000)))
            state['calls'].add((values['name'], values['errno'], tuple(values['arguments'])))
            if (state['seal'] and values['name'] in {'open', 'openat', 'openat2'} and values['errno'] == errno.EPERM
                    and Path(decode_path_hex(values.get('path_bytes'))).name == 'P2-mp3-libmp3lame.mp3'):
                raw_flags = values.get('flags')
                if type(raw_flags) is not int or raw_flags < 0:
                    raise ValueError('required N2 raw open flags must be a nonnegative integer')
                state['secondary_denials'].add(raw_flags & os.O_ACCMODE)
            if (state['seal'] and values['name'] in {'open', 'openat', 'openat2'} and values['errno'] == errno.EPERM
                    and Path(decode_path_hex(values.get('path_bytes'))).name == 'unexpected_lq04_dependency.py'):
                state['late_import'] = True
        if (record['record_type'] == 'syscall-event' and values.get('phase') == 'exit' and values.get('name') == 'lseek'
                and values['result'] == 0 and values['errno'] == 0):
            arguments = values.get('arguments')
            if arguments is not None and arguments[1:3] in ([0, os.SEEK_CUR], (0, os.SEEK_CUR)):
                state['zero_offsets'].add(arguments[0])
        if record['record_type'] == 'termination' and values.get('actor') in {'parent-os.kill', 'parent-os.killpg'} and values.get('result') == 0:
            state['kill'] = True
    if set(labels)-seen:
        raise ValueError(f'required subcases missing: {sorted(set(labels)-seen)}')
    if index == 4:
        if set(rejections) != set(labels):
            raise ValueError('required named N1 rejection/NA records missing')
        if any(pid not in processes for metadata in rejections.values() for pid in metadata.get('pids', [])):
            raise ValueError('required N1 rejection child identity is unregistered')
    else:
        root_labels = {state['label'] for state in processes.values()}
        if set(labels)-{'strict-records'}-root_labels:
            raise ValueError('required root child envelope missing')
    for state in processes.values():
        if not all(state[field] for field in ('resources', 'terminal', 'reap')) or state['outputs'] != {'stdout', 'stderr'}:
            raise ValueError('required resource/terminal/reap/output envelope missing')
        exempt = state['label'] in {'N6-missing-bootstrap', 'N7-controlled-cancellation'}
        if not exempt and not (state['seal'] and state['loads']):
            raise ValueError('required seal/consumed-code coverage missing')
        if state['label'] == 'N7-controlled-cancellation' and not state['cancel']:
            raise ValueError('required controlled cancellation request missing')
        if index == 7 and not ({('execve', 1, False), ('clone3', 1, False), ('io_uring_setup', 1, False)}.issubset(state['denials'])
                and any(name in {'clone', 'clone3'} and thread and error == 1 for name, error, thread in state['denials'])):
            raise ValueError('required N4 native denial subrecords missing')
        parsed = control_returns.get(state['pid'])
        if index == 5:
            fd, _before, _after = _required_readonly_input(state, fixtures, 'N2')
            if (not isinstance(parsed, dict) or type(parsed.get('access')) is not int or parsed['access'] != os.O_RDONLY
                    or not isinstance(parsed.get('read'), str) or not re.fullmatch(r'(?:[0-9a-f]{2})+', parsed['read'])
                    or type(parsed.get('write_errno')) is not int or parsed['write_errno'] != errno.EBADF
                    or parsed.get('secondary_open_errno') != [errno.EPERM, errno.EPERM]
                    or any(type(item) is not int for item in parsed['secondary_open_errno'])
                    or not state['input_read'] or not {os.O_RDONLY, os.O_WRONLY}.issubset(state['secondary_denials'])
                    or not any(name == 'write' and error == errno.EBADF and args[0] == fd for name, error, args in state['calls'])):
                raise ValueError('required N2 read-only input/read/write and secondary denial outcomes missing')
        if index == 9:
            if state['label'] == 'N6-missing-bootstrap':
                inputs = state['input_fds']
                if (not isinstance(parsed, dict) or parsed.get('bootstrap_failed_closed') is not True
                        or type(parsed.get('input_offset')) is not int or parsed['input_offset'] != 0
                        or state['seal'] or not state['loads'] or state['terminal_status'] != 0
                        or any(type(state.get(field)) is not int or state[field] != 0
                               for field in ('terminal_input_before', 'terminal_input_after'))
                        or not isinstance(inputs, list) or len(inputs) != 1 or type(inputs[0]) is not int
                        or inputs[0] not in state['zero_offsets']):
                    raise ValueError('required N6 missing-bootstrap phase/zero-offset/import proof missing')
            elif not isinstance(parsed, dict) or parsed.get('unexpected_import_denied') is not True or not state['late_import']:
                raise ValueError('required N6 post-seal late-import denial missing')
        if index == 8:
            fd, before, after = _required_readonly_input(state, fixtures, 'N5')
            if (not isinstance(parsed, dict) or parsed.get('regular') is not True
                    or parsed.get('input_fd') != fd or type(parsed.get('input_fd')) is not int
                    or not isinstance(parsed.get('fds'), list) or any(type(item) is not int for item in parsed['fds'])
                    or len(parsed['fds']) != 4 or set(parsed['fds']) != {0, 1, 2, fd}
                    or type(parsed.get('flags')) is not int or parsed['flags'] != os.O_RDONLY
                    or any(type(parsed.get(key)) is not int or parsed[key] != after[key] for key in ('device', 'inode', 'size'))):
                raise ValueError('required N5 observed FD inventory/identity/rights missing')
        if index == 6 and not {2, 1}.issubset({args[0] for name, error, args in state['calls'] if name == 'socket' and error == 1}):
            raise ValueError('required IPv4/Unix socket denial subrecords missing')
        if index == 7 and (not isinstance(parsed, dict) or parsed.get('thread_exception') != 'RuntimeError'
                or not any(name in {'fork', 'clone', 'clone3'} and error == 1 and not thread
                           for name, error, thread in state['denials'])):
            raise ValueError('required Python thread outcome/fork denial missing')
        if index == 11:
            if (type(clock_ticks) is not int or clock_ticks <= 0 or state['kill']
                    or not os.WIFSIGNALED(state['terminal_status']) or os.WTERMSIG(state['terminal_status']) != signal.SIGKILL
                    or state['cpu'] < 30-1/clock_ticks):
                raise ValueError('required CPU-only kernel-attributed termination missing')
        if index == 10 and not state['kill']:
            raise ValueError('required timeout/cancellation signal action missing')
        if state['label'] in {'N8-AS', 'N8-DATA'}:
            subcase = state['label'][3:]
            if (not isinstance(parsed, dict) or parsed.get('subcase') != subcase
                    or parsed.get('mmap_failed') is not True or parsed.get('errno') != errno.ENOMEM
                    or not any(name == 'mmap' and error == errno.ENOMEM for name, error, _ in state['calls'])):
                raise ValueError('required native AS/DATA return/errno subrecord missing')
            before, after = parsed.get('before'), parsed.get('after')
            request = parsed.get('request_bytes')
            if (not isinstance(before, dict) or not isinstance(after, dict) or type(request) is not int or request <= 0
                    or any(type(metrics.get(name)) is not int or metrics[name] < 0
                           for metrics in (before, after) for name in ('VmRSS', 'VmSize', 'VmData'))):
                raise ValueError('required measured memory headroom fields missing')
            if subcase == 'AS' and not (before['VmSize']+request > 256*1024*1024
                    and before['VmData'] < 128*1024*1024 and before['VmRSS'] < 128*1024*1024):
                raise ValueError('required isolated AS headroom missing')
            if subcase == 'DATA' and not (before['VmSize']+request+16*1024*1024 < 256*1024*1024
                    and before['VmData']+request > 128*1024*1024):
                raise ValueError('required isolated DATA headroom missing')
        if state['label'] == 'N8-RSS' and not (state['rss_overrange'] and state['kill']):
            raise ValueError('required native RSS overrange/kill subrecord missing')
        for label, stream, cap in (('N8-stdout', 'stdout', 65536), ('N8-stderr', 'stderr', 16384)):
            if state['label'] == label and not (state['output_lengths'][stream] > cap and state['kill']):
                raise ValueError('required native overflow/kill subrecord missing')
    if index == 5:
        from lq04_runner import FIXTURE_SHA256
        sentinel = fixtures.get('P2-mp3-libmp3lame.mp3', {})
        if (sentinel.get('sha256') != FIXTURE_SHA256['P2-mp3-libmp3lame.mp3']
                or any(sentinels.get(stage, {}).get('path') != 'P2-mp3-libmp3lame.mp3'
                       or sentinels.get(stage, {}).get('sha256') != sentinel['sha256']
                       for stage in ('N2-sentinel-before', 'N2-sentinel-after'))):
            raise ValueError('required N2 sentinel identity/hash before/after missing or changed')
    if index == 12 and (schema_cases != {0, 1, 2, 3} or not missing_rss):
        raise ValueError('required N8 UNIT-injected subrecords missing')
    return {'evidence_complete': True, 'native_qualification': False,
            'evidence_kind': 'unit-simulated' if not kinds & {'native-observed', 'native-control'} else 'native-records-unqualified'}


def _required_readonly_input(state, fixtures, group):
    from lq04_runner import FIXTURE_SHA256
    inputs = state['input_fds']
    if not isinstance(inputs, list) or len(inputs) != 1 or type(inputs[0]) is not int or inputs[0] < 3:
        raise ValueError(f'required {group} authorized input FD missing')
    fd = inputs[0]
    before = state['inherited_fds'].get(fd)
    inventory = state['seal_inventory']
    fixture = fixtures.get('P1-video-only-mpeg4.mp4')
    if (set(state['inherited_fds']) != {0, 1, 2, fd} or not isinstance(inventory, list)
            or any(not isinstance(item, dict) or type(item.get('fd')) is not int for item in inventory)
            or len(inventory) != 4 or {item['fd'] for item in inventory} != {0, 1, 2, fd}
            or not isinstance(fixture, dict) or fixture['sha256'] != FIXTURE_SHA256['P1-video-only-mpeg4.mp4']):
        raise ValueError(f'required {group} before/after-seal FD/fixture inventory missing')
    after = next(item for item in inventory if item['fd'] == fd)
    for identity in (before, after):
        if (not isinstance(identity, dict)
                or any(type(identity.get(key)) is not int or type(fixture.get(key)) is not int
                       or identity[key] != fixture[key] for key in ('device', 'inode', 'size'))
                or not isinstance(identity.get('flags_octal'), str)
                or not re.fullmatch(r'[0-7]+', identity['flags_octal'])
                or int(identity['flags_octal'], 8) & os.O_ACCMODE != os.O_RDONLY):
            raise ValueError(f'required {group} input identity/read-only rights mismatch')
    return fd, before, after


class _NativeCollectorAuthority:
    def __init__(self) -> None:
        self.active = True

    def close(self) -> None:
        self.active = False


class _SyscallEntry(ctypes.Structure):
    _fields_ = [("number", ctypes.c_uint64), ("arguments", ctypes.c_uint64 * 6)]


class _SyscallExit(ctypes.Structure):
    _fields_ = [("result", ctypes.c_int64), ("is_error", ctypes.c_uint8)]


class _SyscallData(ctypes.Union):
    _fields_ = [("entry", _SyscallEntry), ("exit", _SyscallExit)]


class _SyscallInfo(ctypes.Structure):
    _fields_ = [
        ("operation", ctypes.c_uint8),
        ("padding", ctypes.c_uint8 * 3),
        ("architecture", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("stack_pointer", ctypes.c_uint64),
        ("data", _SyscallData),
    ]


class _IOVec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("length", ctypes.c_size_t)]


class PtraceAPI:
    """Read-only ptrace ABI for the pinned Linux x86_64 qualification cell."""

    def __init__(self) -> None:
        if sys.platform != "linux" or os.uname().machine != "x86_64":
            raise RuntimeError("OBS-STARTUP-RO-01 currently supports only Linux x86_64")
        self._libc = ctypes.CDLL(None, use_errno=True)
        self._ptrace = self._libc.ptrace
        self._ptrace.restype = ctypes.c_long
        self._ptrace.argtypes = [
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]

    def traceme_in_preexec(self) -> None:
        ctypes.set_errno(0)
        result = int(self._ptrace(_PTRACE_TRACEME, 0, None, None))
        error = ctypes.get_errno()
        if result == -1 and error:
            raise OSError(error, os.strerror(error))

    def call(self, request: int, pid: int, address: int = 0, data: int = 0) -> int:
        if request not in {_PTRACE_PEEKDATA, _PTRACE_SYSCALL, _PTRACE_SETOPTIONS,
                            _PTRACE_GETEVENTMSG, _PTRACE_GETSIGINFO, _PTRACE_GET_SYSCALL_INFO, 0x4204}:
            raise ValueError('unselected or mutating ptrace observer request is forbidden')
        ctypes.set_errno(0)
        result = int(
            self._ptrace(
                request,
                pid,
                ctypes.c_void_p(address),
                ctypes.c_void_p(data),
            )
        )
        error = ctypes.get_errno()
        if result == -1 and error:
            raise OSError(error, os.strerror(error))
        return result

    def get_syscall_info(self, pid: int) -> dict[str, object]:
        info = _SyscallInfo()
        size = ctypes.sizeof(info)
        copied = self.call(_PTRACE_GET_SYSCALL_INFO, pid, size, ctypes.addressof(info))
        required = {
            1: _SyscallInfo.data.offset + ctypes.sizeof(_SyscallEntry),
            2: _SyscallInfo.data.offset + _SyscallExit.is_error.offset + 1,
        }.get(info.operation, _SyscallInfo.data.offset)
        if copied < required:
            raise RuntimeError("PTRACE_GET_SYSCALL_INFO returned a truncated record")
        if info.operation == 1:
            return {
                "operation": "entry",
                "architecture": int(info.architecture),
                "instruction_pointer": int(info.instruction_pointer),
                "stack_pointer": int(info.stack_pointer),
                "syscall_number": int(info.data.entry.number),
                "arguments": tuple(int(item) for item in info.data.entry.arguments),
            }
        if info.operation == 2:
            return {
                "operation": "exit",
                "architecture": int(info.architecture),
                "instruction_pointer": int(info.instruction_pointer),
                "stack_pointer": int(info.stack_pointer),
                "result": int(info.data.exit.result),
                "is_error": bool(info.data.exit.is_error),
            }
        raise RuntimeError(f"unsupported ptrace syscall-info operation {info.operation}")

    def event_message(self, pid: int) -> int:
        message = ctypes.c_ulonglong()
        self.call(_PTRACE_GETEVENTMSG, pid, 0, ctypes.addressof(message))
        return int(message.value)

    def get_registers(self, pid: int) -> dict[str, int]:
        registers = (ctypes.c_uint64 * 27)()
        vector = _IOVec(ctypes.addressof(registers), ctypes.sizeof(registers))
        self.call(0x4204, pid, 1, ctypes.addressof(vector))  # GETREGSET / NT_PRSTATUS
        if vector.length != ctypes.sizeof(registers):
            raise RuntimeError("PTRACE_GETREGSET returned truncated registers")
        return {"orig_rax": int(registers[15]), "rip": int(registers[16]),
                "rsp": int(registers[19])}

    def start_ticks(self, pid: int) -> int:
        return proc_start_ticks(pid)

    def signal_info(self, pid: int) -> bytes:
        info = ctypes.create_string_buffer(128)
        self.call(_PTRACE_GETSIGINFO, pid, 0, ctypes.addressof(info))
        return bytes(info.raw)

    def peek_bytes(self, pid: int, address: int, size: int, deadline: float) -> bytes:
        """Retired by E-LQ04-PUMP-01: every routed capture path uses the
        continuation engine over peek_bytes_slice; a direct call is a defect."""
        raise RuntimeError(
            "peek_bytes raising wrapper was retired by E-LQ04-PUMP-01; "
            "route captures through peek_bytes_slice with the capture-continuation engine")

    def peek_bytes_slice(self, pid: int, address: int, size: int, deadline: float) -> bytes:
        """Return complete PEEKDATA words captured within one fair event-pump slice."""
        word_size = ctypes.sizeof(ctypes.c_long)
        buffer = bytearray()
        aligned = address - address % word_size
        prefix = address - aligned
        for offset in range(0, size + prefix, word_size):
            if time.monotonic() >= deadline:
                break
            ctypes.set_errno(0)
            word = int(self._ptrace(
                _PTRACE_PEEKDATA,
                pid,
                ctypes.c_void_p(aligned + offset),
                ctypes.c_void_p(0),
            ))
            error = ctypes.get_errno()
            if word == -1 and error:
                raise OSError(error, os.strerror(error))
            buffer.extend((word & ((1 << (word_size * 8)) - 1)).to_bytes(word_size, sys.byteorder))
        return bytes(buffer[prefix:prefix + size])


class EvidenceBundleBudget:
    def __init__(self) -> None:
        self.used_bytes = 0

    def reserve(self, case_used: int, amount: int, *, reserve: bool) -> None:
        case_limit = _MAX_CASE_BYTES if reserve else _MAX_CASE_BYTES - 64 * 1024
        bundle_limit = 64 * 1024 * 1024 if reserve else 64 * 1024 * 1024 - 1024 * 1024
        if case_used + amount > case_limit:
            raise OverflowError("per-case evidence budget exhausted")
        if self.used_bytes + amount > bundle_limit:
            raise OverflowError("evidence bundle budget exhausted")
        self.used_bytes += amount


_EVIDENCE_BUNDLE_BUDGET = EvidenceBundleBudget()


class _PlainEvidenceBudget:
    """Plain-qualification sidecar budget: persistence is not the gate (PLAN-01 simple-qualification)."""

    def __init__(self) -> None:
        self.used_bytes = 0

    def reserve(self, case_used: int, amount: int, *, reserve: bool) -> None:
        self.used_bytes += amount


class NativeEvidenceWriter:
    """Bounded append-only JSONL for records created by an active ptrace capture."""

    def __init__(
        self,
        output: Path,
        *,
        run_id: str,
        node_id: str,
        manifest_sha256: str,
        source_sha256: str,
        policy_sha256: str,
        collector_sha256: str,
        bundle_budget: EvidenceBundleBudget | None = None,
        fixture_sha256: str | None = None,
    ) -> None:
        self.path = Path(output)
        self.run_id = run_id
        self.node_id = node_id
        self.manifest_sha256 = manifest_sha256
        self.source_sha256 = source_sha256
        self.policy_sha256 = policy_sha256
        self.collector_sha256 = collector_sha256
        self.fixture_sha256 = fixture_sha256
        self.bundle_budget = bundle_budget or _EVIDENCE_BUNDLE_BUDGET
        self.authority = _NativeCollectorAuthority()
        self._fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        self._case_bytes = 0
        self._bundle_bytes = 0
        self._closed = False
        self._identity = None
        self._prefix_credit = 0
        self.blobs: list[Path] = []

    def append(
        self,
        record_type: str,
        *,
        status: str,
        pid: int,
        start_ticks: int | None,
        origin: str,
        collector_id: str,
        values: Mapping[str, object],
        subcase: str | None = None,
        evidence_kind: str = "native-observed",
        fixture_sha256: str | None = None,
        reason: str | None = None,
        reserve: bool = False,
    ) -> None:
        record: dict[str, object] = {
            "schema_v": 1,
            "record_type": record_type,
            "evidence_kind": evidence_kind,
            "status": status,
            "run_id": self.run_id,
            "node_id": self.node_id,
            "source_sha256": self.source_sha256,
            "policy_sha256": self.policy_sha256,
            "collector_sha256": self.collector_sha256,
            "manifest_sha256": self.manifest_sha256,
            "origin": origin,
            "collector_id": collector_id,
            "pid": pid,
            "values": dict(values),
        }
        if start_ticks is not None:
            record["start_ticks"] = start_ticks
        if subcase is not None:
            record["subcase"] = subcase
        fixture_digest = fixture_sha256 or self.fixture_sha256
        if fixture_digest is not None:
            record["fixture_sha256"] = fixture_digest
        if reason is not None:
            record["reason"] = reason
        checked = validate_record(record, authority=self.authority)
        fixed = {key: checked[key] for key in ('run_id', 'node_id', 'source_sha256',
                 'policy_sha256', 'collector_sha256', 'manifest_sha256', 'origin', 'collector_id')}
        if self._identity is None:
            self.append_unit('identity', subcase='case-identity', status='DECLARED',
                             values=fixed, evidence_kind='declared')
            self._identity = fixed
        elif self._identity != fixed:
            raise ValueError('trace identity drift inside one case ledger')
        checked = {key: value for key, value in checked.items() if key not in fixed}
        checked['identity_ref'] = 'case'
        digest = hashlib.sha256(canonical_record(checked)).hexdigest()
        checked["record_sha256"] = digest
        payload = canonical_record(checked) + b"\n"
        if len(payload) > _MAX_RECORD_BYTES:
            raise OverflowError('hashed record exceeds 16 KiB including newline')
        self.bundle_budget.reserve(self._case_bytes, len(payload), reserve=reserve)
        write_all(self._fd, payload)
        os.fsync(self._fd)
        self._case_bytes += len(payload)
        self._bundle_bytes += len(payload)

    def append_unit(
        self,
        record_type: str,
        *,
        subcase: str,
        status: str,
        values: Mapping[str, object],
        reason: str | None = None,
        evidence_kind: str = "unit-injected",
    ) -> None:
        if evidence_kind not in {'unit-injected', 'unit-simulated', 'declared'}:
            raise ValueError('unit writer cannot promote records to native')
        record: dict[str, object] = {
            "schema_v": 1,
            "record_type": record_type,
            "evidence_kind": evidence_kind,
            "status": status,
            "run_id": self.run_id,
            "node_id": self.node_id,
            "subcase": subcase,
            "values": dict(values),
        }
        if reason is not None:
            record["reason"] = reason
        checked = validate_record(record)
        checked["record_sha256"] = hashlib.sha256(canonical_record(checked)).hexdigest()
        payload = canonical_record(checked) + b"\n"
        if len(payload) > _MAX_RECORD_BYTES:
            raise OverflowError('hashed record exceeds 16 KiB including newline')
        self.bundle_budget.reserve(self._case_bytes, len(payload), reserve=False)
        write_all(self._fd, payload)
        os.fsync(self._fd)
        self._case_bytes += len(payload)
        self._bundle_bytes += len(payload)

    def reserve_prefix_bytes(self, amount):
        self.bundle_budget.reserve(self._case_bytes, amount, reserve=False)
        self._case_bytes += amount
        self._bundle_bytes += amount
        self._prefix_credit += amount

    def write_blob(self, name: str, data: bytes, *, reserve: bool = False, prepaid: bool = False) -> tuple[str, str]:
        if Path(name).name != name or not name:
            raise ValueError("evidence blob name must be a basename")
        blob_path = self.path.parent / name
        if blob_path.exists() or blob_path.is_symlink():
            raise FileExistsError(f"evidence blob already exists: {name}")
        if len(self.blobs) >= 32:
            raise OverflowError('prefix blob inventory exceeds two streams per 16 lineage PIDs')
        if prepaid:
            if len(data) > self._prefix_credit:
                raise ValueError('prefix blob has no observed-byte budget reservation')
            self._prefix_credit -= len(data)
        if not prepaid:
            self.bundle_budget.reserve(self._case_bytes, len(data), reserve=reserve)
        fd = os.open(blob_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        self.blobs.append(blob_path)
        if not prepaid:
            self._case_bytes += len(data)
            self._bundle_bytes += len(data)
        return name, hashlib.sha256(data).hexdigest()

    def close(self) -> None:
        if not self._closed:
            self.authority.close()
            primary = None
            try:
                os.fsync(self._fd)
            except BaseException as error:
                primary = error
                raise
            finally:
                try:
                    os.close(self._fd)
                except BaseException as error:
                    if primary is None:
                        raise
                    primary.add_note(f'writer descriptor close failed: {error}')
                finally:
                    self._closed = True  # Retired even on error: never retry a possibly reused FD.

    def __enter__(self) -> NativeEvidenceWriter:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            self.close()
        except BaseException as error:
            if exc_value is None:
                raise
            exc_value.add_note(f'writer finalization failed: {error}')


def canonical_record(record: Mapping[str, object]) -> bytes:
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


_ARTIFACT_REF = re.compile(r"^artifact-\d+$")


def reconcile_compaction_totals(records, *, summary) -> dict[str, object]:
    """W6: exact accounting — every syscall/sample/load is full, compact+count,
    decimated-with-declared-policy, or referenced; totals reconcile exactly."""
    if not isinstance(summary, Mapping):
        raise ValueError('compaction reconciliation requires the case summary')
    tally: dict[str, dict[str, int]] = {}
    full = compact = 0
    samples_emitted = 0
    loads_full = loads_referenced = 0
    full_refs: set[str] = set()
    reference_refs: list[str] = []
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError('compaction reconciliation requires record objects')
        record_type = record.get('record_type')
        values = record.get('values')
        if record_type == 'syscall-event' and isinstance(values, Mapping):
            batch = values.get('batch')
            frames = batch if isinstance(batch, list) else [values]
            for frame in frames:
                if not isinstance(frame, Mapping):
                    raise ValueError('compaction reconciliation requires frame objects')
                name = frame.get('name')
                phase = frame.get('phase')
                if not isinstance(name, str) or phase not in {'entry', 'exit'}:
                    raise ValueError('compaction reconciliation requires syscall frame identity')
                bucket = tally.setdefault(name, {'entry': 0, 'exit': 0, 'errors': 0})
                bucket['exit' if phase == 'exit' else 'entry'] += 1
                if phase == 'exit' and frame.get('errno', 0) != 0:
                    bucket['errors'] += 1
                if frame is not values:
                    compact += 1
                elif frame.get('compact') is True:
                    compact += 1
                else:
                    full += 1
        elif record_type == 'resource-sample':
            samples_emitted += 1
        elif record_type == 'source-load' and isinstance(values, Mapping):
            ref = values.get('artifact_ref')
            if isinstance(ref, str) and 'mapping' not in values:
                loads_referenced += 1
                reference_refs.append(ref)
            elif isinstance(ref, str):
                loads_full += 1
                full_refs.add(ref)
            else:
                loads_full += 1
    if tally != {name: dict(buckets) for name, buckets in summary.items()
                 if isinstance(summary.get(name), Mapping) and set(summary[name]) == {'entry', 'exit', 'errors'}}:
        raise ValueError('syscall-counts summary does not reconcile with emitted frames')
    for key in ('resource_samples_emitted', 'resource_samples_decimated', 'resource_samples_total'):
        if type(summary.get(key)) is not int:
            raise ValueError(f'case summary lacks the declared {key}')
    if summary['resource_samples_emitted'] != samples_emitted \
            or summary['resource_samples_emitted'] + summary['resource_samples_decimated'] \
            != summary['resource_samples_total']:
        raise ValueError('resource-sample decimation totals do not reconcile exactly')
    unresolved = sorted(set(reference_refs) - full_refs)
    if unresolved:
        raise ValueError(f'source-load references do not resolve: {unresolved}')
    return {
        'syscall_events_full': full,
        'syscall_events_compact': compact,
        'resource_samples_emitted': samples_emitted,
        'resource_samples_decimated': summary['resource_samples_decimated'],
        'source_loads_full': loads_full,
        'source_loads_referenced': loads_referenced,
        'unresolved_references': unresolved,
    }


def build_artifact_index(records) -> dict[str, dict[str, object]]:
    """Post-run index {artifact_ref: first full emission context} for F2 resolution."""
    index: dict[str, dict[str, object]] = {}
    for record in records:
        if not isinstance(record, Mapping) or record.get('record_type') != 'source-load':
            continue
        values = record.get('values', {})
        ref = values.get('artifact_ref') if isinstance(values, Mapping) else None
        if not isinstance(ref, str):
            continue
        mapping = values.get('mapping')
        if isinstance(mapping, dict) and isinstance(mapping.get('file'), dict):
            index.setdefault(ref, {
                'operation': values.get('operation') or values.get('mapping_operation') or 'mmap',
                'mapping': mapping,
            })
    return index


def resolve_source_load_reference(values, index) -> dict[str, object]:
    """F2/W2: reconstruct a referenced source-load from its first full record."""
    if not isinstance(values, Mapping) or not isinstance(values.get('artifact_ref'), str):
        raise ValueError('source-load reference resolution requires an artifact reference')
    first = index.get(values['artifact_ref']) if isinstance(index, Mapping) else None
    if not isinstance(first, dict) or not isinstance(first.get('mapping'), dict):
        raise ValueError(f'unresolvable source-load artifact reference: {values["artifact_ref"]}')
    mapping = dict(first['mapping'])
    artifact = mapping.get('file')
    if not isinstance(artifact, dict) or values.get('span_sha256') != artifact.get('sha256'):
        raise ValueError('referenced span hash differs from the attested first record')
    mapping['offset'] = int(values['offset'])
    mapping['length'] = int(values['length'])
    return {'operation': first.get('operation'), 'mapping': mapping}


def resolve_record_identity(record, identity):
    if record.get('identity_ref') != 'case' or not isinstance(identity, dict):
        raise ValueError('missing or unknown static trace identity reference')
    if set(record) & set(identity):
        raise ValueError('trace frame shadows its frozen static identity')
    return {**identity, **{key: value for key, value in record.items() if key != 'identity_ref'}}


def write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError(errno.EIO, "short write to evidence sidecar")
        offset += written


def classify_wait_status(status: int, *, expect_exec_stop: bool = False) -> str:
    if type(status) is not int or status < 0:
        raise ValueError("wait status must be a nonnegative integer")
    if os.WIFEXITED(status) or os.WIFSIGNALED(status):
        return "terminal"
    if not os.WIFSTOPPED(status):
        raise ValueError("wait status is neither a stop nor a terminal outcome")
    event = status >> 16
    if event == _PTRACE_EVENT_FORK:
        return "fork-event"
    if event == _PTRACE_EVENT_VFORK:
        return "vfork-event"
    if event == _PTRACE_EVENT_CLONE:
        return "clone-event"
    if event == _PTRACE_EVENT_EXEC:
        return "exec-event"
    if event == _PTRACE_EVENT_EXIT:
        return "exit-event"
    if event == _PTRACE_EVENT_STOP:
        return "owned-event-stop"
    if event:
        return "unknown-ptrace-event"
    stop_signal = os.WSTOPSIG(status)
    if expect_exec_stop and stop_signal == signal.SIGTRAP:
        return "exec-stop"
    if stop_signal == _SIGTRAP_SYSCALL:
        return "syscall-stop"
    return "signal-delivery-stop"


class OwnChildSupervisor:
    """Serial wait/event owner. Injected backends are UNIT-only; live use requires PtraceAPI."""

    def __init__(
        self,
        api: PtraceAPI | object,
        emit=None,
        *,
        expected_hashes: Mapping[str, str] | None = None,
        expected_executables: Mapping[str, str] | None = None,
        expected_identities: Mapping[str, Mapping[str, int]] | None = None,
        fixture_root: Path | None = None,
        device_reconciliation: Mapping[str, object] | None = None,
        mountinfo_text: str | None = None,
        wait4_func=None,
        sample_live=None,
        resource_sample_policy: ResourceSamplePolicy | None = None,
        plain_mode: bool = False,
    ) -> None:
        self.api = api
        self.emit = emit or (lambda record: None)
        self.evidence_kind = "native-observed" if type(api) is PtraceAPI else "unit-simulated"
        self.plain_mode = bool(plain_mode)
        self._resource_sample_policy = resource_sample_policy
        self.tracees: dict[int, dict[str, object]] = {}
        self.terminal: dict[int, tuple[int, object]] = {}
        self.invalid_reasons: list[str] = []
        self.expected_hashes = {str(Path(path).resolve()): digest for path, digest in (expected_hashes or {}).items()}
        self.expected_executables = {
            str(Path(path).resolve()): digest for path, digest in (expected_executables or {}).items()
        }
        self.expected_identities = dict(expected_identities or {})
        self.device_reconciliation = device_reconciliation
        self.mountinfo_text = mountinfo_text
        self.fixture_root = Path(fixture_root).resolve() if fixture_root is not None else None
        self._wait4_func = wait4_func or os.wait4
        self._sample_live_override = sample_live
        self._resource_sample_policy = resource_sample_policy
        self.slice_end_hook = None
        self._verified_expected: set[str] = set()

    def register(self, pid: int, start_ticks: int, pgid: int, *, root: bool = False) -> None:
        if type(pid) is not int or pid <= 0 or type(start_ticks) is not int or start_ticks <= 0:
            raise ValueError("registered tracee requires positive pid/start-tick identity")
        if pid in self.tracees:
            raise ValueError("tracee PID registered twice")
        if len(self.tracees) >= _MAX_TRACE_PIDS:
            raise OverflowError("ptrace lineage exceeds 16 processes")
        self.tracees[pid] = {
            "pid": pid,
            "start_ticks": start_ticks,
            "pgid": pgid,
            "root": root,
            "exec_pending": True,
            "initial_exec_return_pending": False,
            "fork_return_entry": None,
            "child_stop_pending": not root,
            "syscall_entry": None,
            "terminal_seen": False,
            "terminal_delivered": False,
            "fd_generation": {},
            "last_fd_generation": 0,
            "fds": {},
            "offsets": {},
            "mappings": {},
            "pending_capture": None,
            "pending_memory_capture": None,
            "syscall_counts": {},
            "unknown_syscalls": [],
            "sealed": False,
            "input_bytes_before_seal": 0,
            "input_bytes_after_seal": 0,
        }

    def classify(self, pid: int, status: int, *, rusage=None) -> tuple[str, object | None]:
        tracee = self.tracees.get(pid)
        if tracee is None:
            self._invalidate(f"wait outcome for unregistered pid {pid}")
            raise ValueError(self.invalid_reasons[-1])
        if tracee["terminal_seen"]:
            self._invalidate(f"duplicate terminal wait outcome for pid {pid}")
            raise ValueError(self.invalid_reasons[-1])
        kind = classify_wait_status(status, expect_exec_stop=bool(tracee["exec_pending"]))
        if tracee["pending_memory_capture"] is not None and kind != "terminal":
            self._invalidate("new ptrace stop while a memory capture is pending")
            raise ValueError(self.invalid_reasons[-1])
        event: dict[str, object] = {
            "pid": pid,
            "start_ticks": tracee["start_ticks"],
            "wait_status": status,
            "event": kind,
            "monotonic_ns": time.monotonic_ns(),
        }
        if kind == "terminal":
            tracee['terminal_reap_ns'] = event['monotonic_ns']
            entry = tracee["syscall_entry"]
            if entry is not None and entry.get("name") not in {"exit", "exit_group"}:
                if not os.WIFSIGNALED(status):
                    self._invalidate(f"terminal wait status with unmatched syscall entry for pid {pid}")
                event["interrupted_syscall"] = entry
            tracee["syscall_entry"] = None
            if tracee["exec_pending"]:
                self._invalidate(f"PID {pid} terminated before successful exec-stop handshake")
            tracee["terminal_seen"] = True
            if tracee["pending_memory_capture"] is not None:
                self._invalidate("tracee terminated while a memory capture was pending")
                self._discard_memory_capture(pid, tracee, self.invalid_reasons[-1])
            event.update(input_bytes_before_seal=tracee['input_bytes_before_seal'], input_bytes_after_seal=tracee['input_bytes_after_seal'])
            event["rusage"] = dict(rusage) if isinstance(rusage, Mapping) else {}
            event["syscall_counts"] = dict(sorted(tracee["syscall_counts"].items()))
            if tracee["exec_pending"]:
                event["status"] = "MISSING"
                event["reason"] = self.invalid_reasons[-1]
            self.terminal[pid] = (status, rusage)
            self.emit({"evidence_kind": self.evidence_kind, **event})
            return "terminal", event
        if kind == "exec-stop":
            tracee["exec_pending"] = False
            tracee['initial_exec_return_pending'] = True
            self.emit({"evidence_kind": self.evidence_kind, **event})
            return "set-options-and-resume", event
        if kind == "owned-event-stop":
            if not tracee["child_stop_pending"]:
                self._invalidate(f"unowned PTRACE_EVENT_STOP for pid {pid}")
                raise ValueError(self.invalid_reasons[-1])
            tracee["child_stop_pending"] = False
            self.emit({"evidence_kind": self.evidence_kind, **event})
            return "resume-syscall", event
        if kind == "syscall-stop":
            syscall_info = self.api.get_syscall_info(pid)
            syscall_info['wait_status'] = status
            syscall_info['monotonic_ns'] = event['monotonic_ns']
            if self.evidence_kind == "native-observed":
                registers = self.api.get_registers(pid)
                if syscall_info.get('operation') == 'exit':
                    syscall_info['syscall_number'] = registers['orig_rax']
                if registers["rip"] != syscall_info["instruction_pointer"]:
                    raise RuntimeError("syscall-info instruction pointer differs from GETREGSET")
            operation = syscall_info.get("operation")
            if operation == "entry":
                tracee['initial_exec_return_pending'] = False
                tracee['fork_return_entry'] = None
                if tracee["syscall_entry"] is not None:
                    self._invalidate(f"overlapping syscall entry for pid {pid}")
                    raise ValueError(self.invalid_reasons[-1])
                syscall_info = self._observe_syscall_entry(pid, tracee, syscall_info)
                tracee["syscall_entry"] = syscall_info
            elif operation == "exit":
                if tracee["syscall_entry"] is None:
                    if (tracee['initial_exec_return_pending']
                            and syscall_info.get('architecture') == _AUDIT_ARCH_X86_64
                            and syscall_info.get('syscall_number') in {59, 322}
                            and syscall_info.get('result') == 0 and syscall_info.get('is_error') is False):
                        tracee['initial_exec_return_pending'] = False
                        self.emit({'evidence_kind': self.evidence_kind, 'record_type': 'syscall-event',
                                   'status': 'OBSERVED', 'pid': pid, 'start_ticks': tracee['start_ticks'],
                                   'values': {**syscall_info, 'phase': 'initial-exec-return',
                                              'entry_status': 'DECLARED',
                                              'entry_basis': 'verified initial exec identity; entry predates SYSCALL supervision'}})
                        return 'resume-syscall', event
                    if tracee['fork_return_entry'] is not None and syscall_info.get('result') == 0:
                        tracee['syscall_entry'] = {**tracee['fork_return_entry'],
                            'entry_status': 'DECLARED', 'entry_basis': 'owned parent fork entry inherited by descendant'}
                        tracee['fork_return_entry'] = None
                    else:
                        self._invalidate(f"syscall exit without entry for pid {pid}")
                        raise ValueError(self.invalid_reasons[-1])
                if syscall_info.get("architecture") != _AUDIT_ARCH_X86_64:
                    self._invalidate(f"unsupported syscall-exit ABI for pid {pid}")
                    raise RuntimeError(self.invalid_reasons[-1])
                entry = tracee["syscall_entry"]
                tracee["syscall_entry"] = None
                syscall_info = self._observe_syscall_exit(pid, tracee, entry, syscall_info)
            else:
                self._invalidate(f"unknown syscall-info operation for pid {pid}")
                raise ValueError(self.invalid_reasons[-1])
            event["syscall"] = syscall_info
            if tracee["pending_memory_capture"] is not None:
                return "memory-capture-pending", event
            if syscall_info.get("capture_pending"):
                return "capture-pending", event
            return "resume-syscall", event
        if kind in {"fork-event", "vfork-event", "clone-event"}:
            child_pid = int(self.api.event_message(pid))
            if child_pid <= 0 or child_pid in self.tracees:
                self._invalidate(f"invalid descendant identity for pid {pid}")
                raise ValueError(self.invalid_reasons[-1])
            self.register(child_pid, self.api.start_ticks(child_pid), int(tracee['pgid']), root=False)
            child = self.tracees[child_pid]
            child['fork_return_entry'] = tracee['syscall_entry']
            child['deadline'] = tracee.get('deadline')
            child["fds"] = {fd: dict(info) for fd, info in tracee["fds"].items()}
            child["fd_generation"] = dict(tracee["fd_generation"])
            child['last_fd_generation'] = tracee['last_fd_generation']
            child["offsets"] = dict(tracee["offsets"])
            child["mappings"] = {key: dict(mapping) for key, mapping in tracee["mappings"].items()}
            if len(child["fds"]) > _MAX_TRACE_FDS or len(child["mappings"]) > _MAX_TRACE_ARTIFACTS:
                self._invalidate("forked child inherited state beyond finite FD/mapping bounds")
                raise OverflowError(self.invalid_reasons[-1])
            event["child_pid"] = child_pid
            self.emit({"evidence_kind": self.evidence_kind, **event})
            return "resume-syscall", event
        if kind == "signal-delivery-stop":
            if tracee["child_stop_pending"] and os.WSTOPSIG(status) == signal.SIGSTOP:
                try:
                    signal_info = self.api.signal_info(pid)
                except OSError as error:
                    self._invalidate(f"new-child SIGSTOP ownership is ambiguous for pid {pid}: {error.errno}")
                    raise RuntimeError(self.invalid_reasons[-1]) from error
                if len(signal_info) != 128:
                    raise RuntimeError('new-child stop lacks a complete siginfo identity')
                signo, _errno, code = struct.unpack_from('iii', signal_info, 0)
                sender = struct.unpack_from('i', signal_info, 16)[0]
                if signo == signal.SIGSTOP and code in {0, 128} and sender == 0:
                    tracee["child_stop_pending"] = False
                    event["event"] = "owned-child-initial-stop"
                    event["signal_info_hex"] = signal_info.hex()
                    self.emit({"evidence_kind": self.evidence_kind, **event})
                    return "suppress-owned-child-stop", event
            try:
                signal_info = self.api.signal_info(pid)
            except OSError as error:
                self._invalidate(f"signal stop is unclassifiable/group-stop for pid {pid}: {error.errno}")
                raise RuntimeError(self.invalid_reasons[-1]) from error
            event["signal_info_hex"] = signal_info.hex()
            event["forward_signal"] = os.WSTOPSIG(status)
            self.emit({"evidence_kind": self.evidence_kind, **event})
            return "forward-signal-and-resume", event
        if kind in {"exec-event", "exit-event"}:
            event["event_message"] = self.api.event_message(pid)
            if kind == "exec-event":
                tracee["exec_pending"] = False
                tracee['initial_exec_return_pending'] = tracee['syscall_entry'] is None
                event["exec_identity"] = self._record_exec_identity(pid, tracee)
            self.emit({"evidence_kind": self.evidence_kind, **event})
            return "resume-syscall", event
        self._invalidate(f"unclassifiable ptrace stop {kind} for pid {pid}")
        raise ValueError(self.invalid_reasons[-1])

    def terminal_for_popen(self, pid: int) -> tuple[int, object] | None:
        tracee = self.tracees.get(pid)
        outcome = self.terminal.get(pid)
        if tracee is None or outcome is None or tracee["terminal_delivered"]:
            return None
        tracee["terminal_delivered"] = True
        tracee['terminal_wait_delivery_ns'] = time.monotonic_ns()
        return outcome

    def seed_fds(self, pid: int, inherited: tuple[int, ...]) -> None:
        tracee = self.tracees.get(pid)
        if tracee is None:
            raise ValueError("cannot seed FDs for an unregistered pid")
        for fd in sorted({0, 1, 2, *inherited}):
            self._bind_fd(pid, tracee, fd, "inherited", origin="parent-pass-fd")

    def _record_exec_identity(self, pid: int, tracee: dict[str, object]) -> dict[str, object]:
        executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        path = str(executable)
        if self.plain_mode:
            digest = file_sha256(executable)
        else:
            digest = self._verify_frozen_artifact(executable)
        expected = self.expected_executables.get(path)
        if not self.plain_mode and (expected is None or expected != digest):
            self._invalidate(f"exec path/hash is outside frozen executable closure: {path}")
            raise RuntimeError(self.invalid_reasons[-1])
        raw_argv = Path(f"/proc/{pid}/cmdline").read_bytes()
        argv = [item for item in raw_argv.split(b"\0") if item]
        validate_exec_argv(tracee, argv)
        self._record_initial_mappings(pid, tracee)
        identity = {"path": path, "sha256": digest,
                    "argv_sha256": [hashlib.sha256(item).hexdigest() for item in argv]}
        for fd, info in tuple(tracee["fds"].items()):
            if info.get("close_on_exec"):
                try:
                    os.readlink(f"/proc/{pid}/fd/{fd}")
                except FileNotFoundError:
                    pass
                else:
                    self._invalidate(f"CLOEXEC fd {fd} remained open across exec")
                    raise RuntimeError(self.invalid_reasons[-1])
                tracee["fds"].pop(fd, None)
                tracee['fd_generation'].pop(fd, None)
                tracee["offsets"].pop(fd, None)
                self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                           "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                           "values": {"operation": "exec-close-cloexec", "fd": fd, **info}})
        return identity

    def _record_initial_mappings(self, pid, tracee):
        tracee['mappings'] = {}
        with Path(f'/proc/{pid}/maps').open(encoding='ascii') as stream:
            for line in stream:
                fields = line.rstrip().split(maxsplit=5)
                first, last = fields[0].split('-')
                start, end = int(first, 16), int(last, 16)
                path = fields[5] if len(fields) == 6 else None
                artifact = None
                if path and path.startswith('/'):
                    candidate = Path(path).resolve(strict=True)
                    digest = self.expected_hashes.get(str(candidate)) or self.expected_executables.get(str(candidate))
                    if digest is None and self.plain_mode:
                        digest = file_sha256(candidate)
                        self._invalidate(f"initial mapping outside the trusted closure (plain): {path}")
                    elif digest is None or self._verify_frozen_artifact(candidate) != digest:
                        raise RuntimeError(f'initial executable mapping outside frozen closure: {path}')
                    major, minor = fields[3].split(':')
                    info = candidate.stat()
                    maps_device = os.makedev(int(major, 16), int(minor, 16))
                    maps_inode = int(fields[4])
                    reconciliation = None
                    if (maps_device, maps_inode) != (info.st_dev, info.st_ino):
                        if self.plain_mode:
                            self._invalidate(f"initial mapping device mismatch without declared topology (plain): {path}")
                        else:
                            from lq04_runner import reconcile_mapping_device
                            mountinfo_text = self.mountinfo_text
                            if mountinfo_text is None:
                                mountinfo_text = Path('/proc/self/mountinfo').read_text(encoding='ascii')
                                self.mountinfo_text = mountinfo_text
                            reconciliation = reconcile_mapping_device(
                                maps_device=maps_device, maps_inode=maps_inode,
                                stat_device=info.st_dev, stat_inode=info.st_ino,
                                artifact_path=str(candidate), frozen_path=str(candidate),
                                digest_ok=True, declared_topology=self.device_reconciliation,
                                mountinfo_text=mountinfo_text)
                    artifact = {'path': str(candidate), 'device': info.st_dev, 'inode': info.st_ino,
                                'sha256': digest}
                    if reconciliation is not None:
                        artifact['device_reconciliation'] = reconciliation
                elif 'x' in fields[1] and path not in {'[vdso]', '[vsyscall]'}:
                    if not self.plain_mode:
                        raise RuntimeError('unexpected initial executable anonymous mapping')
                    self._invalidate('unexpected initial executable anonymous mapping (plain)')
                if len(tracee['mappings']) >= _MAX_TRACE_ARTIFACTS:
                    raise OverflowError('initial maps exceed artifact bound')
                prot = (1 if 'r' in fields[1] else 0) | (2 if 'w' in fields[1] else 0) | (4 if 'x' in fields[1] else 0)
                mapping = {'start': start, 'end': end, 'length': end - start,
                           'offset': int(fields[2], 16), 'prot': prot, 'permissions': fields[1],
                           'file': artifact, 'kernel_label': path if artifact is None else None}
                tracee['mappings'][f'{pid}:{start:x}'] = mapping
                self.emit({'record_type': 'source-load', 'evidence_kind': self.evidence_kind,
                           'status': 'OBSERVED' if artifact else 'DECLARED',
                           'pid': pid, 'start_ticks': tracee['start_ticks'],
                           'values': {'operation': 'initial-exec-map', 'mapping': mapping}})

    def _observe_syscall_entry(
        self, pid: int, tracee: dict[str, object], info: dict[str, object]
    ) -> dict[str, object]:
        if info.get("architecture") != _AUDIT_ARCH_X86_64:
            self._invalidate(f"unsupported syscall ABI for pid {pid}")
            raise RuntimeError(self.invalid_reasons[-1])
        number = int(info["syscall_number"])
        name = _SYSCALL_NAMES.get(number, "unknown")
        arguments = tuple(int(item) for item in info["arguments"])
        if name == "unknown":
            self._invalidate(f"unrecognized x86_64 syscall number {number}")
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "syscall-event",
                       "status": "MISSING", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "reason": self.invalid_reasons[-1],
                       "values": {"phase": "entry", "syscall_number": number,
                                  "arguments": arguments}})
            raise RuntimeError(self.invalid_reasons[-1])
        audit_detail = name in _DETAIL_SYSCALL_NAMES
        info = {**info, "name": name, "audit_detail": audit_detail}
        tracee["syscall_counts"].setdefault(f"{number}:{name}", 0)
        deadline = time.monotonic() + 0.001
        if name == "open":
            data, pending = self._capture_entry_bytes(
                pid, tracee, deadline, kind="string", address=int(arguments[0]), maximum=4096,
                name=name, number=number, arguments=arguments, info=info)
            if pending:
                return info
            info["path_bytes"] = data.hex()
            info["flags"] = arguments[1]
        elif name in {"openat", "openat2", "newfstatat", "readlinkat", "statx",
                      "faccessat", "faccessat2", "name_to_handle_at"}:
            info["dirfd"] = arguments[0]
            data, pending = self._capture_entry_bytes(
                pid, tracee, deadline, kind="string", address=int(arguments[1]), maximum=4096,
                name=name, number=number, arguments=arguments, info=info)
            if pending:
                return info
            info["path_bytes"] = data.hex()
            if name == "openat":
                info["flags"] = arguments[2]
            elif name == "openat2":
                how_size = int(arguments[3])
                if not 24 <= how_size <= 256:
                    self._invalidate("openat2 open_how size is outside the frozen parser bound")
                    raise RuntimeError(self.invalid_reasons[-1])
                data, pending = self._capture_entry_bytes(
                    pid, tracee, deadline, kind="struct", address=int(arguments[2]),
                    maximum=how_size, name=name, number=number, arguments=arguments, info=info)
                if pending:
                    return info
                info["open_how_size"] = how_size
                info["open_how_bytes_hex"] = data.hex()
                info["flags"] = int.from_bytes(data[0:8], sys.byteorder)
                info["mode"] = int.from_bytes(data[8:16], sys.byteorder)
                info["resolve"] = int.from_bytes(data[16:24], sys.byteorder)
        elif name in {"stat", "lstat", "readlink", "execve"}:
            data, pending = self._capture_entry_bytes(
                pid, tracee, deadline, kind="string", address=int(arguments[0]), maximum=4096,
                name=name, number=number, arguments=arguments, info=info)
            if pending:
                return info
            info["path_bytes"] = data.hex()
        elif name == "memfd_create":
            data, pending = self._capture_entry_bytes(
                pid, tracee, deadline, kind="string", address=int(arguments[0]), maximum=4096,
                name=name, number=number, arguments=arguments, info=info)
            if pending:
                return info
            info["name_bytes"] = data.hex()
        elif name == "execveat":
            info["dirfd"] = arguments[0]
            data, pending = self._capture_entry_bytes(
                pid, tracee, deadline, kind="string", address=int(arguments[1]), maximum=4096,
                name=name, number=number, arguments=arguments, info=info)
            if pending:
                return info
            info["path_bytes"] = data.hex()
        elif name == 'clone':
            info['clone_flags'] = arguments[0]
        elif name == 'clone3':
            size = arguments[1]
            if not 8 <= size <= 256:
                raise RuntimeError('clone3 argument size is outside bounded inspection contract')
            data, pending = self._capture_entry_bytes(
                pid, tracee, deadline, kind="struct", address=int(arguments[0]), maximum=size,
                name=name, number=number, arguments=arguments, info=info)
            if pending:
                return info
            info['clone_args_hex'] = data.hex()
            info['clone_flags'] = int.from_bytes(data[:8], sys.byteorder)
        if audit_detail:
            self.emit({
                "evidence_kind": self.evidence_kind,
                "record_type": "syscall-event",
                "status": "OBSERVED",
                "pid": pid,
                "start_ticks": tracee["start_ticks"],
                "values": {"phase": "entry", **info},
            })
        return info

    def _observe_syscall_exit(
        self,
        pid: int,
        tracee: dict[str, object],
        entry: dict[str, object],
        exit_info: dict[str, object],
    ) -> dict[str, object]:
        name = str(entry.get("name", "unknown"))
        number = int(entry["syscall_number"])
        arguments = tuple(int(item) for item in entry["arguments"])
        result = int(exit_info["result"])
        is_error = bool(exit_info["is_error"])
        error_number = -result if is_error else 0
        if tracee["sealed"] and name in _SECCOMP_DENIAL_NAMES and not is_error:
            self._invalidate(f"post-seal denied syscall {name} succeeded")
            raise RuntimeError(self.invalid_reasons[-1])
        tracee["syscall_counts"][f"{number}:{name}"] = int(
            tracee["syscall_counts"].get(f"{number}:{name}", 0)
        ) + 1
        if name in {"open", "openat", "openat2"} and not is_error:
            self._bind_fd(
                pid,
                tracee,
                result,
                name,
                origin=decode_path_hex(entry.get("path_bytes")),
                close_on_exec=bool(int(entry.get("flags", entry.get("open_how_flags", 0))) & os.O_CLOEXEC),
            )
        elif name in {"pipe", "pipe2"} and not is_error:
            deadline = time.monotonic() + 0.001
            state = self._new_memory_capture_state(
                pid, tracee, kind="struct", address=int(arguments[0]),
                maximum=2 * ctypes.sizeof(ctypes.c_int), syscall_name=name,
                syscall_number=number, arguments=arguments,
                partial_info={"defer": "pipe",
                              "cloexec": bool(name == "pipe2" and arguments[1] & os.O_CLOEXEC)})
            if self._advance_memory_capture_state(pid, tracee, state, deadline):
                raw_fds = bytes(state["buffer"])
                first_fd, second_fd = (int(item) for item in struct.unpack("ii", raw_fds))
                cloexec = bool(state["partial_info"]["cloexec"])
                self._bind_fd(pid, tracee, first_fd, name, origin="pipe-fd-array", close_on_exec=cloexec)
                self._bind_fd(pid, tracee, second_fd, name, origin="pipe-fd-array", close_on_exec=cloexec)
            else:
                tracee["pending_memory_capture"] = state
        elif name == "close" and not is_error:
            try:
                os.readlink(f"/proc/{pid}/fd/{arguments[0]}")
            except FileNotFoundError:
                pass
            else:
                self._invalidate(f"close returned success but fd {arguments[0]} remains open")
                raise RuntimeError(self.invalid_reasons[-1])
            tracee["fds"].pop(arguments[0], None)
            tracee['fd_generation'].pop(arguments[0], None)
            tracee["offsets"].pop(arguments[0], None)
        elif name in {"dup", "dup2", "dup3"} and not is_error:
            source = arguments[0]
            target = result
            source_info = tracee["fds"].get(source)
            if source_info is None:
                self._invalidate(f"dup source {source} has no tracked file description")
                raise RuntimeError(self.invalid_reasons[-1])
            target_info = self._proc_fd_identity(pid, target)
            if (target_info["device"], target_info["inode"]) != (
                source_info["device"], source_info["inode"]
            ):
                self._invalidate("dup result identity differs from source descriptor")
                raise RuntimeError(self.invalid_reasons[-1])
            if source != target:
                self._duplicate_fd(pid, tracee, source, target,
                                   name == "dup3" and bool(arguments[2] & os.O_CLOEXEC))
        elif name == "fcntl" and not is_error and arguments[1] in {0, 1030}:
            source_info = tracee["fds"].get(arguments[0])
            if source_info is None:
                self._invalidate("fcntl duplicate source has no tracked file description")
                raise RuntimeError(self.invalid_reasons[-1])
            target_info = self._proc_fd_identity(pid, result)
            if (target_info["device"], target_info["inode"]) != (
                source_info["device"], source_info["inode"]
            ):
                self._invalidate("fcntl duplicate identity differs from source descriptor")
                raise RuntimeError(self.invalid_reasons[-1])
            self._duplicate_fd(pid, tracee, arguments[0], result, arguments[1] == 1030)
        elif name == "fcntl" and not is_error and arguments[1] == 2:
            tracee["fds"][arguments[0]]["close_on_exec"] = bool(arguments[2] & 1)
        elif name == "close_range" and not is_error:
            first, last, flags = arguments[:3]
            if flags & ~0x6:
                self._invalidate(f"unsupported close_range flags {flags:#x}")
                raise RuntimeError(self.invalid_reasons[-1])
            if flags & 0x4:  # CLOSE_RANGE_CLOEXEC
                affected = []
                for fd, info in tracee["fds"].items():
                    if first <= fd <= last:
                        info["close_on_exec"] = True
                        affected.append(fd)
            else:
                affected = []
                for fd in tuple(tracee["fds"]):
                    if first <= fd <= last:
                        tracee["fds"].pop(fd, None)
                        tracee['fd_generation'].pop(fd, None)
                        tracee["offsets"].pop(fd, None)
                        affected.append(fd)
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"operation": "close_range", "first": first, "last": last,
                                  "flags": flags, "affected_fds": affected}})
        elif name == "lseek" and not is_error:
            self._update_description_offset(tracee, arguments[0], result)
        elif name in {"read", "pread64"} and not is_error:
            fd = arguments[0]
            offset = int(arguments[3]) if name == "pread64" else int(tracee["offsets"].get(fd, 0))
            segments = self._observe_read_bytes(pid, tracee, fd, arguments[1], result, offset)
            if segments:
                tracee["pending_capture"] = {"segments": segments, "index": 0}
                exit_info["capture_pending"] = True
            if name == "read":
                self._update_description_offset(tracee, fd, offset + result)
        elif name in {"readlink", "readlinkat"} and not is_error:
            buffer_address = arguments[1] if name == "readlink" else arguments[2]
            if result > 4096:
                self._invalidate("readlink returned more than the path bound")
                raise RuntimeError(self.invalid_reasons[-1])
            deadline = time.monotonic() + 0.001
            state = self._new_memory_capture_state(
                pid, tracee, kind="struct", address=int(buffer_address), maximum=int(result),
                syscall_name=name, syscall_number=number, arguments=arguments,
                partial_info={"defer": "readlink"})
            if self._advance_memory_capture_state(pid, tracee, state, deadline):
                target = bytes(state["buffer"])
                self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                           "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                           "values": {"operation": name, "return_bytes": result,
                                      "target_hex": target.hex(),
                                      "target_sha256": hashlib.sha256(target).hexdigest()}})
            else:
                tracee["pending_memory_capture"] = state
        elif name in {"getdents", "getdents64"} and not is_error:
            fd = arguments[0]
            descriptor = tracee["fds"].get(fd)
            if descriptor is None:
                self._invalidate(f"directory read from untracked fd {fd}")
                raise RuntimeError(self.invalid_reasons[-1])
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"operation": name, "fd": fd, "directory": descriptor,
                                  "returned_bytes": result}})
        elif name in {"readv", "preadv", "preadv2"} and not is_error:
            fd = arguments[0]
            offset = (int(tracee["offsets"].get(fd, 0)) if name == "readv"
                      else signed_u64(arguments[3] | (arguments[4] << 32)))
            segments = self._observe_readv_bytes(
                pid, tracee, fd, arguments[1], arguments[2], result, offset,
                syscall_name=name, syscall_number=number, arguments=arguments)
            if segments is None:
                return exit_info
            if segments:
                tracee["pending_capture"] = {"segments": segments, "index": 0}
                exit_info["capture_pending"] = True
            if name == "readv":
                self._update_description_offset(tracee, fd, offset + result)
        elif name == "mmap" and not is_error:
            fd = ctypes.c_int(arguments[4]).value
            fd_info = tracee["fds"].get(fd)
            if arguments[3] & 0x20:  # MAP_ANONYMOUS ignores fd, including unsigned -1.
                fd_info = None
            elif fd >= 0 and fd_info is None:
                self._invalidate(f"mmap references untracked fd {fd}")
                raise RuntimeError(self.invalid_reasons[-1])
            mapping_id = f"{pid}:{result:x}"
            if arguments[3] & 0x10:
                self._split_mapping_range(tracee, result, arguments[1], None)
            if len(tracee["mappings"]) >= _MAX_TRACE_ARTIFACTS:
                self._invalidate("live mapping/artifact inventory exceeds 4096 identities")
                raise OverflowError(self.invalid_reasons[-1])
            mapping = {
                "start": result,
                "end": result + arguments[1],
                "length": arguments[1],
                "offset": arguments[5],
                "prot": arguments[2],
                "flags": arguments[3],
                "fd": fd,
                "file": dict(fd_info) if fd_info is not None else None,
            }
            live_map = find_live_mapping(pid, result,
                allow_anonymous_zero=bool(arguments[3] & 0x20 and arguments[3] & 1 and not arguments[2] & 4))
            mapping["live_proc_maps"] = live_map
            mapped_path = live_map.get("path")
            if mapped_path:
                resolved_path = str(Path(mapped_path).resolve(strict=True))
                frozen_hash = self.expected_hashes.get(resolved_path)
                if frozen_hash is None:
                    self._invalidate(f"mapped native file has no frozen expected hash: {mapped_path}")
                    if not self.plain_mode:
                        raise RuntimeError(self.invalid_reasons[-1])
                if fd_info is None:
                    self._invalidate("mmap proc identity differs from tracked descriptor identity")
                    raise RuntimeError(self.invalid_reasons[-1])
                reconciliation = None
                if (live_map["device"], live_map["inode"]) != (fd_info["device"], fd_info["inode"]):
                    if self.plain_mode:
                        self._invalidate(f"mapping device mismatch without declared topology (plain): {mapped_path}")
                    else:
                        from lq04_runner import reconcile_mapping_device
                        mountinfo_text = self.mountinfo_text
                        if mountinfo_text is None:
                            mountinfo_text = Path('/proc/self/mountinfo').read_text(encoding='ascii')
                            self.mountinfo_text = mountinfo_text
                        reconciliation = reconcile_mapping_device(
                            maps_device=live_map["device"], maps_inode=live_map["inode"],
                            stat_device=fd_info["device"], stat_inode=fd_info["inode"],
                            artifact_path=resolved_path, frozen_path=resolved_path,
                            digest_ok=True, declared_topology=self.device_reconciliation,
                            mountinfo_text=mountinfo_text)
                if reconciliation is not None:
                    mapping["device_reconciliation"] = reconciliation
                mapping["expected_file_sha256"] = frozen_hash
            else:
                mapping["expected_file_sha256"] = None
            if arguments[2] & 4 and fd_info is None:
                self._invalidate("unexpected executable anonymous mapping")
                raise RuntimeError(self.invalid_reasons[-1])
            tracee["mappings"][mapping_id] = mapping
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "source-load",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"mapping": mapping}})
            if fd_info is not None and is_source_or_cache_path(str(fd_info["path"])):
                captured = min(int(arguments[1]), max(0, int(fd_info["size"]) - int(arguments[5])))
                if captured:
                    tracee["pending_capture"] = {
                        "segments": [self._new_capture_segment(
                            pid, tracee, fd_info, result, captured, int(arguments[5])
                        )],
                        "index": 0,
                    }
                    exit_info["capture_pending"] = True
        elif name in {"sendfile", "splice", "copy_file_range"} and not is_error:
            source_fd = arguments[1] if name == "sendfile" else arguments[0]
            source_info = tracee["fds"].get(source_fd)
            if source_info is None:
                self._invalidate(f"{name} source fd is outside tracked descriptor closure")
                raise RuntimeError(self.invalid_reasons[-1])
            if is_source_or_cache_path(str(source_info["path"])):
                self._invalidate(f"{name} consumed source/cache bytes without a user buffer")
                raise RuntimeError(self.invalid_reasons[-1])
            if source_info.get("media_input"):
                self._record_media_input_read(pid, tracee, source_info, result, name)
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"operation": name, "source_fd": source_fd,
                                  "source": source_info, "result_bytes": result}})
        elif name == "process_vm_readv" and not is_error and result:
            self._invalidate("process_vm_readv read another process without declared capture coverage")
            raise RuntimeError(self.invalid_reasons[-1])
        elif name == "prctl" and not is_error and arguments[0] == 22 and arguments[1] == 2:
            tracee["sealed"] = True
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "case-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"stage": "seccomp-seal", "syscall": name,
                                  "result": result, "errno": 0,
                                  "fd_inventory": self._fd_snapshot(tracee)}})
        elif name == "seccomp" and not is_error and arguments[0] == 1:
            tracee["sealed"] = True
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "case-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"stage": "seccomp-seal", "syscall": name,
                                  "result": result, "errno": 0,
                                  "fd_inventory": self._fd_snapshot(tracee)}})
        elif name in {"munmap", "mprotect", "mremap"}:
            self._observe_mapping_change(pid, tracee, name, arguments, result, is_error)
        elif name in {"open", "openat", "openat2", "read", "pread64", "readv", "preadv", "preadv2",
                      "lseek", "close", "dup", "dup2", "dup3", "fcntl", "mmap", "munmap",
                      "mprotect", "mremap", "execve", "execveat", "readlink", "readlinkat",
                      "stat", "lstat", "newfstatat", "fstat", "getdents", "getdents64", "close_range"}:
            pass
        exit_info = {
            **exit_info,
            "name": name,
            "syscall_number": number,
            "errno": error_number,
            "arguments": arguments,
            "audit_detail": bool(entry.get("audit_detail")),
        }
        if 'clone_flags' in entry:
            exit_info['clone_flags'] = entry['clone_flags']
        if 'entry_status' in entry:
            exit_info.update(entry_status=entry['entry_status'], entry_basis=entry['entry_basis'])
        if 'path_bytes' in entry:
            exit_info['path_bytes'] = entry['path_bytes']
        if 'flags' in entry:
            exit_info['flags'] = entry['flags']
        if entry.get("audit_detail"):
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "syscall-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"phase": "exit", **exit_info}})
        return exit_info

    @staticmethod
    def _fd_snapshot(tracee: Mapping[str, object]) -> list[dict[str, object]]:
        return [
            {
                "fd": int(fd),
                "path": info["path"],
                "device": int(info["device"]),
                "inode": int(info["inode"]),
                "size": int(info["size"]),
                "flags_octal": info["flags_octal"],
                "close_on_exec": bool(info["close_on_exec"]),
                "generation": int(info["generation"]),
            }
            for fd, info in sorted(tracee["fds"].items())
        ]

    def _duplicate_fd(self, pid, tracee, source, target, cloexec):
        if target not in tracee["fds"] and len(tracee["fds"]) >= _MAX_TRACE_FDS:
            raise OverflowError("duplicate exceeds 256 live FDs")
        generation = self._next_fd_generation(tracee)
        tracee["fd_generation"][target] = generation
        tracee["fds"][target] = {**tracee["fds"][source], "fd": target,
                                 "generation": generation, "close_on_exec": cloexec}
        tracee["offsets"][target] = tracee["offsets"][source]
        self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                   "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                   "values": {"operation": "duplicate", "source_fd": source,
                              **tracee["fds"][target]}})

    @staticmethod
    def _next_fd_generation(tracee):
        generation = max(tracee.get('last_fd_generation', 0), max(tracee['fd_generation'].values(), default=0)) + 1
        tracee['last_fd_generation'] = generation
        return generation

    def _bind_fd(
        self,
        pid: int,
        tracee: dict[str, object],
        fd: int,
        operation: str,
        *,
        origin: str,
        close_on_exec: bool = False,
    ) -> None:
        if len(tracee["fds"]) >= _MAX_TRACE_FDS and fd not in tracee["fds"]:
            self._invalidate(f"PID {pid} exceeded 256 tracked file descriptors")
            raise OverflowError(self.invalid_reasons[-1])
        proc_identity = self._proc_fd_identity(pid, fd)
        target = str(proc_identity["path"])
        info = os.stat(f"/proc/{pid}/fd/{fd}")
        fdinfo = Path(f"/proc/{pid}/fdinfo/{fd}").read_text(encoding="ascii")
        flags = next((line.split(":", 1)[1].strip() for line in fdinfo.splitlines()
                      if line.startswith("flags:")), None)
        try:
            resolved = str(Path(target).resolve(strict=True))
        except OSError:
            resolved = target
        if stat.S_ISREG(info.st_mode) and not resolved.startswith(("/proc/", "/dev/")):
            expected_hash = self.expected_hashes.get(resolved)
            if expected_hash is None:
                self._invalidate(f"regular file is outside the frozen dependency/input closure: {resolved}")
                if not self.plain_mode:
                    raise RuntimeError(self.invalid_reasons[-1])
            else:
                self._verify_frozen_artifact(Path(resolved))
        fixture_path = None
        candidate_path = Path(resolved)
        if (self.fixture_root is not None and candidate_path.suffix.lower() in {".mp3", ".mp4"}
                and candidate_path.is_relative_to(self.fixture_root)):
            fixture_path = PurePosixPath(candidate_path.relative_to(self.fixture_root).as_posix()).as_posix()
        media_input = fixture_path is not None and resolved in self.expected_hashes
        fixture_sha256 = self.expected_hashes.get(resolved) if media_input else None
        description_id = tracee["fds"].get(fd, {}).get("description_id")
        generation = self._next_fd_generation(tracee)
        if description_id is None:
            description_id = f"{pid}:{fd}:{generation}"
        record = {"fd": fd, "path": target, "resolved_path": resolved,
                  "device": info.st_dev, "inode": info.st_ino,
                  "size": info.st_size, "mode": info.st_mode, "flags_octal": flags,
                   "generation": generation,
                  "description_id": description_id, "media_input": media_input,
                  "fixture_path": fixture_path, "fixture_sha256": fixture_sha256,
                  "close_on_exec": close_on_exec,
                  "opened_by": operation, "requested_path_hex": origin}
        tracee["fds"][fd] = record
        tracee["fd_generation"][fd] = record["generation"]
        tracee["offsets"].setdefault(fd, 0)
        self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                   "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                   "values": {"operation": operation, **record}})

    @staticmethod
    def _proc_fd_identity(pid: int, fd: int) -> dict[str, object]:
        path = f"/proc/{pid}/fd/{fd}"
        target = os.readlink(path)
        info = os.stat(path)
        return {"path": target, "device": info.st_dev, "inode": info.st_ino,
                "size": info.st_size, "mode": info.st_mode}

    def _verify_frozen_artifact(self, path):
        path = Path(path).resolve(strict=True)
        key = str(path)
        expected = self.expected_identities.get(key)
        digest = self.expected_hashes.get(key) or self.expected_executables.get(key)
        if expected is None or digest is None:
            raise RuntimeError(f'artifact has no frozen hash/stat identity: {key}')
        info = path.stat()
        actual = {'device': info.st_dev, 'inode': info.st_ino,
                  'size': info.st_size, 'mtime_ns': info.st_mtime_ns}
        if actual != expected:
            raise RuntimeError(f'opened artifact inode/size/mtime differs from frozen identity: {key}')
        if key not in self._verified_expected:
            if len(self._verified_expected) >= _MAX_TRACE_ARTIFACTS:
                raise OverflowError('artifact inventory exceeds 4096 identities')
            self._verified_expected.add(key)
        return digest

    def _observe_read_bytes(
        self, pid: int, tracee: dict[str, object], fd: int, address: int, count: int, offset: int
    ) -> list[dict[str, object]]:
        descriptor = tracee["fds"].get(fd)
        if descriptor is None:
            self._invalidate(f"read from untracked fd {fd}")
            raise RuntimeError(self.invalid_reasons[-1])
        path = str(descriptor["path"])
        if is_source_or_cache_path(path):
            return [self._new_capture_segment(pid, tracee, descriptor, address, count, offset)]
        else:
            if descriptor.get("media_input"):
                self._record_media_input_read(pid, tracee, descriptor, count, "read")
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"operation": "read-span", "fd": fd, "path": path,
                                   "offset": offset, "length": count, "payload_retained": False}})
            return []

    def _record_media_input_read(self, pid, tracee, descriptor, count: int, operation: str) -> None:
        field = "input_bytes_after_seal" if tracee["sealed"] else "input_bytes_before_seal"
        tracee[field] += count
        if not tracee["sealed"]:
            self._invalidate("media input bytes were read before the seccomp seal")
            raise RuntimeError(self.invalid_reasons[-1])
        self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                   "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                   "values": {"operation": operation, "media_input": True,
                              "fd": descriptor["fd"], "path": descriptor["path"],
                              "length": count, "input_bytes_before_seal": tracee["input_bytes_before_seal"],
                              "input_bytes_after_seal": tracee["input_bytes_after_seal"]}})

    def _update_description_offset(self, tracee: dict[str, object], fd: int, offset: int) -> None:
        descriptor = tracee["fds"].get(fd)
        if descriptor is None:
            self._invalidate(f"offset update for untracked fd {fd}")
            raise RuntimeError(self.invalid_reasons[-1])
        description_id = descriptor["description_id"]
        for other in self.tracees.values():
            for alias, alias_info in other["fds"].items():
                if alias_info["description_id"] == description_id:
                    other["offsets"][alias] = offset

    def _new_capture_segment(
        self, pid: int, tracee: dict[str, object], descriptor,
        address: int, length: int, offset: int,
    ) -> dict[str, object]:
        path = str(Path(str(descriptor["path"])).resolve(strict=True))
        expected_hash = self.expected_hashes.get(path)
        if expected_hash is None:
            self._invalidate(f"source/cache path has no frozen expected hash: {path}")
            if not self.plain_mode:
                self.emit({"evidence_kind": self.evidence_kind, "record_type": "source-load",
                           "status": "MISSING", "pid": pid,
                           "start_ticks": tracee["start_ticks"], "reason": self.invalid_reasons[-1],
                           "values": {"path": path, "offset": offset, "expected_length": length,
                                      "captured_length": 0, "coverage": "MISSING"}})
                raise RuntimeError(self.invalid_reasons[-1])
            expected_hash = file_sha256(path)
        return {"path": path, "device": int(descriptor["device"]), "inode": int(descriptor["inode"]),
                "address": address, "length": length, "offset": offset, "cursor": 0,
                "expected_sha256": expected_hash, "digest": hashlib.sha256()}

    def _advance_capture(self, pid: int, tracee: dict[str, object], deadline: float) -> bool:
        state = tracee["pending_capture"]
        if state is None:
            return True
        segments = state["segments"]
        index = int(state["index"])
        if index >= len(segments):
            tracee["pending_capture"] = None
            return True
        segment = segments[index]
        identity = Path(segment['path']).stat()
        if (identity.st_dev, identity.st_ino) != (segment['device'], segment['inode']):
            self._invalidate('consumed source/cache inode differs from frozen descriptor identity')
            self.emit({'evidence_kind': self.evidence_kind, 'record_type': 'source-load',
                       'status': 'MISSING', 'pid': pid, 'start_ticks': tracee['start_ticks'],
                       'reason': self.invalid_reasons[-1], 'values': {
                           'path': segment['path'], 'captured_length': segment['cursor'],
                           'expected_inode': segment['inode'], 'observed_inode': identity.st_ino}})
            raise RuntimeError(self.invalid_reasons[-1])
        cursor = int(segment["cursor"])
        size = min(16 * 1024, int(segment["length"]) - cursor)
        if size <= 0:
            state["index"] = index + 1
            return self._advance_capture(pid, tracee, deadline)
        actual = self.api.peek_bytes_slice(pid, int(segment["address"]) + cursor, size, deadline)
        if not actual:
            return False
        with Path(str(segment["path"])).open("rb") as expected_file:
            expected_file.seek(int(segment["offset"]) + cursor)
            expected = expected_file.read(len(actual))
        if len(expected) != len(actual) or actual != expected:
            self._invalidate(f"consumed source/cache bytes differ from frozen path {segment['path']}")
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "source-load",
                       "status": "MISSING", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "reason": self.invalid_reasons[-1],
                       "values": {"path": segment["path"], "offset": int(segment["offset"]) + cursor,
                                  "expected_length": len(actual), "actual_span_sha256": hashlib.sha256(actual).hexdigest(),
                                  "expected_file_sha256": segment["expected_sha256"],
                                  "captured_prefix_length": cursor}})
            raise RuntimeError(self.invalid_reasons[-1])
        segment["digest"].update(actual)
        segment["cursor"] = cursor + len(actual)
        if segment["cursor"] >= segment["length"]:
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "source-load",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"path": segment["path"], "device": segment["device"],
                                  "inode": segment["inode"], "offset": segment["offset"],
                                  "length": segment["length"],
                                  "consumed_span_sha256": segment["digest"].hexdigest(),
                                  "expected_file_sha256": segment["expected_sha256"],
                                  "coverage": "complete-span"}})
            state["index"] = index + 1
        if state["index"] >= len(segments):
            tracee["pending_capture"] = None
            return True
        return False

    def _new_memory_capture_state(
        self, pid: int, tracee: dict[str, object], *, kind: str, address: int,
        maximum: int, syscall_name: str, syscall_number: int,
        arguments: tuple[int, ...], partial_info: dict[str, object],
    ) -> dict[str, object]:
        """Bounded per-tracee continuation state for one memory capture."""
        return {
            "pid": pid,
            "start_ticks": tracee["start_ticks"],
            "kind": kind,
            "address": int(address),
            "offset": 0,
            "buffer": bytearray(),
            "remaining": int(maximum),
            "maximum": int(maximum),
            "whole_child_deadline": tracee.get("deadline"),
            "syscall_number": int(syscall_number),
            "syscall_name": str(syscall_name),
            "arguments": tuple(int(item) for item in arguments),
            "partial_info": partial_info,
        }

    def _advance_memory_capture_state(
        self, pid: int, tracee: dict[str, object], state: dict[str, object], deadline: float
    ) -> bool:
        """Advance one capture state within the slice budget; True when complete.

        Strings scan word-aligned chunks to the NUL; structured reads fetch the
        exact remaining span. Slice exhaustion alone never raises (it returns
        False with bounded state retained); every other failure keeps today's
        fail-closed identity.
        """
        maximum = int(state["maximum"])
        buffer = state["buffer"]
        if state["kind"] == "string":
            word = ctypes.sizeof(ctypes.c_long)
            base = int(state["address"])
            while int(state["offset"]) < maximum:
                offset = int(state["offset"])
                chunk_size = min(word - (base + offset) % word, maximum - offset)
                chunk = self.api.peek_bytes_slice(pid, base + offset, chunk_size, deadline)
                if len(chunk) < chunk_size:
                    terminator = chunk.find(b"\0")
                    if terminator >= 0:
                        buffer.extend(chunk[:terminator])
                        state["offset"] = offset + terminator
                        return True
                    buffer.extend(chunk)
                    state["offset"] = offset + len(chunk)
                    return False
                terminator = chunk.find(b"\0")
                buffer.extend(chunk if terminator < 0 else chunk[:terminator])
                state["offset"] = offset + (terminator if terminator >= 0 else chunk_size)
                if terminator >= 0:
                    return True
            raise ValueError("syscall path string is not NUL-terminated within 4 KiB")
        if state["kind"] == "struct":
            base = int(state["address"])
            while int(state["offset"]) < maximum:
                offset = int(state["offset"])
                chunk = self.api.peek_bytes_slice(pid, base + offset, maximum - offset, deadline)
                buffer.extend(chunk)
                state["offset"] = offset + len(chunk)
                if int(state["offset"]) < maximum:
                    return False
            return True
        raise RuntimeError(f"unsupported pending memory capture kind {state['kind']!r}")

    def _advance_memory_capture(self, pid: int, tracee: dict[str, object], deadline: float) -> bool:
        """Phase B: advance the tracee's pending memory capture within the pump slice."""
        state = tracee.get("pending_memory_capture")
        if state is None:
            return True
        if state["pid"] != pid or state["start_ticks"] != tracee["start_ticks"]:
            self._invalidate("pending memory capture identity does not match the stopped tracee")
            raise RuntimeError(self.invalid_reasons[-1])
        if state["kind"] not in {"string", "struct"}:
            self._invalidate("pending memory capture has an unsupported kind")
            raise RuntimeError(self.invalid_reasons[-1])
        buffer = state["buffer"]
        if (not isinstance(buffer, bytearray) or len(buffer) != int(state["offset"])
                or int(state["offset"]) > int(state["maximum"])):
            self._invalidate("pending memory capture buffer state is malformed")
            raise RuntimeError(self.invalid_reasons[-1])
        whole_child_deadline = state.get("whole_child_deadline")
        if whole_child_deadline is not None and time.monotonic() >= whole_child_deadline:
            raise TimeoutError("ptrace memory capture exceeded the tracee's whole-child deadline")
        return self._advance_memory_capture_state(pid, tracee, state, deadline)

    def _capture_entry_bytes(
        self, pid: int, tracee: dict[str, object], deadline: float, *, kind: str,
        address: int, maximum: int, name: str, number: int, arguments: tuple[int, ...],
        info: dict[str, object],
    ) -> tuple[bytes | None, bool]:
        """One fair-slice capture attempt for a syscall-entry argument.

        Returns (data, False) when the capture completed within the slice, or
        (None, True) after stashing the continuation state — the entry event
        emission is deferred and the tracee stays stopped at its syscall stop.
        """
        state = self._new_memory_capture_state(
            pid, tracee, kind=kind, address=address, maximum=maximum,
            syscall_name=name, syscall_number=number, arguments=arguments, partial_info=info)
        if self._advance_memory_capture_state(pid, tracee, state, deadline):
            return bytes(state["buffer"]), False
        tracee["pending_memory_capture"] = state
        return None, True

    def _complete_memory_capture(self, pid: int, tracee: dict[str, object], deadline: float) -> bool:
        """Finish a completed capture: emit the deferred event ONCE, clear the state.

        Returns True when the tracee may be resumed (optionally with a read-bytes
        continuation now pending); False when a multi-part capture re-stashed and
        the tracee must stay stopped without any emission.
        """
        state = tracee["pending_memory_capture"]
        partial_info = state["partial_info"]
        if isinstance(partial_info, Mapping) and partial_info.get("defer") == "iovec":
            return self._complete_iovec_capture(pid, tracee, state, deadline)
        if isinstance(partial_info, Mapping) and partial_info.get("defer") is not None:
            return self._complete_exit_capture(pid, tracee, state)
        return self._complete_entry_capture(pid, tracee, state, deadline)

    def _complete_entry_capture(
        self, pid: int, tracee: dict[str, object], state: dict[str, object], deadline: float
    ) -> bool:
        info = state["partial_info"]
        data = bytes(state["buffer"])
        name = str(state["syscall_name"])
        arguments = tuple(state["arguments"])
        if name == "openat2" and state["kind"] == "string":
            info["path_bytes"] = data.hex()
            how_size = int(arguments[3])
            if not 24 <= how_size <= 256:
                self._invalidate("openat2 open_how size is outside the frozen parser bound")
                raise RuntimeError(self.invalid_reasons[-1])
            how_state = self._new_memory_capture_state(
                pid, tracee, kind="struct", address=int(arguments[2]), maximum=how_size,
                syscall_name=name, syscall_number=int(state["syscall_number"]),
                arguments=arguments, partial_info=info)
            if not self._advance_memory_capture_state(pid, tracee, how_state, deadline):
                tracee["pending_memory_capture"] = how_state
                return False
            return self._complete_entry_capture(pid, tracee, how_state, deadline)
        if name == "openat2" and state["kind"] == "struct":
            info["open_how_size"] = int(state["maximum"])
            info["open_how_bytes_hex"] = data.hex()
            info["flags"] = int.from_bytes(data[0:8], sys.byteorder)
            info["mode"] = int.from_bytes(data[8:16], sys.byteorder)
            info["resolve"] = int.from_bytes(data[16:24], sys.byteorder)
        elif name == "memfd_create":
            info["name_bytes"] = data.hex()
        elif name in {"open", "openat", "newfstatat", "readlinkat", "statx",
                      "faccessat", "faccessat2", "name_to_handle_at"}:
            info["path_bytes"] = data.hex()
            if name == "open":
                info["flags"] = int(arguments[1])
            elif name == "openat":
                info["flags"] = int(arguments[2])
        elif name in {"stat", "lstat", "readlink", "execve", "execveat"}:
            info["path_bytes"] = data.hex()
        elif name == "clone3":
            info["clone_args_hex"] = data.hex()
            info["clone_flags"] = int.from_bytes(data[:8], sys.byteorder)
        else:
            self._invalidate(f"pending memory capture names unhandled syscall {name}")
            raise RuntimeError(self.invalid_reasons[-1])
        tracee["pending_memory_capture"] = None
        if name in _DETAIL_SYSCALL_NAMES:
            self.emit({
                "evidence_kind": self.evidence_kind,
                "record_type": "syscall-event",
                "status": "OBSERVED",
                "pid": pid,
                "start_ticks": tracee["start_ticks"],
                "capture_deferred_completion": True,
                "values": {"phase": "entry", **info},
            })
        return True

    def _complete_exit_capture(self, pid: int, tracee: dict[str, object], state: dict[str, object]) -> bool:
        data = bytes(state["buffer"])
        name = str(state["syscall_name"])
        defer = str(state["partial_info"]["defer"])
        if defer == "pipe":
            first_fd, second_fd = (int(item) for item in struct.unpack("ii", data))
            cloexec = bool(state["partial_info"]["cloexec"])
            self._bind_fd(pid, tracee, first_fd, name, origin="pipe-fd-array", close_on_exec=cloexec)
            self._bind_fd(pid, tracee, second_fd, name, origin="pipe-fd-array", close_on_exec=cloexec)
        elif defer == "readlink":
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"operation": name, "return_bytes": int(state["maximum"]),
                                  "target_hex": data.hex(),
                                  "target_sha256": hashlib.sha256(data).hexdigest()}})
        else:
            self._invalidate(f"pending memory capture defers unknown exit capture {defer}")
            raise RuntimeError(self.invalid_reasons[-1])
        tracee["pending_memory_capture"] = None
        return True

    @staticmethod
    def _parse_iovec_entry(loop: dict[str, object], entry: bytes) -> None:
        word = ctypes.sizeof(ctypes.c_void_p)
        base = int.from_bytes(entry[:word], sys.byteorder)
        length = int.from_bytes(entry[word:], sys.byteorder)
        size = min(length, int(loop["remaining"]))
        if size:
            loop["vectors"].append((base, size))
            loop["remaining"] = int(loop["remaining"]) - size
        loop["index"] = int(loop["index"]) + 1

    def _capture_iovec_headers(self, pid: int, tracee: dict[str, object],
                               loop: dict[str, object], deadline: float, *,
                               syscall_name: str, syscall_number: int,
                               arguments: tuple[int, ...]) -> bool:
        """Capture the bounded 16-byte iovec header entries within the slice budget.

        Returns True when the header loop finished; False when the next entry was
        stashed and the exit event stays deferred (the tracee remains stopped)."""
        word = ctypes.sizeof(ctypes.c_void_p)
        while int(loop["index"]) < int(loop["iov_count"]) and int(loop["remaining"]) > 0:
            state = self._new_memory_capture_state(
                pid, tracee, kind="struct",
                address=int(loop["iov_pointer"]) + int(loop["index"]) * 2 * word,
                maximum=2 * word, syscall_name=syscall_name, syscall_number=syscall_number,
                arguments=arguments, partial_info={"defer": "iovec", "iovec": loop})
            if not self._advance_memory_capture_state(pid, tracee, state, deadline):
                tracee["pending_memory_capture"] = state
                return False
            self._parse_iovec_entry(loop, bytes(state["buffer"]))
        return True

    def _complete_iovec_capture(self, pid: int, tracee: dict[str, object],
                                state: dict[str, object], deadline: float) -> bool:
        loop = state["partial_info"]["iovec"]
        self._parse_iovec_entry(loop, bytes(state["buffer"]))
        if not self._capture_iovec_headers(
                pid, tracee, loop, deadline, syscall_name=str(state["syscall_name"]),
                syscall_number=int(state["syscall_number"]),
                arguments=tuple(state["arguments"])):
            return False
        if int(loop["remaining"]):
            self._invalidate("readv return length exceeds captured iovecs")
            raise RuntimeError(self.invalid_reasons[-1])
        segments = []
        cursor = int(loop["offset"])
        for address, size in loop["vectors"]:
            segments.extend(self._observe_read_bytes(pid, tracee, int(loop["fd"]), address, size, cursor))
            cursor += size
        if segments:
            tracee["pending_capture"] = {"segments": segments, "index": 0}
        if loop["name"] == "readv":
            self._update_description_offset(tracee, int(loop["fd"]), int(loop["offset"]) + int(loop["result"]))
        tracee["pending_memory_capture"] = None
        return True

    def _discard_memory_capture(self, pid: int, tracee: dict[str, object], reason: str) -> None:
        """Terminal/containment cleanup: retain the partial capture honestly; never emit deferred."""
        state = tracee.get("pending_memory_capture")
        if state is None:
            return
        buffer = state.get("buffer")
        captured = len(buffer) if isinstance(buffer, bytearray) else 0
        partial_info = state.get("partial_info")
        defer = partial_info.get("defer") if isinstance(partial_info, Mapping) else None
        if defer is not None:
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "fd-event",
                       "status": "MISSING", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "reason": reason,
                       "values": {"operation": str(state["syscall_name"]),
                                  "captured_length": captured}})
        else:
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "syscall-event",
                       "status": "MISSING", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "reason": reason,
                       "values": {"phase": "entry", "syscall_number": int(state["syscall_number"]),
                                  "arguments": tuple(state["arguments"]),
                                  "captured_length": captured}})
        tracee["pending_memory_capture"] = None

    def _observe_readv_bytes(self, pid, tracee, fd, iov_pointer, iov_count, result, offset, *,
                             syscall_name="readv", syscall_number=19, arguments=(0, 0, 0, 0, 0, 0)):
        if result == 0:
            return []
        if not 0 <= iov_count <= 64:
            self._invalidate("readv iovec count exceeds the finite 64-vector capture bound")
            raise RuntimeError(self.invalid_reasons[-1])
        deadline = time.monotonic() + 0.001
        loop: dict[str, object] = {
            "iov_pointer": int(iov_pointer), "iov_count": int(iov_count), "index": 0,
            "vectors": [], "remaining": int(result), "fd": int(fd), "offset": int(offset),
            "result": int(result), "name": str(syscall_name)}
        if not self._capture_iovec_headers(pid, tracee, loop, deadline,
                                           syscall_name=str(syscall_name),
                                           syscall_number=int(syscall_number),
                                           arguments=tuple(int(item) for item in arguments)):
            return None
        if int(loop["remaining"]):
            self._invalidate("readv return length exceeds captured iovecs")
            raise RuntimeError(self.invalid_reasons[-1])
        cursor = offset
        segments = []
        for address, size in loop["vectors"]:
            segments.extend(self._observe_read_bytes(pid, tracee, fd, address, size, cursor))
            cursor += size
        return segments

    def _observe_mapping_change(self, pid, tracee, name, arguments, result, is_error) -> None:
        if is_error:
            return
        if name == "munmap":
            start, length = arguments[:2]
            self._split_mapping_range(tracee, start, length, None)
            if proc_maps_overlap(pid, start, start + length):
                self._invalidate("successful munmap still appears in proc maps")
                raise RuntimeError(self.invalid_reasons[-1])
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "source-load",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"mapping_operation": "munmap", "start": start, "length": length,
                                  "remaining_mappings": len(tracee["mappings"])}})
        elif name == "mprotect":
            start, length, prot = arguments[:3]
            self._split_mapping_range(tracee, start, length, lambda mapping: mapping.update(prot=prot))
            if prot & 4:
                for mapping in tracee["mappings"].values():
                    if mapping["start"] < start + length and start < mapping["end"] and not mapping.get("file"):
                        self._invalidate("mprotect created executable anonymous memory")
                        raise RuntimeError(self.invalid_reasons[-1])
            live_map = find_live_mapping(pid, start)
            if live_map["permissions"][0:3] != prot_permissions(prot):
                self._invalidate("mprotect proc-map permissions differ from successful syscall")
                raise RuntimeError(self.invalid_reasons[-1])
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "source-load",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"mapping_operation": "mprotect", "start": start,
                                  "length": length, "prot": prot,
                                  "live_proc_maps": find_live_mapping(pid, start)}})
        elif name == "mremap":
            old_start, old_size, new_size, flags = arguments[:4]
            new_start = arguments[4] if flags & 2 else result
            overlap = [
                (key, mapping) for key, mapping in tracee["mappings"].items()
                if mapping["start"] <= old_start and mapping["end"] >= old_start + old_size
            ]
            if len(overlap) != 1:
                self._invalidate("mremap cannot be bound to exactly one tracked mapping")
                raise RuntimeError(self.invalid_reasons[-1])
            key, mapping = overlap[0]
            del tracee["mappings"][key]
            original_start, original_end = int(mapping["start"]), int(mapping["end"])
            old_end = old_start + old_size
            if original_start < old_start:
                self._add_mapping_segment(tracee, mapping, original_start, old_start,
                                          original_start, "mremap-left")
            moved = dict(mapping)
            moved.update(start=new_start, end=new_start + new_size,
                         length=new_size, offset=int(mapping["offset"]) + old_start - original_start)
            tracee["mappings"][f"{pid}:{new_start:x}"] = moved
            if old_end < original_end:
                self._add_mapping_segment(tracee, mapping, old_end, original_end,
                                          original_start, "mremap-right")
            self.emit({"evidence_kind": self.evidence_kind, "record_type": "source-load",
                       "status": "OBSERVED", "pid": pid, "start_ticks": tracee["start_ticks"],
                       "values": {"mapping_operation": "mremap", "old_start": old_start,
                                  "old_size": old_size, "new_start": new_start, "new_size": new_size,
                                  "file": moved.get("file"),
                                  "live_proc_maps": find_live_mapping(pid, new_start)}})

    def _split_mapping_range(self, tracee, start, length, update) -> None:
        end = start + length
        for key, mapping in tuple(tracee["mappings"].items()):
            map_start, map_end = int(mapping["start"]), int(mapping["end"])
            overlap_start, overlap_end = max(start, map_start), min(end, map_end)
            if overlap_start >= overlap_end:
                continue
            del tracee["mappings"][key]
            if map_start < overlap_start:
                self._add_mapping_segment(tracee, mapping, map_start, overlap_start, map_start, "left")
            middle = dict(mapping)
            middle.update(start=overlap_start, end=overlap_end, length=overlap_end - overlap_start,
                          offset=int(mapping["offset"]) + overlap_start - map_start)
            if update is not None:
                if len(tracee['mappings']) >= _MAX_TRACE_ARTIFACTS:
                    raise OverflowError('mapping split exceeds 4096 artifact identities')
                update(middle)
                tracee["mappings"][f"{tracee['pid']}:{overlap_start:x}"] = middle
            if overlap_end < map_end:
                self._add_mapping_segment(tracee, mapping, overlap_end, map_end, map_start, "right")

    def _add_mapping_segment(self, tracee, template, start, end, origin_start, label) -> None:
        if len(tracee["mappings"]) >= _MAX_TRACE_ARTIFACTS:
            self._invalidate("live mapping/artifact inventory exceeds 4096 identities")
            raise OverflowError(self.invalid_reasons[-1])
        segment = dict(template)
        segment.update(start=start, end=end, length=end - start,
                       offset=int(template["offset"]) + start - origin_start)
        tracee["mappings"][f"{tracee['pid']}:{start:x}:{label}"] = segment

    def attach_root(self, pid: int, pgid: int, deadline: float) -> None:
        if pid not in self.tracees:
            self.register(pid, proc_start_ticks(pid), pgid, root=True)
        if os.getpgid(pid) != pgid:
            self.invalidate_and_reap("process group identity changed before initial exec stop")
            raise RuntimeError("process group identity mismatch")
        while time.monotonic() < deadline:
            self.pump()
            tracee = self.tracees[pid]
            if not tracee["exec_pending"]:
                return
            if tracee["terminal_seen"]:
                raise RuntimeError("tracee terminated before expected initial exec stop")
            time.sleep(min(0.0001, max(0.0, deadline - time.monotonic())))
        self.invalidate_and_reap("initial exec stop exceeded the caller's original deadline")
        raise TimeoutError("initial exec stop exceeded the caller's original deadline")

    def pump(self, *, max_events: int = 64, max_seconds: float = 0.001) -> int:
        """One fair event-pump slice; the F5 batch buffer flushes at every slice end."""
        try:
            return self._pump_slice(max_events=max_events, max_seconds=max_seconds)
        finally:
            hook = self.slice_end_hook
            if hook is not None:
                hook()

    def _pump_slice(self, *, max_events: int = 64, max_seconds: float = 0.001) -> int:
        started = time.monotonic()
        processed = 0
        while processed < max_events and time.monotonic() - started < max_seconds:
            made_progress = False
            for pid, tracee in tuple(self.tracees.items()):
                if tracee["terminal_seen"]:
                    continue
                if tracee["pending_memory_capture"] is not None:
                    if not self._advance_memory_capture(pid, tracee, started + max_seconds):
                        self._sample_process(pid, tracee)
                        return max(1, processed)
                    if not self._complete_memory_capture(pid, tracee, started + max_seconds):
                        self._sample_process(pid, tracee)
                        return max(1, processed)
                    made_progress = True
                    processed += 1
                    if tracee["pending_capture"] is None:
                        self.api.call(_PTRACE_SYSCALL, pid, 0, 0)
                    elif self._advance_capture(pid, tracee, started + max_seconds):
                        self.api.call(_PTRACE_SYSCALL, pid, 0, 0)
                    else:
                        self._sample_process(pid, tracee)
                        return max(1, processed)
                    if processed >= max_events or time.monotonic() - started >= max_seconds:
                        return processed
                if tracee["pending_capture"] is not None:
                    complete = self._advance_capture(pid, tracee, started + max_seconds)
                    if complete:
                        self.api.call(_PTRACE_SYSCALL, pid, 0, 0)
                    else:
                        self._sample_process(pid, tracee)
                        return max(1, processed)
                    made_progress = True
                    processed += 1
                    if processed >= max_events or time.monotonic() - started >= max_seconds:
                        return processed
                try:
                    waited_pid, status, usage = self._wait4_func(pid, os.WNOHANG | _WAIT_WALL)
                except InterruptedError:
                    continue
                except ChildProcessError as error:
                    self._invalidate(f"wait4 returned ECHILD for tracked pid {pid}")
                    raise RuntimeError(self.invalid_reasons[-1]) from error
                if waited_pid == 0:
                    continue
                made_progress = True
                processed += 1
                rusage = {
                    "user_seconds": float(usage.ru_utime),
                    "system_seconds": float(usage.ru_stime),
                    "max_rss_kib": int(usage.ru_maxrss),
                }
                action, event = self.classify(pid, status, rusage=rusage)
                if action != "terminal":
                    self._sample_process(pid, tracee)
                if action == "set-options-and-resume":
                    identity = (
                        self._record_exec_identity(pid, tracee)
                        if self.evidence_kind == "native-observed"
                        else {"unit_event": "synthetic-exec-stop"}
                    )
                    self.emit({"evidence_kind": self.evidence_kind, "record_type": "run-event",
                               "status": "OBSERVED", "pid": pid,
                               "start_ticks": tracee["start_ticks"],
                               "values": {"stage": "initial-exec-stop", **identity}})
                    options = (
                        _PTRACE_O_TRACESYSGOOD | _PTRACE_O_TRACEEXEC | _PTRACE_O_TRACEEXIT
                        | _PTRACE_O_TRACEFORK | _PTRACE_O_TRACEVFORK | _PTRACE_O_TRACECLONE
                        | _PTRACE_O_EXITKILL
                    )
                    self.api.call(_PTRACE_SETOPTIONS, pid, 0, options)
                    self.api.call(_PTRACE_SYSCALL, pid, 0, 0)
                elif action == "resume-syscall":
                    self.api.call(_PTRACE_SYSCALL, pid, 0, 0)
                elif action == "forward-signal-and-resume":
                    self.api.call(_PTRACE_SYSCALL, pid, 0, int(event["forward_signal"]))
                elif action == "suppress-owned-child-stop":
                    self.api.call(_PTRACE_SYSCALL, pid, 0, 0)
                elif action == "capture-pending":
                    if self._advance_capture(pid, tracee, started + max_seconds):
                        self.api.call(_PTRACE_SYSCALL, pid, 0, 0)
                    else:
                        self._sample_process(pid, tracee)
                        return max(1, processed)
                elif action == "memory-capture-pending":
                    pass
                elif action != "terminal":
                    self.invalidate_and_reap(f"unknown supervisor action {action}")
                    raise RuntimeError(self.invalid_reasons[-1])
                if processed >= max_events or time.monotonic() - started >= max_seconds:
                    break
            if not made_progress:
                break
        return processed

    def waitpid_adapter(self, pid: int, flags: int) -> tuple[int, int]:
        tracee = self.tracees.get(pid)
        if tracee is None:
            self._invalidate(f"Popen wait requested unregistered pid {pid}")
            raise RuntimeError(self.invalid_reasons[-1])
        if flags & os.WNOHANG:
            self.pump()
            terminal = self.terminal_for_popen(pid)
            return (pid, terminal[0]) if terminal is not None else (0, 0)
        while True:
            self.pump()
            terminal = self.terminal_for_popen(pid)
            if terminal is not None:
                return pid, terminal[0]
            if tracee["terminal_seen"]:
                self._invalidate(f"Popen attempted to reap PID {pid} more than once")
                raise RuntimeError(self.invalid_reasons[-1])
            deadline = tracee.get("deadline")
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(f"observed PID {pid}", 0)
            time.sleep(0.0001)

    def invalidate_and_reap(self, reason: str) -> None:
        self._invalidate(reason)
        original_emit = self.emit
        def cleanup_emit(record):
            try:
                original_emit(record)
            except (OSError, ValueError, OverflowError, RuntimeError) as error:
                self._invalidate(f"cleanup evidence could not be retained: {type(error).__name__}")
        self.emit = cleanup_emit
        try:
            self._contain_and_reap(reason)
        finally:
            self.emit = original_emit

    def _contain_and_reap(self, reason: str) -> None:
        for tracee in tuple(self.tracees.values()):
            pid = int(tracee["pid"])
            pgid = int(tracee["pgid"])
            if tracee["terminal_seen"]:
                continue
            identity_getter = getattr(self.api, 'start_ticks', None)
            if identity_getter is not None:
                try:
                    same_identity = identity_getter(pid) == tracee['start_ticks']
                except OSError:
                    same_identity = False
                if not same_identity:
                    self._invalidate(f'containment identity unavailable or changed for PID {pid}; no signal sent')
                    continue
            self._discard_memory_capture(pid, tracee, reason)
            pending = tracee.get("pending_capture")
            if pending is not None:
                segments = pending["segments"]
                index = int(pending["index"])
                if index < len(segments):
                    segment = segments[index]
                    self.emit({
                        "evidence_kind": self.evidence_kind,
                        "record_type": "source-load",
                        "status": "MISSING",
                        "pid": pid,
                        "start_ticks": tracee["start_ticks"],
                        "reason": reason,
                        "values": {"path": segment["path"], "offset": segment["offset"],
                                   "expected_length": segment["length"],
                                   "captured_length": segment["cursor"],
                                   "captured_prefix_sha256": segment["digest"].hexdigest()},
                    })
                tracee["pending_capture"] = None
            try:
                if self.evidence_kind == 'native-observed' and os.getpgid(pid) != pgid:
                    self._invalidate(f'process group identity changed for PID {pid}')
                    os.kill(pid, signal.SIGKILL)
                else:
                    os.killpg(pgid, signal.SIGKILL)
            except OSError:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            if all(state["terminal_seen"] for state in self.tracees.values()):
                break
            try:
                if self.pump() == 0:
                    time.sleep(0.0001)
            except (ChildProcessError, OSError, RuntimeError):
                break
        for state in self.tracees.values():
            if not state["terminal_seen"]:
                self._invalidate(f"cleanup lacks matching-PID terminal reap proof: {state['pid']}")

    def _sample_live_process(self, pid: int, tracee: Mapping[str, object]) -> None:
        try:
            observed_start_ticks = proc_start_ticks(pid)
            if observed_start_ticks != tracee["start_ticks"]:
                raise ProcessLookupError("PID start-tick identity changed")
            values = read_process_status(pid)
            values.update(read_process_limits(pid))
        except (OSError, ValueError, ProcessLookupError) as error:
            missing_live_metrics = (
                isinstance(error, ValueError)
                and str(error) == "required live proc metrics missing")
            if missing_live_metrics and (tracee.get("terminal_seen")
                                          or _process_is_zombie_or_gone(pid, tracee)):
                return
            self._invalidate(f"live metrics missing for pid {pid}: {type(error).__name__}")
            raise RuntimeError(self.invalid_reasons[-1]) from error
        policy = self._resource_sample_policy
        if policy is not None:
            emit_now, include_limits = policy.admit(time.monotonic(), values, pid,
                                                    tracee["start_ticks"])
            if not include_limits:
                values = {name: value for name, value in values.items()
                          if name not in _RESOURCE_SAMPLE_LIMIT_FIELDS}
            if not emit_now:
                return
        self.emit({
            "evidence_kind": self.evidence_kind,
            "record_type": "resource-sample",
            "status": "OBSERVED",
            "pid": pid,
            "start_ticks": tracee["start_ticks"],
            "values": values,
        })

    def flush_last_resource_sample(self) -> bool:
        """Emit the bounded pending 'last' decimated sample (F1 case-end flush)."""
        policy = self._resource_sample_policy
        if policy is None:
            return False
        pending = policy.take_pending()
        if pending is None:
            return False
        self.emit({
            "evidence_kind": self.evidence_kind,
            "record_type": "resource-sample",
            "status": "OBSERVED",
            "pid": pending["pid"],
            "start_ticks": pending["start_ticks"],
            "values": pending["values"],
        })
        return True

    def _sample_process(self, pid: int, tracee: Mapping[str, object]) -> None:
        now = time.monotonic()
        # Opportunity-based probes, not every syscall: no measured sample is
        # discarded, and real native guard/termination boundaries remain separate.
        if self._sample_live_override is None and now < tracee.get('next_sample_at', 0):
            return
        if self._sample_live_override is None:
            tracee['next_sample_at'] = now + 0.01
        if self._sample_live_override is None:
            self._sample_live_process(pid, tracee)
        else:
            self._sample_live_override(pid, tracee)

    def _invalidate(self, reason: str) -> None:
        self.invalid_reasons.append(reason)


class _PumpingSelector:
    def __init__(self, underlying, supervisor: OwnChildSupervisor):
        self._underlying = underlying
        self._supervisor = supervisor

    def __getattr__(self, name):
        return getattr(self._underlying, name)

    def select(self, timeout=None):
        end = None if timeout is None else time.monotonic() + max(0.0, timeout)
        while True:
            ready = self._underlying.select(0)
            if ready:
                return ready
            remaining = None if end is None else end - time.monotonic()
            if remaining is not None and remaining <= 0:
                return []
            self._supervisor.pump(max_seconds=min(.001, remaining, max(0.0, timeout))
                                  if remaining is not None else .001)
            ready = self._underlying.select(0)
            if ready:
                return ready
            if end is not None:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    return []
                time.sleep(min(0.0001, remaining))
            else:
                time.sleep(0.0001)


class EvidenceCapture:
    """Synchronous, context-scoped observer for the selected formal test hooks."""

    def __init__(
        self,
        *,
        node_id: str,
        output_dir: Path,
        run_id: str,
        manifest_sha256: str,
        validator_module,
        expected_file_hashes: Mapping[str, str],
        expected_executable_hashes: Mapping[str, str],
        expected_file_identities: Mapping[str, Mapping[str, int]],
        fixture_sha256: str | None = None,
        device_reconciliation: Mapping[str, object] | None = None,
        compact_frame_batching: bool = False,
        plain_mode: bool = False,
    ) -> None:
        self.node_id = node_id
        self.plain_mode = bool(plain_mode)
        self.frozen_manifest = None
        self.bundle_budget = _PlainEvidenceBudget() if self.plain_mode else None
        self.output_dir = Path(output_dir)
        self.run_id = run_id
        self.manifest_sha256 = manifest_sha256
        self.validator_module = validator_module
        self.original_limits = validator_module._apply_validator_limits
        self.original_popen = subprocess.Popen
        self.original_fork_exec = subprocess._fork_exec
        self.original_waitpid = os.waitpid
        self.original_wait4 = os.wait4
        self.original_wait = os.wait
        self.original_waitid = getattr(os, "waitid", None)
        self.original_read = os.read
        self.original_killpg = os.killpg
        self.original_kill = os.kill
        self.original_selector = selectors.DefaultSelector
        self.writer: NativeEvidenceWriter | None = None
        self.spawn_pending = False
        self.spawn_record: dict[str, object] | None = None
        self.pipe_roles: dict[int, tuple[int, str]] = {}
        self.pipe_states: dict[tuple[int, str], dict[str, object]] = {}
        self.spawn_fd_baseline: set[int] = set()
        self.processes: dict[int, object] = {}
        self.instance_methods: dict[int, tuple[object, object]] = {}
        self.case_start_ns = time.monotonic_ns()
        self.source_sha256 = file_sha256(Path(validator_module.__file__).resolve())
        policy_path = Path(validator_module.__file__).resolve().with_name("sandbox.py")
        self.policy_sha256 = file_sha256(policy_path)
        self.collector_origin = str(Path(__file__).resolve())
        self.collector_sha256 = file_sha256(Path(__file__).resolve())
        self.collector_id = "OBS-STARTUP-RO-01"
        self.fixture_sha256 = fixture_sha256
        self.active = False
        self.current_subcase: str | None = None
        self.current_evidence_kind = "native-observed"
        self.current_fixture_sha256: str | None = fixture_sha256
        self._seen_syscall_kinds: set[tuple[str, str]] = set()
        self._syscall_counts: dict[str, dict[str, int]] = {}
        self._resource_sample_policy = None if self.plain_mode else ResourceSamplePolicy()
        self._artifact_registry: dict[tuple[str, int, int], str] = {}
        self._artifact_index: dict[str, dict[str, object]] = {}
        self.compact_frame_batching = bool(compact_frame_batching)
        self._compact_batch: list[dict[str, object]] = []
        self.expected_file_hashes = dict(expected_file_hashes)
        self.expected_executable_hashes = dict(expected_executable_hashes)
        self.fixture_root = Path(os.environ["AUDIOSCRIBE_LQ04_FIXTURE_ROOT"]).resolve(strict=True)
        self._capture_token = None
        self._next_deadline: float | None = None
        self.original_run_child = validator_module._run_child
        self.original_drain_child = validator_module._drain_child
        self.original_kill_child = validator_module._kill_child
        self.original_rss = validator_module._child_rss_bytes
        self.original_threads = validator_module._child_thread_count
        self.supervisor = OwnChildSupervisor(
            PtraceAPI(), self._emit_event, expected_hashes=self.expected_file_hashes,
            expected_executables=self.expected_executable_hashes,
            expected_identities=expected_file_identities,
            fixture_root=self.fixture_root,
            device_reconciliation=device_reconciliation,
            resource_sample_policy=self._resource_sample_policy,
            plain_mode=self.plain_mode,
        )
        if self.compact_frame_batching:
            self.supervisor.slice_end_hook = self._flush_compact_batch

    @classmethod
    def from_environment(
        cls,
        *,
        node_id: str,
        validator_module,
        fixture_sha256: str | None = None,
    ) -> EvidenceCapture:
        if "AUDIOSCRIBE_EVIDENCE_MANIFEST" not in os.environ:
            return cls._from_plain_environment(
                node_id=node_id, validator_module=validator_module, fixture_sha256=fixture_sha256)
        manifest_path = Path(os.environ["AUDIOSCRIBE_EVIDENCE_MANIFEST"]).resolve(strict=True)
        expected_manifest_hash = os.environ["AUDIOSCRIBE_EVIDENCE_MANIFEST_SHA256"]
        if file_sha256(manifest_path) != expected_manifest_hash:
            raise RuntimeError("frozen evidence manifest hash mismatch before test setup")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        from lq04_runner import verify_frozen_closure
        verify_frozen_closure(manifest)
        from lq04_runner import formal_gate_blockers
        gate_blockers = formal_gate_blockers(manifest["parent_production_sha256"])
        if gate_blockers:
            raise RuntimeError('; '.join(gate_blockers))
        run_id = os.environ["AUDIOSCRIBE_EVIDENCE_RUN_ID"]
        if manifest.get("evidence_id") != "E-LQ04-SNAPSHOT-01" or manifest.get("run_id") != run_id:
            raise RuntimeError("run identity differs from the frozen evidence manifest")
        approval = os.environ.get('AUDIOSCRIBE_LQ04_H6_APPROVAL', '')
        marker = manifest_path.parent / 'attempt-start.json'
        if not marker.is_file() or marker.is_symlink():
            raise RuntimeError('H6 has no exclusive authorized attempt-start marker')
        validate_attempt_authority(json.loads(marker.read_text()), expected_manifest_hash, run_id, approval)
        from lq04_runner import prior_attempt_records, reject_attempt_replay
        reject_attempt_replay(prior_attempt_records(manifest_path.parents[2]), run_id,
                              expected_manifest_hash, active_case=True)
        trusted_files = manifest.get("trusted_file_hashes")
        trusted_executables = manifest.get("trusted_executable_hashes")
        trusted_identities = manifest.get('trusted_file_identities')
        if not isinstance(trusted_identities, dict) or not trusted_identities:
            raise RuntimeError('frozen manifest lacks inode/stat identity for bounded artifact binding')
        if not isinstance(trusted_files, dict) or not isinstance(trusted_executables, dict):
            raise RuntimeError("frozen manifest lacks trusted source/cache/executable closure")
        if not trusted_files or not trusted_executables:
            raise RuntimeError("frozen trusted closure is empty")
        fixture_root = Path(manifest["snapshot_root"]) / "fixtures"
        if Path(os.environ["AUDIOSCRIBE_LQ04_FIXTURE_ROOT"]).resolve(strict=True) != fixture_root.resolve(strict=True):
            raise RuntimeError("formal fixture root differs from frozen snapshot identity")
        expected_output = manifest_path.parent / "evidence"
        if Path(os.environ["AUDIOSCRIBE_EVIDENCE_OUTPUT_DIR"]).resolve() != expected_output.resolve():
            raise RuntimeError("sidecar output path is not the frozen run's output/evidence directory")
        validator_path = Path(validator_module.__file__).resolve(strict=True)
        snapshot = Path(manifest['snapshot_root']).resolve(strict=True)
        if (validator_path != snapshot / 'src/audioscribe/upload/validator.py'
                or Path(__file__).resolve() != snapshot / 'tests/lq04_evidence.py'):
            raise RuntimeError('workspace/rebased collector or production module execution is forbidden')
        if node_id not in manifest.get('expected_nodes', []):
            raise RuntimeError('formal node is outside frozen 13-item collection')
        policy_path = validator_path.with_name("sandbox.py")
        if file_sha256(validator_path) != manifest.get("parent_production_sha256"):
            raise RuntimeError("production validator hash differs from frozen parent identity")
        if file_sha256(policy_path) != manifest.get("sandbox_policy_sha256"):
            raise RuntimeError("sandbox policy hash differs from frozen parent identity")
        declared_policy = manifest.get("budget_fit_policy")
        if not isinstance(declared_policy, dict) \
                or type(declared_policy.get("compact_frame_batching")) is not bool:
            raise RuntimeError("frozen manifest lacks the declared E-LQ04-FIT-01 budget-fit policy")
        capture = cls(
            node_id=node_id,
            output_dir=Path(os.environ["AUDIOSCRIBE_EVIDENCE_OUTPUT_DIR"]),
            run_id=run_id,
            manifest_sha256=expected_manifest_hash,
            validator_module=validator_module,
            expected_file_hashes=trusted_files,
            expected_executable_hashes=trusted_executables,
            expected_file_identities=trusted_identities,
            fixture_sha256=fixture_sha256,
            device_reconciliation=manifest.get('device_reconciliation'),
            compact_frame_batching=bool(declared_policy["compact_frame_batching"]),
        )
        capture.frozen_manifest = manifest
        return capture

    @classmethod
    def _from_plain_environment(
        cls,
        *,
        node_id: str,
        validator_module,
        fixture_sha256: str | None = None,
    ) -> EvidenceCapture:
        """Plain-qualification entry (PLAN-01 simple-qualification): live observation, no forensic ceremony."""
        plain_root = Path(os.environ.get(
            "AUDIOSCRIBE_PLAIN_EVIDENCE_ROOT",
            "/tmp/opencode/audioscribe-plan01.dJebPg/plain-evidence",
        )).resolve()
        case_dir = plain_root / f"plain-{time.time_ns()}"
        evidence_dir = case_dir / "evidence"
        runtime_dir = case_dir / "runtime"
        evidence_dir.mkdir(mode=0o700, parents=True)
        runtime_dir.mkdir(mode=0o700)
        os.environ.setdefault(
            "AUDIOSCRIBE_LQ04_FIXTURE_ROOT",
            "/tmp/opencode/audioscribe-plan01.dJebPg/lq04-fixtures/C-LQ04-BOOTSTRAP-01")
        os.environ.setdefault("AUDIOSCRIBE_LQ04_RUNTIME_ROOT", str(runtime_dir))
        return cls(
            node_id=node_id,
            output_dir=evidence_dir,
            run_id="plain-qualification-01",
            manifest_sha256=hashlib.sha256(b"plain-qualification-01 (PLAN-01 simple-qualification)").hexdigest(),
            validator_module=validator_module,
            expected_file_hashes={},
            expected_executable_hashes={},
            expected_file_identities={},
            fixture_sha256=fixture_sha256,
            device_reconciliation=None,
            compact_frame_batching=True,
            plain_mode=True,
        )

    def __enter__(self) -> EvidenceCapture:
        try:
            return self._enter_capture()
        except BaseException as primary:
            try:
                if any(not state['terminal_seen'] for state in self.supervisor.tracees.values()):
                    self.supervisor.invalidate_and_reap('capture entry failed')
            except BaseException as cleanup_error:
                primary.add_note(f'entry containment failed: {type(cleanup_error).__name__}')
            self._restore_capture(primary)
            raise

    def _enter_capture(self) -> EvidenceCapture:
        if not self.output_dir.is_dir() or self.output_dir.is_symlink():
            raise RuntimeError("evidence output directory must be pre-created")
        if stat.S_IMODE(self.output_dir.stat().st_mode) & 0o077:
            raise RuntimeError("evidence output directory must be owner-only")
        output = self.output_dir / f"{safe_name(self.node_id)}.jsonl"
        self.writer = NativeEvidenceWriter(
            output,
            run_id=self.run_id,
            node_id=self.node_id,
            manifest_sha256=self.manifest_sha256,
            source_sha256=self.source_sha256,
            policy_sha256=self.policy_sha256,
            collector_sha256=self.collector_sha256,
            fixture_sha256=self.fixture_sha256,
            bundle_budget=self.bundle_budget,
        )
        self.current_subcase = safe_name(self.node_id)
        self.active = True
        self._capture_token = _ACTIVE_CAPTURE.set(self)
        self.current_evidence_kind = "declared"
        capture = self
        def observed_run_child(*args, **kwargs):
            try:
                return capture.original_run_child(*args, **kwargs)
            finally:
                capture.clear_next_deadline()

        self.validator_module._run_child = observed_run_child
        self.validator_module._drain_child = self._make_drain_proxy()
        self.validator_module._child_rss_bytes = self._make_metric_proxy(self.original_rss, 'rss_bytes')
        self.validator_module._child_thread_count = self._make_metric_proxy(self.original_threads, 'thread_count')
        self.validator_module._kill_child = self._make_kill_child_proxy()
        self.popen_proxy = self._make_popen_proxy()
        self.fork_exec_proxy = self._make_fork_exec_proxy()
        self.waitpid_proxy = self._make_waitpid_proxy()
        self.wait4_proxy = self._make_wait4_proxy()
        self.wait_proxy = self._make_wait_proxy()
        self.waitid_proxy = self._make_waitid_proxy() if self.original_waitid is not None else None
        self.read_proxy = self._make_read_proxy()
        self.killpg_proxy = self._make_killpg_proxy()
        self.kill_proxy = self._make_kill_proxy()
        self.selector_proxy = self._make_selector_proxy()
        subprocess.Popen = self.popen_proxy
        subprocess._fork_exec = self.fork_exec_proxy
        os.waitpid = self.waitpid_proxy
        os.wait4 = self.wait4_proxy
        os.wait = self.wait_proxy
        if self.waitid_proxy is not None:
            os.waitid = self.waitid_proxy
        os.read = self.read_proxy
        os.killpg = self.killpg_proxy
        os.kill = self.kill_proxy
        selectors.DefaultSelector = self.selector_proxy
        self._emit_record(
            "case-event",
            status="DECLARED",
            pid=os.getpid(),
            start_ticks=proc_start_ticks(os.getpid()),
            values={
                "stage": "capture-start",
                "evidence_id": "E-LQ04-SNAPSHOT-01",
                "observer": "OBS-STARTUP-RO-01",
                "monotonic_ns": self.case_start_ns,
                "cpu_wall_limit_seconds": self.validator_module._WALL_SECONDS,
                "as_limit_bytes": self.validator_module._AS_BYTES,
                "data_limit_bytes": self.validator_module._DATA_BYTES,
                "rss_limit_bytes": self.validator_module._MEMORY_BYTES,
                "stdout_limit_bytes": self.validator_module._STDOUT_LIMIT,
                "stderr_limit_bytes": self.validator_module._STDERR_LIMIT,
                "cpu_clock_ticks_per_second": int(os.sysconf("SC_CLK_TCK")),
                "page_size_bytes": int(os.sysconf("SC_PAGE_SIZE")),
                "child_deadline_seconds": (
                    45 if self.node_id.endswith("test_formal_n7_cpu_limit_terminates_child") else 30
                ),
            },
        )
        self.current_evidence_kind = "native-observed"
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        try:
            if any(not state["terminal_seen"] for state in self.supervisor.tracees.values()):
                self.supervisor.invalidate_and_reap("case ended while a traced process remained live")
            for pid, process in self.processes.items():
                if process.returncode is None:
                    process.poll()
                state = self.supervisor.tracees.get(pid)
                terminal = self.supervisor.terminal.get(pid)
                if state is None or terminal is None or not state['terminal_seen'] or not state['terminal_delivered']:
                    raise RuntimeError('required original Popen terminal/reap proof missing')
                self.current_subcase = state['subcase']
                self.current_evidence_kind = state['evidence_kind']
                self._emit_record('termination', pid=pid, start_ticks=state['start_ticks'], reserve=True,
                    values=self._popen_reap_values(process))
            for (pid, stream_name), state in self.pipe_states.items():
                tracee = self.supervisor.tracees.get(pid)
                if tracee is None:
                    continue
                self.current_subcase = str(state["subcase"] or "unassigned")
                self.current_evidence_kind = str(state["evidence_kind"])
                prefix = bytes(state["prefix"])
                completion = output_completion(state, tracee)
                blob_name = f"{safe_name(self.node_id)}.{pid}.{stream_name}.prefix"
                blob_path, blob_sha256 = self.writer.write_blob(blob_name, prefix, prepaid=True)
                self._emit_record(
                    "output-event",
                    pid=pid,
                    start_ticks=int(tracee["start_ticks"]),
                    status=completion['status'],
                    reason=None if completion['status'] == 'OBSERVED' else "pipe lacks EOF or terminal closure evidence",
                    reserve=True,
                    values={
                        "stream": stream_name,
                        "observed_length": int(state["observed_length"]),
                        "retained_prefix_length": len(prefix),
                        "retained_prefix_sha256": blob_sha256,
                        "retained_prefix_path": blob_path,
                        "truncated": int(state["observed_length"]) > len(prefix),
                        "eof": bool(state["eof"]),
                        "coverage": completion['coverage'],
                        "terminal_reap_observed": completion['terminal_reap_observed'],
                    },
                )
            self.current_subcase = None
            self.current_evidence_kind = "native-observed"
            self._flush_compact_batch()
            self.supervisor.flush_last_resource_sample()
            if getattr(self, '_syscall_counts', None):
                self._emit_record('syscall-counts', pid=os.getpid(),
                                  start_ticks=proc_start_ticks(os.getpid()),
                                  values=self._syscall_counts_summary(), reserve=True)
            if self.plain_mode:
                acceptance = {}
            else:
                from lq04_runner import verify_frozen_closure
                verify_frozen_closure(self.frozen_manifest)
                acceptance = reconcile_case_evidence(self.node_id, self.iter_records(), authority=self.writer.authority)
            if self.plain_mode:
                notes = self.supervisor.invalid_reasons
                reason_summary = "; ".join(notes[:8])
                if len(notes) > 8:
                    reason_summary += f"; (+{len(notes) - 8} more plain-mode notes)"
            else:
                reason_summary = "; ".join(self.supervisor.invalid_reasons)
            self._emit_record(
                "case-event",
                pid=os.getpid(),
                start_ticks=proc_start_ticks(os.getpid()),
                status="OBSERVED" if exc_type is None and not self.supervisor.invalid_reasons else "MISSING",
                reason=(reason_summary or "test case raised")
                if exc_type is not None or self.supervisor.invalid_reasons else None,
                values={"stage": "case-end", "elapsed_ns": time.monotonic_ns() - self.case_start_ns,
                        "process_count": len(self.processes),
                        **self.case_summary_values(), **acceptance},
                reserve=True,
            )
        except BaseException as observer_error:
            self.supervisor._invalidate(f'finalization failed: {type(observer_error).__name__}')
            try:
                self._emit_record('case-event', pid=os.getpid(), start_ticks=proc_start_ticks(os.getpid()),
                    status='MISSING', reason=str(observer_error)[:512], reserve=True,
                    values={'stage': 'case-end', 'evidence_complete': False, 'native_qualification': False})
            except BaseException as sidecar_error:
                observer_error.add_note(f'failed finalization receipt: {type(sidecar_error).__name__}')
            if exc_value is None:
                raise
            exc_value.add_note(f'observer finalization error: {type(observer_error).__name__}: {observer_error}')
        finally:
            self._restore_capture(exc_value or sys.exc_info()[1])

    def _restore_capture(self, primary=None):
        """Rollback the finite hook set; one failure must not skip other restores."""
        self.active = False
        errors = []
        def restore(action):
            try:
                action()
            except BaseException as error:
                errors.append(error)
        bindings = [(self.validator_module, name, original) for name, original in (
            ('_run_child', self.original_run_child), ('_drain_child', self.original_drain_child),
            ('_kill_child', self.original_kill_child), ('_child_rss_bytes', self.original_rss),
            ('_child_thread_count', self.original_threads))]
        bindings += [(owner, name, original) for owner, name, original in (
            (selectors, 'DefaultSelector', self.original_selector), (os, 'kill', self.original_kill),
            (os, 'killpg', self.original_killpg), (os, 'read', self.original_read),
            (os, 'waitpid', self.original_waitpid), (os, 'wait4', self.original_wait4),
            (os, 'wait', self.original_wait), (subprocess, '_fork_exec', self.original_fork_exec),
            (subprocess, 'Popen', self.original_popen))]
        if self.original_waitid is not None:
            bindings.append((os, 'waitid', self.original_waitid))
        for owner, name, original in bindings:
            restore(lambda owner=owner, name=name, original=original: setattr(owner, name, original))
        if self._capture_token is not None:
            restore(lambda: _ACTIVE_CAPTURE.reset(self._capture_token))
            self._capture_token = None
        for pid, originals in self.instance_methods.items():
            process = self.processes.get(pid)
            if process is None:
                errors.append(RuntimeError(f'original Popen adapter owner missing: {pid}'))
                continue
            for name, original in zip(('_internal_poll', '_try_wait'), originals):
                restore(lambda process=process, name=name, original=original: setattr(process, name, original))
            original_exit = getattr(self, 'instance_exit_handlers', {}).get(pid)
            if original_exit is not None:
                restore(lambda process=process, original_exit=original_exit: setattr(process, '_handle_exitstatus', original_exit))
        for process in self.processes.values():
            for name in ('stdin', 'stdout', 'stderr'):
                def close_stream(process=process, name=name):
                    stream = getattr(process, name, None)
                    if stream is not None:
                        stream.close()
                restore(close_stream)
        if self.writer is not None:
            restore(self.writer.close)
        if errors:
            self.supervisor._invalidate('hook/context/FD restoration failed')
            if primary is None:
                raise errors[0]
            for error in errors:
                primary.add_note(f'observer restoration error: {type(error).__name__}: {error}')

    def _buffer_compact_frame(self, event: Mapping[str, object], values: Mapping[str, object]) -> None:
        """F5: bounded per-slice buffering of compact frames (≤40 frames, ≤16 KiB record)."""
        entry = {
            'pid': int(event.get('pid', 0)),
            'subcase': self.current_subcase,
            'evidence_kind': self.current_evidence_kind,
            'values': dict(values),
        }
        if self._compact_batch:
            head = self._compact_batch[0]
            if (head['pid'] != entry['pid'] or head['subcase'] != entry['subcase']
                    or head['evidence_kind'] != entry['evidence_kind']):
                self._flush_compact_batch()
        if len(self._compact_batch) >= _COMPACT_FRAME_BATCH_MAX:
            self._flush_compact_batch()
        self._compact_batch.append(entry)
        if len(self._compact_batch) >= _COMPACT_FRAME_BATCH_MAX:
            self._flush_compact_batch()

    def _flush_compact_batch(self) -> None:
        """F5: emit buffered compact frames as one bounded per-slice batch record."""
        if not self._compact_batch:
            return
        if self.writer is None:
            raise RuntimeError("evidence writer is unavailable")
        frames, self._compact_batch = self._compact_batch, []
        self.writer.append(
            'syscall-event',
            status='OBSERVED',
            pid=int(frames[0]['pid']),
            start_ticks=None,
            origin=self.collector_origin,
            collector_id=self.collector_id,
            values={'batch': [frame['values'] for frame in frames]},
            subcase=frames[0]['subcase'],
            evidence_kind=frames[0]['evidence_kind'],
            fixture_sha256=self.current_fixture_sha256,
        )

    def _emit_event(self, event: Mapping[str, object]) -> None:
        record_type = str(event.get("record_type", "run-event"))
        excluded = {"evidence_kind", "record_type", "status", "pid", "start_ticks", "reason", "values",
                    "capture_deferred_completion"}
        values = {**event.get("values", {}),
                  **{key: value for key, value in event.items() if key not in excluded}}
        prior_kind = self.current_evidence_kind
        if event.get('evidence_kind') in {'unit-injected', 'unit-simulated'}:
            self.current_evidence_kind = event['evidence_kind']
        try:
            if (record_type == 'syscall-event'
                    and self.current_evidence_kind in {'native-observed', 'native-control'}):
                values = self._compact_or_count_syscall(event, values)
            elif (record_type == 'source-load'
                    and self.current_evidence_kind in {'native-observed', 'native-control'}):
                values = self._reference_or_full_source_load(values)
            if (getattr(self, 'compact_frame_batching', False) and record_type == 'syscall-event'
                    and event.get('status') == 'OBSERVED'
                    and self.current_evidence_kind in {'native-observed', 'native-control'}
                    and isinstance(values, Mapping) and values.get('compact') is True):
                self._buffer_compact_frame(event, values)
                return
            self._emit_record(
                record_type,
                status=str(event.get("status", "OBSERVED")),
                pid=int(event.get("pid", 0)),
                start_ticks=int(event.get("start_ticks", 0)),
                values=values,
                reason=event.get("reason") if isinstance(event.get("reason"), str) else None,
                reserve=event.get("status") == "MISSING",
            )
        finally:
            self.current_evidence_kind = prior_kind

    def _compact_or_count_syscall(self, event: Mapping[str, object],
                                  values: Mapping[str, object]) -> Mapping[str, object]:
        counts = getattr(self, '_syscall_counts', None)
        seen = getattr(self, '_seen_syscall_kinds', None)
        if counts is None or seen is None:
            return values
        number = values.get('syscall_number')
        raw_name = values.get('name')
        name = raw_name if isinstance(raw_name, str) and raw_name \
            else _SYSCALL_NAMES.get(number, 'unknown')
        phase = values.get('phase')
        first_of_kind = False
        if phase in {'entry', 'exit', 'initial-exec-return'}:
            first_of_kind = (name, phase) not in seen
            seen.add((name, phase))
            buckets = counts.setdefault(name, {'entry': 0, 'exit': 0, 'errors': 0})
            bucket = 'entry' if phase == 'entry' else 'exit'
            buckets[bucket] += 1
            if bucket == 'exit' and values.get('errno', 0) != 0:
                buckets['errors'] += 1
        if (event.get('status') == 'OBSERVED' and phase in {'entry', 'exit'}
                and not is_boundary_syscall_event(
                    values, first_of_kind=first_of_kind,
                    capture_deferred_completion=bool(event.get('capture_deferred_completion')))):
            compact: dict[str, object] = {'name': name, 'phase': phase, 'compact': True}
            if phase == 'exit':
                compact['result'] = values['result']
                compact['errno'] = values['errno']
            return compact
        return values

    def _reference_or_full_source_load(self, values: Mapping[str, object]) -> Mapping[str, object]:
        """F2: first occurrence of an artifact emits full; repeats emit a static reference."""
        mapping = values.get('mapping')
        if not isinstance(mapping, dict) or not isinstance(mapping.get('file'), dict):
            return values
        artifact = mapping['file']
        path, device, inode = artifact.get('path'), artifact.get('device'), artifact.get('inode')
        span_sha256 = artifact.get('sha256')
        if (not isinstance(path, str) or not path or type(device) is not int
                or type(inode) is not int or not isinstance(span_sha256, str)
                or not _SHA256.fullmatch(span_sha256)):
            return values
        key = (path, device, inode)
        operation = values.get('operation') or values.get('mapping_operation') or 'mmap'
        ref = self._artifact_registry.get(key)
        if ref is None:
            if len(self._artifact_registry) >= _MAX_TRACE_ARTIFACTS:
                raise OverflowError('source-load artifact references exceed 4096 identities')
            ref = f'artifact-{len(self._artifact_registry)}'
            self._artifact_registry[key] = ref
            self._artifact_index[ref] = {'operation': operation, 'mapping': mapping}
            return {**values, 'artifact_ref': ref}
        return {'artifact_ref': ref, 'operation': operation,
                'offset': int(mapping.get('offset', 0)), 'length': int(mapping.get('length', 0)),
                'span_sha256': span_sha256}

    def _syscall_counts_summary(self) -> dict[str, dict[str, int]]:
        return {name: dict(buckets) for name, buckets in
                sorted(getattr(self, '_syscall_counts', {}).items())}

    def _make_drain_proxy(self):
        def drain(process, *, deadline=None):
            try:
                return self.original_drain_child(process, deadline=deadline)
            except BaseException as error:
                tracee = self.supervisor.tracees.get(process.pid)
                if tracee is not None:
                    tracee['drain_exception'] = type(error).__name__
                    try:
                        self._emit_record('termination', pid=process.pid,
                            start_ticks=int(tracee['start_ticks']), reserve=True,
                            values={'stage': '_drain_child-exception',
                                    'exception_type': type(error).__name__,
                                    'exception_message': str(error)[:512],
                                    'deadline': deadline, 'monotonic_ns': time.monotonic_ns(),
                                    **{name + '_bytes_observed': int(state['observed_length'])
                                       for (pid, name), state in self.pipe_states.items() if pid == process.pid}})
                    except BaseException as observer_error:
                        self.supervisor._invalidate('drain exception sidecar could not be retained')
                        error.add_note(f'observer error: {type(observer_error).__name__}')
                raise
        return drain

    def _make_metric_proxy(self, original, field):
        def measured(pid):
            value = original(pid)
            tracee = self.supervisor.tracees.get(pid)
            if tracee is not None:
                self._emit_record('child-sample', pid=pid, start_ticks=tracee['start_ticks'],
                                  values={field: value, 'collector': 'original-validator-metric'})
                self.supervisor._sample_live_process(pid, tracee)
            return value
        return measured

    def _make_kill_child_proxy(self):
        def killed(process, **kwargs):
            source_error = sys.exc_info()[1]
            pid = int(getattr(process, 'pid', 0) or 0)
            tracee = self.supervisor.tracees.get(pid)
            observer_error = None
            if tracee is not None:
                try:
                    self._emit_record('termination', pid=pid, start_ticks=tracee['start_ticks'],
                        reserve=True, values={'stage': '_kill_child-entry', 'actor': 'validator-helper',
                            'reason_type': type(source_error).__name__ if source_error else 'explicit-helper-request',
                            'reason': str(source_error)[:256] if source_error else 'explicit-helper-request',
                            'monotonic_ns': time.monotonic_ns()})
                except BaseException as error:
                    observer_error = error
                    self.supervisor._invalidate('kill entry sidecar could not be retained')
            try:
                result = self.original_kill_child(process, **kwargs)
            except BaseException as error:
                observer_error = observer_error or error
                result = None
            if tracee is not None and not tracee['terminal_seen']:
                try:
                    self.supervisor.invalidate_and_reap('original _kill_child lacks terminal reap proof')
                except BaseException as error:
                    observer_error = observer_error or error
            if observer_error is not None:
                if source_error is not None:
                    source_error.add_note(f'observer cleanup failure: {type(observer_error).__name__}: {observer_error}')
                else:
                    raise observer_error
            return result
        return killed

    def _emit_record(
        self,
        record_type: str,
        *,
        pid: int,
        start_ticks: int,
        values: Mapping[str, object],
        status: str = "OBSERVED",
        reason: str | None = None,
        reserve: bool = False,
        fixture_sha256: str | None = None,
    ) -> None:
        if self.writer is None:
            raise RuntimeError("evidence writer is unavailable")
        if (record_type == 'syscall-event' and values.get('compact') is True):
            start_ticks = None
        elif getattr(self, 'compact_frame_batching', False) and self._compact_batch:
            self._flush_compact_batch()
        if self.current_evidence_kind in {"unit-simulated", "unit-injected", "declared"}:
            self.writer.append_unit(
                record_type,
                subcase=self.current_subcase or "unit-unspecified",
                status=status,
                values=values,
                reason=reason,
                evidence_kind=self.current_evidence_kind,
            )
            return
        self.writer.append(
            record_type,
            status=status,
            pid=pid,
            start_ticks=start_ticks,
            origin=self.collector_origin,
            collector_id=self.collector_id,
            values=values,
            subcase=self.current_subcase,
            evidence_kind=self.current_evidence_kind,
            fixture_sha256=fixture_sha256 or self.current_fixture_sha256,
            reason=reason,
            reserve=reserve,
        )

    def set_subcase(self, name: str, *, evidence_kind: str = "native-observed") -> None:
        if not name or len(name) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("subcase label is invalid")
        if evidence_kind not in {"native-observed", "native-control", "unit-injected", "unit-simulated"}:
            raise ValueError("unsupported subcase evidence kind")
        self.current_subcase = name
        self.current_evidence_kind = evidence_kind

    def case_summary_values(self) -> dict[str, object]:
        """Declared F1 decimation summary; recorded in the case-end record."""
        policy = getattr(self.supervisor, '_resource_sample_policy', None)
        if policy is None:
            return {}
        return policy.summary()

    def record_fixture(self, relative_path: str, path: Path, digest: str) -> None:
        path = Path(path).resolve(strict=True)
        label = PurePosixPath(relative_path)
        if len(label.parts) != 1 or label.name in {'.', '..'} or path != (self.fixture_root / label.name).resolve(strict=True):
            raise RuntimeError('fixture relative path does not match actual frozen fixture identity')
        if not self.plain_mode and self.expected_file_hashes.get(str(path)) != digest:
            raise RuntimeError(f"fixture path/hash is outside frozen snapshot: {relative_path}")
        self.current_fixture_sha256 = digest
        info = path.stat()
        self._emit_record(
            "fixture",
            pid=os.getpid(),
            start_ticks=proc_start_ticks(os.getpid()),
            values={"relative_path": relative_path, "device": info.st_dev,
                    "inode": info.st_ino, "size": info.st_size},
            fixture_sha256=digest,
        )

    def record_case_result(self, node_id: str, report) -> None:
        suffix = node_id.rsplit("::", 1)[-1]
        expected = _EXPECTED_CASES.get(suffix)
        if expected is None:
            raise ValueError(f"formal node has no frozen expected outcome: {node_id}")
        outcome = str(getattr(report, "outcome", "unknown"))
        longrepr = getattr(report, "longrepr", None)
        summary = str(longrepr).replace(str(self.output_dir.parent), "<run-root>")[:1024] if longrepr else ""
        self._emit_record(
            "case-event",
            pid=os.getpid(),
            start_ticks=proc_start_ticks(os.getpid()),
            status="OBSERVED",
            reserve=True,
            values={"stage": "pytest-call-result", "node_id": node_id,
                    "expected_outcome": expected, "observed_outcome": outcome,
                    "evidence_complete": False, "evidence_completeness": "PENDING_FINALIZATION",
                    "duration_seconds": float(getattr(report, "duration", 0.0)),
                    "failure_summary": summary},
        )

    def record_parent_event(self, stage, values):
        prior = self.current_evidence_kind
        self.current_evidence_kind = 'parent-observed'
        try:
            self._emit_record('case-event', pid=os.getpid(), start_ticks=proc_start_ticks(os.getpid()),
                              values={'stage': stage, **values})
        finally:
            self.current_evidence_kind = prior

    def iter_records(self):
        if self.writer is None:
            raise RuntimeError("evidence writer is not open")
        identity = None
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f'duplicate sidecar JSON key: {key}')
                result[key] = value
            return result
        with self.writer.path.open("rb") as stream:
            for line in stream:
                if len(line) > _MAX_RECORD_BYTES:
                    raise ValueError('sidecar record exceeds 16 KiB')
                record = json.loads(line, object_pairs_hook=unique)
                if not isinstance(record, dict):
                    raise ValueError('sidecar record must be an object')
                claimed = record.pop("record_sha256", None)
                if claimed != hashlib.sha256(canonical_record(record)).hexdigest():
                    raise ValueError("evidence record hash mismatch")
                if record.get('record_type') == 'identity':
                    if identity is not None:
                        raise ValueError('duplicate case trace identity')
                    identity = record['values']
                elif 'identity_ref' in record:
                    record = resolve_record_identity(record, identity)
                validate_record(record, authority=getattr(self.writer, 'authority', None))
                yield record

    def _make_preexec(self, original):
        api = self.supervisor.api

        def wrapped_preexec() -> None:
            original()
            api.traceme_in_preexec()

        return wrapped_preexec

    def _make_popen_proxy(self):
        capture = self
        original_class = self.original_popen

        class ObservedPopen(original_class):
            def __init__(self, *args, **kwargs):
                if not capture.active:
                    super().__init__(*args, **kwargs)
                    return
                bound = inspect.signature(original_class.__init__).bind_partial(self, *args, **kwargs)
                original_preexec = bound.arguments.get("preexec_fn")
                if "preexec_fn" not in kwargs or original_preexec is not capture.original_limits:
                    raise RuntimeError("unrecognized Popen call inside evidence scope; refusing untraced child")
                options = popen_options(args, kwargs, original_class)
                validate_popen_options(options)
                if not capture.plain_mode:
                    declared_scripts = frozen_child_script_hashes(
                        Path(__file__).parent, capture.fixture_root,
                        Path(os.environ['AUDIOSCRIBE_LQ04_RUNTIME_ROOT']), tuple(options['pass_fds']),
                        node_suffix=capture.node_id.rsplit('::', 1)[-1])
                    if script_sha256(args, kwargs) not in declared_scripts:
                        raise RuntimeError('child script is outside frozen templates/typed substitutions')
                wrapper = capture._make_preexec(original_preexec)
                capture.spawn_pending = True
                try:
                    capture.spawn_fd_baseline = {
                        int(name) for name in os.listdir("/proc/self/fd") if name.isdigit()
                    }
                except OSError as error:
                    capture.spawn_pending = False
                    raise RuntimeError("cannot inventory parent descriptors before Popen") from error
                capture.spawn_record = {
                    "started_ns": time.monotonic_ns(),
                    "script_sha256": script_sha256(args, kwargs),
                    "original_preexec_sha256": code_sha256(original_preexec),
                    "wrapper_preexec_sha256": code_sha256(wrapper),
                    "original_preexec_identity": callable_identity(original_preexec),
                    "wrapper_preexec_identity": callable_identity(wrapper),
                    "argv": safe_argv(args, kwargs),
                    "popen_options": options,
                    "kwargs": dict(kwargs),
                    "argv_hashes": [hashlib.sha256(os.fsencode(value)).hexdigest()
                                    for value in (args[0] if args else kwargs['args'])],
                }
                deadline = capture._caller_deadline(sys._getframe(1))
                capture.spawn_record["deadline_ns"] = int(deadline * 1_000_000_000)
                kwargs["preexec_fn"] = wrapper
                try:
                    with capture._parent_spawn_deadline():
                        super().__init__(*args, **kwargs)
                except BaseException:
                    capture.spawn_pending = False
                    capture.spawn_record = None
                    capture.spawn_fd_baseline.clear()
                    capture._next_deadline = None
                    for tracee in capture.supervisor.tracees.values():
                        if not tracee["terminal_seen"]:
                            try:
                                capture.supervisor.invalidate_and_reap(
                                    "Popen constructor failed before child exposure"
                                )
                            except BaseException:
                                pass
                            break
                    raise
                capture.spawn_pending = False
                capture.spawn_fd_baseline.clear()
                capture.processes[self.pid] = self
                capture._install_wait_adapters(self)
                capture.supervisor.seed_fds(
                    self.pid,
                    tuple((capture.spawn_record or {}).get("popen_options", {}).get("pass_fds", ())),
                )
                capture.supervisor.attach_root(self.pid, os.getpgid(self.pid), capture.spawn_deadline())
                capture._register_pipe(self.pid, "stdout", self.stdout)
                capture._register_pipe(self.pid, "stderr", self.stderr)
                capture._next_deadline = None

        return ObservedPopen

    def _make_fork_exec_proxy(self):
        capture = self
        original = self.original_fork_exec

        def fork_exec(*args, **kwargs):
            pid = original(*args, **kwargs)
            if capture.active and capture.spawn_pending:
                if pid in capture.supervisor.tracees:
                    raise RuntimeError("observed PID was registered before fork_exec")
                if not capture.spawn_record["popen_options"].get("start_new_session"):
                    raise RuntimeError("observed child must retain start_new_session=True")
                capture.supervisor.register(pid, proc_start_ticks(pid), pid, root=True)
                capture.supervisor.tracees[pid]["deadline"] = capture.spawn_deadline()
                capture.supervisor.tracees[pid]['expected_argv_hashes'] = capture.spawn_record['argv_hashes']
                capture.supervisor.tracees[pid]['subcase'] = capture.current_subcase
                capture.supervisor.tracees[pid]['evidence_kind'] = capture.current_evidence_kind
                record = capture.spawn_record or {}
                capture._emit_record(
                    "run-event",
                    pid=pid,
                    start_ticks=proc_start_ticks(pid),
                    values={
                        "stage": "fork-exec-return",
                        "pgid": pid,
                        "script_sha256": record.get("script_sha256", ""),
                        "original_preexec_sha256": record.get("original_preexec_sha256", ""),
                        "wrapper_preexec_sha256": record.get("wrapper_preexec_sha256", ""),
                        "original_preexec_identity": record.get("original_preexec_identity", {}),
                        "wrapper_preexec_identity": record.get("wrapper_preexec_identity", {}),
                        "caller_wall_deadline_ns": record.get("deadline_ns", 0),
                        "popen_started_ns": record.get("started_ns", 0),
                        "preexec_kwarg_delta": "original limits once, then PTRACE_TRACEME",
                        "popen_options": record.get("popen_options", {}),
                        "argv": record.get("argv", []),
                    },
                )
            return pid

        return fork_exec

    def _make_waitpid_proxy(self):
        capture = self
        original = self.original_waitpid

        def waitpid(pid, options):
            if capture.active and pid in capture.supervisor.tracees:
                return capture.supervisor.waitpid_adapter(pid, options)
            if capture.active and capture.supervisor.tracees and (
                pid in {-1, 0} or pid < -1 and any(state["pgid"] == -pid for state in capture.supervisor.tracees.values())
            ):
                capture.supervisor._invalidate("unscoped waitpid would compete with the single supervisor")
                raise RuntimeError(capture.supervisor.invalid_reasons[-1])
            return original(pid, options)

        return waitpid

    def _make_wait4_proxy(self):
        capture = self
        original = self.original_wait4

        def wait4(pid, options):
            if capture.active and capture.supervisor.tracees and (
                pid in {-1, 0} or pid in capture.supervisor.tracees
                or pid < -1 and any(state["pgid"] == -pid for state in capture.supervisor.tracees.values())
            ):
                capture.supervisor._invalidate("unscoped parent wait4 would compete with the ptrace coordinator")
                raise RuntimeError(capture.supervisor.invalid_reasons[-1])
            return original(pid, options)

        return wait4

    def _make_wait_proxy(self):
        def wait():
            self.supervisor._invalidate("os.wait would compete with the ptrace coordinator")
            raise RuntimeError(self.supervisor.invalid_reasons[-1])

        return wait

    def _make_waitid_proxy(self):
        capture = self
        original = self.original_waitid

        def waitid(idtype, ident, options):
            if capture.active and capture.supervisor.tracees:
                capture.supervisor._invalidate("os.waitid would compete with the ptrace coordinator")
                raise RuntimeError(capture.supervisor.invalid_reasons[-1])
            return original(idtype, ident, options)

        return waitid

    def _popen_reap_values(self, process):
        state = self.supervisor.tracees[process.pid]
        status, _usage = self.supervisor.terminal[process.pid]
        return {'stage': 'popen-reap', 'wait_status': status, 'returncode': process.returncode,
                'terminal_delivered': state['terminal_delivered'], 'terminal_reap_observed': state['terminal_seen'],
                'terminal_reap_ns': state['terminal_reap_ns'],
                'terminal_wait_delivery_ns': state['terminal_wait_delivery_ns'],
                'monotonic_end_ns': state['popen_exitstatus_ns'], 'finalization_ns': time.monotonic_ns()}

    def _install_wait_adapters(self, process) -> None:
        capture = self
        pid = process.pid
        original_internal = process._internal_poll
        original_try_wait = process._try_wait
        self.instance_methods[pid] = (original_internal, original_try_wait)
        original_exit = getattr(process, '_handle_exitstatus', None)
        if original_exit is not None:
            if not hasattr(self, 'instance_exit_handlers'):
                self.instance_exit_handlers = {}
            self.instance_exit_handlers[pid] = original_exit
            def handle_exitstatus(status):
                result = original_exit(status)  # Original returncode update, under its original lock.
                state = capture.supervisor.tracees[pid]
                if not state['terminal_delivered'] or capture.supervisor.terminal[pid][0] != status:
                    raise RuntimeError('Popen exitstatus is not the owned terminal delivery')
                state.setdefault('popen_exitstatus_ns', time.monotonic_ns())
                return result
            process._handle_exitstatus = handle_exitstatus

        def internal_poll(_deadstate=None, _waitpid=None):
            return original_internal(_deadstate, _waitpid=capture.supervisor.waitpid_adapter)

        def try_wait(wait_flags):
            # Unlike _internal_poll, _try_wait looks up the scoped os.waitpid
            # adapter dynamically; retain CPython's original error semantics.
            return original_try_wait(wait_flags)

        process._internal_poll = internal_poll
        process._try_wait = try_wait

    def _register_pipe(self, pid: int, name: str, stream) -> None:
        if stream is not None:
            fd = stream.fileno()
            self.pipe_roles[fd] = (pid, name)
            cap = 64 * 1024 if name == "stdout" else 16 * 1024
            self.pipe_states[(pid, name)] = {
                "observed_length": 0,
                "prefix": bytearray(),
                "cap": cap,
                "eof": False,
                "subcase": self.current_subcase,
                "evidence_kind": self.current_evidence_kind,
            }

    def _make_read_proxy(self):
        capture = self
        original = self.original_read

        def read(fd, count):
            data = original(fd, count)
            role = capture.pipe_roles.get(fd) if capture.active else None
            if role is not None:
                pid, name = role
                tracee = capture.supervisor.tracees[pid]
                state = capture.pipe_states[(pid, name)]
                state["observed_length"] += len(data)
                missing = int(state["cap"]) - len(state["prefix"])
                if missing > 0:
                    retained = data[:missing]
                    capture.writer.reserve_prefix_bytes(len(retained))
                    state["prefix"].extend(retained)
                if not data:
                    state["eof"] = True
                capture._emit_record(
                    "output-event",
                    pid=pid,
                    start_ticks=int(tracee["start_ticks"]),
                        values={"stream": name, "observed_chunk_length": len(data),
                            "total_observed_length": int(state["observed_length"]),
                            "eof": not bool(data)},
                    )
            elif capture.active and capture.spawn_pending and fd not in capture.spawn_fd_baseline:
                capture._emit_record(
                    "run-event",
                    pid=os.getpid(),
                    start_ticks=proc_start_ticks(os.getpid()),
                    values={"stage": "popen-error-pipe-read", "fd": fd,
                            "observed_length": len(data), "eof": not bool(data),
                            "chunk_sha256": hashlib.sha256(data).hexdigest()},
                )
            return data

        return read

    def output_observed(self, subcase: str, stream_name: str) -> int:
        return sum(
            int(state["observed_length"])
            for (pid, name), state in self.pipe_states.items()
            if name == stream_name and state.get("subcase") == subcase
        )

    def _make_killpg_proxy(self):
        capture = self
        original = self.original_killpg

        def killpg(pgid, sig):
            for pid, tracee in capture.supervisor.tracees.items():
                if tracee["pgid"] == pgid:
                    record = {"actor": "parent-os.killpg", "signal": int(sig), "pgid": int(pgid),
                              "monotonic_ns": time.monotonic_ns()}
                    break
            else:
                pid, tracee, record = 0, None, None
            try:
                result = original(pgid, sig)
            except OSError as error:
                if tracee is not None:
                    capture._emit_record(
                        "termination", pid=pid, start_ticks=int(tracee["start_ticks"]),
                        reserve=True,
                        values={**record, "result": -1, "errno": int(error.errno or 0)},
                    )
                raise
            if tracee is not None:
                capture._emit_record(
                    "termination", pid=pid, start_ticks=int(tracee["start_ticks"]),
                    reserve=True,
                    values={**record, "result": 0, "errno": 0},
                )
            return result

        return killpg

    def _make_kill_proxy(self):
        capture = self
        original = self.original_kill

        def kill(pid, sig):
            tracee = capture.supervisor.tracees.get(pid)
            record = {"actor": "parent-os.kill", "signal": int(sig), "monotonic_ns": time.monotonic_ns()}
            try:
                result = original(pid, sig)
            except OSError as error:
                if tracee is not None:
                    capture._emit_record(
                        "termination", pid=pid, start_ticks=int(tracee["start_ticks"]),
                        reserve=True,
                        values={**record, "result": -1, "errno": int(error.errno or 0)},
                    )
                raise
            if tracee is not None:
                capture._emit_record(
                    "termination", pid=pid, start_ticks=int(tracee["start_ticks"]),
                    reserve=True,
                    values={**record, "result": 0, "errno": 0},
                )
            return result

        return kill

    def _make_selector_proxy(self):
        capture = self
        original = self.original_selector

        def make_selector(*args, **kwargs):
            return _PumpingSelector(original(*args, **kwargs), capture.supervisor)

        return make_selector

    def spawn_deadline(self) -> float:
        record = self.spawn_record or {}
        if "deadline_ns" in record:
            return int(record["deadline_ns"]) / 1_000_000_000
        raise RuntimeError('original caller deadline is unavailable')

    def _caller_deadline(self, frame):
        deadline = self._next_deadline
        if deadline is None:
            while frame is not None:
                if frame.f_code is self.original_run_child.__code__:
                    deadline = frame.f_locals.get('deadline')
                    break
                frame = frame.f_back
        if type(deadline) not in {float, int} or not math.isfinite(deadline):
            raise RuntimeError('original caller deadline is unavailable; refusing clock reset')
        return deadline

    def set_next_deadline(self, deadline: float) -> None:
        if self._next_deadline is not None:
            raise RuntimeError("one observed child deadline is already pending")
        self._next_deadline = deadline

    def clear_next_deadline(self) -> None:
        self._next_deadline = None

    @contextlib.contextmanager
    def _parent_spawn_deadline(self):
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("Popen observation must run on the owning main thread")
        prior_handler = signal.getsignal(signal.SIGALRM)
        prior_delay, prior_interval = signal.getitimer(signal.ITIMER_REAL)
        started = time.monotonic()
        remaining = max(0.0, prior_delay)
        deadline = self.spawn_deadline()
        timeout = max(0.000001, deadline - started)

        def expired(_signum, _frame):
            if remaining and remaining <= timeout:
                if callable(prior_handler):
                    return prior_handler(_signum, _frame)
                raise RuntimeError('earlier watchdog has an unsupported default/ignored signal handler')
            raise TimeoutError("validator wall deadline expired during Popen construction")

        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, min(timeout, remaining) if remaining else timeout)
        try:
            yield
        finally:
            elapsed = time.monotonic() - started
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, prior_handler)
            if prior_delay:
                signal.setitimer(signal.ITIMER_REAL, max(0.000001, prior_delay - elapsed), prior_interval)


def active_evidence_capture():
    return _ACTIVE_CAPTURE.get()


def output_completion(state, tracee):
    return {'status': 'OBSERVED' if state['eof'] or tracee['terminal_seen'] else 'MISSING',
            'coverage': 'consumed-by-parent-only', 'eof': bool(state['eof']),
            'terminal_reap_observed': bool(tracee['terminal_seen'])}


def validate_attempt_authority(record, manifest_sha256, run_id, approval):
    if not isinstance(approval, str) or not approval or record.get('approval_reference') != approval:
        raise ValueError('H6 requires exact separately recorded explicit approval')
    if (record.get('evidence_id') != 'E-LQ04-SNAPSHOT-01'
            or record.get('manifest_sha256') != manifest_sha256 or record.get('run_id') != run_id):
        raise ValueError('attempt-start identity differs from approved freeze')


def validate_exec_argv(tracee, argv):
    if tracee['root']:
        actual = [hashlib.sha256(item).hexdigest() for item in argv]
        if actual != tracee.get('expected_argv_hashes'):
            raise RuntimeError('root exec argv/script differs from recorded Popen identity')
    elif argv != [b'/sbin/ldconfig', b'-p']:
        raise RuntimeError('descendant exec argv is outside the finite ldconfig resolver closure')


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def decode_path_hex(value: object) -> str:
    if not isinstance(value, str):
        return ""
    try:
        return os.fsdecode(bytes.fromhex(value))
    except (ValueError, UnicodeError):
        return ""


def signed_u64(value: int) -> int:
    return ctypes.c_int64(value).value


def is_source_or_cache_path(path: str) -> bool:
    normalized = path.removesuffix(" (deleted)").lower()
    return normalized.endswith((".py", ".pyc", ".pth"))


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)[:160]


def code_sha256(function) -> str:
    code = getattr(function, "__code__", None)
    if code is None:
        raise ValueError("preexec hook has no Python code object")
    return hashlib.sha256(code.co_code + repr(code.co_consts).encode("utf-8")).hexdigest()


def callable_identity(function) -> dict[str, object]:
    code = getattr(function, "__code__", None)
    return {
        "module": getattr(function, "__module__", None),
        "qualname": getattr(function, "__qualname__", type(function).__qualname__),
        "object_identity": id(function),
        "code_filename": getattr(code, "co_filename", None),
        "code_firstlineno": getattr(code, "co_firstlineno", None),
    }


def script_sha256(args, kwargs) -> str:
    argv = args[0] if args else kwargs.get("args", ())
    if isinstance(argv, (list, tuple)) and "-c" in argv:
        index = argv.index("-c")
        if index + 1 >= len(argv) or not isinstance(argv[index + 1], str):
            raise ValueError("embedded child script is unavailable")
        return hashlib.sha256(argv[index + 1].encode("utf-8")).hexdigest()
    return hashlib.sha256(repr(argv).encode("utf-8")).hexdigest()


def safe_argv(args, kwargs) -> list[object]:
    argv = args[0] if args else kwargs.get("args", ())
    values = list(argv) if isinstance(argv, (list, tuple)) else [repr(argv)]
    if "-c" in values:
        index = values.index("-c")
        if index + 1 < len(values):
            values[index + 1] = {"script_sha256": script_sha256(args, kwargs)}
    return values


def popen_options(args, kwargs, popen_class) -> dict[str, object]:
    bound = inspect.signature(popen_class.__init__).bind_partial(None, *args, **kwargs)
    values = bound.arguments

    def stream_identity(value):
        if value is None:
            return "inherit"
        if value == subprocess.PIPE:
            return "pipe"
        if value == subprocess.DEVNULL:
            return "devnull"
        if isinstance(value, int):
            return {"fd": value}
        fileno = getattr(value, "fileno", None)
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}",
                "fd": int(fileno()) if callable(fileno) else None}

    environment = values.get("env")
    inherited_environment = os.environ if environment is None else environment
    normalized_environment = {str(key): str(value) for key, value in inherited_environment.items()}
    return {
        "executable": str(values["executable"]) if values.get("executable") is not None else None,
        "cwd": str(values["cwd"]) if values.get("cwd") is not None else None,
        "stdin": stream_identity(values.get("stdin")),
        "stdout": stream_identity(values.get("stdout")),
        "stderr": stream_identity(values.get("stderr")),
        "close_fds": bool(values.get("close_fds", True)),
        "pass_fds": sorted(int(fd) for fd in values.get("pass_fds", ())),
        "start_new_session": bool(values.get("start_new_session", False)),
        "restore_signals": bool(values.get("restore_signals", True)),
        "process_group": values.get("process_group"),
        "shell": bool(values.get("shell", False)),
        "umask": values.get("umask", -1),
        "user": values.get("user"),
        "group": values.get("group"),
        "extra_groups": list(values.get("extra_groups") or ()),
        "bufsize": values.get("bufsize", -1),
        "text_mode": bool(values.get("text") or values.get("universal_newlines")
                           or values.get("encoding") or values.get("errors")),
        "environment_names": sorted(normalized_environment),
        "environment_sha256": hashlib.sha256(canonical_record(normalized_environment)).hexdigest(),
    }


def validate_popen_options(options: Mapping[str, object]) -> None:
    expected = {
        "stdin": "devnull",
        "stdout": "pipe",
        "stderr": "pipe",
        "close_fds": True,
        "start_new_session": True,
        "restore_signals": True,
        "process_group": None,
        "shell": False,
        "executable": None,
        "cwd": None,
        "user": None,
        "group": None,
        "extra_groups": [],
        "umask": -1,
        "text_mode": False,
    }
    for key, value in expected.items():
        if options.get(key) != value:
            raise ValueError(f"Popen option {key} differs from the frozen isolation contract")
    pass_fds = options.get("pass_fds")
    if not isinstance(pass_fds, list) or len(pass_fds) > 1 or any(type(fd) is not int or fd < 3 for fd in pass_fds):
        raise ValueError("Popen pass_fds differs from the one-read-only-input contract")


def native_n8_control_specs() -> tuple[dict[str, str], ...]:
    """Frozen source strings for distinct native limits; constructing these launches nothing."""
    prefix = '''import ctypes, errno, json, mmap, os, resource, time
status_fd = os.open("/proc/self/status", os.O_RDONLY | os.O_CLOEXEC)
libc = ctypes.CDLL(None, use_errno=True)
libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int,
                      ctypes.c_int, ctypes.c_long]
libc.mmap.restype = ctypes.c_void_p
def proc_values():
    os.lseek(status_fd, 0, os.SEEK_SET)
    payload = os.read(status_fd, 16384).decode("ascii")
    values = {}
    for line in payload.splitlines():
        key, sep, value = line.partition(":")
        if sep and key in ("VmRSS", "VmSize", "VmData"):
            values[key] = int(value.split()[0]) * 1024
    if set(values) != {"VmRSS", "VmSize", "VmData"}:
        raise RuntimeError("required native headroom metrics missing")
    return values
'''
    return (
        {
            "subcase": "AS",
            "preseal": prefix,
            "postseal": r'''
before = proc_values()
as_soft, as_hard = resource.getrlimit(resource.RLIMIT_AS)
data_soft, data_hard = resource.getrlimit(resource.RLIMIT_DATA)
page = os.sysconf("SC_PAGE_SIZE")
remaining = as_soft - before["VmSize"]
request = max(page, remaining + page)
if before["VmData"] >= data_soft or before["VmRSS"] >= 64 * 1024 * 1024:
    raise RuntimeError("AS control cannot isolate DATA/RSS headroom")
ctypes.set_errno(0)
address = libc.mmap(None, request, 0, mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
call_errno = ctypes.get_errno()
failed = address == ctypes.c_void_p(-1).value
after = proc_values()
print(json.dumps({"subcase": "AS", "request_bytes": request, "mmap_failed": failed,
                  "errno": call_errno, "as_soft": as_soft, "as_hard": as_hard,
                  "data_soft": data_soft, "data_hard": data_hard,
                  "before": before, "after": after}, separators=(",", ":")))
''',
        },
        {
            "subcase": "DATA",
            "preseal": prefix,
            "postseal": r'''
before = proc_values()
as_soft, as_hard = resource.getrlimit(resource.RLIMIT_AS)
data_soft, data_hard = resource.getrlimit(resource.RLIMIT_DATA)
request = 129 * 1024 * 1024
margin = 16 * 1024 * 1024
if before["VmSize"] + request + margin >= as_soft:
    raise RuntimeError("DATA control lacks measured AS headroom")
if before["VmData"] + request <= data_soft:
    raise RuntimeError("DATA demand does not exceed measured DATA limit")
ctypes.set_errno(0)
address = libc.mmap(None, request, mmap.PROT_READ | mmap.PROT_WRITE,
                    mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS, -1, 0)
call_errno = ctypes.get_errno()
failed = address == ctypes.c_void_p(-1).value
after = proc_values()
print(json.dumps({"subcase": "DATA", "request_bytes": request, "mmap_failed": failed,
                  "errno": call_errno, "as_soft": as_soft, "as_hard": as_hard,
                  "data_soft": data_soft, "data_hard": data_hard,
                  "before": before, "after": after}, separators=(",", ":")))
''',
        },
        {
            "subcase": "RSS",
            "preseal": prefix,
            "postseal": r'''
before = proc_values()
as_soft, as_hard = resource.getrlimit(resource.RLIMIT_AS)
data_soft, data_hard = resource.getrlimit(resource.RLIMIT_DATA)
page = os.sysconf("SC_PAGE_SIZE")
request = 129 * 1024 * 1024
if before["VmSize"] + request + 16 * 1024 * 1024 >= as_soft:
    raise RuntimeError("RSS control lacks measured AS headroom")
if before["VmData"] >= data_soft:
    raise RuntimeError("RSS control starts without DATA headroom")
memory = mmap.mmap(-1, request, flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                   prot=mmap.PROT_READ | mmap.PROT_WRITE)
for index in range(0, request, page):
    memory[index] = 1
    if index % (4 * 1024 * 1024) == 0:
        os.write(1, b".")
    if index % (16 * 1024 * 1024) == 0:
        time.sleep(0.001)
print(json.dumps({"subcase": "RSS", "request_bytes": request,
                  "as_soft": as_soft, "as_hard": as_hard,
                  "data_soft": data_soft, "data_hard": data_hard,
                  "before": before, "after": proc_values()}, separators=(",", ":")))
''',
        },
        {
            "subcase": "stdout",
            "preseal": prefix,
            "postseal": "os.write(1, b'x' * 65537)\n",
        },
        {
            "subcase": "stderr",
            "preseal": prefix,
            "postseal": "os.write(2, b'x' * 16385)\n",
        },
    )


def frozen_child_script_hashes(tests_root, fixture_root, runtime_root, pass_fds, *, node_suffix=None):
    """Materialize only this matrix's frozen string templates, never execute child code."""
    from lq04_controls import build_sealed_script
    tests_root = Path(tests_root)
    substitutions = {
        'str(secondary)': str(Path(fixture_root) / 'P2-mp3-libmp3lame.mp3'),
        'str(sentinel_root)': str(Path(runtime_root) / 'N6-late-import'),
        "str(Path(__file__).resolve().parents[1] / 'src')": str(tests_root.parent / 'src'),
    }
    if pass_fds:
        if len(pass_fds) != 1 or type(pass_fds[0]) is not int or not 3 <= pass_fds[0] < 2**31:
            raise ValueError('runtime FD substitution violates declared integer/range contract')
        substitutions['descriptor'] = pass_fds[0]

    def string_value(node):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            chunks = []
            for part in node.values:
                if isinstance(part, ast.Constant):
                    chunks.append(part.value)
                elif isinstance(part, ast.FormattedValue) and part.format_spec is None:
                    key = ast.unparse(part.value)
                    if key not in substitutions:
                        return None
                    value = substitutions[key]
                    chunks.append(repr(value) if part.conversion == 114 else str(value))
                else:
                    raise ValueError('unsupported frozen control string expression')
            return ''.join(chunks)
        return None

    scripts = set()
    formal = ast.parse((tests_root / 'test_upload_lq04_formal.py').read_text())
    for function in formal.body:
        if not isinstance(function, ast.FunctionDef) or not function.name.startswith('test_formal_'):
            continue
        if node_suffix and function.name != node_suffix:
            continue
        values = {}
        events = sorted((node for node in ast.walk(function)
                         if isinstance(node, (ast.Assign, ast.AugAssign, ast.Call))),
                        key=lambda node: (node.lineno, node.col_offset))
        for node in events:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                name = node.targets[0].id
                value = string_value(node.value)
                if value is not None:
                    values[name] = value
                    if name == 'script':
                        scripts.add(hashlib.sha256(value.encode()).hexdigest())
            elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
                value = string_value(node.value)
                if node.target.id in values and value is not None and isinstance(node.op, ast.Add):
                    values[node.target.id] += value
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
                    'run_sealed_control', 'build_sealed_script'} and len(node.args) >= 2:
                parts = [values.get(arg.id) if isinstance(arg, ast.Name) else string_value(arg)
                         for arg in node.args[:2]]
                if all(isinstance(part, str) for part in parts):
                    scripts.add(hashlib.sha256(build_sealed_script(*parts).encode()).hexdigest())
        if function.name.endswith('n8_resource_record_and_output_limits_fail_closed'):
            for spec in native_n8_control_specs():
                scripts.add(hashlib.sha256(build_sealed_script(spec['preseal'], spec['postseal']).encode()).hexdigest())
    if node_suffix is None or node_suffix.startswith(('test_formal_p', 'test_formal_n1_')):
        validator = ast.parse((tests_root.parent / 'src/audioscribe/upload/validator.py').read_text())
        function = next(node for node in validator.body if isinstance(node, ast.FunctionDef) and node.name == '_run_child')
        for node in ast.walk(function):
            if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'script' for target in node.targets):
                value = string_value(node.value)
                if value is not None:
                    scripts.add(hashlib.sha256(value.encode()).hexdigest())
    return scripts


def proc_start_ticks(pid: int) -> int:
    text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    closing = text.rfind(")")
    if closing < 0:
        raise ValueError("malformed proc stat comm field")
    fields = text[closing + 1 :].split()
    if len(fields) <= 19:
        raise ValueError("proc stat lacks start ticks")
    return int(fields[19])


def _process_is_zombie_or_gone(pid: int, tracee: Mapping[str, object]) -> bool:
    """True when the tracee already left its live-mm state (reaped, zombie, or exit trace-stop).

    Sampling is opportunistic: an exiting tracee released its mm and has no live
    resource metrics to sample. A live traced child always carries Vm*/Threads.
    """
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except OSError:
        return True
    closing = text.rfind(")")
    if closing < 0:
        return False
    fields = text[closing + 1 :].split()
    if len(fields) <= 19:
        return False
    try:
        if int(fields[19]) != int(tracee["start_ticks"]):
            return False
    except (TypeError, ValueError):
        return False
    if fields[0] in {"Z", "X", "x"}:
        return True
    try:
        maps_text = Path(f"/proc/{pid}/maps").read_text(encoding="ascii")
    except OSError:
        return True
    return maps_text.strip() == ""


def read_process_status(pid: int) -> dict[str, int]:
    fields: dict[str, int] = {}
    with open(f"/proc/{pid}/status", encoding="ascii") as stream:
        for line in stream:
            name, separator, raw = line.partition(":")
            if not separator:
                continue
            parts = raw.split()
            if name in {"VmRSS", "VmHWM", "VmSize", "VmData"}:
                if len(parts) < 2 or parts[1] != "kB":
                    raise ValueError(f"malformed proc status value {name}")
                fields[{"VmRSS": "rss_bytes", "VmHWM": "vmhwm_bytes",
                        "VmSize": "vmsize_bytes", "VmData": "vmdata_bytes"}[name]] = int(parts[0]) * 1024
            elif name == "Threads":
                fields["thread_count"] = int(parts[0])
    required = {"rss_bytes", "vmhwm_bytes", "vmsize_bytes", "vmdata_bytes", "thread_count"}
    if not required.issubset(fields):
        raise ValueError("required live proc metrics missing")
    return fields


def read_process_limits(pid: int) -> dict[str, int]:
    limits = {
        "as_soft_bytes": resource.RLIMIT_AS,
        "as_hard_bytes": resource.RLIMIT_AS,
        "data_soft_bytes": resource.RLIMIT_DATA,
        "data_hard_bytes": resource.RLIMIT_DATA,
        "cpu_soft_seconds": resource.RLIMIT_CPU,
        "cpu_hard_seconds": resource.RLIMIT_CPU,
    }
    result: dict[str, int] = {}
    for name, resource_id in limits.items():
        soft, hard = resource.prlimit(pid, resource_id)
        value = soft if name.endswith("soft_bytes") or name.endswith("soft_seconds") else hard
        if value == resource.RLIM_INFINITY or value < 0:
            raise ValueError(f"unbounded live rlimit {name}")
        result[name] = int(value)
    return result


def find_live_mapping(pid: int, address: int, *, allow_anonymous_zero: bool = False) -> dict[str, object]:
    with open(f"/proc/{pid}/maps", encoding="ascii") as stream:
        for line in stream:
            parts = line.rstrip("\n").split(maxsplit=5)
            start_text, end_text = parts[0].split("-", 1)
            start, end = int(start_text, 16), int(end_text, 16)
            if not start <= address < end:
                continue
            major_text, minor_text = parts[3].split(":", 1)
            path = parts[5] if len(parts) > 5 else ""
            anonymous_zero = allow_anonymous_zero and path == '/dev/zero (deleted)' and 'x' not in parts[1]
            if path.endswith(" (deleted)") and not anonymous_zero:
                raise ValueError("mapped file was deleted during observer capture")
            return {
                "start": start,
                "end": end,
                "permissions": parts[1],
                "offset": int(parts[2], 16),
                "device": os.makedev(int(major_text, 16), int(minor_text, 16)),
                "inode": int(parts[4]),
                "path": path if path.startswith("/") and not anonymous_zero else None,
                "kernel_label": path if anonymous_zero else None,
            }
    raise ValueError(f"ptrace mmap result {address:#x} is absent from proc maps")


def proc_maps_overlap(pid: int, start: int, end: int) -> bool:
    with open(f"/proc/{pid}/maps", encoding="ascii") as stream:
        for line in stream:
            range_text = line.split(maxsplit=1)[0]
            first, last = range_text.split("-", 1)
            mapping_start, mapping_end = int(first, 16), int(last, 16)
            if mapping_start < end and start < mapping_end:
                return True
    return False


def prot_permissions(prot: int) -> str:
    return ("r" if prot & 1 else "-") + ("w" if prot & 2 else "-") + ("x" if prot & 4 else "-")


def _validate_native_provenance(record: Mapping[str, object]) -> None:
    for field in ("source_sha256", "policy_sha256", "collector_sha256", "manifest_sha256",
                  "origin", "collector_id"):
        if field not in record:
            raise ValueError(f"native evidence requires {field}")
    for field in ("source_sha256", "policy_sha256", "collector_sha256", "manifest_sha256"):
        if not isinstance(record[field], str) or not _SHA256.fullmatch(record[field]):
            raise ValueError(f"{field} must be a lowercase SHA-256")
    for field in ("origin", "collector_id"):
        if not isinstance(record[field], str) or not record[field]:
            raise ValueError(f"{field} must be a nonempty string")
    for field in ("pid",):
        if type(record.get(field)) is not int or record[field] <= 0:
            raise ValueError(f"native evidence requires positive {field}")
    start_ticks = record.get("start_ticks")
    if start_ticks is None:
        compact_values = record.get("values")
        tracee_referenced = (
            record.get("record_type") == "syscall-event"
            and isinstance(compact_values, Mapping)
            and (compact_values.get("compact") is True or isinstance(compact_values.get("batch"), list))
        )
        if not tracee_referenced:
            raise ValueError("native evidence requires positive start_ticks")
    elif type(start_ticks) is not int or start_ticks <= 0:
        raise ValueError("native evidence requires positive start_ticks")


def parse_record(raw: bytes) -> dict[str, object]:
    if not isinstance(raw, bytes) or len(raw) > _MAX_RECORD_BYTES:
        raise ValueError("record input must be bytes no larger than 16 KiB")

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    try:
        decoded = json.loads(raw, object_pairs_hook=unique_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"malformed evidence JSON: {error}") from error
    return validate_record(decoded)


class SyntheticEventContract:
    """UNIT-only event transcript; it performs no ptrace, wait, or child I/O."""

    _EVENTS = {"exec-stop", "syscall-entry", "syscall-exit", "signal-delivery", "terminal"}

    def __init__(self, pid: int, start_ticks: int):
        if type(pid) is not int or pid <= 0 or type(start_ticks) is not int or start_ticks <= 0:
            raise ValueError("synthetic child identity must be positive integers")
        self.pid = pid
        self.start_ticks = start_ticks
        self._exec_seen = False
        self._syscall_open = False
        self._terminal_seen = False
        self._events: list[dict[str, object]] = []

    @property
    def terminal_seen(self) -> bool:
        return self._terminal_seen

    def accept(self, event: Mapping[str, object]) -> None:
        if not isinstance(event, Mapping):
            raise ValueError("synthetic event must be an object")
        if self._terminal_seen:
            raise ValueError("event follows terminal observation")
        if event.get("pid") != self.pid or event.get("start_ticks") != self.start_ticks:
            raise ValueError("event does not match registered pid/start-tick identity")
        kind = event.get("event")
        if not isinstance(kind, str) or kind not in self._EVENTS:
            raise ValueError("unknown synthetic event")
        if not self._exec_seen:
            if kind != "exec-stop":
                raise ValueError("first owned event must be the post-exec stop")
            self._exec_seen = True
        elif kind == "exec-stop":
            raise ValueError("duplicate post-exec stop")
        elif kind == "syscall-entry":
            if self._syscall_open or type(event.get("syscall_nr")) is not int:
                raise ValueError("invalid or overlapping syscall entry")
            self._syscall_open = True
        elif kind == "syscall-exit":
            if not self._syscall_open or type(event.get("result")) is not int:
                raise ValueError("syscall exit has no matching entry or integer result")
            self._syscall_open = False
        elif kind == "signal-delivery":
            if type(event.get("signal")) is not int or event["signal"] <= 0:
                raise ValueError("signal delivery requires a positive signal number")
        elif kind == "terminal":
            if self._syscall_open or type(event.get("wait_status")) is not int:
                raise ValueError("terminal outcome requires closed syscall and raw wait status")
            if not isinstance(event.get("rusage"), Mapping):
                raise ValueError("terminal outcome requires raw rusage mapping")
            self._terminal_seen = True
        self._events.append(dict(event))

    def transcript(self) -> dict[str, object]:
        return {
            "evidence_kind": "unit-simulated",
            "observer_status": "NOT_NATIVE",
            "terminal_seen": self._terminal_seen,
            "event_count": len(self._events),
            "events": [dict(event) for event in self._events],
        }
