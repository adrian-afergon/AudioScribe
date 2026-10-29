"""Fixed local L-Q04 groups for C-LQ04-BOOTSTRAP-01; invoke only after freeze."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import json
import mmap
import os
import signal
import socket
import subprocess
import sys
import threading
import time

if sys.platform == "linux":
    import fcntl
from pathlib import Path

import pytest

from audioscribe.upload.validator import (
    InvalidMediaError,
    ValidatorIsolationError,
    _WALL_SECONDS,
    _apply_validator_limits,
    _child_rss_bytes,
    _parse_child_record,
    validate_media,
)
from lq04_controls import run_sealed_control
from lq04_fixture_hashes import LQ04_FIXTURE_SHA256, fixture_sha256

pytest_plugins = ("lq04_evidence",) if sys.platform == "linux" else ()


def _drain_child(process, *, deadline):
    from audioscribe.upload import validator
    return validator._drain_child(process, deadline=deadline)


FIXTURE_ROOT = Path(os.environ.get(
    "AUDIOSCRIBE_LQ04_FIXTURE_ROOT",
    "/tmp/opencode/audioscribe-plan01.dJebPg/lq04-fixtures/C-LQ04-BOOTSTRAP-01",
))

# This file is the Linux qualification harness (LQ04): it exercises the real
# isolated validator child, which is only qualified for Linux, against the
# hash-pinned fixture bootstrap.
pytestmark = [
    pytest.mark.skipif(sys.platform != "linux",
                       reason="the isolated media validator is qualified for Linux only"),
    pytest.mark.skipif(not FIXTURE_ROOT.is_dir(),
                       reason="LQ04 fixtures are not available; run the qualification bootstrap"),
]


@pytest.fixture(autouse=True)
def _formal_case_watchdog():
    prior = signal.getsignal(signal.SIGALRM)

    def expired(_signum, _frame):
        raise TimeoutError("formal L-Q04 case exceeded its 45 second watchdog")

    signal.signal(signal.SIGALRM, expired)
    signal.alarm(45)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, prior)


@pytest.fixture
def _evidence_capture(_formal_evidence_capture):
    return _formal_evidence_capture


@pytest.fixture(autouse=True)
def _formal_evidence_capture(request):
    from lq04_evidence import EvidenceCapture
    from audioscribe.upload import validator as validator_module

    capture = EvidenceCapture.from_environment(
        node_id=request.node.nodeid,
        validator_module=validator_module,
    )
    with capture:
        yield capture
        report = getattr(request.node, "rep_call", None)
        if report is not None:
            capture.record_case_result(request.node.nodeid, report)


def _fixture(label: str) -> Path:
    path = FIXTURE_ROOT / label
    assert path.is_file(), f"required frozen fixture missing: {label}"
    digest = fixture_sha256(path)
    assert digest == LQ04_FIXTURE_SHA256[label], f"frozen fixture changed: {label}"
    from lq04_evidence import active_evidence_capture

    capture = active_evidence_capture()
    if capture is not None:
        capture.record_fixture(label, path, digest)
    return path


def test_formal_p1_original_video_only_mp4():
    result = validate_media(_fixture("P1-video-only-mpeg4.mp4"), ".mp4")
    print("P1", result)
    assert result.valid is True
    assert result.has_media_frame is True
    assert result.audio_streams == 0
    assert result.video_streams == 1
    assert result.child_threads_before_seal == 1
    assert result.parent_peak_threads == 1
    assert result.preloaded_stream_wrappers == 3
    assert result.input_bytes_before_seal == 0
    assert result.input_bytes_after_open > 0


def test_formal_p2_genuine_mp3():
    result = validate_media(_fixture("P2-mp3-libmp3lame.mp3"), ".mp3")
    print("P2", result)
    assert result.valid is True
    assert result.has_media_frame is True
    assert result.audio_streams >= 1


def test_formal_p3_audio_bearing_mp4():
    result = validate_media(_fixture("P3-audio-bearing-aac.mp4"), ".mp4")
    print("P3", result)
    assert result.valid is True
    assert result.has_media_frame is True
    assert result.audio_streams >= 1


def test_formal_p4_h264_mp4():
    result = validate_media(_fixture("P4-video-h264.mp4"), ".mp4")
    print("P4", result)
    assert result.valid is True
    assert result.has_media_frame is True
    assert result.video_streams >= 1


def test_formal_n1_empty_malformed_brand_and_extension_mismatch():
    from lq04_evidence import active_evidence_capture

    cases = (
        ("N1-empty.mp3", ".mp3"),
        ("N1-malformed.mp4", ".mp4"),
        ("N1-quicktime-brand.mp4", ".mp4"),
        ("N1-extension-mismatch.mp3", ".mp3"),
    )
    for name, extension in cases:
        capture = active_evidence_capture()
        if capture is not None:
            capture.set_subcase(name, evidence_kind="native-control")
        before_pids = set(capture.processes) if capture is not None else set()
        with pytest.raises(InvalidMediaError) as rejection:
            validate_media(_fixture(name), extension)
        if capture is not None:
            new_pids = sorted(set(capture.processes) - before_pids)
            capture.record_parent_event('N1-rejection', {
                'fixture_path': name, 'exception_type': type(rejection.value).__name__,
                'popen_registrations_before': len(before_pids), 'popen_registrations_after': len(capture.processes),
                'exception_message': str(rejection.value)[:512],
                'phase': 'after-child' if new_pids else 'before-child',
                'child_metadata': {'status': 'OBSERVED', 'pids': new_pids} if new_pids else {
                    'status': 'NA', 'reason': 'rejection occurred with zero new Popen registrations'}})
        print("N1 expected safe rejection", name)


def test_formal_n2_secondary_file_denied_readonly_descriptor_preserved(tmp_path):
    input_file = _fixture("P1-video-only-mpeg4.mp4")
    secondary = _fixture("P2-mp3-libmp3lame.mp3")
    sentinel = fixture_sha256(secondary)
    from lq04_evidence import active_evidence_capture
    capture = active_evidence_capture()
    if capture is not None:
        capture.record_parent_event('N2-sentinel-before', {'path': secondary.name, 'sha256': sentinel})
    descriptor = os.open(input_file, os.O_RDONLY)
    try:
        preseal = (
            "import errno, fcntl, json, os\n"
            f"fd = {descriptor}\n"
            f"secondary = {str(secondary)!r}\n"
        )
        postseal = """
access = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
data = os.read(fd, 4)
try:
    os.write(fd, b"X")
except OSError as error:
    write_errno = error.errno
else:
    write_errno = 0
for flags in (os.O_RDONLY, os.O_WRONLY):
    try:
        os.open(secondary, flags)
    except OSError as error:
        open_errors.append(error.errno)
    else:
        open_errors.append(0)
print(json.dumps({"access": access, "read": data.hex(), "write_errno": write_errno,
                  "secondary_open_errno": open_errors}))
"""
        # Keep this local mutable list in the child's trusted pre-seal startup.
        preseal += "open_errors = []\n"
        record, _measurements = run_sealed_control(preseal, postseal, (descriptor,))
    finally:
        os.close(descriptor)
    assert record["access"] == os.O_RDONLY
    assert record["read"] != ""
    assert record["write_errno"] == errno.EBADF
    assert record["secondary_open_errno"] == [errno.EPERM, errno.EPERM]
    after_sentinel = fixture_sha256(secondary)
    if capture is not None:
        capture.record_parent_event('N2-sentinel-after', {'path': secondary.name, 'sha256': after_sentinel})
    assert after_sentinel == sentinel
    print("N2", record, "sentinel-preserved", sentinel)


def test_formal_n3_network_socket_families_denied_without_traffic():
    preseal = "import errno, json, socket\n"
    postseal = """
errors = []
for family in (socket.AF_INET, socket.AF_UNIX):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        errors.append(error.errno)
    else:
        sock.close()
        errors.append(0)
print(json.dumps({"socket_errno": errors}))
"""
    record, measurements = run_sealed_control(preseal, postseal)
    assert record["socket_errno"] == [errno.EPERM, errno.EPERM]
    assert measurements.peak_threads == 1
    print("N3", record, "peak-threads", measurements.peak_threads)


def test_formal_n4_exec_clone_and_io_uring_denied(_evidence_capture):
    _evidence_capture.set_subcase("N4-native-denials", evidence_kind="native-control")
    preseal = """
import ctypes, ctypes.util, errno, json, os, subprocess, threading
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
seccomp_lib = ctypes.CDLL(ctypes.util.find_library("seccomp"))
seccomp_lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
seccomp_lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
syscalls = {name: seccomp_lib.seccomp_syscall_resolve_name(name.encode())
            for name in ("clone3", "io_uring_setup")}
"""
    postseal = """
errors = {}
try:
    os.fork()
except OSError as error:
    errors["fork"] = error.errno
else:
    errors["fork"] = 0
try:
    os.execve("/bin/true", ["true"], {})
except OSError as error:
    errors["exec"] = error.errno
else:
    errors["exec"] = 0
try:
    threading.Thread(target=lambda: None).start()
except RuntimeError as error:
    errors["thread_exception"] = type(error).__name__
else:
    errors["thread_exception"] = "none"
clone_args = (ctypes.c_ulong * 11)()
ctypes.set_errno(0)
libc.syscall(syscalls["clone3"], ctypes.byref(clone_args), ctypes.sizeof(clone_args))
errors["clone3"] = ctypes.get_errno()
params = (ctypes.c_ulong * 64)()
ctypes.set_errno(0)
libc.syscall(syscalls["io_uring_setup"], 1, ctypes.byref(params))
errors["io_uring"] = ctypes.get_errno()
print(json.dumps(errors))
"""
    record, measurements = run_sealed_control(preseal, postseal)
    assert record == {"fork": errno.EPERM, "exec": errno.EPERM,
                      "thread_exception": "RuntimeError", "clone3": errno.EPERM,
                      "io_uring": errno.EPERM}
    assert measurements.peak_threads == 1
    clone_denial = any(
        item.get("record_type") == "syscall-event"
        and item.get("subcase") == "N4-native-denials"
        and item.get("values", {}).get("phase") == "exit"
        and item.get("values", {}).get("name") in {"clone", "clone3"}
        and item.get("values", {}).get("clone_flags", 0) & 0x10000
        and item.get("values", {}).get("errno") == errno.EPERM
        for item in _evidence_capture.iter_records()
    )
    assert clone_denial is True
    print("N4", record, "peak-threads", measurements.peak_threads)


def test_formal_n5_only_expected_readonly_input_descriptor_inherited():
    media = _fixture("P1-video-only-mpeg4.mp4")
    expected = media.stat()
    descriptor = os.open(media, os.O_RDONLY)
    try:
        preseal = f"""
import fcntl, json, os, stat
fd = {descriptor}
directory_fd = os.open("/proc/self/fd", os.O_RDONLY | os.O_DIRECTORY)
entries = sorted(int(name) for name in os.listdir(directory_fd) if name.isdigit())
os.close(directory_fd)
def descriptor_is_open(item):
    try:
        os.fstat(item)
        return True
    except OSError:
        return False
entries = [item for item in entries if descriptor_is_open(item)]
flags = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
info = os.fstat(fd)
"""
        postseal = """
info = os.fstat(fd)
print(json.dumps({"fds": entries, "input_fd": fd, "flags": flags,
                  "regular": stat.S_ISREG(info.st_mode), "device": info.st_dev,
                  "inode": info.st_ino, "size": info.st_size}))
"""
        record, _measurements = run_sealed_control(preseal, postseal, (descriptor,))
    finally:
        os.close(descriptor)
    assert set(record["fds"]) == {0, 1, 2, record["input_fd"]}
    assert record["flags"] == os.O_RDONLY
    assert record["regular"] is True
    assert (record["device"], record["inode"], record["size"]) == (
        expected.st_dev, expected.st_ino, expected.st_size
    )
    print("N5", record)


def test_formal_n6_missing_bootstrap_fails_before_media_read_and_late_import_is_denied(_evidence_capture):
    _evidence_capture.set_subcase("N6-missing-bootstrap", evidence_kind="native-control")
    media = _fixture("P1-video-only-mpeg4.mp4")
    descriptor = os.open(media, os.O_RDONLY)
    try:
        preseal = f"""
import importlib.abc, json, os, sys
fd = {descriptor}
class MissingSubtitleBootstrap(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "av.subtitles.stream":
            raise ImportError("fixed bootstrap dependency unavailable")
        return None
sys.meta_path.insert(0, MissingSubtitleBootstrap())
import av
from av.audio.stream import AudioStream
try:
    from av.subtitles.stream import SubtitleStream
except ImportError:
    print(json.dumps({{"bootstrap_failed_closed": True,
                      "input_offset": os.lseek(fd, 0, os.SEEK_CUR)}}))
    sys.exit(0)
"""
        # An intentional missing trusted module exits before sandbox/open; the helper's seal is bypassed only by this preseal sys.exit.
        missing = run_sealed_control(preseal, "raise AssertionError('should not reach seal')", (descriptor,))[0]
    finally:
        os.close(descriptor)
    assert missing == {"bootstrap_failed_closed": True, "input_offset": 0}
    print("N6 missing-bootstrap", missing)

    runtime_root = Path(os.environ["AUDIOSCRIBE_LQ04_RUNTIME_ROOT"])
    sentinel_root = runtime_root / "N6-late-import"
    sentinel_root.mkdir(mode=0o700, exist_ok=False)
    unexpected_module = sentinel_root / "unexpected_lq04_dependency.py"
    unexpected_module.write_text("marker = 1\n", encoding="utf-8")
    preseal = f"""
import importlib, json, sys
sys.path.insert(0, {str(sentinel_root)!r})
import av
from av.audio.stream import AudioStream
from av.subtitles.stream import SubtitleStream
from av.video.stream import VideoStream
"""
    postseal = """
try:
    importlib.import_module("unexpected_lq04_dependency")
except OSError as error:
    denied = error.errno == 1
else:
    denied = False
print(json.dumps({"unexpected_import_denied": denied}))
"""
    _evidence_capture.set_subcase("N6-late-import", evidence_kind="native-control")
    late, _measurements = run_sealed_control(preseal, postseal)
    assert late["unexpected_import_denied"] is True
    print("N6 post-seal-import", late)


def test_formal_n7_closed_pipes_live_child_is_killed_and_reaped(_evidence_capture):
    from audioscribe.upload.validator import _WALL_SECONDS

    script = (
        "import os,sys,time\n"
        f"sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / 'src')!r})\n"
        "from audioscribe.upload.sandbox import restrict_local_io\n"
        "restrict_local_io()\n"
        "os.close(1); os.close(2); time.sleep(35)\n"
    )
    started = time.monotonic()
    deadline = started + _WALL_SECONDS
    _evidence_capture.set_subcase("N7-closed-pipes", evidence_kind="native-control")
    _evidence_capture.set_next_deadline(deadline)
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", script], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        start_new_session=True, preexec_fn=_apply_validator_limits,
    )
    with pytest.raises(TimeoutError, match="deadline"):
        _drain_child(process, deadline=deadline)
    assert process.poll() is not None
    elapsed = time.monotonic() - started
    assert elapsed <= _WALL_SECONDS
    print("N7 pipe-eof-live-child timeout/reaped", round(elapsed, 3), "returncode", process.returncode)
    from audioscribe.upload import validator
    _evidence_capture.set_subcase('N7-controlled-cancellation', evidence_kind='native-control')
    _evidence_capture.set_next_deadline(time.monotonic() + _WALL_SECONDS)
    cancelled = subprocess.Popen(
        [sys.executable, '-I', '-c', script], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        start_new_session=True, preexec_fn=_apply_validator_limits,
    )
    tracee = _evidence_capture.supervisor.tracees[cancelled.pid]
    _evidence_capture._emit_record('termination', pid=cancelled.pid,
        start_ticks=tracee['start_ticks'], values={
            'stage': 'controlled-cancellation-request', 'actor': 'N7-controlled-helper',
            'monotonic_ns': time.monotonic_ns()})
    validator._kill_child(cancelled)
    assert cancelled.poll() is not None
    assert tracee['terminal_seen'] is True
    assert tracee['terminal_delivered'] is True


def test_formal_n7_cpu_limit_terminates_child(_evidence_capture):
    from lq04_controls import build_sealed_script

    preseal = "import json\n"
    postseal = "while True:\n    pass\n"
    script = build_sealed_script(preseal, postseal)
    _evidence_capture.set_subcase("N7-CPU30-outer45", evidence_kind="native-control")
    started = time.monotonic()
    deadline = started + 45
    _evidence_capture.set_next_deadline(deadline)
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", script], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True,
        start_new_session=True, preexec_fn=_apply_validator_limits,
    )
    measurements = _drain_child(process, deadline=deadline)
    elapsed = time.monotonic() - started
    assert measurements.returncode != 0
    assert process.poll() is not None
    assert elapsed <= 45
    pid = process.pid
    terminal = next(
        item for item in _evidence_capture.iter_records()
        if item.get("record_type") == "run-event" and item.get("pid") == pid
        and item.get("subcase") == "N7-CPU30-outer45"
        and item.get("values", {}).get("event") == "terminal"
    )
    usage = terminal["values"]["rusage"]
    assert os.WIFSIGNALED(terminal["values"]["wait_status"])
    assert os.WTERMSIG(terminal['values']['wait_status']) == signal.SIGKILL
    assert usage["user_seconds"] + usage["system_seconds"] >= 30 - 1 / os.sysconf('SC_CLK_TCK')
    assert any(
        item.get("record_type") == "resource-sample"
        and item.get("pid") == pid
        and item.get("subcase") == "N7-CPU30-outer45"
        and item.get("values", {}).get("cpu_soft_seconds") == 30
        and item.get("values", {}).get("cpu_hard_seconds") == 30
        for item in _evidence_capture.iter_records()
    )
    assert not any(
        item.get("record_type") == "termination"
        and item.get("pid") == pid
        and item.get("values", {}).get("actor", "").startswith("parent-os.kill")
        for item in _evidence_capture.iter_records()
    )
    print("N7 CPU exhaustion/reaped", round(elapsed, 3), "returncode", measurements.returncode)


def test_formal_n8_resource_record_and_output_limits_fail_closed(_evidence_capture):
    from lq04_evidence import native_n8_control_specs
    from audioscribe.upload.validator import _child_rss_bytes, _parse_child_record

    base = {
        "valid": False,
        "has_media_frame": False,
        "audio_streams": 0,
        "video_streams": 0,
        "container_format": "",
        "child_peak_rss_kib": 100,
        "child_vm_hwm_kib": 100,
        "child_threads_before_seal": 1,
        "preloaded_stream_wrappers": 3,
        "input_bytes_before_seal": 0,
        "input_bytes_after_open": 0,
    }
    malformed_records = []
    for mutate in (
        lambda value: value.pop("container_format"),
        lambda value: value.update(child_peak_rss_kib=True),
        lambda value: value.update(unexpected="not allowed"),
        lambda value: value.update(input_bytes_after_open=20_000_000_001),
    ):
        candidate = dict(base)
        mutate(candidate)
        malformed_records.append(candidate)
    _evidence_capture.set_subcase("strict-records", evidence_kind="unit-injected")
    for index, record in enumerate(malformed_records):
        with pytest.raises(ValidatorIsolationError):
            _parse_child_record(json.dumps(record).encode())
        _evidence_capture._emit_record(
            "resource-sample",
            pid=os.getpid(),
            start_ticks=1,
            status="OBSERVED",
            values={"unit_assertion": "strict-child-record-rejected", "case_index": index},
        )
    with pytest.raises(ValidatorIsolationError, match="RSS metric"):
        _child_rss_bytes(2**30)
    _evidence_capture._emit_record(
        "resource-sample",
        pid=os.getpid(),
        start_ticks=1,
        status="MISSING",
        reason="injected unavailable RSS PID; UNIT only",
        values={"unit_assertion": "missing-rss-fails-closed"},
    )

    controls = {item["subcase"]: item for item in native_n8_control_specs()}
    for subcase in ("AS", "DATA"):
        _evidence_capture.set_subcase(f"N8-{subcase}", evidence_kind="native-control")
        control = controls[subcase]
        record, _measurements = run_sealed_control(
            control["preseal"], control["postseal"], deadline_seconds=30
        )
        assert record["subcase"] == subcase
        assert record["mmap_failed"] is True
        assert record["errno"] == errno.ENOMEM
        assert record["as_soft"] == 256 * 1024 * 1024
        assert record["data_soft"] == 128 * 1024 * 1024
        if subcase == "AS":
            assert record["before"]["VmData"] < record["data_soft"]
            assert record["before"]["VmRSS"] < 128 * 1024 * 1024
            assert record["before"]["VmSize"] + record["request_bytes"] > record["as_soft"]
        else:
            assert record["before"]["VmSize"] + record["request_bytes"] + 16 * 1024 * 1024 < record["as_soft"]
            assert record["before"]["VmData"] + record["request_bytes"] > record["data_soft"]
        assert any(
            item.get("record_type") == "syscall-event"
            and item.get("subcase") == f"N8-{subcase}"
            and item.get("values", {}).get("name") == "mmap"
            and item.get("values", {}).get("phase") == "exit"
            and item.get("values", {}).get("errno") == errno.ENOMEM
            and item.get("values", {}).get("result", 0) < 0
            for item in _evidence_capture.iter_records()
        )

    _evidence_capture.set_subcase("N8-RSS", evidence_kind="native-control")
    rss = controls["RSS"]
    with pytest.raises(ValidatorIsolationError, match="RSS target"):
        run_sealed_control(rss["preseal"], rss["postseal"], deadline_seconds=30)
    samples = (
        record for record in _evidence_capture.iter_records()
        if record.get("record_type") == "resource-sample"
        and record.get("subcase") == "N8-RSS"
    )
    rss_samples = [record["values"] for record in samples]
    assert any(value.get("rss_bytes", 0) > 128 * 1024 * 1024 for value in rss_samples)
    assert all(value.get("as_soft_bytes") == 256 * 1024 * 1024 for value in rss_samples)
    assert all(value.get("data_soft_bytes") == 128 * 1024 * 1024 for value in rss_samples)
    assert all(value.get("vmdata_bytes", 0) < 128 * 1024 * 1024 for value in rss_samples)

    for subcase, descriptor, size, cap in (
        ("N8-stdout", 1, 65_537, 65_536),
        ("N8-stderr", 2, 16_385, 16_384),
    ):
        _evidence_capture.set_subcase(subcase, evidence_kind="native-control")
        stream_name = 'stdout' if descriptor == 1 else 'stderr'
        control = controls[stream_name]
        with pytest.raises(ValidatorIsolationError, match="output budget"):
            run_sealed_control(control['preseal'], control['postseal'],
                                deadline_seconds=30)
        assert _evidence_capture.output_observed(subcase, stream_name) >= cap + 1
