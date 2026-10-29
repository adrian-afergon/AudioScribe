from __future__ import annotations

import json
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path


_MIB = 1024 * 1024
_WALL_SECONDS = 30
_REAP_GRACE_SECONDS = 1.0
_MEMORY_BYTES = 128 * _MIB
_AS_BYTES = 256 * _MIB
_DATA_BYTES = 128 * _MIB
_MAX_MEDIA_BYTES = 20_000_000_000
_STDOUT_LIMIT = 64 * 1024
_STDERR_LIMIT = 16 * 1024
_CHILD_RECORD_KEYS = frozenset({
    "valid", "has_media_frame", "audio_streams", "video_streams",
    "container_format", "child_peak_rss_kib", "child_vm_hwm_kib",
    "child_threads_before_seal", "preloaded_stream_wrappers",
    "input_bytes_before_seal", "input_bytes_after_open",
})
_PARENT_RECORD_KEYS = frozenset({"parent_peak_rss_kib", "parent_peak_threads"})


class InvalidMediaError(ValueError):
    pass


class ValidatorIsolationError(RuntimeError):
    pass


@dataclass(frozen=True)
class MediaValidation:
    valid: bool
    has_media_frame: bool
    audio_streams: int
    video_streams: int
    container_format: str
    child_peak_rss_kib: int
    child_threads_before_seal: int
    preloaded_stream_wrappers: int
    input_bytes_before_seal: int
    input_bytes_after_open: int
    parent_peak_rss_kib: int
    parent_peak_threads: int
    child_vm_hwm_kib: int = 0


@dataclass(frozen=True)
class ChildProcessMeasurements:
    stdout: bytes
    stderr: bytes
    returncode: int
    peak_rss_bytes: int
    peak_threads: int


def validate_media(path: Path, extension: str) -> MediaValidation:
    if os.name != "posix" or sys.platform != "linux":
        raise ValidatorIsolationError("The isolated validator is not qualified for this operating system.")
    path = Path(path)
    extension = extension.lower()
    if extension not in (".mp3", ".mp4"):
        raise InvalidMediaError("unsupported media extension")
    try:
        before = path.lstat()
    except OSError as error:
        raise InvalidMediaError("media file is unavailable") from error
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode) or before.st_size <= 0:
        raise InvalidMediaError("media file must be a nonempty regular file")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise InvalidMediaError("media file could not be opened safely") from error
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != before.st_dev
                or opened.st_ino != before.st_ino or opened.st_size != before.st_size):
            raise InvalidMediaError("media file identity changed before validation")
        header = os.read(descriptor, 12)
        os.lseek(descriptor, 0, os.SEEK_SET)
        if not _signature_matches(extension, header):
            raise InvalidMediaError("media signature does not match its extension")
        stdout, stderr, returncode = _run_child(descriptor, extension)
    finally:
        os.close(descriptor)
    if returncode != 0:
        raise ValidatorIsolationError("The isolated media validator exited unsuccessfully.")
    result = _parse_child_record(stdout, require_parent_metrics=True,
                                 maximum_input_bytes=opened.st_size)
    if not result.valid or not result.has_media_frame:
        failure_type = stderr.decode("ascii", errors="ignore").strip()[:96]
        raise InvalidMediaError(
            f"media container is unreadable (format={result.container_format!r}, "
            f"audio={result.audio_streams}, video={result.video_streams}, "
            f"frame={result.has_media_frame}, {failure_type})"
        )
    return result


def _signature_matches(extension: str, header: bytes) -> bool:
    if extension == ".mp3":
        return header.startswith(b"ID3") or (
            len(header) >= 2 and header[0] == 0xFF and header[1] & 0xE0 == 0xE0
        )
    if len(header) < 12 or header[4:8] != b"ftyp":
        return False
    brand = header[8:12]
    return brand in {b"isom", b"iso2", b"iso3", b"iso4", b"iso5", b"iso6",
                     b"mp41", b"mp42", b"avc1", b"M4V ", b"M4A ", b"MSNV"}


def _apply_validator_limits() -> None:
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (_AS_BYTES, _AS_BYTES))
    resource.setrlimit(resource.RLIMIT_DATA, (_DATA_BYTES, _DATA_BYTES))
    resource.setrlimit(resource.RLIMIT_CPU, (_WALL_SECONDS, _WALL_SECONDS))


def _parse_child_record(payload: bytes, *, require_parent_metrics: bool = False,
                        maximum_input_bytes: int = _MAX_MEDIA_BYTES) -> MediaValidation:
    if len(payload) > _STDOUT_LIMIT:
        raise ValidatorIsolationError("The isolated media validator record exceeds its byte limit.")

    def unique_object(pairs):
        record = {}
        for key, value in pairs:
            if key in record:
                raise ValueError("duplicate JSON key")
            record[key] = value
        return record

    try:
        record = json.loads(payload, object_pairs_hook=unique_object)
    except (UnicodeError, ValueError) as error:
        if str(error) == "duplicate JSON key":
            raise ValidatorIsolationError("The isolated media validator returned a duplicate JSON key.") from error
        raise ValidatorIsolationError("The isolated media validator returned invalid JSON.") from error
    expected_keys = _CHILD_RECORD_KEYS | (_PARENT_RECORD_KEYS if require_parent_metrics else frozenset())
    if type(record) is not dict or set(record) != expected_keys:
        raise ValidatorIsolationError("The isolated media validator returned an invalid record schema.")
    if type(record["valid"]) is not bool or type(record["has_media_frame"]) is not bool:
        raise ValidatorIsolationError("The isolated media validator returned invalid boolean fields.")
    integer_keys = ["audio_streams", "video_streams", "child_peak_rss_kib",
                    "child_vm_hwm_kib", "child_threads_before_seal",
                    "preloaded_stream_wrappers",
                    "input_bytes_before_seal", "input_bytes_after_open"]
    if require_parent_metrics:
        integer_keys.extend(("parent_peak_rss_kib", "parent_peak_threads"))
    for key in integer_keys:
        if type(record[key]) is not int:
            raise ValidatorIsolationError("The isolated media validator returned invalid integer fields.")
    if not 0 <= record["audio_streams"] <= 64 or not 0 <= record["video_streams"] <= 64:
        raise ValidatorIsolationError("The isolated media validator returned out-of-range stream counts.")
    if record["child_peak_rss_kib"] < 0:
        raise ValidatorIsolationError("The isolated media validator returned an out-of-range RSS value.")
    if not 1 <= record["child_vm_hwm_kib"] <= _MEMORY_BYTES // 1024:
        raise ValidatorIsolationError("The isolated media validator returned an out-of-range VM-HWM value.")
    if record["child_threads_before_seal"] != 1:
        raise ValidatorIsolationError("The isolated validator had more than one thread before sealing.")
    if record["preloaded_stream_wrappers"] != 3 or record["input_bytes_before_seal"] != 0:
        raise ValidatorIsolationError("The trusted bootstrap occurred after child input access.")
    if not 0 <= record["input_bytes_after_open"] <= maximum_input_bytes:
        raise ValidatorIsolationError("The isolated validator returned an out-of-range input-byte count.")
    if require_parent_metrics:
        if not 0 <= record["parent_peak_rss_kib"] <= _MEMORY_BYTES // 1024:
            raise ValidatorIsolationError("The parent-observed validator RSS is outside the approved range.")
        if record["parent_peak_threads"] != 1:
            raise ValidatorIsolationError("The parent observed more than one validator thread.")
    container_format = record["container_format"]
    if type(container_format) is not str or len(container_format) > 128:
        raise ValidatorIsolationError("The isolated media validator returned an invalid format field.")
    if record["valid"] != record["has_media_frame"]:
        raise ValidatorIsolationError("The isolated media validator returned an inconsistent result.")
    if record["valid"] and record["input_bytes_after_open"] <= 0:
        raise ValidatorIsolationError("The validator reported valid media without reading input bytes.")
    values = dict(record)
    values.setdefault("parent_peak_rss_kib", 0)
    values.setdefault("parent_peak_threads", 0)
    return MediaValidation(**values)


def _run_child(descriptor: int, extension: str) -> tuple[bytes, bytes, int]:
    source_root = Path(__file__).resolve().parents[2]
    script = r'''import json, os, resource, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[3])
import av
av.logging.set_level(av.logging.PANIC)
from av.audio.stream import AudioStream
from av.subtitles.stream import SubtitleStream
from av.video.stream import VideoStream
from audioscribe.upload.sandbox import restrict_local_io
descriptor = int(sys.argv[1])
extension = sys.argv[2]
try:
    status_fd = os.open("/proc/self/status", os.O_RDONLY)
except OSError:
    print("validator-vmhwm-unavailable", file=sys.stderr)
    sys.exit(74)
class ReadMeter:
    def __init__(self, raw):
        self.raw = raw
        self.bytes_read = 0
    def read(self, size=-1):
        value = self.raw.read(size)
        self.bytes_read += len(value or b"")
        return value
    def seek(self, offset, whence=0):
        return self.raw.seek(offset, whence)
    def tell(self):
        return self.raw.tell()
    def readable(self):
        return self.raw.readable()
    def seekable(self):
        return self.raw.seekable()
    def __getattr__(self, name):
        return getattr(self.raw, name)
stream = ReadMeter(os.fdopen(descriptor, "rb", closefd=False))
preloaded_stream_wrappers = sum(name in sys.modules for name in
    ("av.audio.stream", "av.subtitles.stream", "av.video.stream"))
input_bytes_before_seal = stream.bytes_read
if preloaded_stream_wrappers != 3 or input_bytes_before_seal != 0:
    print("validator-bootstrap-order-failed", file=sys.stderr)
    sys.exit(73)
threads_before_seal = len(os.listdir("/proc/self/task"))
if threads_before_seal != 1:
    print("validator-thread-count-before-seal", file=sys.stderr)
    sys.exit(72)
try:
    restrict_local_io()
except Exception as error:
    print("validator-error:" + type(error).__name__ + ":" + str(getattr(error, "errno", "")),
          file=sys.stderr)
    print(json.dumps({"isolation_error": True}))
    sys.exit(71)
try:
    options = {"probesize": str(8 * 1024 * 1024), "analyzeduration": "5000000", "threads": "1"}
    with av.open(stream, mode="r", options=options, buffer_size=32768,
                 timeout=(5.0, 5.0)) as container:
        stream_count = len(container.streams)
        streams = list(container.streams) if stream_count <= 64 else []
        audio_streams = [item for item in streams if item.type == "audio"]
        video_streams = [item for item in streams if item.type == "video"]
        valid_format = ((extension == ".mp3" and "mp3" in container.format.name)
                        or (extension == ".mp4" and "mp4" in container.format.name))
        found = False
        if stream_count <= 64 and valid_format:
            for item in streams:
                if item.type in ("audio", "video"):
                    item.codec_context.thread_count = 1
            for packet in container.demux():
                if packet.stream.type in ("audio", "video") and packet.size and packet.decode():
                    found = True
                    break
        input_bytes_after_open = stream.bytes_read
        report = {"valid": bool(valid_format and stream_count <= 64 and found),
                  "has_media_frame": bool(found), "audio_streams": len(audio_streams),
                  "video_streams": len(video_streams), "container_format": container.format.name,
                  "child_peak_rss_kib": int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
                  "child_threads_before_seal": threads_before_seal,
                  "preloaded_stream_wrappers": preloaded_stream_wrappers,
                  "input_bytes_before_seal": input_bytes_before_seal,
                  "input_bytes_after_open": input_bytes_after_open}
except Exception as error:
    print("validator-error:" + type(error).__name__ + ":" + str(getattr(error, "errno", "")),
          file=sys.stderr)
    report = {"valid": False, "has_media_frame": False, "audio_streams": 0,
              "video_streams": 0, "container_format": "", "child_peak_rss_kib":
              int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss),
              "child_threads_before_seal": threads_before_seal,
              "preloaded_stream_wrappers": preloaded_stream_wrappers,
              "input_bytes_before_seal": input_bytes_before_seal,
              "input_bytes_after_open": stream.bytes_read}
try:
    status_text = os.pread(status_fd, 65536, 0).decode("ascii", "replace")
    vm_hwm_kib = next(int(line.split()[1]) for line in status_text.splitlines()
                      if line.startswith("VmHWM:"))
except (OSError, StopIteration, IndexError, ValueError):
    print("validator-vmhwm-unavailable", file=sys.stderr)
    sys.exit(74)
report["child_vm_hwm_kib"] = vm_hwm_kib
print(json.dumps(report, separators=(",", ":")))
'''

    deadline = time.monotonic() + _WALL_SECONDS
    process = subprocess.Popen(
        [sys.executable, "-I", "-c", script, str(descriptor), extension, str(source_root)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=(descriptor,),
        start_new_session=True,
        preexec_fn=_apply_validator_limits,
    )
    returncode: int
    try:
        if time.monotonic() >= deadline:
            _kill_child(process)
            raise TimeoutError("isolated validator exceeded its 30 second startup deadline")
        measurements = _drain_child(process, deadline=deadline)
    finally:
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    stdout, stderr, returncode = measurements.stdout, measurements.stderr, measurements.returncode
    if len(stdout) > _STDOUT_LIMIT or len(stderr) > _STDERR_LIMIT:
        raise ValidatorIsolationError("The isolated validator exceeded its output budget.")
    maximum_input_bytes = os.fstat(descriptor).st_size
    record = _parse_child_record(stdout, maximum_input_bytes=maximum_input_bytes)
    if record.child_vm_hwm_kib * 1024 > _MEMORY_BYTES or measurements.peak_rss_bytes > _MEMORY_BYTES:
        raise ValidatorIsolationError("The isolated validator exceeded its 128 MiB RSS target.")
    if record.child_threads_before_seal != 1 or measurements.peak_threads != 1:
        raise ValidatorIsolationError("The validator did not preserve the single-thread contract.")
    final_record = asdict(record)
    final_record["parent_peak_rss_kib"] = (measurements.peak_rss_bytes + 1023) // 1024
    final_record["parent_peak_threads"] = measurements.peak_threads
    stdout = json.dumps(final_record, separators=(",", ":")).encode("ascii")
    if len(stdout) > _STDOUT_LIMIT:
        raise ValidatorIsolationError("The strict validator record exceeded the stdout budget.")
    return stdout, stderr, returncode


def _drain_child(process: subprocess.Popen[bytes], *, deadline: float | None = None) -> ChildProcessMeasurements:
    assert process.stdout is not None and process.stderr is not None
    selector = selectors.DefaultSelector()
    output = {process.stdout: bytearray(), process.stderr: bytearray()}
    limits = {process.stdout: _STDOUT_LIMIT, process.stderr: _STDERR_LIMIT}
    for pipe in output:
        os.set_blocking(pipe.fileno(), False)
        selector.register(pipe, selectors.EVENT_READ)
    deadline = time.monotonic() + _WALL_SECONDS if deadline is None else deadline
    kill_deadline = deadline - _REAP_GRACE_SECONDS
    peak_rss_bytes = 0
    peak_threads = 0
    live_samples = 0
    try:
        while selector.get_map() or process.poll() is None:
            remaining = kill_deadline - time.monotonic()
            if remaining <= 0:
                _kill_child(process, reap_deadline=deadline)
                raise TimeoutError("isolated validator exceeded its 30 second wall deadline")
            if process.poll() is None:
                try:
                    child_rss = _child_rss_bytes(process.pid)
                    child_threads = _child_thread_count(process.pid)
                except ValidatorIsolationError:
                    time.sleep(min(remaining, 0.005))
                    if process.poll() is None:
                        raise
                    child_rss = child_threads = None
                if child_rss is not None and child_threads is not None:
                    live_samples += 1
                    peak_rss_bytes = max(peak_rss_bytes, child_rss)
                    peak_threads = max(peak_threads, child_threads)
                    if child_rss > _MEMORY_BYTES:
                        raise ValidatorIsolationError("The isolated validator exceeded its 128 MiB RSS target.")
                    if child_threads != 1:
                        raise ValidatorIsolationError("The parent observed more than one validator thread.")
            if not selector.get_map():
                time.sleep(min(remaining, 0.01))
                continue
            for key, _ in selector.select(min(remaining, 0.01)):
                pipe = key.fileobj
                chunk = os.read(pipe.fileno(), 4096)
                if not chunk:
                    selector.unregister(pipe)
                    continue
                buffer = output[pipe]
                if len(buffer) + len(chunk) > limits[pipe]:
                    raise ValidatorIsolationError("The isolated validator exceeded its output budget.")
                buffer.extend(chunk)
        returncode = process.wait(timeout=0)
        if live_samples == 0:
            raise ValidatorIsolationError("The validator exited before live resource metrics were captured.")
        return ChildProcessMeasurements(
            bytes(output[process.stdout]), bytes(output[process.stderr]), returncode,
            peak_rss_bytes, peak_threads,
        )
    except BaseException:
        _kill_child(process, reap_deadline=min(deadline, time.monotonic() + _REAP_GRACE_SECONDS))
        raise
    finally:
        selector.close()


def _child_rss_bytes(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/status", encoding="ascii") as stream:
            for line in stream:
                if line.startswith("VmRSS:"):
                    try:
                        return int(line.split()[1]) * 1024
                    except (IndexError, ValueError) as error:
                        raise ValidatorIsolationError("The isolated validator RSS metric is malformed.") from error
    except OSError as error:
        raise ValidatorIsolationError("The isolated validator RSS metric is unavailable.") from error
    raise ValidatorIsolationError("The isolated validator RSS metric is missing.")


def _child_thread_count(pid: int) -> int:
    try:
        return len(os.listdir(f"/proc/{pid}/task"))
    except OSError as error:
        raise ValidatorIsolationError("The isolated validator thread metric is unavailable.") from error


def _kill_child(process: subprocess.Popen[bytes], *, reap_deadline: float | None = None) -> int:
    if process.poll() is not None:
        return process.returncode
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        process.kill()
    if reap_deadline is None:
        reap_deadline = time.monotonic() + _REAP_GRACE_SECONDS
    remaining = reap_deadline - time.monotonic()
    if remaining <= 0:
        raise ValidatorIsolationError("The isolated validator child was not reaped within its cleanup window.")
    try:
        return process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        raise ValidatorIsolationError("The isolated validator child was not reaped within its cleanup window.")
