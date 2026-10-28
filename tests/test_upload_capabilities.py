import hashlib
import os
import subprocess
import sys
import time
import tomllib
import json
from pathlib import Path

import pytest

from audioscribe.config import Config
from audioscribe.service import Scanner
from audioscribe.store import Store
from audioscribe.upload.capabilities import (
    UnownedStagingArea,
    ensure_owned_staging,
    owned_staging_path,
)


def test_upload_extra_pins_audited_stack():
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))

    assert set(project["project"]["optional-dependencies"]["upload"]) == {
        "uvicorn==0.54.0",
        "h11==0.16.0",
        "av==15.1.0",
    }


def test_scanner_excludes_only_identity_validated_staging(tmp_path):
    for name in ("input", "output", "brain", "data"):
        (tmp_path / name).mkdir()
    config = Config(*(str(tmp_path / name) for name in ("input", "output", "brain", "data")), recursive=True)
    root = Path(config.input_dir)
    staging = root / ".audioscribe-upload-staging"
    staging.mkdir(mode=0o700)
    root_stat, staging_stat = root.stat(), staging.stat()
    marker = staging / "owner.json"
    marker.write_text(json.dumps({
        "format": 1,
        "root_device": root_stat.st_dev,
        "root_inode": root_stat.st_ino,
        "staging_device": staging_stat.st_dev,
        "staging_inode": staging_stat.st_ino,
    }), encoding="utf-8")
    marker.chmod(0o600)
    (staging / "partial.mp3").write_bytes(b"partial")
    expected = root / "complete.mp3"
    expected.write_bytes(b"complete")
    store = Store(config.database)
    try:
        assert Scanner(config, store).paths() == [expected]
    finally:
        store.close()


def test_unowned_staging_path_is_neither_hidden_nor_deleted(tmp_path):
    for name in ("input", "output", "brain", "data"):
        (tmp_path / name).mkdir()
    config = Config(*(str(tmp_path / name) for name in ("input", "output", "brain", "data")), recursive=True)
    root = Path(config.input_dir)
    staging = root / ".audioscribe-upload-staging"
    staging.mkdir()
    user_media = staging / "keep.mp3"
    user_media.write_bytes(b"user data")
    store = Store(config.database)
    try:
        assert Scanner(config, store).paths() == [user_media]
        with pytest.raises(UnownedStagingArea):
            ensure_owned_staging(root)
        assert user_media.read_bytes() == b"user data"
    finally:
        store.close()


def test_owned_staging_creation_records_private_mount_identity(tmp_path):
    input_root = tmp_path / "input"
    input_root.mkdir()

    staging = ensure_owned_staging(input_root)

    assert owned_staging_path(input_root) == staging
    assert staging.stat().st_mode & 0o077 == 0
    assert (staging / "owner.json").stat().st_mode & 0o077 == 0


def test_atomic_link_capability_on_disposable_fixture_mount(tmp_path):
    root = tmp_path / "fixture-input"
    root.mkdir()
    source = root / ".link-source-probe"
    competing_source = root / ".link-competing-probe"
    published = root / ".link-final-probe"
    source.write_bytes(b"non-media source probe")
    competing_source.write_bytes(b"different non-media probe")
    original_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    try:
        os.link(source, published)
        assert source.stat().st_dev == published.stat().st_dev == root.stat().st_dev
        assert source.stat().st_ino == published.stat().st_ino
        assert competing_source.stat().st_ino != published.stat().st_ino
        with pytest.raises(FileExistsError):
            os.link(competing_source, published)
        assert hashlib.sha256(published.read_bytes()).hexdigest() == original_hash
    finally:
        for path in (published, source, competing_source):
            path.unlink(missing_ok=True)


def test_linux_validator_restrictions_deny_network_and_secondary_files(tmp_path):
    if sys.platform != "linux":
        pytest.skip("This test exercises the local Linux seccomp policy; native OS gates remain separate.")
    source = tmp_path / "validator-source.bin"
    secondary = tmp_path / "secondary-secret.bin"
    source.write_bytes(b"fixture")
    secondary.write_bytes(b"must-not-open")
    descriptor = os.open(source, os.O_RDONLY)
    source_root = Path(__file__).resolve().parents[1] / "src"
    script = f"""
import os, socket, sys
sys.path.insert(0, {str(source_root)!r})
from audioscribe.upload.sandbox import restrict_local_io
restrict_local_io()
data = os.read({descriptor}, 7).decode()
try:
    socket.socket()
except OSError:
    network = 'denied'
else:
    network = 'allowed'
try:
    os.open({str(secondary)!r}, os.O_RDONLY)
except OSError:
    secondary_file = 'denied'
else:
    secondary_file = 'allowed'
print(data + '|' + network + '|' + secondary_file)
"""
    try:
        result = subprocess.run([sys.executable, "-c", script], pass_fds=(descriptor,),
                                capture_output=True, text=True, timeout=10, check=False)
    finally:
        os.close(descriptor)

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "fixture|denied|denied"


def test_validator_accepts_readable_video_only_mp4():
    from audioscribe.upload.validator import validate_media

    media = _fixed_lq04_fixture("P1-video-only-mpeg4.mp4")
    result = validate_media(media, ".mp4")

    assert result.valid is True
    assert result.has_media_frame is True
    assert result.audio_streams == 0
    assert result.child_threads_before_seal == 1
    assert result.parent_peak_threads == 1
    assert result.preloaded_stream_wrappers == 3
    assert result.input_bytes_before_seal == 0
    assert result.input_bytes_after_open > 0


def test_validator_accepts_genuine_mp3_fixture():
    from audioscribe.upload.validator import validate_media

    media = _fixed_lq04_fixture("P2-mp3-libmp3lame.mp3")
    result = validate_media(media, ".mp3")

    assert result.valid is True
    assert result.has_media_frame is True
    assert result.audio_streams == 1


def test_validator_accepts_audio_bearing_mp4_fixture():
    from audioscribe.upload.validator import validate_media

    media = _fixed_lq04_fixture("P3-audio-bearing-aac.mp4")
    result = validate_media(media, ".mp4")

    assert result.valid is True
    assert result.has_media_frame is True
    assert result.audio_streams >= 1


def test_validator_accepts_h264_mp4_fixture():
    from audioscribe.upload.validator import validate_media

    media = _fixed_lq04_fixture("P4-video-h264.mp4")
    result = validate_media(media, ".mp4")

    assert result.valid is True
    assert result.has_media_frame is True
    assert result.video_streams == 1


def test_validator_rejects_fixed_n1_negative_media_fixtures():
    from audioscribe.upload.validator import InvalidMediaError, validate_media

    for name, extension in (
        ("N1-empty.mp3", ".mp3"),
        ("N1-malformed.mp4", ".mp4"),
        ("N1-quicktime-brand.mp4", ".mp4"),
        ("N1-extension-mismatch.mp3", ".mp3"),
    ):
        with pytest.raises(InvalidMediaError):
            validate_media(_fixed_lq04_fixture(name), extension)


def test_signature_allowlist_accepts_m4a_audio_brand():
    from audioscribe.upload.validator import _signature_matches

    m4a_header = b"\x00\x00\x00\x20ftypM4A \x00\x00\x00\x00"
    assert _signature_matches(".mp4", m4a_header) is True
    assert _signature_matches(".mp4", b"\x00\x00\x00\x20ftypqt  \x00\x00\x00\x00") is False


def test_validator_rejects_boolean_child_rss_before_memory_arithmetic(monkeypatch):
    import json

    from audioscribe.upload import validator
    from audioscribe.upload.validator import ValidatorIsolationError

    child_record = {
        "valid": True,
        "has_media_frame": True,
        "audio_streams": 0,
        "video_streams": 1,
        "container_format": "mp4",
        "child_peak_rss_kib": True,
        "child_vm_hwm_kib": 1024,
        "child_threads_before_seal": 1,
        "preloaded_stream_wrappers": 3,
        "input_bytes_before_seal": 0,
        "input_bytes_after_open": 1,
    }

    class ExitedProcess:
        stdout = None
        stderr = None

        def poll(self):
            return 0

    monkeypatch.setattr(validator.subprocess, "Popen", lambda *_args, **_kwargs: ExitedProcess())
    monkeypatch.setattr(validator, "_drain_child",
                        lambda _process, **_kwargs: validator.ChildProcessMeasurements(
                            json.dumps(child_record).encode(), b"", 0, 1024, 1))

    with pytest.raises(ValidatorIsolationError, match="integer"):
        validator._run_child(3, ".mp4")


def test_validator_rejects_child_input_count_above_parent_file_size():
    import json

    from audioscribe.upload.validator import ValidatorIsolationError, _parse_child_record

    record = {
        "valid": True,
        "has_media_frame": True,
        "audio_streams": 0,
        "video_streams": 1,
        "container_format": "mp4",
        "child_peak_rss_kib": 1024,
        "child_vm_hwm_kib": 1024,
        "child_threads_before_seal": 1,
        "preloaded_stream_wrappers": 3,
        "input_bytes_before_seal": 0,
        "input_bytes_after_open": 101,
    }

    with pytest.raises(ValidatorIsolationError, match="input-byte"):
        _parse_child_record(json.dumps(record).encode(), maximum_input_bytes=100)


def test_validator_rejects_unknown_child_record_fields():
    import json

    from audioscribe.upload.validator import ValidatorIsolationError, _parse_child_record

    record = {
        "valid": False,
        "has_media_frame": False,
        "audio_streams": 0,
        "video_streams": 0,
        "container_format": "",
        "child_peak_rss_kib": 1200,
        "child_vm_hwm_kib": 1200,
        "child_threads_before_seal": 1,
        "preloaded_stream_wrappers": 3,
        "input_bytes_before_seal": 0,
        "input_bytes_after_open": 0,
        "debug_trace": "must-not-be-accepted",
    }

    with pytest.raises(ValidatorIsolationError, match="schema"):
        _parse_child_record(json.dumps(record).encode())


def test_validator_rejects_duplicate_child_record_keys():
    from audioscribe.upload.validator import ValidatorIsolationError, _parse_child_record

    payload = (
        b'{"valid":false,"valid":false,"has_media_frame":false,'
        b'"audio_streams":0,"video_streams":0,"container_format":"",'
        b'"child_peak_rss_kib":100,"child_vm_hwm_kib":100,'
        b'"child_threads_before_seal":1,'
        b'"preloaded_stream_wrappers":3,"input_bytes_before_seal":0,'
        b'"input_bytes_after_open":0}'
    )

    with pytest.raises(ValidatorIsolationError, match="duplicate"):
        _parse_child_record(payload)


def _self_vm_rss_kib():
    with open("/proc/self/status", encoding="ascii") as stream:
        for line in stream:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    raise AssertionError("VmRSS is unavailable on this platform")


def test_validator_accepts_media_when_forking_parent_holds_high_rss():
    from audioscribe.upload.validator import _MEMORY_BYTES, validate_media

    ballast = bytearray(160 * 1024 * 1024)
    view = memoryview(ballast)
    for offset in range(0, len(view), 4096):
        view[offset] = 1
    try:
        held = _self_vm_rss_kib()
        assert held > _MEMORY_BYTES // 1024, f"precondition failed: parent holds only {held} KiB"
        result = validate_media(_fixed_lq04_fixture("P2-mp3-libmp3lame.mp3"), ".mp3")
    finally:
        del ballast, view

    assert result.valid is True
    assert result.has_media_frame is True
    assert result.audio_streams == 1


def test_validator_record_requires_child_reported_vm_hwm():
    import json

    from audioscribe.upload.validator import ValidatorIsolationError, _parse_child_record

    record = {
        "valid": True,
        "has_media_frame": True,
        "audio_streams": 0,
        "video_streams": 1,
        "container_format": "mp4",
        "child_peak_rss_kib": 1024,
        "child_threads_before_seal": 1,
        "preloaded_stream_wrappers": 3,
        "input_bytes_before_seal": 0,
        "input_bytes_after_open": 1,
    }

    with pytest.raises(ValidatorIsolationError, match="schema"):
        _parse_child_record(json.dumps(record).encode())


def test_validator_budget_ignores_fork_inherited_rusage_and_reads_vm_hwm():
    import json

    from audioscribe.upload.validator import _parse_child_record

    record = {
        "valid": True,
        "has_media_frame": True,
        "audio_streams": 0,
        "video_streams": 1,
        "container_format": "mp4",
        "child_peak_rss_kib": 200_000,
        "child_vm_hwm_kib": 44_000,
        "child_threads_before_seal": 1,
        "preloaded_stream_wrappers": 3,
        "input_bytes_before_seal": 0,
        "input_bytes_after_open": 1,
    }

    parsed = _parse_child_record(json.dumps(record).encode())

    assert parsed.child_vm_hwm_kib == 44_000
    assert parsed.child_peak_rss_kib == 200_000


def test_run_child_enforces_rss_budget_on_child_reported_vm_hwm(tmp_path, monkeypatch):
    import json
    import os

    from audioscribe.upload import validator
    from audioscribe.upload.validator import ValidatorIsolationError

    def child_record(child_peak_rss_kib, child_vm_hwm_kib):
        return {
            "valid": True,
            "has_media_frame": True,
            "audio_streams": 0,
            "video_streams": 1,
            "container_format": "mp4",
            "child_peak_rss_kib": child_peak_rss_kib,
            "child_vm_hwm_kib": child_vm_hwm_kib,
            "child_threads_before_seal": 1,
            "preloaded_stream_wrappers": 3,
            "input_bytes_before_seal": 0,
            "input_bytes_after_open": 4,
        }

    class ExitedProcess:
        stdout = None
        stderr = None

        def poll(self):
            return 0

    media = tmp_path / "input.mp3"
    media.write_bytes(b"\xff\xfb" + b"\x00" * 14)
    descriptor = os.open(media, os.O_RDONLY)
    try:
        monkeypatch.setattr(validator.subprocess, "Popen", lambda *_args, **_kwargs: ExitedProcess())

        monkeypatch.setattr(validator, "_drain_child",
                            lambda _process, **_kwargs: validator.ChildProcessMeasurements(
                                json.dumps(child_record(1024, 200_000)).encode(), b"", 0, 1024, 1))
        with pytest.raises(ValidatorIsolationError, match="VM-HWM"):
            validator._run_child(descriptor, ".mp3")

        monkeypatch.setattr(validator, "_drain_child",
                            lambda _process, **_kwargs: validator.ChildProcessMeasurements(
                                json.dumps(child_record(1024, 44_000)).encode(), b"", 0,
                                200 * 1024 * 1024, 1))
        with pytest.raises(ValidatorIsolationError, match="RSS target"):
            validator._run_child(descriptor, ".mp3")

        monkeypatch.setattr(validator, "_drain_child",
                            lambda _process, **_kwargs: validator.ChildProcessMeasurements(
                                json.dumps(child_record(200_000, 44_000)).encode(), b"", 0, 1024, 1))
        stdout, _stderr, _returncode = validator._run_child(descriptor, ".mp3")
        final = json.loads(stdout)
        assert final["child_vm_hwm_kib"] == 44_000
        assert final["child_peak_rss_kib"] == 200_000
        assert final["parent_peak_rss_kib"] == 1
    finally:
        os.close(descriptor)


def test_validator_rejects_zero_and_over_budget_child_vm_hwm():
    import json

    from audioscribe.upload.validator import ValidatorIsolationError, _parse_child_record

    record = {
        "valid": True,
        "has_media_frame": True,
        "audio_streams": 0,
        "video_streams": 1,
        "container_format": "mp4",
        "child_peak_rss_kib": 1024,
        "child_vm_hwm_kib": 44_000,
        "child_threads_before_seal": 1,
        "preloaded_stream_wrappers": 3,
        "input_bytes_before_seal": 0,
        "input_bytes_after_open": 1,
    }

    for value in (0, 131_073):
        with pytest.raises(ValidatorIsolationError, match="VM-HWM"):
            _parse_child_record(json.dumps(dict(record, child_vm_hwm_kib=value)).encode())


def test_validator_deadline_covers_wait_after_both_pipes_close(monkeypatch):
    import subprocess
    import sys

    from audioscribe.upload import validator

    process = subprocess.Popen(
        [sys.executable, "-c", "import os,time; os.close(1); os.close(2); time.sleep(0.5)"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    monkeypatch.setattr(validator, "_WALL_SECONDS", 0.05)
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="deadline"):
            validator._drain_child(process)
        assert process.poll() is not None
        assert time.monotonic() - started < 0.3
    finally:
        validator._kill_child(process)


def _fixed_lq04_fixture(name):
    import os
    import sys

    test_directory = str(Path(__file__).resolve().parent)
    if test_directory not in sys.path:
        sys.path.insert(0, test_directory)
    from lq04_fixture_hashes import LQ04_FIXTURE_SHA256, fixture_sha256

    root = Path(os.environ.get(
        "AUDIOSCRIBE_LQ04_FIXTURE_ROOT",
        "/tmp/opencode/audioscribe-plan01.dJebPg/lq04-fixtures/C-LQ04-BOOTSTRAP-01",
    ))
    fixture = root / name
    if not fixture.is_file():
        pytest.skip("LQ04 fixtures are not available; run the qualification bootstrap")
    assert fixture_sha256(fixture) == LQ04_FIXTURE_SHA256[name], f"fixed fixture changed: {name}"
    return fixture


def test_missing_live_child_rss_is_not_zero_memory(monkeypatch):
    import builtins

    from audioscribe.upload import validator
    from audioscribe.upload.validator import ValidatorIsolationError

    original_open = builtins.open

    def deny_metric(path, *args, **kwargs):
        if path == "/proc/123/status":
            raise PermissionError("metrics unavailable")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", deny_metric)

    with pytest.raises(ValidatorIsolationError, match="RSS"):
        validator._child_rss_bytes(123)
