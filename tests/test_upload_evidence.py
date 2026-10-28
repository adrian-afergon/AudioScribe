"""PLAN-05 step 1: the falsifiable resource/evidence harness.

The harness lives in ``tools/measure_upload_resources.py`` (the operator CLI
from VERIFICATION §5); these unit tests prove the fail-closed contracts the
plan requires: report validation rejects deliberately violating records,
missing measurements and incomplete scope aggregates instead of pretending a
local report is a release, fixture generation streams with bounded buffers,
process sampling streams raw samples to disk, and reports redact secrets and
carry reproducible checksums.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

# The sampler reads Linux /proc metrics; the harness is qualified for Linux only.
pytestmark = pytest.mark.skipif(sys.platform != "linux",
                                reason="the resource sampler reads Linux /proc metrics")

TOOLS = Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))

import measure_upload_resources as harness  # noqa: E402


SECRET = "a" * 43


def _sample(size_bytes, peak_kib, label="server", scope="local", **extra):
    record = {
        "size_bytes": size_bytes,
        "label": label,
        "scope": scope,
        "baseline_rss_kib": 60_000,
        "transient_peak_rss_kib": peak_kib,
    }
    record.update(extra)
    return record


def test_evidence_rejects_linear_rss_growth():
    """Deliberately linear memory growth must fail the plateau target."""
    linear = [_sample(67_108_864, 70_000), _sample(1_073_741_824, 90_000),
              _sample(20_000_000_000, 150_000)]
    ok, findings = harness.validate_resource_report(linear, scope="local")
    assert not ok
    assert any("linear" in finding or "plateau" in finding for finding in findings)

    plateau = [_sample(67_108_864, 70_000), _sample(1_073_741_824, 72_500),
               _sample(20_000_000_000, 71_000)]
    ok, findings = harness.validate_resource_report(plateau, scope="local")
    assert ok, findings


def test_evidence_rejects_unmeasured_proxy():
    """A release aggregate without proxy/browser samples is incomplete, and a
    local report must label its missing whole-ingress evidence honestly."""
    release = [_sample(67_108_864, 70_000, label="server", scope="release"),
               _sample(67_108_864, 40_000, label="validator", scope="release")]
    ok, findings = harness.validate_resource_report(release, scope="release")
    assert not ok
    assert any("proxy" in finding and "browser" in finding for finding in findings)

    local = [_sample(67_108_864, 70_000, label="server", scope="local"),
             _sample(67_108_864, 40_000, label="validator", scope="local")]
    ok, findings = harness.validate_resource_report(local, scope="local")
    assert ok, findings
    assert any("full ingress" in finding or "whole-path" in finding
               for finding in findings)


def test_evidence_detects_reserve_and_cleanup_failure():
    """Every transfer needs admission reserve accounting and a terminal
    cleanup outcome; a cleanup failure must stay surfaced, never zeroed."""
    events = [
        {"kind": "reserve", "upload_id": "u1", "committed_bytes": 1000},
        {"kind": "cleanup", "upload_id": "u1", "outcome": "released"},
    ]
    ok, findings = harness.validate_lifecycle_events(events)
    assert ok, findings

    missing_reserve = [{"kind": "cleanup", "upload_id": "u2", "outcome": "released"}]
    ok, findings = harness.validate_lifecycle_events(missing_reserve)
    assert not ok
    assert any("reserve" in finding for finding in findings)

    failed_cleanup_hidden = [
        {"kind": "reserve", "upload_id": "u3", "committed_bytes": 1000},
        {"kind": "cleanup", "upload_id": "u3", "outcome": "cleanup_failed"},
    ]
    ok, findings = harness.validate_lifecycle_events(failed_cleanup_hidden)
    assert not ok, "a failed cleanup must fail the report, not be recorded as success"
    assert any("cleanup_failed" in finding or "quarantine" in finding
               for finding in findings)


def test_mp3_fixture_streams_bounded_frames(tmp_path):
    """Fixture generation repeats valid frames with bounded writes, never a
    full-file buffer, and the result is a real MP3 frame stream."""
    target = 417 * 1000 + 100
    path = tmp_path / "streamed.mp3"
    writes = []
    harness.generate_mp3_stream(path, target, chunk_hook=writes.append)
    assert path.stat().st_size == target
    assert writes and max(writes) <= harness.MAX_FIXTURE_WRITE_BYTES
    data = path.read_bytes()
    assert data[0] == 0xFF and data[1] & 0xE0 == 0xE0, "frame sync required"
    # Every aligned frame repeats the same header pattern.
    for offset in range(0, len(data) - 417, 417):
        assert data[offset:offset + 2] == b"\xff\xfb", offset


def test_sampler_streams_samples_to_disk(tmp_path):
    """The sampler writes timestamped raw samples at the configured rate and
    returns a bounded summary without retaining an unbounded sample list."""
    output = tmp_path / "rss-samples.jsonl"
    stop = threading.Event()
    sampler = threading.Thread(
        target=harness.sample_process_rss,
        args=(0.05, output, stop, {"label": "self"}),
        daemon=True)
    sampler.start()
    time.sleep(0.3)
    stop.set()
    sampler.join(5)
    lines = output.read_text().strip().splitlines()
    assert len(lines) >= 3, "samples must stream to disk at the configured rate"
    for line in lines:
        record = json.loads(line)
        assert record["label"] == "self"
        assert record["rss_kib"] > 0
        assert record["ts"] > 0
    summary = harness.summarize_samples(output, label="self")
    assert summary["sample_count"] == len(lines)
    assert summary["peak_rss_kib"] == max(json.loads(line)["rss_kib"] for line in lines)


def test_child_peak_attribution(tmp_path):
    """A spawned child's peak RSS is attributed to the child record, not the
    parent, and its lifetime is bounded by the watch window."""
    output = tmp_path / "child-samples.jsonl"
    stop = threading.Event()
    sleeper = subprocess.Popen(
        [sys.executable, "-c", "import time, os; os.makedirs(os.environ['AF'], exist_ok=True); "
         "open(os.path.join(os.environ['AF'], 'ready'), 'w').close(); time.sleep(30)"],
        env={**__import__("os").environ, "AF": str(tmp_path)},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        watcher = threading.Thread(
            target=harness.watch_child_processes,
            args=(os.getpid(), 0.05, output, stop),
            daemon=True)
        watcher.start()
        ready = tmp_path / "ready"
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.3)
        stop.set()
        watcher.join(5)
    finally:
        sleeper.terminate()
        sleeper.wait(10)
    lines = output.read_text().strip().splitlines()
    assert lines, "the live child must produce attributed samples"
    for line in lines:
        record = json.loads(line)
        assert record["pid"] == sleeper.pid
        assert record["label"] == "validator-child"


def test_report_redacts_secrets(tmp_path):
    """The 43-character secret never survives into a report file."""
    record = {"error": f"login failed for {SECRET}", "size_bytes": 10}
    output = tmp_path / "events.jsonl"
    harness.write_redacted_event(output, record, secret=SECRET)
    text = output.read_text()
    assert SECRET not in text
    assert json.loads(text)["error"] != record["error"]
    assert "[REDACTED]" in text


def test_report_checksums_reproducible(tmp_path):
    """The evidence checksum file is deterministic and detects tampering."""
    first = tmp_path / "a.jsonl"
    harness.write_redacted_event(first, {"n": 1}, secret=SECRET)
    manifest = harness.write_checksums(tmp_path)
    again = harness.write_checksums(tmp_path)
    assert manifest == again
    assert harness.verify_checksums(tmp_path)
    first.write_text(first.read_text() + "tampered\n")
    assert not harness.verify_checksums(tmp_path)


def test_missing_measurements_fail_closed(tmp_path):
    """A report directory without raw samples is a failed report, never a
    zero-valued measurement, and the failure names the missing evidence."""
    ok, findings = harness.validate_report_directory(tmp_path, scope="local")
    assert not ok
    assert any("missing" in finding.lower() for finding in findings)


def test_unit_conversions():
    """Page counts convert to KiB through the real page size."""
    assert harness.pages_to_kib(0) == 0
    assert harness.pages_to_kib(256) == 256 * 4, "4 KiB pages on x86_64 Linux"
    assert harness.kib_to_mib(16 * 1024) == 16.0
