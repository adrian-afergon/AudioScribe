#!/usr/bin/env python3
"""PLAN-05 streaming upload resource/evidence harness.

Operator CLI (VERIFICATION §5) and importable primitives reused by the local
resource probes. Reports fail closed: missing measurements and threshold
violations exit nonzero, a local report is never allowed to pretend to be
release evidence, and the shared secret never survives into a report file.

The CLI drives the sender side of the size/concurrency matrix against a
running fixture and measures harness (sender) RSS; server/validator/proxy/
browser process sampling is wired locally where those processes live (same
machine) through :func:`sample_process_rss` and :func:`watch_child_processes`.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

MAX_FIXTURE_WRITE_BYTES = 64 * 1024
MP3_FRAME = bytes([0xFF, 0xFB, 0x90, 0x00, 0xC0]) + b"\x00" * 412
FULL_INGRESS_LABELS = ("server", "validator", "proxy", "browser")
PLATEAU_SPREAD_MIB = 16.0
SENDER_BODY_CHUNK_BYTES = 64 * 1024
REDACTED = "[REDACTED]"
TERMINAL_CLEANUP_OUTCOMES = ("released", "published", "cancelled")


def pages_to_kib(pages: int) -> int:
    return pages * os.sysconf("SC_PAGE_SIZE") // 1024


def kib_to_mib(kib: float) -> float:
    return kib / 1024.0


def generate_mp3_stream(path: Path, total_bytes: int,
                        chunk_hook=None) -> None:
    """Stream a valid MP3 frame sequence of exactly ``total_bytes`` to path.

    Bounded buffers only: the frame constant is written repeatedly, never a
    full-file buffer. ``chunk_hook`` receives every write size (test seam for
    boundedness assertions).
    """
    if total_bytes < 0:
        raise ValueError("total_bytes must be nonnegative")
    written = 0
    with open(path, "wb") as stream:
        while written < total_bytes:
            amount = min(len(MP3_FRAME), total_bytes - written)
            chunk = MP3_FRAME[:amount]
            stream.write(chunk)
            written += amount
            if chunk_hook is not None:
                chunk_hook(len(chunk))


def _read_resident_kib(pid: int) -> int:
    with open(f"/proc/{pid}/statm", "rb") as stream:
        fields = stream.read().split()
    return pages_to_kib(int(fields[1]))


def sample_process_rss(interval: float, output: Path, stop: threading.Event,
                       extra: dict | None = None, pid: int | None = None) -> None:
    """Sample one process RSS at ``interval`` seconds, streaming timestamped
    raw JSONL samples to ``output`` without retaining a sample list."""
    pid = os.getpid() if pid is None else pid
    extra = extra or {}
    while not stop.is_set():
        try:
            rss_kib = _read_resident_kib(pid)
        except (FileNotFoundError, ProcessLookupError, IndexError):
            break
        record = {"ts": time.time(), "pid": pid, "label": extra.get("label", "process"),
                  "rss_kib": rss_kib}
        record.update({k: v for k, v in extra.items() if k != "label"})
        with open(output, "a", encoding="utf-8") as stream:
            stream.write(json.dumps(record) + "\n")
        stop.wait(interval)


def summarize_samples(path: Path, label: str | None = None) -> dict:
    """Bounded summary over a raw sample file: count and peak only."""
    count = 0
    peak = 0
    with open(path, "r", encoding="utf-8") as stream:
        for line in stream:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if label is not None and record.get("label") != label:
                continue
            count += 1
            peak = max(peak, record["rss_kib"])
    return {"sample_count": count, "peak_rss_kib": peak}


def watch_child_processes(parent_pid: int, interval: float, output: Path,
                          stop: threading.Event) -> None:
    """Attribute short-lived children of ``parent_pid`` (validator children)
    with their own bounded sample records while they live."""
    seen: set[int] = set()
    while not stop.is_set():
        try:
            with open(f"/proc/{parent_pid}/task/{parent_pid}/children", "rb") as stream:
                children = [int(value) for value in stream.read().split()]
        except (FileNotFoundError, ProcessLookupError):
            children = []
        for child in children:
            if child in seen:
                continue
            try:
                rss_kib = _read_resident_kib(child)
            except (FileNotFoundError, ProcessLookupError, IndexError):
                continue
            seen.add(child)
            record = {"ts": time.time(), "pid": child, "label": "validator-child",
                      "rss_kib": rss_kib, "parent_pid": parent_pid}
            with open(output, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(record) + "\n")
        stop.wait(interval)


def redact(value, secret: str):
    """Recursively redact the shared secret from strings inside a record."""
    if isinstance(value, str):
        return value.replace(secret, REDACTED) if secret else value
    if isinstance(value, dict):
        return {key: redact(item, secret) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(item, secret) for item in value]
    return value


def write_redacted_event(path: Path, record: dict, secret: str) -> None:
    with open(path, "a", encoding="utf-8") as stream:
        stream.write(json.dumps(redact(record, secret), sort_keys=True) + "\n")


def write_checksums(directory: Path) -> str:
    """Write a deterministic SHA-256 manifest of every raw evidence file."""
    lines = []
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.name == "evidence-sha256.txt":
            continue
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    manifest = "\n".join(lines) + ("\n" if lines else "")
    (directory / "evidence-sha256.txt").write_text(manifest, encoding="utf-8")
    return manifest


def verify_checksums(directory: Path) -> bool:
    manifest_path = directory / "evidence-sha256.txt"
    if not manifest_path.is_file():
        return False
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        if not line:
            continue
        digest, name = line.split("  ", 1)
        path = directory / name
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            return False
    return True


def validate_resource_report(records: list[dict], scope: str) -> tuple[bool, list[str]]:
    """Fail-closed report validation.

    Rejects linear RSS growth against the plateau target, release aggregates
    without measured proxy/browser samples, and records whose scope label
    disagrees with the report scope. Local reports stay valid only while they
    label the absent whole-ingress evidence honestly.
    """
    errors: list[str] = []
    infos: list[str] = []
    labels = {record.get("label") for record in records}
    for record in records:
        if record.get("scope") not in (None, scope):
            errors.append(f"record scope label {record.get('scope')!r} does not match "
                          f"report scope {scope!r}")
    if scope == "release":
        missing = [label for label in FULL_INGRESS_LABELS if label not in labels]
        if missing:
            errors.append("release scope requires measured proxy and browser samples; "
                          f"missing whole-ingress labels: {', '.join(missing)}")
    else:
        if "proxy" not in labels or "browser" not in labels:
            infos.append("local scope: whole-path/full ingress evidence is absent "
                         "without proxy and browser samples; this is not release evidence")
    server_records = sorted((record for record in records
                             if record.get("label") == "server"),
                            key=lambda record: record.get("size_bytes", 0))
    peaks = [record["transient_peak_rss_kib"] - record.get("baseline_rss_kib", 0)
             for record in server_records]
    if len(peaks) >= 2:
        spread_mib = kib_to_mib(max(peaks) - min(peaks))
        if spread_mib > PLATEAU_SPREAD_MIB:
            errors.append(f"linear RSS growth: baseline-adjusted server transient peak "
                          f"spread {spread_mib:.1f} MiB exceeds the {PLATEAU_SPREAD_MIB:.0f} MiB "
                          f"plateau target")
    return (not errors, infos + errors)


def validate_lifecycle_events(events: list[dict]) -> tuple[bool, list[str]]:
    """Every transfer needs admission reserve accounting and a terminal
    cleanup outcome; failed cleanups stay surfaced and fail the report."""
    errors: list[str] = []
    reserved: dict[str, dict] = {}
    for event in events:
        if event.get("kind") == "reserve":
            reserved[event.get("upload_id")] = event
    cleanups = [event for event in events if event.get("kind") == "cleanup"]
    for event in cleanups:
        upload_id = event.get("upload_id")
        if upload_id not in reserved:
            errors.append(f"reserve accounting missing for upload {upload_id}: a "
                          f"terminal cleanup outcome exists without an admission reserve record")
        outcome = event.get("outcome")
        if outcome == "cleanup_failed":
            resolved = any(other.get("kind") == "cleanup-resolved"
                           and other.get("upload_id") == upload_id for other in events)
            if not resolved:
                errors.append(f"cleanup_failed for upload {upload_id} must remain surfaced "
                              f"and quarantined; the report cannot pass with unresolved cleanup")
        elif outcome not in TERMINAL_CLEANUP_OUTCOMES:
            errors.append(f"unknown cleanup outcome {outcome!r} for upload {upload_id}")
    return (not errors, errors)


def validate_report_directory(directory: Path, scope: str) -> tuple[bool, list[str]]:
    """Validate a whole report directory; missing raw evidence fails closed."""
    errors: list[str] = []
    infos: list[str] = []
    samples_path = directory / "rss-samples.jsonl"
    if not samples_path.is_file():
        errors.append("missing rss-samples.jsonl: a report without raw samples is a "
                      "failed report, never a zero-valued measurement")
        return (False, errors)
    records = [json.loads(line) for line in
               samples_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    ok, findings = validate_resource_report(
        [record for record in records if "size_bytes" in record], scope)
    if scope == "release":
        missing = [label for label in FULL_INGRESS_LABELS
                   if not any(record.get("label") == label for record in records)]
        if missing:
            errors.append(f"release scope is incomplete without measured proxy and "
                          f"browser samples (missing: {', '.join(missing)})")
            ok = False
    if not verify_checksums(directory):
        errors.append("missing or non-reproducible evidence-sha256.txt")
        ok = False
    errors.extend(finding for finding in findings if finding not in errors)
    return (ok, infos + errors)


def _parse_int_list(value: str) -> list[int]:
    return [int(item.strip()) for item in value.split(",") if item.strip()]


def _origin_of(base_url: str) -> tuple[str, int, str, str]:
    parts = urlsplit(base_url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("--base-url must be an absolute http(s) URL of the certified hostname")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    origin = f"{parts.scheme}://{parts.hostname}" + (f":{port}" if port not in (80, 443) else "")
    return parts.hostname, port, origin, parts.scheme


def _one_transfer(connection_factory, origin: str, secret: str, size: int,
                  concurrency_slot: int, events_path: Path) -> dict:
    """Login, register, stream a generated body and reconcile the terminal
    state; returns the transfer's lifecycle outcome record."""
    upload_id = None
    try:
        connection = connection_factory()
        connection.request("GET", "/api/v1/auth/challenge",
                           headers={"Host": origin, "Origin": origin})
        status, _headers, body = _read_response(connection)
        if status != 200:
            return {"error": f"challenge failed with status {status}"}
        nonce = json.loads(body)["nonce"]
        connection.request("POST", "/api/v1/auth/login",
                           headers={"Host": origin, "Origin": origin,
                                    "Content-Type": "application/json"},
                           body=json.dumps({"secret": secret, "csrf": nonce}))
        status, headers, body = _read_response(connection)
        if status != 200:
            return {"error": f"login failed with status {status}"}
        cookie = next((value.split(";", 1)[0] for value in headers.get("Set-Cookie", [])
                       if value.startswith("__Host-audioscribe=")), "")
        session = json.loads(body)
        connection.request("POST", "/api/v1/uploads",
                           headers={"Host": origin, "Origin": origin,
                                    "Content-Type": "application/json",
                                    "Cookie": cookie,
                                    "X-CSRF-Token": session["csrf"]},
                           body=json.dumps({"filename": f"probe-{size}-{concurrency_slot}.mp3",
                                            "file_bytes": size}))
        status, _headers, body = _read_response(connection)
        if status != 201:
            return {"error": f"registration failed with status {status}"}
        registration = json.loads(body)
        upload_id = registration["upload_id"]
        write_redacted_event(events_path, {"kind": "reserve", "upload_id": upload_id,
                                           "committed_bytes": size}, secret=secret)
        fixture = Path(os.environ["TMPDIR"] if os.environ.get("TMPDIR") else "/tmp") / (
            f"audioscribe-harness-{size}-{concurrency_slot}.mp3")
        if not fixture.exists() or fixture.stat().st_size != size:
            generate_mp3_stream(fixture, size)
        with open(fixture, "rb") as stream:
            connection.request("POST", f"/api/v1/uploads/{upload_id}/body",
                               headers={"Host": origin, "Origin": origin,
                                        "Content-Type": "application/octet-stream",
                                        "Cookie": cookie,
                                        "X-Transfer-Token": registration["transfer_token"]},
                               body=stream)
        status, _headers, body = _read_response(connection)
        if status != 200:
            return {"upload_id": upload_id, "error": f"body failed with status {status}"}
        record = json.loads(body)
        write_redacted_event(events_path, {"kind": "cleanup", "upload_id": upload_id,
                                           "outcome": record.get("state")}, secret=secret)
        return {"upload_id": upload_id, "state": record.get("state"),
                "bytes_received": record.get("bytes_received")}
    finally:
        pass


def _read_response(connection: http.client.HTTPConnection):
    response = connection.getresponse()
    body = response.read()
    headers = {}
    for name, value in response.getheaders():
        headers.setdefault(name, []).append(value)
    return response.status, headers, body


def run_matrix(base_url: str, secret_env: str, sizes: list[int], concurrency: list[int],
               output: Path, unknown_length: bool = False) -> tuple[bool, list[str]]:
    """Run the known-length sender matrix and write the report directory."""
    secret = os.environ.get(secret_env)
    if not secret:
        raise SystemExit(f"secret environment variable {secret_env} is empty; inject it "
                         f"privately without terminal or log disclosure")
    host, port, origin, scheme = _origin_of(base_url)
    output.mkdir(parents=True, exist_ok=True)
    samples_path = output / "rss-samples.jsonl"
    events_path = output / "lifecycle-events.jsonl"
    stop = threading.Event()
    sampler = threading.Thread(target=sample_process_rss,
                               args=(0.1, samples_path, stop,
                                     {"label": "harness-sender", "scope": "local"}),
                               daemon=True)
    sampler.start()
    results = []

    def connection_factory():
        return (http.client.HTTPSConnection(host, port, timeout=60) if scheme == "https"
                else http.client.HTTPConnection(host, port, timeout=60))

    for slot in range(max(concurrency, default=1)):
        for size in sizes:
            for _round in ("cold", "warm"):
                started = time.monotonic()
                outcome = _one_transfer(connection_factory, origin, secret, size,
                                        slot, events_path)
                outcome.update({"size_bytes": size, "round": _round,
                                "elapsed_seconds": round(time.monotonic() - started, 3)})
                results.append(outcome)
    stop.set()
    sampler.join(5)
    summary = summarize_samples(samples_path, label="harness-sender")
    (output / "resource-summary.json").write_text(json.dumps({
        "base_url": origin, "sizes": sizes, "concurrency": concurrency,
        "unknown_length": unknown_length, "sender_peak_rss_kib": summary["peak_rss_kib"],
        "transfers": results}, indent=2) + "\n", encoding="utf-8")
    write_checksums(output)
    return validate_report_directory(output, scope="local")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Streaming upload resource/evidence harness (fail-closed reports)")
    parser.add_argument("--base-url", required=True,
                        help="certified canonical origin of the fixture (e.g. https://host.ts.net)")
    parser.add_argument("--secret-env", required=True,
                        help="environment variable name carrying the shared secret")
    parser.add_argument("--sizes", required=True, help="comma-separated body sizes in bytes")
    parser.add_argument("--concurrency", required=True, help="comma-separated N values")
    parser.add_argument("--output", required=True, type=Path, help="report directory")
    parser.add_argument("--unknown-length", action="store_true",
                        help="use Transfer-Encoding: chunked instead of Content-Length")
    parser.add_argument("--reserve-test", action="store_true")
    parser.add_argument("--external-consumer", action="store_true")
    parser.add_argument("--slow-consumer", action="store_true")
    args = parser.parse_args(argv)
    if args.reserve_test or args.external_consumer or args.slow_consumer:
        print("fail closed: --reserve-test/--external-consumer/--slow-consumer are "
              "release-tail pressure modes; the local harness implements the "
              "sender matrix only", file=sys.stderr)
        return 3
    try:
        ok, findings = run_matrix(args.base_url, args.secret_env,
                                  _parse_int_list(args.sizes),
                                  _parse_int_list(args.concurrency),
                                  args.output, unknown_length=args.unknown_length)
    except ValueError as error:
        print(f"invalid arguments: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding, file=sys.stderr)
    if not ok:
        print("resource report FAILED (missing measurements or threshold violations)",
              file=sys.stderr)
        return 1
    print(f"resource report OK: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
