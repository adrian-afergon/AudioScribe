# Deprecated as qualification infrastructure; superseded by the plain qualification contract (PLAN-01). Retained as history.
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path


def run_sealed_control(preseal: str, postseal: str, pass_fds: tuple[int, ...] = (),
                       *, expected_returncode: int = 0, deadline_seconds: float = 30):
    from audioscribe.upload.validator import _drain_child, _kill_child
    from lq04_evidence import active_evidence_capture

    deadline = time.monotonic() + deadline_seconds
    evidence_capture = active_evidence_capture()
    if evidence_capture is not None:
        evidence_capture.set_next_deadline(deadline)
    try:
        process = start_sealed_process(preseal, postseal, pass_fds)
    except BaseException:
        if evidence_capture is not None:
            evidence_capture.clear_next_deadline()
        raise
    try:
        measurements = _drain_child(process, deadline=deadline)
    except BaseException as original_error:
        try:
            _kill_child(process)
        except BaseException as cleanup_error:
            original_error.add_note(f"observer cleanup error: {type(cleanup_error).__name__}: {cleanup_error}")
        raise
    finally:
        if evidence_capture is not None:
            evidence_capture.clear_next_deadline()
    if measurements.returncode != expected_returncode:
        raise AssertionError(
            f"sealed control exited {measurements.returncode}: "
            f"stdout={measurements.stdout!r} stderr={measurements.stderr!r}"
        )
    record = json.loads(measurements.stdout)
    if evidence_capture is not None:
        evidence_capture.record_parent_event('control-return', {'child_pid': process.pid, 'control_record': record})
    return record, measurements


def build_sealed_script(preseal: str, postseal: str) -> str:
    source_root = Path(__file__).resolve().parents[1] / "src"
    return (
        "import json, os, sys\n"
        "sys.dont_write_bytecode = True\n"
        f"sys.path.insert(0, {str(source_root)!r})\n"
        f"{preseal}\n"
        "from audioscribe.upload.sandbox import restrict_local_io\n"
        "restrict_local_io()\n"
        f"{postseal}\n"
    )


def start_sealed_process(preseal: str, postseal: str, pass_fds: tuple[int, ...] = ()):
    from audioscribe.upload.validator import _apply_validator_limits

    return subprocess.Popen(
        [sys.executable, "-I", "-c", build_sealed_script(preseal, postseal)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        pass_fds=pass_fds,
        start_new_session=True,
        preexec_fn=_apply_validator_limits,
    )
