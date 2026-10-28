"""Frozen L-Q04 fixture provenance for the retained plain qualification test.

The deprecated fixture generator module (tests/lq04_fixtures.py) was removed
with the rest of the deprecated evidence harness (review required-action 12);
the frozen digests below are the live datum the qualification test and the
validator fixtures assert against. GENERATOR NEVER INVOKED — fixtures come
from AUDIOSCRIBE_LQ04_FIXTURE_ROOT (see RESULT-LQ04.md).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_P1_SHA256 = "9629fc6a9511763aa5bb5b1971a8b7b05ba141a93c2a04025ea66321f2741f9e"
LQ04_FIXTURE_SHA256 = {
    "P1-video-only-mpeg4.mp4": _P1_SHA256,
    "P2-mp3-libmp3lame.mp3": "716d408e2a2396bdb135273e54e0eb8fba1e8779de53a34d30e32c7ce54cfb02",
    "P3-audio-bearing-aac.mp4": "94052ea089030c69df37700e8b48347a6197647460143e840ff7e14c64e786b8",
    "P4-video-h264.mp4": "caec72c9be7d319d99b5045ba743a6e149b588abe237665512f13ebaddb7a87e",
    "N1-empty.mp3": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "N1-malformed.mp4": "537553fed3a22cc2a9b162a055d6751bec2627aa91cb0f94906099194940bae3",
    "N1-quicktime-brand.mp4": "44ff78090fb1a13b9c5871681679c32cf47777a6f32e0cf61ad10ce85d3d2389",
    "N1-extension-mismatch.mp3": _P1_SHA256,
}


def fixture_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
