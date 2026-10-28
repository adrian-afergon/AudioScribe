"""PLAN-02 slice 3: atomic no-overwrite publication on the actual mount."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from audioscribe.upload.publication import (InvalidFilename, file_sha256,
                                            normalize_media_filename,
                                            probe_link_capability,
                                            publish_atomically)


def test_q03_probe_atomic_no_overwrite_on_actual_mount(tmp_path):
    report = probe_link_capability(tmp_path)
    assert report["link_shares_identity"] is True
    assert report["collision_preserves_original"] is True
    assert not list(tmp_path.iterdir())


def test_colliding_names_never_overwrite(tmp_path):
    existing = tmp_path / "clip.mp3"
    existing.write_bytes(b"original-bytes")
    original_hash = file_sha256(existing)
    staging = tmp_path / "staged.mp3"
    staging.write_bytes(b"new-bytes")
    final = publish_atomically(staging, tmp_path, "clip.mp3")
    assert final.name == "clip-2.mp3"
    assert existing.read_bytes() == b"original-bytes"
    assert file_sha256(existing) == original_hash
    assert final.read_bytes() == b"new-bytes"
    second = publish_atomically(staging, tmp_path, "clip.mp3")
    assert second.name == "clip-3.mp3"
    case_target = tmp_path / "CLIP.MP3"
    case_target.write_bytes(b"casefold-target")
    case_hash = file_sha256(case_target)
    if os.path.exists(case_target):
        with pytest.raises(OSError):
            os.link(staging, case_target, follow_symlinks=False)
        third = publish_atomically(staging, tmp_path, "clip.mp3")
        assert third.name == "clip-4.mp3"
        assert file_sha256(case_target) == case_hash


def test_publish_never_uses_rename_or_replace(tmp_path):
    existing = tmp_path / "song.mp3"
    existing.write_bytes(b"do-not-touch")
    staging = tmp_path / "part.mp3"
    staging.write_bytes(b"replacement")
    with pytest.raises(FileExistsError):
        os.link(staging, existing, follow_symlinks=False)
    assert existing.read_bytes() == b"do-not-touch"
    assert staging.exists()


def test_filename_containment_cross_platform():
    assert normalize_media_filename("My Podcast Episode.MP3")[0] == "my podcast episode.mp3"
    assert normalize_media_filename("café.mp4")[0] == "café.mp4"
    for bad in ("../escape.mp3", "a/b.mp3", "a\\b.mp3", ".hidden.mp3",
                "ads:stream.mp3", "CON.mp3", "name.mp3.", " ", "name\x07.mp3",
                "video.mov", "video.avi", ""):
        with pytest.raises(InvalidFilename):
            normalize_media_filename(bad)
    name, stem = normalize_media_filename("ñ" * 400 + ".mp3")
    assert len(name.encode("utf-8")) <= 240
    assert name.endswith(".mp3")


def test_first_root_upload_not_baselined(tmp_path):
    from audioscribe.config import Config
    from audioscribe.service import Scanner
    from audioscribe.store import Store
    (tmp_path / "in").mkdir()
    config = Config(str(tmp_path / "in"), str(tmp_path / "out"), str(tmp_path / "brain"),
                    str(tmp_path / "data"), stable_seconds=0)
    store = Store(config.database)
    scanner = Scanner(config, store)
    preexisting = tmp_path / "in" / "old.mp3"
    preexisting.write_bytes(b"preexisting")
    scanner.baseline()
    published = tmp_path / "in" / "uploaded.mp3"
    published.write_bytes(b"uploaded-media")
    scanner.scan()
    rows = {row["path"]: row["ignored"] for row in
            store.db.execute("SELECT path,ignored FROM files").fetchall()}
    assert rows[str(published)] == 0
    assert rows[str(preexisting)] == 1


# -- review required-action 9: non-destructive probe names ---------------------


def test_probe_never_touches_preexisting_files_or_fixed_names(tmp_path):
    """The probe must use private unique names and never unlink or write
    operator-visible fixed names in the input root: a pre-existing user file
    at a probe name (or a symlink planted there) must survive untouched."""
    legacy_source = tmp_path / ".audioscribe-probe-src"
    legacy_target = tmp_path / ".audioscribe-probe-dst"
    user_bytes = b"user data that must survive every enable"
    legacy_source.write_bytes(user_bytes)
    legacy_target.write_bytes(user_bytes)
    sentinel = tmp_path / "keep-me.mp3"
    sentinel.write_bytes(b"sentinel")

    report = probe_link_capability(tmp_path)

    assert report["link_shares_identity"] is True
    assert report["collision_preserves_original"] is True
    assert legacy_source.read_bytes() == user_bytes
    assert legacy_target.read_bytes() == user_bytes
    assert sentinel.read_bytes() == b"sentinel"
    # No probe residue at the legacy fixed names or anywhere else.
    assert legacy_source.read_bytes() == user_bytes
    assert legacy_target.read_bytes() == user_bytes
    leftovers = [p.name for p in tmp_path.iterdir() if p.name != "keep-me.mp3"
                 and not p.name.startswith(".audioscribe-probe-")]
    assert leftovers == [], f"probe left residue: {leftovers}"
    assert legacy_source.stat().st_size == len(user_bytes)
    assert legacy_target.stat().st_size == len(user_bytes)


def test_probe_tolerates_symlink_planted_at_legacy_name(tmp_path):
    """A symlink planted at the old fixed name must neither be followed (no
    writes through it) nor unlinked."""
    outside = tmp_path.parent / "outside-probe-target.txt"
    outside.write_bytes(b"outside")
    planted = tmp_path / ".audioscribe-probe-src"
    planted.symlink_to(outside)
    try:
        report = probe_link_capability(tmp_path)
        assert report["link_shares_identity"] is True
        assert report["collision_preserves_original"] is True
        assert outside.read_bytes() == b"outside", "the symlink target must be untouched"
        assert planted.is_symlink(), "the planted symlink must not be unlinked"
    finally:
        if planted.is_symlink():
            planted.unlink()
        outside.unlink(missing_ok=True)
