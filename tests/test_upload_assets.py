"""PLAN-04 slice 5: browser assets and the upload extra in advertised installs."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_upload_assets_in_distribution():
    static = ROOT / "src" / "audioscribe" / "upload" / "static"
    for name in ("index.html", "app.js", "app.css"):
        assert (static / name).is_file(), f"packaged asset missing: {name}"
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    package_data = pyproject["tool"]["setuptools"].get("package-data", {})
    audioscribe = package_data.get("audioscribe", [])
    pattern = "upload/static/*"
    assert pattern in audioscribe or "upload/static/" in " ".join(audioscribe), \
        f"package data must advertise {pattern}: {package_data}"


def test_bootstrap_selects_upload_extra():
    bootstrap = (ROOT / "installer" / "bootstrap.py").read_text(encoding="utf-8")
    assert 'f"{wheel}[engine,upload]"' in bootstrap, \
        "the advertised bootstrap install must include the upload extra"
    assert 'f"{wheel}[engine]"' not in bootstrap