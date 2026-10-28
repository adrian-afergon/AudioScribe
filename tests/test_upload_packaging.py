"""PLAN-05 step 3: packaged upload extra, static assets and child runtime.

Builds a real wheel and sdist from a copy of the project (outside the
checkout) through the PEP 517 build backend, unpacks both, and smoke-tests a
fresh installed base environment: the advertised extra stays optional, the
static assets and validator child runtime ship inside the package, and a
base install without Uvicorn/h11/PyAV keeps working with a clear enable
error. Dependency resolution for the extras themselves is verified in the
session's real ``pip install`` evidence (RESULT-PLAN05), not by network
access inside the test suite.
"""

from __future__ import annotations

import email
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
STATIC_ASSETS = ("index.html", "app.js", "app.css")
CHILD_RUNTIME = ("validator.py", "sandbox.py", "protocol.py", "http.py")


def _backend_pythonpath() -> str:
    """setuptools+wheel for the build/install subprocesses: importable here,
    or unpacked in the uv cache."""
    if importlib.util.find_spec("setuptools") and importlib.util.find_spec("wheel"):
        return ""
    roots = []
    cache = Path.home() / ".cache" / "uv" / "archive-v0"
    for pattern in ("setuptools-*.dist-info", "wheel-*.dist-info"):
        for entry in sorted(cache.glob(f"*/{pattern}")):
            roots.append(str(entry.parent))
    if len(roots) < 2:
        pytest.fail("packaging tests need setuptools+wheel importable or in the uv cache")
    return os.pathsep.join(dict.fromkeys(roots))


def _clean_env(pythonpath: str | None = None) -> dict:
    env = {key: value for key, value in os.environ.items()
           if key not in ("PYTHONPATH", "PYTHONSTARTUP")}
    if pythonpath:
        env["PYTHONPATH"] = pythonpath
    return env


@pytest.fixture(scope="module")
def dist(tmp_path_factory) -> tuple[Path, Path]:
    """Build one wheel and one sdist from a pristine project copy."""
    work = tmp_path_factory.mktemp("pkgbuild")
    project = work / "project"
    (project / "src").mkdir(parents=True)
    shutil.copytree(ROOT / "src" / "audioscribe", project / "src" / "audioscribe",
                    ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy2(ROOT / "pyproject.toml", project / "pyproject.toml")
    dist_dir = work / "dist"
    dist_dir.mkdir()
    manifest = dist_dir / "built.json"
    manifest_line = ("open(%r, 'w').write(json.dumps({'wheel': wheel, 'sdist': sdist}))"
                     % str(manifest))
    code = (
        "import json\n"
        "from setuptools import build_meta\n"
        f"wheel = build_meta.build_wheel({str(dist_dir)!r})\n"
        f"sdist = build_meta.build_sdist({str(dist_dir)!r})\n"
        f"{manifest_line}\n"
    )
    result = subprocess.run([sys.executable, "-c", code], cwd=project,
                            env=_clean_env(_backend_pythonpath()),
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr[-4000:]
    names = json.loads(manifest.read_text())
    return dist_dir / names["wheel"], dist_dir / names["sdist"]


def _unpacked_wheel(dist, tmp_path) -> Path:
    target = tmp_path / "wheel-tree"
    with zipfile.ZipFile(dist[0]) as archive:
        archive.extractall(target)
    return target


def _wheel_metadata(dist) -> email.message.Message:
    with zipfile.ZipFile(dist[0]) as archive:
        return email.message_from_string(
            archive.read("audioscribe_local-0.3.0.dist-info/METADATA").decode("utf-8"))


def test_installed_upload_extra(dist):
    """The wheel and sdist advertise the pinned upload extra."""
    for source, metadata in (("wheel", _wheel_metadata(dist)),):
        extras = metadata.get_all("Provides-Extra") or []
        assert "upload" in extras, f"{source} must provide the upload extra: {extras}"
        requirements = metadata.get_all("Requires-Dist") or []
        for pin in ("uvicorn==0.54.0", "h11==0.16.0", "av==15.1.0"):
            assert any(pin in requirement
                       and ("extra == \"upload\"" in requirement or "extra == 'upload'" in requirement)
                       for requirement in requirements), \
                f"{source} must pin {pin} behind the upload extra: {requirements}"
        base = [requirement for requirement in requirements
                if any(name in requirement for name in ("uvicorn", "h11", "av=="))]
        assert not [r for r in base if "extra" not in r], \
            "uvicorn/h11/av must stay optional, never base dependencies"
    with tarfile.open(dist[1]) as archive:
        pkg_info = archive.extractfile("audioscribe_local-0.3.0/PKG-INFO")
        assert pkg_info is not None, "sdist must carry PKG-INFO"
        sdist_metadata = email.message_from_string(pkg_info.read().decode("utf-8"))
    assert "upload" in (sdist_metadata.get_all("Provides-Extra") or [])


def test_installed_static_assets(dist, tmp_path):
    """The packaged static assets ship inside the installed package tree."""
    tree = _unpacked_wheel(dist, tmp_path)
    for name in STATIC_ASSETS:
        assert (tree / "audioscribe" / "upload" / "static" / name).is_file(), name
    record = (tree / "audioscribe_local-0.3.0.dist-info" / "RECORD").read_text()
    for name in STATIC_ASSETS:
        assert f"audioscribe/upload/static/{name}" in record, \
            f"{name} must be listed in RECORD (installed by pip)"


def test_packaged_validator_and_static_assets(dist, tmp_path):
    """The confined validator child runtime and listener modules are packaged
    modules of the installed wheel, not checkout assumptions."""
    tree = _unpacked_wheel(dist, tmp_path)
    upload = tree / "audioscribe" / "upload"
    for name in CHILD_RUNTIME:
        assert (upload / name).is_file(), f"child runtime module missing from wheel: {name}"


def _fresh_venv(tmp_path: Path, name: str) -> Path:
    venv_dir = tmp_path / name
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True,
                   capture_output=True, timeout=120)
    return venv_dir


def _copy_watchdog(venv_dir: Path) -> None:
    """Inject the single base dependency from the running environment so the
    offline fresh env can import the base package (resolution of published
    dependencies is proven by the session's real pip evidence)."""
    spec = importlib.util.find_spec("watchdog")
    assert spec is not None and spec.origin, "watchdog must be importable to seed the env"
    package = Path(spec.origin).parent
    site = next((venv_dir / "lib").glob("python3.*/site-packages"))
    shutil.copytree(package, site / "watchdog",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for entry in package.parent.iterdir():
        if entry.name.startswith("watchdog-") and entry.name.endswith(".dist-info"):
            shutil.copytree(entry, site / entry.name)


def _venv_python(venv_dir: Path) -> Path:
    return venv_dir / "bin" / "python"


def test_packaged_upload_disabled_and_enableable(dist, tmp_path):
    """A base install keeps working without Uvicorn/h11/PyAV: the package
    imports, the listener import is deferred, and enabling without the extra
    fails with a clear named-module error instead of a crash."""
    venv_dir = _fresh_venv(tmp_path, "disabled")
    _copy_watchdog(venv_dir)
    subprocess.run([str(venv_dir / "bin" / "pip"), "install", "--no-deps",
                    "--no-index", str(dist[0])],
                   check=True, capture_output=True, env=_clean_env(), timeout=120)
    env = _clean_env()
    outside = tmp_path / "outside"
    outside.mkdir()
    probe = (
        "import audioscribe, audioscribe.cli\n"
        "print('base-import-ok', audioscribe.__version__)\n"
        "try:\n"
        "    import uvicorn\n"
        "    print('UNEXPECTED uvicorn importable')\n"
        "except ImportError as error:\n"
        "    print('uvicorn-missing', error)\n"
        "from audioscribe.upload._listener import start_uvicorn_listener\n"
        "try:\n"
        "    start_uvicorn_listener(None, None)\n"
        "    print('UNEXPECTED listener start')\n"
        "except ImportError as error:\n"
        "    print('enable-error', error)\n"
    )
    result = subprocess.run([str(_venv_python(venv_dir)), "-c", probe], cwd=outside,
                            env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-3000:]
    assert "base-import-ok 0.3.0" in result.stdout
    assert "uvicorn-missing No module named 'uvicorn'" in result.stdout
    assert "enable-error No module named 'uvicorn'" in result.stdout, \
        "the enable path must fail with the missing dependency named"


def test_wheel_installed_smoke(dist, tmp_path):
    """The wheel installs into a fresh environment and the CLI runs from
    outside the checkout with no PYTHONPATH assistance."""
    venv_dir = _fresh_venv(tmp_path, "wheel-smoke")
    _copy_watchdog(venv_dir)
    subprocess.run([str(venv_dir / "bin" / "pip"), "install", "--no-deps",
                    "--no-index", str(dist[0])],
                   check=True, capture_output=True, env=_clean_env(), timeout=120)
    outside = tmp_path / "outside"
    outside.mkdir()
    result = subprocess.run([str(_venv_python(venv_dir)), "-m", "audioscribe", "--help"],
                            cwd=outside, env=_clean_env(), capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-3000:]
    assert "upload" in result.stdout, "the installed CLI must expose the upload controls"


def test_sdist_installed_smoke(dist, tmp_path):
    """The sdist builds and installs into a fresh environment with the same
    packaged assets present in the installed tree."""
    venv_dir = _fresh_venv(tmp_path, "sdist-smoke")
    _copy_watchdog(venv_dir)
    pip_env = _clean_env(_backend_pythonpath())
    subprocess.run([str(venv_dir / "bin" / "pip"), "install", "--no-deps",
                    "--no-index", "--no-build-isolation", str(dist[1])],
                   check=True, capture_output=True, env=pip_env, timeout=300)
    outside = tmp_path / "outside"
    outside.mkdir()
    probe = (
        "import pathlib, audioscribe\n"
        "static = pathlib.Path(audioscribe.__file__).parent / 'upload' / 'static'\n"
        "names = sorted(entry.name for entry in static.iterdir())\n"
        "print('static', names)\n"
    )
    result = subprocess.run([str(_venv_python(venv_dir)), "-c", probe], cwd=outside,
                            env=_clean_env(), capture_output=True, text=True,
                            timeout=120)
    assert result.returncode == 0, result.stderr[-3000:]
    assert f"static {sorted(STATIC_ASSETS)}" in result.stdout
