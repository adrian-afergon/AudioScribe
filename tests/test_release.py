import importlib.util
import io
from pathlib import Path
import zipfile

import pytest

spec = importlib.util.spec_from_file_location("release_tools", Path(__file__).resolve().parents[1] / "installer/release_tools.py")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)


def test_tag_must_match_both_versions(tmp_path):
    (tmp_path / "src/audioscribe").mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "1.2.3"\n')
    runtime = tmp_path / "src/audioscribe/__init__.py"
    runtime.write_text('__version__ = "1.2.3"\n')
    assert release.version(tmp_path, "refs/tags/v1.2.3") == "1.2.3"
    assert release.version(tmp_path, "refs/heads/main") == "1.2.3"
    for ref in ("refs/tags/v1.2.4", "refs/tags/v1.2.3-beta", "refs/tags/vlatest"):
        with pytest.raises(ValueError):
            release.version(tmp_path, ref)
    runtime.write_text('__version__ = "1.2.2"\n')
    with pytest.raises(ValueError):
        release.version(tmp_path, "refs/tags/v1.2.3")


def test_release_requires_all_five_nonempty_installers(tmp_path):
    names = release.asset_names("1.2.3")
    for name in names[:-1]:
        (tmp_path / name).write_bytes(b"installer")
    with pytest.raises(ValueError):
        release.checksums(tmp_path, "1.2.3")
    (tmp_path / names[-1]).touch()
    with pytest.raises(ValueError):
        release.checksums(tmp_path, "1.2.3")
    (tmp_path / names[-1]).write_bytes(b"installer")
    release.checksums(tmp_path, "1.2.3")
    assert len((tmp_path / "SHA256SUMS.txt").read_text().splitlines()) == 5
    (tmp_path / "unexpected.exe").touch()
    with pytest.raises(ValueError):
        release.checksums(tmp_path, "1.2.3")


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_rejects_wrong_embedded_version(newline):
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("audioscribe_local-1.2.3.dist-info/METADATA", newline.join(["Name: audioscribe-local", "Version: 1.2.3", ""]))
    release.check_wheel(data.getvalue(), "1.2.3")
    with pytest.raises(ValueError):
        release.check_wheel(data.getvalue(), "1.2.4")
