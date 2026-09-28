import json
import plistlib
from pathlib import Path
import pytest
from audioscribe import shortcuts as s

@pytest.mark.parametrize("desktop,apps,count", [(False,False,0),(True,False,1),(False,True,1),(True,True,2)])
def test_linux_options(tmp_path, monkeypatch, desktop, apps, count):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr(s.shutil, "which", lambda _: None)
    options = s.ShortcutOptions(desktop, apps)
    paths = s.create_launchers(tmp_path, tmp_path / "python", tmp_path / "config.toml", options, platform="linux", home=tmp_path / "home")
    assert len(paths) == count
    assert all(p.exists() and "Terminal=false" in p.read_text(encoding="utf-8") for p in paths)
    assert s.ShortcutOptions.load(tmp_path) == options
    assert s.create_launchers(tmp_path, tmp_path / "python", tmp_path / "config.toml", options, platform="linux", home=tmp_path / "home") == paths

@pytest.mark.parametrize("desktop,apps,count", [(False,False,0),(True,False,1),(False,True,5),(True,True,6)])
def test_windows_selection(tmp_path, desktop, apps, count):
    script = s.windows_script(tmp_path, tmp_path / "python.exe", tmp_path / "config with spaces.toml", s.ShortcutOptions(desktop,apps))
    assert script.count("link.Save") == count
    assert ('SpecialFolders("Desktop")' in script) == desktop
    assert ('SpecialFolders("Programs")' in script) == apps
    if count:
        assert "pythonw.exe" in script
        assert '""' in script

def test_windows_no_shortcuts(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        pytest.fail("Should not execute cscript")
    monkeypatch.setattr(s.subprocess, "run", fail)
    assert s.create_launchers(tmp_path, tmp_path / "python.exe", tmp_path / "config.toml", s.ShortcutOptions(False,False), platform="win32") == []

def test_mac_bundle_and_choices(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(s, "link_app", lambda source,target: calls.append((source,target)))
    paths = s.create_launchers(tmp_path, tmp_path / "python", tmp_path / "config.toml", s.ShortcutOptions(True,True), platform="darwin", home=tmp_path / "home")
    assert len(calls) == len(paths) == 2
    app = tmp_path / "AudioScribe.app/Contents"
    assert plistlib.loads((app / "Info.plist").read_bytes())["CFBundleExecutable"] == "AudioScribe"
    assert "panel" in (app / "MacOS/AudioScribe").read_text()
    assert paths == [tmp_path / "home/Applications/AudioScribe.app", tmp_path / "home/Desktop/AudioScribe.app"]

def test_preserve_other_app(tmp_path):
    target = tmp_path / "AudioScribe.app"
    target.write_text("existing")
    with pytest.raises(FileExistsError):
        s.link_app(tmp_path / "new", target)
    assert target.read_text() == "existing"

def test_pin_requires_menu(tmp_path):
    with pytest.raises(ValueError):
        s.create_launchers(tmp_path, tmp_path / "python", tmp_path / "config", s.ShortcutOptions(False,False,True))

def test_defaults(tmp_path):
    assert s.ShortcutOptions.load(tmp_path) == s.ShortcutOptions(False,True,False)
