from audioscribe.config import Config


def test_legacy_config_defaults_disabled(tmp_path):
    config_path = tmp_path / "config.toml"
    (tmp_path / "brain").mkdir()
    config_path.write_text(
        'input_dir = "' + str(tmp_path / "input") + '"\n'
        'output_dir = "' + str(tmp_path / "output") + '"\n'
        'brain_dir = "' + str(tmp_path / "brain") + '"\n'
        'data_dir = "' + str(tmp_path / "data") + '"\n',
        encoding="utf-8",
    )
    config = Config.load(config_path)

    assert config.upload_enabled is False
    assert config.upload_origin == ""
    assert config.upload_port == 8765
    assert config.upload_max_bytes == 20_000_000_000
    assert config.upload_concurrency == 2
    assert config.upload_reserve_bytes == 25_000_000_000
    assert config.upload_inactivity_seconds == 600


def test_wizard_preserves_upload_settings(tmp_path, monkeypatch):
    import queue

    from audioscribe import wizard as wizard_module
    from audioscribe.wizard import Wizard

    paths = [str(tmp_path / name) for name in ("input", "output", "brain", "data")]
    (tmp_path / "brain").mkdir()
    existing = Config(*paths, upload_enabled=True, upload_origin="https://scribe.example.ts.net",
                      upload_port=9443, upload_max_bytes=123_456, upload_concurrency=3,
                      upload_reserve_bytes=456_789, upload_inactivity_seconds=90)
    wizard = Wizard.__new__(Wizard)

    class Value:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

        def set(self, value):
            self.value = value

    class Control:
        def configure(self, **_kwargs):
            pass

        def start(self):
            pass

    class ImmediateThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            self.target()

    wizard.existing = existing
    wizard.variables = dict(zip(("input_dir", "output_dir", "brain_dir", "data_dir"),
                                [Value(path) for path in paths]))
    wizard.recursive = Value(True)
    wizard.autostart = Value(True)
    wizard.model = Value("base")
    wizard.device = Value("cpu")
    wizard.download = Value(False)
    wizard.token = Value("")
    wizard.config_path = tmp_path / "config.toml"
    wizard.install_callback = None
    wizard.desktop_shortcut = Value(False)
    wizard.applications_shortcut = Value(False)
    wizard.pin_help = Value(False)
    wizard.busy = False
    wizard.button = Control()
    wizard.progress = Control()
    wizard.events = queue.Queue()
    saved = []
    monkeypatch.setattr(wizard_module, "configure", lambda config, *_args: saved.append(config))
    monkeypatch.setattr(wizard_module.threading, "Thread", ImmediateThread)

    wizard.submit()
    configured = saved[0]

    assert configured.model == "base"
    assert configured.recursive is True
    assert configured.upload_enabled is True
    assert configured.upload_origin == "https://scribe.example.ts.net"
    assert configured.upload_port == 9443
    assert configured.upload_max_bytes == 123_456
    assert configured.upload_concurrency == 3
    assert configured.upload_reserve_bytes == 456_789
    assert configured.upload_inactivity_seconds == 90


def test_upload_config_rejects_boolean_integer_limits(tmp_path):
    (tmp_path / "brain").mkdir()
    paths = [str(tmp_path / name) for name in ("input", "output", "brain", "data")]
    config = Config(*paths, upload_max_bytes=True)

    try:
        config.validate(probe=False)
    except ValueError as error:
        assert "upload_max_bytes" in str(error)
    else:
        raise AssertionError("bool must not be accepted as upload_max_bytes")


def test_upload_config_rejects_zero_concurrency(tmp_path):
    (tmp_path / "brain").mkdir()
    paths = [str(tmp_path / name) for name in ("input", "output", "brain", "data")]
    config = Config(*paths, upload_concurrency=0)

    try:
        config.validate(probe=False)
    except ValueError as error:
        assert "upload_concurrency" in str(error)
    else:
        raise AssertionError("zero concurrency must be rejected")


def test_wizard_rejects_protected_changes_while_enabled(tmp_path, monkeypatch):
    """S01.03/S04.08: with uploads enabled, input/output root or protected
    limit changes through the wizard are rejected at the save point."""
    import queue

    from audioscribe import wizard as wizard_module
    from audioscribe.wizard import Wizard

    paths = [str(tmp_path / name) for name in ("input", "output", "brain", "data")]
    (tmp_path / "brain").mkdir()
    existing = Config(*paths, upload_enabled=True, upload_origin="https://scribe.example.ts.net")
    wizard = Wizard.__new__(Wizard)

    class Value:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

        def set(self, value):
            self.value = value

    class Control:
        def configure(self, **_kwargs):
            pass

        def start(self):
            pass

    class ImmediateThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            self.target()

    rejected = []
    monkeypatch.setattr(wizard_module.messagebox, "showerror",
                        lambda *_args, **_kwargs: rejected.append(True))
    wizard.existing = existing
    changed = str(tmp_path / "other-input")
    wizard.variables = dict(zip(("input_dir", "output_dir", "brain_dir", "data_dir"),
                                [Value(changed)] + [Value(path) for path in paths[1:]]))
    wizard.recursive = Value(False)
    wizard.autostart = Value(True)
    wizard.model = Value("base")
    wizard.device = Value("cpu")
    wizard.download = Value(False)
    wizard.token = Value("")
    wizard.config_path = tmp_path / "config.toml"
    wizard.install_callback = None
    wizard.desktop_shortcut = Value(False)
    wizard.applications_shortcut = Value(False)
    wizard.pin_help = Value(False)
    wizard.busy = False
    wizard.button = Control()
    wizard.progress = Control()
    wizard.events = queue.Queue()
    saved = []
    monkeypatch.setattr(wizard_module, "configure", lambda config, *_args: saved.append(config))
    monkeypatch.setattr(wizard_module.threading, "Thread", ImmediateThread)

    wizard.submit()

    assert saved == [], "the wizard must never save a protected change while uploads are enabled"
    assert rejected, "the operator must see the rejection"
    assert not (tmp_path / "other-input").exists(), \
        "the rejected input folder must not be created"


def test_wizard_accepts_unrelated_changes_while_enabled(tmp_path, monkeypatch):
    import queue

    from audioscribe import wizard as wizard_module
    from audioscribe.wizard import Wizard

    paths = [str(tmp_path / name) for name in ("input", "output", "brain", "data")]
    (tmp_path / "brain").mkdir()
    existing = Config(*paths, upload_enabled=True, upload_origin="https://scribe.example.ts.net",
                      model="small")
    wizard = Wizard.__new__(Wizard)

    class Value:
        def __init__(self, value):
            self.value = value

        def get(self):
            return self.value

        def set(self, value):
            self.value = value

    class Control:
        def configure(self, **_kwargs):
            pass

        def start(self):
            pass

    class ImmediateThread:
        def __init__(self, target, daemon):
            self.target = target

        def start(self):
            self.target()

    rejected = []
    monkeypatch.setattr(wizard_module.messagebox, "showerror",
                        lambda *_args, **_kwargs: rejected.append(True))
    wizard.existing = existing
    wizard.variables = dict(zip(("input_dir", "output_dir", "brain_dir", "data_dir"),
                                [Value(path) for path in paths]))
    wizard.recursive = Value(False)
    wizard.autostart = Value(True)
    wizard.model = Value("base")
    wizard.device = Value("cpu")
    wizard.download = Value(False)
    wizard.token = Value("")
    wizard.config_path = tmp_path / "config.toml"
    wizard.install_callback = None
    wizard.desktop_shortcut = Value(False)
    wizard.applications_shortcut = Value(False)
    wizard.pin_help = Value(False)
    wizard.busy = False
    wizard.button = Control()
    wizard.progress = Control()
    wizard.events = queue.Queue()
    saved = []
    monkeypatch.setattr(wizard_module, "configure", lambda config, *_args: saved.append(config))
    monkeypatch.setattr(wizard_module.threading, "Thread", ImmediateThread)

    wizard.submit()

    assert not rejected
    assert saved and saved[0].model == "base", \
        "unrelated changes stay accepted while uploads are enabled"
    assert saved[0].upload_enabled is True
