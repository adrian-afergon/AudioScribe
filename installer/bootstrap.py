"""Small native bootstrapper. ML dependencies live in an isolated managed Python."""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

def trace(message):
    destination = os.environ.get("AUDIOSCRIBE_SELFTEST_LOG")
    if destination:
        with open(destination, "a", encoding="utf-8") as stream:
            stream.write(message + "\n")

trace("bootstrap importing")
import tkinter as tk

from audioscribe.config import Config, atomic_write
from audioscribe.service import InstanceLock, Scanner
from audioscribe.store import Store
from audioscribe.wizard import Wizard, prepare_tk

trace("bootstrap imports complete")


def payload() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "payload"


def default_install() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData/Local")) / "AudioScribe"
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/AudioScribe"
    return Path.home() / ".local/share/audioscribe"


def run_logged(args, env, log_path, token="", input_text=None):
    flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    with log_path.open("a", encoding="utf-8") as log:
        process = subprocess.Popen([str(arg) for arg in args], env=env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            encoding="utf-8", errors="replace", creationflags=flags)
        if input_text is not None:
            process.stdin.write(input_text)
            process.stdin.close()
        for line in process.stdout:
            log.write(line.replace(token, "[token oculto]") if token else line)
            log.flush()
        if process.wait() != 0:
            raise RuntimeError(f"No se completó la instalación o descarga. Revisa {log_path}. Puedes repetir la instalación para continuar.")


from audioscribe.shortcuts import create_launchers, ShortcutOptions


def install(install_dir: Path, config: Config, download: bool, token: str, report, shortcuts: ShortcutOptions | None = None):
    install_dir.mkdir(parents=True, exist_ok=True)
    config_path = install_dir / "config.toml"
    if config_path.exists():
        old = Config.load(config_path)
        if old.data_dir != config.data_dir:
            raise ValueError("Esta instalación ya tiene una base de datos. Conserva su directorio de datos: " + old.data_dir)
    from audioscribe.control import service_active, request
    import time
    if service_active(Path(config.data_dir)):
        report("Deteniendo la versión anterior; se conservarán los bloques completados…")
        request(Path(config.data_dir), "stop")
        deadline = time.monotonic() + 300
        while service_active(Path(config.data_dir)):
            if time.monotonic() > deadline:
                raise RuntimeError("La versión anterior sigue cerrando su trabajo. Espera a que termine y vuelve a instalar.")
            time.sleep(.5)
    lock = InstanceLock(Path(config.data_dir) / "service.lock")
    try:
        config.save(config_path)
        store = Store(config.database)
        try:
            Scanner(config, store).baseline()
        finally:
            store.close()
        uv_name = "uv.exe" if sys.platform == "win32" else "uv"
        source = payload()
        uv = install_dir / uv_name
        shutil.copy2(source / uv_name, uv)
        uv.chmod(0o755)
        wheel = next(source.glob("*.whl"))
        env = dict(os.environ)
        env.update({"UV_PYTHON_INSTALL_DIR": str(install_dir / "runtime"),
                    "UV_CACHE_DIR": str(install_dir / "download-cache"),
                    "HF_HUB_DISABLE_TELEMETRY": "1", "PYANNOTE_METRICS_ENABLED": "0",
                    "PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1"})
        log = install_dir / "installation.log"
        report(f"Descargando Python y preparando la aplicación. Registro: {log}")
        venv = install_dir / "environment"
        python = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
        if not python.exists():
            run_logged([uv, "venv", "--python", "3.11", "--managed-python", venv], env, log)
        report("Instalando dependencias de voz. Esta etapa puede tardar varios minutos…")
        run_logged([uv, "pip", "install", "--python", python, f"{wheel}[engine]"], env, log)
        report("Creando el panel AudioScribe y los accesos de control…")
        create_launchers(install_dir, python, config_path, shortcuts)
        if download:
            report(f"Descargando modelos y verificando su carga. Progreso detallado: {log}")
            code = ("import sys; from pathlib import Path; from audioscribe.config import Config; "
                    "from audioscribe.engine import prepare_models; "
                    "prepare_models(Config.load(Path(sys.argv[1])), sys.stdin.readline().strip())")
            run_logged([python, "-c", code, config_path], env, log, token, token + "\n")
    finally:
        lock.close()
    ready = (config.models / config.model / "model.bin").exists() and (config.models / "diarization/config.yaml").exists()
    if ready:
        report("Activando el servicio local…")
        action = "autostart" if config.autostart else "disable-autostart"
        run_logged([python, "-m", "audioscribe", "--config", config_path, action], env, log)
        from audioscribe.autostart import start
        start(python, config_path)
    from audioscribe.dashboard import launch_panel
    launch_panel(python, config_path)


def main():
    trace("main " + repr(sys.argv))
    prepare_tk()
    if "--self-test" in sys.argv:
        required = list(payload().glob("*.whl"))
        assert required, "Missing application wheel"
        assert (payload() / ("uv.exe" if sys.platform == "win32" else "uv")).exists()
        root = tk.Tk()
        trace("tk created")
        root.withdraw()
        Wizard(root, install_callback=install, default_install=default_install())
        trace("wizard created")
        root.update_idletasks()
        root.destroy()
        trace("self-test complete")
        return
    root = tk.Tk()
    existing = default_install() / "config.toml"
    Wizard(root, config_path=existing if existing.exists() else None,
           install_callback=install, default_install=default_install())
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        import traceback
        trace(traceback.format_exc())
        if "--self-test" in sys.argv:
            sys.exit(1)
        raise
