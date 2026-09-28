"""User-selected launchers. Pinning is completed explicitly in the native shell."""
from __future__ import annotations

import json
import os
import plistlib
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import atomic_write
from . import __version__

ACTIONS = (("AudioScribe", "panel"), ("Configurar", "setup"), ("Iniciar", "run"),
           ("Detener", "stop"), ("Estado", "panel"))


@dataclass
class ShortcutOptions:
    desktop: bool = False
    applications: bool = True
    pin_help: bool = False

    @classmethod
    def load(cls, install: Path):
        try:
            data = json.loads((install / "launcher-options.json").read_text(encoding="utf-8"))
            values = data["options"]
            if any(type(values.get(key)) is not bool for key in ("desktop", "applications", "pin_help")):
                raise ValueError("Opciones de acceso no válidas")
            return cls(**values)
        except FileNotFoundError:
            return cls()


def labels(platform=None):
    platform = platform or sys.platform
    if platform == "win32":
        return ("Crear un acceso directo en el escritorio", "Añadir al menú Inicio (lista de aplicaciones)",
                "Ayudarme a anclar a Inicio o a la barra de tareas al terminar")
    if platform == "darwin":
        return ("Crear un acceso en el escritorio", "Añadir a Aplicaciones de mi usuario",
                "Ayudarme a añadir AudioScribe al Dock al terminar")
    return ("Crear un lanzador en el escritorio", "Añadir al menú de aplicaciones",
            "Ayudarme a añadir a favoritos o al panel al terminar")


def pin_instructions(platform=None):
    platform = platform or sys.platform
    if platform == "win32":
        return ("Abre Inicio, busca AudioScribe y pulsa con el botón derecho: «Anclar a Inicio». "
                "Para la barra de tareas, utiliza «Anclar a la barra de tareas» si aparece en el menú. "
                "Crear el acceso en la lista de aplicaciones no lo fija automáticamente.")
    if platform == "darwin":
        return ("En Finder, abre la carpeta Aplicaciones de tu usuario y arrastra AudioScribe.app "
                "a la zona de aplicaciones del Dock. También puedes usar Opciones > Mantener en el Dock "
                "si AudioScribe aparece al abrirlo. El instalador no cambia la distribución del Dock.")
    return ("Busca AudioScribe en el menú de aplicaciones y utiliza «Añadir a favoritos» "
            "o «Anclar al panel», según tu escritorio (GNOME, KDE u otro). "
            "Si creaste el lanzador de escritorio, puede ser necesario pulsar «Permitir iniciar» "
            "en su menú contextual. Algunos escritorios no muestran iconos en el escritorio.")


def desktop_entry(launcher: Path):
    # Desktop Entry Exec has its own escaping, independent of shell quoting.
    arg = str(launcher).replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$").replace("%", "%%")
    return ('[Desktop Entry]\nType=Application\nName=AudioScribe\n'
            'Comment=Actividad y control de transcripción local\n'
            f'Exec="{arg}"\nTerminal=false\nIcon=audio-input-microphone\nCategories=AudioVideo;Utility;\n')


def mac_bundle(install: Path, python: Path, config: Path) -> Path:
    app = install / "AudioScribe.app"
    contents = app / "Contents"
    executable = contents / "MacOS/AudioScribe"
    atomic_write(executable, "#!/bin/sh\nexec " + shlex.join([str(python), "-m", "audioscribe", "--config", str(config), "panel"]) + "\n")
    executable.chmod(0o755)
    metadata = {"CFBundleName": "AudioScribe", "CFBundleDisplayName": "AudioScribe",
                "CFBundleIdentifier": "local.audioscribe.app", "CFBundlePackageType": "APPL",
                "CFBundleExecutable": "AudioScribe", "CFBundleVersion": __version__,
                "CFBundleShortVersionString": __version__, "NSHighResolutionCapable": True}
    atomic_write(contents / "Info.plist", plistlib.dumps(metadata).decode())
    return app


def link_app(source: Path, target: Path):
    if target.is_symlink() and target.resolve() == source.resolve():
        return
    if target.exists() or target.is_symlink():
        raise FileExistsError(f"Ya existe otro elemento en {target}. No se ha sustituido.")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(source, target_is_directory=True)


def windows_script(install: Path, python: Path, config: Path, options: ShortcutOptions):
    def vb(value):
        return '"' + str(value).replace('"', '""') + '"'
    lines = ['Set shell = CreateObject("WScript.Shell")',
             'Set fs = CreateObject("Scripting.FileSystemObject")']
    groups = []
    if options.applications:
        lines += ['folder = shell.SpecialFolders("Programs") & "\\AudioScribe"',
                  'If Not fs.FolderExists(folder) Then fs.CreateFolder(folder)']
        groups.extend(("folder", name, action) for name, action in ACTIONS)
    if options.desktop:
        # WScript resolves redirected and localized Desktop folders, including OneDrive.
        groups.append(('shell.SpecialFolders("Desktop")', "AudioScribe", "panel"))
    for folder, name, action in groups:
        argument = subprocess.list2cmdline(["-m", "audioscribe", "--config", str(config), action])
        lines.extend([f"linkPath = {folder} & {vb(chr(92) + name + '.lnk')}",
                      "Set link = shell.CreateShortcut(linkPath)",
                      f"link.TargetPath = {vb(python.with_name('pythonw.exe'))}",
                      f"link.Arguments = {vb(argument)}", f"link.WorkingDirectory = {vb(install)}",
                      "link.Save", "WScript.Echo linkPath"])
    return "\n".join(lines)


def create_launchers(install: Path, python: Path, config_path: Path,
                     options: ShortcutOptions | None = None, *, platform=None, home=None) -> list[Path]:
    options = options or ShortcutOptions()
    platform = platform or sys.platform
    home = Path(home) if home is not None else Path.home()
    if options.pin_help and not options.applications:
        raise ValueError("Para anclar la aplicación, selecciona también añadirla a la lista de aplicaciones.")
    created = []
    if platform == "win32":
        if options.desktop or options.applications:
            script = install / "create-shortcuts.vbs"
            script.write_text(windows_script(install, python, config_path, options), encoding="utf-16")
            try:
                completed = subprocess.run(["cscript", "//Nologo", str(script)], check=True,
                    capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                # cscript's console output uses the current OEM code page.
                encoding = "oem" if sys.platform == "win32" else "utf-8"
                created = [Path(line.strip()) for line in completed.stdout.decode(encoding).splitlines() if line.strip()]
            finally:
                script.unlink(missing_ok=True)
    else:
        for name, action in ACTIONS:
            path = install / (name + (".command" if platform == "darwin" else ".sh"))
            atomic_write(path, "#!/bin/sh\nexec " + shlex.join([str(python), "-m", "audioscribe", "--config", str(config_path), action]) + "\n")
            path.chmod(0o755)
        if platform == "darwin":
            app = mac_bundle(install, python, config_path)
            for enabled, folder in ((options.applications, home / "Applications"), (options.desktop, home / "Desktop")):
                if enabled:
                    target = folder / "AudioScribe.app"
                    link_app(app, target)
                    created.append(target)
        else:
            locations = []
            if options.applications:
                configured = os.environ.get("XDG_DATA_HOME", "")
                base = Path(configured) if configured and Path(configured).is_absolute() else home / ".local/share"
                locations.append(base / "applications/audioscribe.desktop")
            if options.desktop:
                folder = home / "Desktop"
                if shutil.which("xdg-user-dir"):
                    result = subprocess.run(["xdg-user-dir", "DESKTOP"], capture_output=True, text=True, check=True)
                    chosen = Path(result.stdout.strip())
                    if chosen.is_absolute():
                        folder = chosen
                if folder == home:
                    raise ValueError("Este entorno tiene desactivada la carpeta de escritorio. Usa el menú de aplicaciones.")
                locations.append(folder / "AudioScribe.desktop")
            for target in locations:
                atomic_write(target, desktop_entry(install / "AudioScribe.sh"))
                target.chmod(0o755)
                created.append(target)
    atomic_write(install / "launcher-options.json", json.dumps(
        {"options": asdict(options), "locations": [str(p) for p in created]}, ensure_ascii=False, indent=2))
    return created
