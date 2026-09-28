"""Build graphical bootstrap archives for Unix targets without cross-compiling Python."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

TARGETS = {
    "linux-x86_64": ("manylinux_2_17_x86_64", "Instalar.sh"),
    "linux-arm64": ("manylinux_2_17_aarch64", "Instalar.sh"),
    "macos-arm64": ("macosx_11_0_arm64", "Instalar.command"),
    "macos-x86_64": ("macosx_10_12_x86_64", "Instalar.command"),
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target", choices=list(TARGETS) + ["all"], default="all")
    parser.add_argument("--offline", action="store_true", help="Reuse uv from existing output archives")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    targets = TARGETS if args.target == "all" else {args.target: TARGETS[args.target]}
    with tempfile.TemporaryDirectory(prefix="audioscribe-portable-") as temp:
        stage = Path(temp)
        wheels = stage / "wheels"
        build_args = ["--no-isolation", "--skip-dependency-check"] if args.offline else []
        subprocess.run([sys.executable, "-m", "build", "--wheel", *build_args, "--outdir", str(wheels), str(project)], check=True)
        app_wheel = next(wheels.glob("*.whl"))
        for target, (platform, launcher) in targets.items():
            folder = stage / target / "AudioScribe"
            payload = folder / "payload"
            payload.mkdir(parents=True)
            if args.offline:
                with tarfile.open(output / f"AudioScribe-{target}.tar.gz") as previous:
                    (payload / "uv").write_bytes(previous.extractfile("AudioScribe/payload/uv").read())
            else:
                subprocess.run([sys.executable, "-m", "pip", "download", "uv==0.12.19", "--no-deps",
                    "--only-binary=:all:", "--platform", platform, "--dest", str(stage / target / "uv-download")], check=True)
                uv_wheel = next((stage / target / "uv-download").glob("*.whl"))
                with zipfile.ZipFile(uv_wheel) as archive:
                    member = next(name for name in archive.namelist() if name.endswith("/uv") and ".data/scripts/" in name)
                    (payload / "uv").write_bytes(archive.read(member))
            shutil.copy2(app_wheel, payload / app_wheel.name)
            shutil.copy2(project / "installer/bootstrap.py", folder / "bootstrap.py")
            shutil.copytree(project / "src/audioscribe", folder / "src/audioscribe", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            (folder / launcher).write_text('''#!/bin/sh
set -eu
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export UV_PYTHON_INSTALL_DIR="$SCRIPT_DIR/.setup-runtime"
export UV_CACHE_DIR="$SCRIPT_DIR/.setup-cache"
export PYTHONPATH="$SCRIPT_DIR/src"
export PYTHONUTF8=1
export HF_HUB_DISABLE_TELEMETRY=1
export PYANNOTE_METRICS_ENABLED=0
chmod +x "$SCRIPT_DIR/payload/uv"
echo "Preparando el asistente de AudioScribe. La primera ejecución descarga Python."
"$SCRIPT_DIR/payload/uv" run --python 3.11 --managed-python --no-project --no-config python "$SCRIPT_DIR/bootstrap.py"
''', encoding="utf-8", newline="\n")
            (folder / "LEEME.txt").write_text(f"AudioScribe — {target}\n\nExtrae toda esta carpeta y ejecuta {launcher}.\nSe necesita Internet para la instalación y una sesión gráfica.\nSi el gestor de archivos no lo ejecuta, abre una terminal en esta carpeta y usa:\nsh ./{launcher}\n\nEl asistente solicitará todas las rutas y el token de Hugging Face.\nEl token no se guarda. No se envían audios.\n\nEste paquete se ha ensamblado en Windows; requiere validación en su sistema de destino.\nLos directorios .setup-runtime y .setup-cache son temporales del asistente;\nse pueden borrar cuando termine la instalación y se cierre el asistente.\n", encoding="utf-8")
            def permissions(info):
                if info.name.endswith(("/uv", "/" + launcher)):
                    info.mode = 0o755
                return info
            with tarfile.open(output / f"AudioScribe-{target}.tar.gz", "w:gz") as archive:
                archive.add(folder, arcname="AudioScribe", filter=permissions)
            print(f"Created {target}")


if __name__ == "__main__":
    main()
