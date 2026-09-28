"""Build on the target OS: python installer/build.py --output /absolute/output."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--offline", action="store_true", help="Use already installed build dependencies")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="audioscribe-build-") as temporary:
        build = Path(temporary)
        payload = build / "payload"
        payload.mkdir()
        build_args = ["--no-isolation", "--skip-dependency-check"] if args.offline else []
        subprocess.run([sys.executable, "-m", "build", "--wheel", *build_args, "--outdir", str(payload), str(project)], check=True)
        uv_name = "uv.exe" if os.name == "nt" else "uv"
        # uv is an explicit build dependency, bundled so the end user needs no Python.
        candidate = Path(sys.executable).parent / uv_name
        if not candidate.exists():
            candidate = Path(shutil.which("uv") or "")
        if not candidate.is_file():
            raise RuntimeError("Install the uv build dependency first.")
        shutil.copy2(candidate, payload / uv_name)
        args = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
                "--name", "AudioScribe-Setup", "--paths", str(project / "src"),
                "--distpath", str(output), "--workpath", str(build / "pyinstaller"),
                "--specpath", str(build), "--add-data", str(payload) + os.pathsep + "payload"]
        for module in ("torch", "torchaudio", "torchcodec", "pyannote", "faster_whisper", "numpy", "av", "huggingface_hub", "onnxruntime", "ctranslate2", "psutil"):
            args.extend(["--exclude-module", module])
        args.append(str(project / "installer/bootstrap.py"))
        env = dict(os.environ)
        env["PYTHONUSERBASE"] = str(build / "isolated-user-base")
        env["PYINSTALLER_CONFIG_DIR"] = str(build / "cache")
        subprocess.run(args, check=True, env=env)


if __name__ == "__main__":
    main()
