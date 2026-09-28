"""Validate tagged releases and their exact installer set before publication."""
from __future__ import annotations

import argparse
import ast
import hashlib
import io
import os
from pathlib import Path
import re
import tarfile
import tomllib
import zipfile
from email.parser import BytesParser

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("linux-x86_64", "linux-arm64", "macos-arm64", "macos-x86_64")


def version(root=ROOT, ref=None):
    value = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    if not re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", value):
        raise ValueError("Use a stable version X.Y.Z in pyproject.toml")
    tree = ast.parse((root / "src/audioscribe/__init__.py").read_text(encoding="utf-8"))
    runtime = next(ast.literal_eval(node.value) for node in tree.body
                   if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in node.targets))
    if runtime != value:
        raise ValueError("Runtime version and pyproject.toml disagree")
    ref = os.environ.get("GITHUB_REF", "") if ref is None else ref
    if ref.startswith("refs/tags/") and ref != f"refs/tags/v{value}":
        raise ValueError(f"Tag must be v{value}; received {ref}")
    return value


def asset_names(value):
    return [f"AudioScribe-{value}-windows-x86_64-Setup.exe", *(
        f"AudioScribe-{value}-{target}.tar.gz" for target in TARGETS)]


def check_wheel(data, value):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        metadata = [n for n in archive.namelist() if n.endswith(".dist-info/METADATA")]
        if len(metadata) != 1 or BytesParser().parsebytes(archive.read(metadata[0]))["Version"] != value:
            raise ValueError("Embedded wheel version differs from release")


def package(directory, kind, value):
    if kind == "windows":
        from PyInstaller.archive.readers import CArchiveReader
        source = directory / "AudioScribe-Setup.exe"
        archive = CArchiveReader(str(source))
        wheels = [name for name in archive.toc if name.endswith(".whl")]
        if len(wheels) != 1:
            raise ValueError("Expected one embedded wheel")
        check_wheel(archive.extract(wheels[0]), value)
        source.rename(directory / asset_names(value)[0])
    else:
        for target in TARGETS:
            source = directory / f"AudioScribe-{target}.tar.gz"
            with tarfile.open(source) as archive:
                wheels = [m for m in archive.getmembers() if m.name.endswith(".whl")]
                if len(wheels) != 1:
                    raise ValueError("Expected one embedded wheel")
                check_wheel(archive.extractfile(wheels[0]).read(), value)
                launcher = "Instalar.command" if target.startswith("macos") else "Instalar.sh"
                for name in ("payload/uv", launcher):
                    if not archive.getmember("AudioScribe/" + name).mode & 0o111:
                        raise ValueError(f"Non-executable launcher: {name}")
            source.rename(directory / f"AudioScribe-{value}-{target}.tar.gz")


def checksums(directory, value):
    expected = set(asset_names(value))
    actual = {p.name for p in directory.iterdir() if p.name != "SHA256SUMS.txt"}
    if actual != expected:
        raise ValueError(f"Incomplete or unexpected release assets: missing={expected-actual}, extra={actual-expected}")
    lines = []
    for name in sorted(expected):
        path = directory / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"Empty or invalid asset: {name}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        lines.append(f"{digest}  {name}\n")
    (directory / "SHA256SUMS.txt").write_text("".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("version", "package", "checksums"))
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    parser.add_argument("--kind", choices=("windows", "unix"))
    args = parser.parse_args()
    value = version()
    if args.action == "package":
        if not args.kind:
            parser.error("package requires --kind")
        package(args.directory, args.kind, value)
    elif args.action == "checksums":
        checksums(args.directory, value)
    print(f"Validated AudioScribe {value}: {args.action}")


if __name__ == "__main__":
    main()
