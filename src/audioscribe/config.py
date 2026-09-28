from __future__ import annotations

import json
import os
import tempfile
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".audioscribe-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@dataclass
class Config:
    input_dir: str
    output_dir: str
    brain_dir: str
    data_dir: str
    recursive: bool = False
    model: str = "small"
    device: str = "cpu"
    cpu_threads: int = 4
    poll_seconds: int = 10
    stable_seconds: int = 30
    chunk_seconds: int = 600
    max_attempts: int = 3
    autostart: bool = True

    @property
    def database(self) -> Path:
        return Path(self.data_dir) / "queue.sqlite3"

    @property
    def models(self) -> Path:
        return Path(self.data_dir) / "models"

    def validate(self, probe: bool = True) -> None:
        paths = {}
        for name in ("input_dir", "output_dir", "brain_dir", "data_dir"):
            value = getattr(self, name)
            if not value.strip() or not Path(value).expanduser().is_absolute():
                raise ValueError(f"{name}: se requiere una ruta absoluta.")
            path = Path(value).expanduser().resolve()
            setattr(self, name, str(path))
            paths[name] = path
        if not paths["brain_dir"].is_dir():
            raise ValueError("Selecciona la carpeta existente de tu second brain.")
        for name in ("output_dir", "data_dir", "brain_dir"):
            p = paths[name]
            incoming = paths["input_dir"]
            if p == incoming or p.is_relative_to(incoming) or incoming.is_relative_to(p):
                raise ValueError("La entrada debe estar separada de salida, datos y second brain.")
        if self.model not in ("tiny", "base", "small", "medium", "large-v3", "turbo"):
            raise ValueError("Modelo Whisper no admitido.")
        if self.device not in ("cpu", "cuda"):
            raise ValueError("El dispositivo debe ser cpu o cuda.")
        for name in ("cpu_threads", "poll_seconds", "stable_seconds", "chunk_seconds", "max_attempts"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError(f"{name} debe ser un entero positivo.")
        if self.chunk_seconds < 30:
            raise ValueError("Los bloques deben durar al menos 30 segundos.")
        if probe:
            for name in ("input_dir", "output_dir", "data_dir"):
                paths[name].mkdir(parents=True, exist_ok=True)
                fd, temporary = tempfile.mkstemp(prefix=".audioscribe-check-", dir=paths[name])
                os.close(fd)
                os.unlink(temporary)
            # Solo lectura: nunca escribir archivos de prueba en el second brain.
            next(paths["brain_dir"].iterdir(), None)

    def save(self, path: Path) -> None:
        rows = ["# AudioScribe — detener el servicio antes de editar", ""]
        for key, value in asdict(self).items():
            rows.append(f"{key} = {json.dumps(value, ensure_ascii=False)}")
        atomic_write(path, "\n".join(rows) + "\n")

    @classmethod
    def load(cls, path: Path) -> Config:
        with path.open("rb") as stream:
            config = cls(**tomllib.load(stream))
        config.validate(probe=False)
        return config
