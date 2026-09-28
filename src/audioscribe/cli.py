from __future__ import annotations

import argparse
import getpass
import json
import logging
from logging.handlers import RotatingFileHandler
import sys
from pathlib import Path

from .config import Config, atomic_write
from .store import Store, digest, profile


def main(argv=None):
    parser = argparse.ArgumentParser(description="AudioScribe — transcripción local")
    parser.add_argument("--config", type=Path, required=True, help="Ruta de config.toml")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("run", help="Vigilar carpeta y procesar la cola")
    sub.add_parser("scan", help="Revisar una vez; no transcribe")
    sub.add_parser("status", help="Mostrar trabajos y rutas de salida")
    sub.add_parser("stop", help="Detener al terminar el bloque actual")
    sub.add_parser("setup", help="Abrir asistente de configuración")
    sub.add_parser("panel", help="Ver actividad y controlar el servicio")
    sub.add_parser("pause", help="Pausar el procesamiento sin perder el trabajo actual")
    sub.add_parser("resume", help="Reanudar el procesamiento")
    sub.add_parser("models", help="Descargar y verificar modelos")
    retry = sub.add_parser("retry", help="Reintentar trabajo con error")
    retry.add_argument("id", type=int)
    reprocess = sub.add_parser("reprocess", help="Transcribir un archivo explícitamente, incluso preexistente")
    reprocess.add_argument("file", type=Path)
    sub.add_parser("autostart", help="Registrar inicio de sesión")
    sub.add_parser("disable-autostart", help="Quitar inicio automático, conservar datos")
    args = parser.parse_args(argv)
    if args.action == "setup":
        from .wizard import launch
        launch(args.config)
        return
    if args.action == "panel":
        from .dashboard import launch
        launch(args.config)
        return
    config = Config.load(args.config)
    Path(config.data_dir).mkdir(parents=True, exist_ok=True)
    log = RotatingFileHandler(Path(config.data_dir) / "audioscribe.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8")
    logging.basicConfig(level=logging.INFO, handlers=[log], format="%(asctime)s %(levelname)s %(message)s")
    if args.action in ("run", "scan"):
        from .service import run
        error_path = Path(config.data_dir) / "startup-error.txt"
        try:
            error_path.unlink(missing_ok=True)
            run(config, once=args.action == "scan")
        except Exception as error:
            logging.exception("El servicio no pudo iniciarse o continuar")
            atomic_write(error_path, str(error))
            raise
    elif args.action == "stop":
        atomic_write(Path(config.data_dir) / "stop.request", "stop\n")
        print("Detención solicitada. Se conservará el progreso.")
    elif args.action in ("pause", "resume"):
        from .control import request
        request(Path(config.data_dir), args.action)
    elif args.action == "models":
        from .engine import prepare_models
        print("Acepta las condiciones: https://huggingface.co/pyannote/speaker-diarization-community-1")
        prepare_models(config, getpass.getpass("Token Hugging Face (no se guarda): "))
    elif args.action in ("autostart", "disable-autostart"):
        from .autostart import register, unregister
        if args.action == "autostart":
            register(Path(sys.executable), args.config.resolve())
        else:
            unregister()
    else:
        store = Store(config.database)
        try:
            if args.action == "status":
                rows = store.db.execute("SELECT id,source,state,attempts,progress,output,error FROM jobs ORDER BY id DESC").fetchall()
                print(json.dumps([dict(row) for row in rows], ensure_ascii=False, indent=2))
            elif args.action == "retry":
                store.retry(args.id)
            else:
                import time
                source = args.file.resolve(strict=True)
                if source.suffix.lower() not in (".mp3", ".mp4"):
                    raise ValueError("Selecciona un archivo .mp3 o .mp4.")
                with store.db:
                    cursor = store.db.execute("INSERT INTO jobs(source,sha256,profile,state,created,updated) VALUES (?,?,?,'pending',?,?)",
                        (str(source), digest(source), profile(config), time.time(), time.time()))
                print(f"Trabajo {cursor.lastrowid} añadido.")
        finally:
            store.close()


if __name__ == "__main__":
    main()
