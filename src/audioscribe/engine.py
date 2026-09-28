from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path

from .config import Config, atomic_write
from .store import digest

os.environ.setdefault("PYANNOTE_METRICS_ENABLED", "0")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")

DIARIZATION_REPO = "pyannote/speaker-diarization-community-1"


def prepare_models(config: Config, token: str, report=print):
    from huggingface_hub import snapshot_download
    from faster_whisper.utils import download_model

    config.models.mkdir(parents=True, exist_ok=True)
    report("Descargando Whisper. El progreso detallado aparece en el registro de instalación…")
    download_model(config.model, output_dir=str(config.models / config.model))
    report("Descargando separación de hablantes (requiere aceptar condiciones de Hugging Face)…")
    snapshot_download(DIARIZATION_REPO, token=token or None,
                      local_dir=config.models / "diarization")
    report("Comprobando que ambos modelos se pueden cargar sin conexión…")
    engine = LocalEngine(config)
    engine.load_whisper()
    engine.load_diarization()
    report("Modelos preparados. Los audios se procesarán localmente.")


def choose_speaker(start: float, end: float, turns: list[dict]) -> str:
    best, overlap = "unknown", 0.0
    for turn in turns:
        if turn["start"] > end:
            break
        amount = min(end, turn["end"]) - max(start, turn["start"])
        if amount > overlap:
            best, overlap = turn["speaker"], amount
    return best


def paragraphs(words: list[dict], turns: list[dict]) -> list[tuple[str, str]]:
    names: dict[str, str] = {}
    result: list[tuple[str, str]] = []
    current, text = None, ""
    # Sweep through turns: no quadratic scan over a three-hour recording.
    cursor = 0
    for word in words:
        while cursor < len(turns) and turns[cursor]["end"] < word["start"]:
            cursor += 1
        stop = cursor
        while stop < len(turns) and turns[stop]["start"] <= word["end"]:
            stop += 1
        speaker = choose_speaker(word["start"], word["end"], turns[cursor:stop])
        if speaker == "unknown":
            label = "Hablante sin determinar"
        else:
            if speaker not in names:
                names[speaker] = f"Hablante {len(names) + 1}"
            label = names[speaker]
        if current is not None and (label != current or len(text) > 1400):
            result.append((current, text.strip()))
            text = ""
        current = label
        text += word["text"]
    if text.strip():
        result.append((current or "Hablante sin determinar", text.strip()))
    return result


class LocalEngine:
    def __init__(self, config: Config):
        self.config = config
        self.whisper = None
        self.diarizer = None

    def load_whisper(self):
        if self.whisper is None:
            from faster_whisper import WhisperModel
            directory = self.config.models / self.config.model
            if not (directory / "model.bin").exists():
                raise RuntimeError("Falta el modelo Whisper. Abre Configurar y descarga los modelos.")
            self.whisper = WhisperModel(str(directory), device=self.config.device,
                compute_type="int8" if self.config.device == "cpu" else "float16",
                cpu_threads=self.config.cpu_threads, local_files_only=True)
        return self.whisper

    def load_diarization(self):
        if self.diarizer is None:
            os.environ.setdefault("MPLCONFIGDIR", str(Path(self.config.data_dir) / "cache/matplotlib"))
            os.environ.setdefault("TORCH_HOME", str(Path(self.config.data_dir) / "cache/torch"))
            from pyannote.audio import Pipeline
            import torch
            directory = self.config.models / "diarization"
            if not (directory / "config.yaml").exists():
                raise RuntimeError("Falta el modelo de hablantes. Abre Configurar y acepta las condiciones de Hugging Face.")
            # Offline local pipeline; never choose the hosted precision pipeline.
            os.environ["HF_HUB_OFFLINE"] = "1"
            torch.set_num_threads(self.config.cpu_threads)
            self.diarizer = Pipeline.from_pretrained(str(directory))
            if self.config.device == "cuda":
                self.diarizer.to(torch.device("cuda"))
        return self.diarizer

    def decode(self, source: Path, destination: Path):
        import av
        import numpy as np
        temp = destination.with_suffix(".partial")
        try:
            with av.open(str(source)) as media, temp.open("wb") as target:
                if not media.streams.audio:
                    raise ValueError("El archivo no contiene una pista de audio.")
                stream = media.streams.audio[0]
                resampler = av.AudioResampler(format="flt", layout="mono", rate=16000)
                for frame_index, frame in enumerate(media.decode(stream)):
                    if frame_index % 32 == 0 and getattr(self, "_control", lambda: False)():
                        raise InterruptedError("Detenido durante la decodificación.")
                    for out in resampler.resample(frame):
                        target.write(out.to_ndarray().astype(np.float32).tobytes())
                for out in resampler.resample(None):
                    target.write(out.to_ndarray().astype(np.float32).tobytes())
                target.flush()
                os.fsync(target.fileno())
            if temp.stat().st_size == 0:
                raise ValueError("El audio está vacío.")
            os.replace(temp, destination)
        finally:
            temp.unlink(missing_ok=True)

    def process(self, job, report, stopped=lambda: False) -> Path:
        import numpy as np
        self._control = stopped
        config = self.config
        source = Path(job["source"])
        if digest(source) != job["sha256"]:
            raise ValueError("El archivo cambió desde su detección. Se procesará como una nueva versión.")
        cache = Path(config.data_dir) / "checkpoints" / str(job["id"])
        cache.mkdir(parents=True, exist_ok=True)
        audio_path = cache / "audio.f32"
        if not audio_path.exists():
            report("Decodificando audio")
            self.decode(source, audio_path)
            if digest(source) != job["sha256"]:
                audio_path.unlink(missing_ok=True)
                raise ValueError("El archivo cambió mientras se decodificaba.")
        audio = np.memmap(audio_path, dtype=np.float32, mode="c")
        duration = len(audio) / 16000
        count = math.ceil(duration / config.chunk_seconds)
        words = []
        for index in range(count):
            if stopped():
                raise InterruptedError("Detenido; se conservaron los bloques completados.")
            checkpoint = cache / f"block-{index:05d}.json"
            report(f"Transcripción: bloque {index + 1}/{count}")
            if checkpoint.exists():
                words.extend(json.loads(checkpoint.read_text(encoding="utf-8")))
                continue
            start = index * config.chunk_seconds
            end = min(duration, start + config.chunk_seconds)
            context_start = max(0, start - 2)
            context_end = min(duration, end + 2)
            segments, _ = self.load_whisper().transcribe(
                audio[int(context_start * 16000):int(context_end * 16000)],
                language="es", task="transcribe", beam_size=5, word_timestamps=True,
                vad_filter=True, condition_on_previous_text=False)
            block = []
            for segment in segments:
                if stopped():
                    raise InterruptedError("Detenido; se conservaron los bloques completados.")
                fraction = min(1, max(0, (segment.end + context_start - start) / (end - start)))
                percent = int(100 * (index + fraction) / count)
                report(f"Transcripción: bloque {index + 1}/{count} · {percent}% del texto")
                for word in segment.words or []:
                    a, b = word.start + context_start, word.end + context_start
                    if start <= (a + b) / 2 < end:
                        block.append({"start": a, "end": b, "text": word.word})
            atomic_write(checkpoint, json.dumps(block, ensure_ascii=False))
            words.extend(block)
        if not words:
            raise ValueError("No se reconoció habla. Revisa el audio antes de reintentar.")
        if stopped():
            raise InterruptedError("Detenido antes de separar hablantes.")
        turns_path = cache / "speakers.json"
        if turns_path.exists():
            turns = json.loads(turns_path.read_text(encoding="utf-8"))
        else:
            report("Separando hablantes en la grabación completa")
            # Release Whisper before loading the diarizer on memory-limited systems.
            self.whisper = None
            import gc
            gc.collect()
            import torch
            def hook(step_name, artifact, file=None, total=None, completed=None):
                if stopped():
                    raise InterruptedError("Detenido durante la separación de hablantes.")
                report(f"Hablantes: {step_name} {completed or 0}/{total or '?'}")
            output = self.load_diarization()(
                {"waveform": torch.from_numpy(audio).unsqueeze(0), "sample_rate": 16000}, hook=hook)
            turns = [{"start": turn.start, "end": turn.end, "speaker": str(speaker)}
                     for turn, speaker in output.exclusive_speaker_diarization]
            turns.sort(key=lambda turn: turn["start"])
            atomic_write(turns_path, json.dumps(turns))
            self.diarizer = None
            gc.collect()
        if digest(source) != job["sha256"]:
            raise ValueError("El original cambió durante el trabajo. No se publicó el resultado.")
        if stopped():
            raise InterruptedError("Detenido antes de publicar el resultado.")
        report("Guardando transcripción")
        safe_name = re.sub(r"[^\w.-]+", "-", source.stem, flags=re.UNICODE).strip(".-")[:70] or "audio"
        output = Path(config.output_dir) / "raw" / "transcripciones" / f"{safe_name}-{job['sha256'][:12]}-{job['id']}.transcripcion.md"
        text = ["---", f"id: audioscribe-{job['id']}-{job['sha256'][:12]}",
                f"source_file: {json.dumps(source.name, ensure_ascii=False)}",
                f"source_sha256: {job['sha256']}", f"language: es", f"duration_seconds: {duration:.2f}",
                f"transcription_model: {config.model}", "diarization_model: pyannote/community-1",
                "type: transcript", "---", "", f"# {source.stem}", "",
                "> Transcripción automática. Las etiquetas distinguen voces dentro de este audio.", ""]
        for speaker, paragraph in paragraphs(words, turns):
            text.extend([f"**{speaker}:** {paragraph}", ""])
        content = "\n".join(text)
        if output.exists() and output.read_text(encoding="utf-8") != content:
            raise FileExistsError("El resultado existente fue modificado. Usa reprocess para crear otra versión.")
        atomic_write(output, content)
        # PCM is disposable; block/speaker checkpoints remain for recovery and audit.
        del audio
        audio_path.unlink(missing_ok=True)
        return output
