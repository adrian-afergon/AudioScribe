"""End-to-end persistence tests with deterministic inference doubles, no downloads."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from audioscribe.config import Config
from audioscribe.engine import LocalEngine
from audioscribe.store import digest, profile


@pytest.fixture
def pipeline(tmp_path, monkeypatch):
    for name in ("in", "out", "brain", "data"):
        (tmp_path / name).mkdir()
    config = Config(*(str(tmp_path / name) for name in ("in", "out", "brain", "data")), chunk_seconds=30)
    source = tmp_path / "in/Prueba con acentos á.mp3"
    source.write_bytes(b"original audio fixture")
    job = {"id":1,"source":str(source),"sha256":digest(source),"profile":profile(config)}
    engine = LocalEngine(config)
    def decode(source, destination):
        np.zeros(61 * 16000, dtype=np.float32).tofile(destination)
    monkeypatch.setattr(engine, "decode", decode)
    calls = []
    class Whisper:
        def transcribe(self, audio, **kwargs):
            calls.append(len(audio))
            return iter([SimpleNamespace(end=4, words=[SimpleNamespace(start=3,end=4,word=" palabra")])]), None
    monkeypatch.setattr(engine, "load_whisper", lambda: Whisper())
    def diarizer(audio, hook):
        return SimpleNamespace(exclusive_speaker_diarization=[(SimpleNamespace(start=0,end=100), "a")])
    monkeypatch.setattr(engine, "load_diarization", lambda: diarizer)
    monkeypatch.setitem(sys.modules, "torch", SimpleNamespace(from_numpy=lambda audio: SimpleNamespace(unsqueeze=lambda _: audio)))
    return engine, config, job, calls


def test_resume_keeps_completed_blocks(pipeline):
    engine, config, job, calls = pipeline
    def stop_after_one():
        return (Path(config.data_dir) / "checkpoints/1/block-00000.json").exists()
    with pytest.raises(InterruptedError):
        engine.process(job, lambda _: None, stop_after_one)
    assert len(calls) == 1
    output = engine.process(job, lambda _: None)
    assert len(calls) == 3  # First block reused, only the remaining two inferred.
    assert "**Hablante 1:**" in output.read_text(encoding="utf-8")
    assert not (Path(config.data_dir) / "checkpoints/1/audio.f32").exists()


def test_source_mutation_fails_before_decode(pipeline):
    engine, config, job, calls = pipeline
    Path(job["source"]).write_bytes(b"changed")
    with pytest.raises(ValueError, match="cambió"):
        engine.process(job, lambda _: None)
    assert not calls


def test_human_output_is_never_overwritten(pipeline):
    engine, config, job, calls = pipeline
    output = engine.process(job, lambda _: None)
    output.write_text("mi corrección", encoding="utf-8")
    with pytest.raises(FileExistsError):
        engine.process(job, lambda _: None)
    assert output.read_text(encoding="utf-8") == "mi corrección"


def test_published_output_reconciles_after_crash(pipeline):
    engine, config, job, calls = pipeline
    output = engine.process(job, lambda _: None)
    original = output.read_bytes()
    assert engine.process(job, lambda _: None).read_bytes() == original
    assert len(calls) == 3
