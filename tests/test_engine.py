from audioscribe.engine import paragraphs, choose_speaker
from audioscribe.autostart import task_xml, systemd_unit
import xml.etree.ElementTree as ET


def test_words_assign_by_overlap_and_preserve_text():
    words = [{"start": 0, "end": 0.5, "text": "Hola,"},
             {"start": 0.5, "end": 1, "text": " eh,"},
             {"start": 2, "end": 3, "text": " sí."}]
    turns = [{"start": 0, "end": 1.5, "speaker": "b"},
             {"start": 2, "end": 4, "speaker": "a"}]
    assert paragraphs(words, turns) == [("Hablante 1", "Hola, eh,"), ("Hablante 2", "sí.")]


def test_unassigned_speech_not_invented():
    assert paragraphs([{"start": 1, "end": 2, "text": "texto"}], []) == [("Hablante sin determinar", "texto")]


def test_same_speaker_keeps_label_on_return():
    words = [{"start": n, "end": n + .5, "text": " voz"} for n in range(3)]
    turns = [{"start": n, "end": n + .6, "speaker": str(n % 2)} for n in range(3)]
    assert [p[0] for p in paragraphs(words, turns)] == ["Hablante 1", "Hablante 2", "Hablante 1"]


def test_scheduled_task_escapes_paths_and_limits_to_current_user():
    argv = [r"C:\Ruta & voz\pythonw.exe", "-m", "audioscribe", "--config", r"C:\Oído & datos\config.toml", "run"]
    xml = ET.fromstring(task_xml(argv, r"EQUIPO\persona"))
    ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}
    assert xml.find(".//t:Command", ns).text == argv[0]
    assert xml.find(".//t:LogonTrigger/t:UserId", ns).text == r"EQUIPO\persona"
    assert "Oído & datos" in xml.find(".//t:Arguments", ns).text


def test_systemd_quotes_paths():
    unit = systemd_unit(["/home/u/a b/python", "--config", '/home/u/100%/$datos.toml'])
    assert '"/home/u/a b/python"' in unit
    assert "100%%/$$datos" in unit
