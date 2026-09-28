from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path
from xml.sax.saxutils import escape

from .config import atomic_write


def command(python: Path, config: Path) -> list[str]:
    executable = python
    if sys.platform == "win32" and python.with_name("pythonw.exe").exists():
        executable = python.with_name("pythonw.exe")
    return [str(executable), "-m", "audioscribe", "--config", str(config), "run"]


def task_xml(argv: list[str], username: str) -> str:
    args = subprocess.list2cmdline(argv[1:])
    return f'''<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
 <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{escape(username)}</UserId></LogonTrigger></Triggers>
 <Principals><Principal id="Author"><UserId>{escape(username)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
 <Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy><DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries><StopIfGoingOnBatteries>false</StopIfGoingOnBatteries><ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Enabled>true</Enabled></Settings>
 <Actions Context="Author"><Exec><Command>{escape(argv[0])}</Command><Arguments>{escape(args)}</Arguments></Exec></Actions>
</Task>'''


def systemd_unit(argv: list[str]) -> str:
    def quote(value):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$").replace("\n", "\\n") + '"'
    return "\n".join(["[Unit]", "Description=AudioScribe local transcription", "", "[Service]",
        "Type=simple", "ExecStart=" + " ".join(quote(arg) for arg in argv), "Restart=on-failure",
        "RestartSec=20", "", "[Install]", "WantedBy=default.target", ""])


def register(python: Path, config: Path):
    argv = command(python, config)
    if sys.platform == "win32":
        username = subprocess.check_output(["whoami"], text=True,
                                           creationflags=subprocess.CREATE_NO_WINDOW).strip()
        fd, filename = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        try:
            Path(filename).write_text(task_xml(argv, username), encoding="utf-16")
            subprocess.run(["schtasks", "/Create", "/TN", "AudioScribe", "/XML", filename, "/F"],
                           check=True, capture_output=True, creationflags=subprocess.CREATE_NO_WINDOW)
        finally:
            Path(filename).unlink(missing_ok=True)
    elif sys.platform == "darwin":
        target = Path.home() / "Library/LaunchAgents/local.audioscribe.plist"
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = {"Label": "local.audioscribe", "ProgramArguments": argv,
                   "RunAtLoad": True, "KeepAlive": {"SuccessfulExit": False},
                   "ThrottleInterval": 20}
        atomic_write(target, plistlib.dumps(payload).decode())
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(target)], capture_output=True)
        subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(target)], check=True, capture_output=True)
    else:
        target = Path.home() / ".config/systemd/user/audioscribe.service"
        atomic_write(target, systemd_unit(argv))
        subprocess.run(["systemctl", "--user", "daemon-reload"], check=True, capture_output=True)
        subprocess.run(["systemctl", "--user", "enable", "audioscribe.service"], check=True, capture_output=True)


def unregister():
    if sys.platform == "win32":
        subprocess.run(["schtasks", "/Delete", "/TN", "AudioScribe", "/F"], capture_output=True,
                       creationflags=subprocess.CREATE_NO_WINDOW)
    elif sys.platform == "darwin":
        target = Path.home() / "Library/LaunchAgents/local.audioscribe.plist"
        subprocess.run(["launchctl", "bootout", f"gui/{os.getuid()}", str(target)], capture_output=True)
        target.unlink(missing_ok=True)
    else:
        subprocess.run(["systemctl", "--user", "disable", "--now", "audioscribe.service"], capture_output=True)
        (Path.home() / ".config/systemd/user/audioscribe.service").unlink(missing_ok=True)
        subprocess.run(["systemctl", "--user", "daemon-reload"], capture_output=True)


def start(python: Path, config: Path):
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    subprocess.Popen(command(python, config), stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=flags, start_new_session=sys.platform != "win32")
