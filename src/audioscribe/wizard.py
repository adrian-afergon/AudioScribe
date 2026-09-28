from __future__ import annotations

import os
import queue
import shutil
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import webbrowser

from .config import Config
from .shortcuts import ShortcutOptions, create_launchers, labels, pin_instructions

MODEL_URL = "https://huggingface.co/pyannote/speaker-diarization-community-1"


def prepare_tk():
    """Use native extended paths: Tcl otherwise misidentifies some Windows folders."""
    if sys.platform != "win32":
        return
    if getattr(sys, "frozen", False):
        folders = {"TCL_LIBRARY": Path(sys._MEIPASS) / "_tcl_data",
                   "TK_LIBRARY": Path(sys._MEIPASS) / "_tk_data"}
    else:
        base = Path(sys.base_prefix).resolve() / "tcl"
        folders = {}
        for key, pattern in (("TCL_LIBRARY", "tcl8.*"), ("TK_LIBRARY", "tk8.*")):
            matches = sorted(base.glob(pattern))
            if matches:
                folders[key] = matches[-1]
    for key, folder in folders.items():
        if folder.is_dir():
            value = folder.resolve().as_posix()
            os.environ[key] = value if value.startswith("//?/") else "//?/" + value


class Wizard:
    def __init__(self, root, config_path: Path | None = None, install_callback=None, default_install=None):
        self.root = root
        self.config_path = config_path
        self.install_callback = install_callback
        self.events = queue.Queue()
        self.busy = False
        root.title("AudioScribe · Instalación y configuración")
        root.geometry("830x790")
        root.minsize(770, 730)
        root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 23, "bold"))
        style.configure("Subtitle.TLabel", font=("Segoe UI", 10), foreground="#465569")
        container = ttk.Frame(root, padding=24)
        container.pack(fill="both", expand=True)
        ttk.Label(container, text="AudioScribe", style="Title.TLabel").pack(anchor="w")
        ttk.Label(container, text="Tus audios, convertidos en conocimiento. Procesamiento local.", style="Subtitle.TLabel").pack(anchor="w", pady=(3, 16))
        outer = container
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        container = ttk.Frame(self.tabs, padding=12)
        accesses = ttk.Frame(self.tabs, padding=16)
        self.tabs.add(container, text="Carpetas y modelos")
        self.tabs.add(accesses, text="Accesos y arranque")
        saved = ShortcutOptions.load(Path(default_install or config_path.parent))
        self.desktop_shortcut = tk.BooleanVar(value=saved.desktop)
        self.applications_shortcut = tk.BooleanVar(value=saved.applications)
        self.pin_help = tk.BooleanVar(value=saved.pin_help)
        desktop_label, apps_label, pin_label = labels()
        ttk.Label(accesses, text="Elige cómo abrir AudioScribe", style="Subtitle.TLabel").pack(anchor="w", pady=(0, 12))
        ttk.Checkbutton(accesses, text=desktop_label, variable=self.desktop_shortcut).pack(anchor="w", pady=6)
        ttk.Checkbutton(accesses, text=apps_label, variable=self.applications_shortcut,
                        command=lambda: self.pin_help.set(False) if not self.applications_shortcut.get() else None).pack(anchor="w", pady=6)
        ttk.Checkbutton(accesses, text=pin_label, variable=self.pin_help,
                        command=lambda: self.applications_shortcut.set(True) if self.pin_help.get() else None).pack(anchor="w", pady=6)
        ttk.Label(accesses, text="El anclado se completa en el sistema al terminar. Se mostrarán los pasos si seleccionas la ayuda.\n\nDesmarcar una opción no elimina accesos que ya existan.", wraplength=690).pack(anchor="w", pady=12)
        ttk.Separator(accesses).pack(fill="x", pady=12)
        form = ttk.Frame(container)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)
        existing = Config.load(config_path) if config_path and config_path.exists() else None
        self.variables = {}
        self.fields = []
        values = []
        if install_callback:
            values.append(("install_dir", "Instalar aplicación en", str(default_install)))
        values.extend([
            ("input_dir", "Carpeta de audios", existing.input_dir if existing else ""),
            ("output_dir", "Carpeta de resultados", existing.output_dir if existing else ""),
            ("brain_dir", "Second brain existente", existing.brain_dir if existing else ""),
            ("data_dir", "Base de datos y modelos", existing.data_dir if existing else str(Path(default_install or config_path.parent) / "data")),
        ])
        for row, (key, label, value) in enumerate(values):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", padx=(0, 12), pady=5)
            variable = tk.StringVar(value=value)
            self.variables[key] = variable
            entry = ttk.Entry(form, textvariable=variable)
            entry.grid(row=row, column=1, sticky="ew", pady=5)
            button = ttk.Button(form, text="Elegir…", command=lambda v=variable: self.browse(v))
            button.grid(row=row, column=2, padx=(8, 0))
            self.fields.extend([entry, button])
            if existing and key == "data_dir":
                entry.configure(state="disabled")
                button.configure(state="disabled")
        self.existing = existing
        self.recursive = tk.BooleanVar(value=existing.recursive if existing else False)
        self.autostart = tk.BooleanVar(value=existing.autostart if existing else True)
        ttk.Checkbutton(container, text="Incluir subcarpetas de entrada", variable=self.recursive).pack(anchor="w", pady=(10, 2))
        ttk.Checkbutton(container, text="Iniciar automáticamente al entrar en mi sesión", variable=self.autostart).pack(anchor="w")
        ttk.Separator(container).pack(fill="x", pady=12)
        options = ttk.Frame(container)
        options.pack(fill="x")
        ttk.Label(options, text="Modelo Whisper").pack(side="left")
        self.model = tk.StringVar(value=existing.model if existing else "small")
        ttk.Combobox(options, textvariable=self.model, values=("small", "medium", "large-v3", "turbo", "base", "tiny"), state="readonly", width=13).pack(side="left", padx=10)
        ttk.Label(options, text="Procesador").pack(side="left", padx=(15, 0))
        self.device = tk.StringVar(value=existing.device if existing else "cpu")
        ttk.Combobox(options, textvariable=self.device, values=("cpu", "cuda"), state="readonly", width=8).pack(side="left", padx=10)
        cpus = os.cpu_count() or 2
        ttk.Label(container, text=f"Detectados {cpus} procesadores lógicos. CPU funciona sin GPU; CUDA requiere NVIDIA compatible.", wraplength=740, style="Subtitle.TLabel").pack(anchor="w", pady=(6, 8))
        ready = existing and (existing.models / existing.model / "model.bin").exists() and (existing.models / "diarization/config.yaml").exists()
        self.download = tk.BooleanVar(value=not ready)
        ttk.Checkbutton(container, text="Descargar y comprobar los modelos ahora", variable=self.download).pack(anchor="w")
        ttk.Label(container, text="La instalación descarga Python, dependencias y modelos (varios GB). Reserva al menos 10 GB libres; más para audios largos. La primera descarga necesita Internet.", wraplength=740, style="Subtitle.TLabel").pack(anchor="w", pady=(5, 8))
        links = ttk.Frame(container)
        links.pack(fill="x")
        ttk.Button(links, text="1. Aceptar condiciones del modelo", command=lambda: webbrowser.open(MODEL_URL)).pack(side="left")
        ttk.Button(links, text="2. Crear token de lectura", command=lambda: webbrowser.open("https://huggingface.co/settings/tokens")).pack(side="left", padx=8)
        token_row = ttk.Frame(container)
        token_row.pack(fill="x", pady=8)
        ttk.Label(token_row, text="Token Hugging Face").pack(side="left")
        self.token = tk.StringVar()
        ttk.Entry(token_row, textvariable=self.token, show="•").pack(side="left", fill="x", expand=True, padx=(12, 0))
        ttk.Label(container, text="Solo para descargar el modelo. No se guarda ni se envían tus audios.\nEl second brain se registra como destino futuro; esta versión no modifica sus notas.", wraplength=740, style="Subtitle.TLabel").pack(anchor="w")
        container = outer
        self.status = tk.StringVar(value="Los audios que ya existan al guardar la configuración quedarán excluidos.")
        ttk.Label(container, textvariable=self.status, wraplength=740).pack(anchor="w", pady=(14, 6))
        self.progress = ttk.Progressbar(container, mode="indeterminate")
        self.progress.pack(fill="x")
        self.button = ttk.Button(container, text="Instalar y configurar" if install_callback else "Guardar configuración", command=self.submit)
        self.button.pack(anchor="e", pady=12)
        self.root.after(150, self.poll)

    def browse(self, variable):
        value = filedialog.askdirectory(parent=self.root, initialdir=variable.get() or str(Path.home()))
        if value:
            variable.set(value)

    def close(self):
        if self.busy:
            messagebox.showinfo("Instalación en curso", "Espera a que termine esta etapa. Las descargas pueden tardar varios minutos.")
        else:
            self.root.destroy()

    def submit(self):
        if self.busy:
            return
        try:
            values = {key: var.get().strip() for key, var in self.variables.items() if key != "install_dir"}
            config = Config(**values, recursive=self.recursive.get(), autostart=self.autostart.get(),
                            model=self.model.get(), device=self.device.get(),
                            cpu_threads=max(1, min(4, (os.cpu_count() or 2) - 1)))
            if self.existing:
                for name in ("cpu_threads", "poll_seconds", "stable_seconds", "chunk_seconds", "max_attempts"):
                    setattr(config, name, getattr(self.existing, name))
            config.validate()
            if shutil.disk_usage(config.data_dir).free < 5 * 1024 ** 3:
                raise ValueError("Hay menos de 5 GB libres en el directorio de datos. Selecciona otro disco.")
            if self.install_callback:
                install = Path(self.variables["install_dir"].get().strip()).expanduser()
                if not install.is_absolute():
                    raise ValueError("Selecciona una ruta absoluta de instalación.")
                install = install.resolve()
                incoming = Path(config.input_dir)
                if install == incoming or install.is_relative_to(incoming) or incoming.is_relative_to(install):
                    raise ValueError("La instalación debe estar separada de la carpeta de audios.")
            else:
                install = None
            shortcuts = ShortcutOptions(self.desktop_shortcut.get(), self.applications_shortcut.get(), self.pin_help.get())
            self.busy = True
            self.button.configure(state="disabled")
            self.progress.start()
            download, token = self.download.get(), self.token.get()
            self.token.set("")
            def work():
                try:
                    report = lambda text: self.events.put(("progress", text))
                    if self.install_callback:
                        self.install_callback(install, config, download, token, report, shortcuts)
                    else:
                        configure(config, self.config_path, download, token, report, shortcuts)
                    ready = (config.models / config.model / "model.bin").exists() and (config.models / "diarization/config.yaml").exists()
                    self.events.put(("done", "Configuración guardada. " + ("Servicio preparado. Consulta su actividad en el panel AudioScribe." if ready else "Descarga los modelos desde Configurar antes de iniciar el servicio.")))
                    if shortcuts.pin_help:
                        self.events.put(("pin-help", pin_instructions()))
                except Exception as error:
                    # No token in logs or dialogs, including errors returned by download clients.
                    message = str(error)
                    if token:
                        message = message.replace(token, "[token oculto]")
                    self.events.put(("error", message))
            threading.Thread(target=work, daemon=True).start()
        except Exception as error:
            messagebox.showerror("Revisa la configuración", str(error))

    def poll(self):
        try:
            while True:
                kind, message = self.events.get_nowait()
                if kind == "pin-help":
                    messagebox.showinfo("Anclar AudioScribe", message, parent=self.root)
                    continue
                self.status.set(message)
                if kind in ("done", "error"):
                    self.busy = False
                    self.progress.stop()
                    self.button.configure(state="normal")
                    if kind == "error":
                        messagebox.showerror("No se completó la configuración", message)
        except queue.Empty:
            pass
        self.root.after(150, self.poll)


def configure(config, path, download, token, report, shortcuts=None):
    from .service import InstanceLock, Scanner
    from .store import Store
    from .engine import prepare_models
    from .autostart import register, unregister, start
    lock = InstanceLock(Path(config.data_dir) / "service.lock")
    try:
        config.save(path)
        create_launchers(path.parent, Path(sys.executable), path, shortcuts)
        store = Store(config.database)
        try:
            Scanner(config, store).baseline()
        finally:
            store.close()
        if download:
            prepare_models(config, token, report)
    finally:
        lock.close()
    ready = (config.models / config.model / "model.bin").exists() and (config.models / "diarization/config.yaml").exists()
    if config.autostart and ready:
        register(Path(sys.executable), path)
    elif not config.autostart:
        unregister()
    if ready:
        start(Path(sys.executable), path)


def launch(config_path: Path):
    prepare_tk()
    root = tk.Tk()
    Wizard(root, config_path=config_path)
    root.mainloop()
