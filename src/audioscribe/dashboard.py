from __future__ import annotations

import os
import re
import sqlite3
import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from . import __version__
from .config import Config
from .control import request, service_active, snapshot
from .store import Store
from .wizard import prepare_tk

STATES = {"starting": "Iniciando", "idle": "Esperando audios", "processing": "Procesando",
          "pausing": "Pausa solicitada", "paused": "En pausa", "stopping": "Deteniendo",
          "stopped": "Servicio detenido", "legacy": "Activo · versión anterior",
          "unresponsive": "Sin señal reciente del servicio"}
JOBS = {"pending": "Pendiente", "processing": "Procesando", "done": "Completado", "error": "Error"}


def open_path(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Todavía no existe: {path}")
    if sys.platform == "win32":
        os.startfile(str(path))
    else:
        subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", str(path)],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def launch_panel(python: Path, config_path: Path):
    executable = python.with_name("pythonw.exe") if sys.platform == "win32" else python
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    subprocess.Popen([str(executable), "-m", "audioscribe", "--config", str(config_path), "panel"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=flags, start_new_session=sys.platform != "win32")


class Dashboard:
    def __init__(self, root: tk.Tk, config_path: Path, reader=snapshot):
        self.root, self.config_path, self.reader = root, config_path, reader
        self.config = Config.load(config_path)
        self.rows = {}
        self.last = {}
        self.after_id = None
        self.pending_start_until = 0
        root.title("AudioScribe · Panel de actividad")
        root.geometry("1080x800")
        root.minsize(880, 650)
        root.protocol("WM_DELETE_WINDOW", self.close)
        style = ttk.Style(root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("Title.TLabel", font=("Segoe UI", 23, "bold"))
        style.configure("State.TLabel", font=("Segoe UI", 15, "bold"), foreground="#155e75")
        style.configure("Muted.TLabel", foreground="#526271")
        style.configure("Treeview", rowheight=29)
        container = ttk.Frame(root, padding=22)
        container.pack(fill="both", expand=True)
        top = ttk.Frame(container)
        top.pack(fill="x")
        ttk.Label(top, text="AudioScribe", style="Title.TLabel").pack(side="left")
        ttk.Label(top, text=f"v{__version__}  ·  Local", style="Muted.TLabel").pack(side="right")
        ttk.Label(container, text="Cerrar este panel mantiene el servicio en segundo plano. Para pararlo, utiliza Detener.",
                  style="Muted.TLabel").pack(anchor="w", pady=(3, 16))
        self.state = tk.StringVar(value="Consultando servicio…")
        ttk.Label(container, textvariable=self.state, style="State.TLabel").pack(anchor="w")
        self.message = tk.StringVar()
        ttk.Label(container, textvariable=self.message, wraplength=990).pack(anchor="w", pady=(5, 8))
        toolbar = ttk.Frame(container)
        toolbar.pack(fill="x", pady=(0, 12))
        self.buttons = {}
        for name, label in (("start", "Iniciar"), ("pause", "Pausar"), ("resume", "Reanudar"), ("stop", "Detener")):
            button = ttk.Button(toolbar, text=label, command=lambda n=name: self.action(n))
            button.pack(side="left", padx=(0, 8))
            self.buttons[name] = button
        ttk.Button(toolbar, text="Configurar…", command=self.configure).pack(side="right")
        self.summary = tk.StringVar()
        ttk.Label(container, textvariable=self.summary, font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=4)
        self.progress_text = tk.StringVar(value="Sin trabajo activo")
        ttk.Label(container, textvariable=self.progress_text, wraplength=990).pack(anchor="w", pady=(5, 5))
        self.progress = ttk.Progressbar(container, mode="determinate", maximum=100)
        self.progress.pack(fill="x", pady=(0, 4))
        ttk.Label(container, text="El porcentaje corresponde a la transcripción; la separación de hablantes muestra su propia etapa.",
                  style="Muted.TLabel").pack(anchor="w", pady=(0, 12))
        table = ttk.Frame(container)
        table.pack(fill="both", expand=True)
        columns = ("file", "state", "progress", "updated")
        self.tree = ttk.Treeview(table, columns=columns, show="headings", selectmode="browse", height=9)
        for name, title, width in (("file", "Audio", 290), ("state", "Estado", 115),
                                   ("progress", "Progreso / etapa", 360), ("updated", "Actualizado", 140)):
            self.tree.heading(name, text=title)
            self.tree.column(name, width=width, minwidth=80, stretch=name in ("file", "progress"))
        self.tree.tag_configure("error", foreground="#a11b32")
        self.tree.tag_configure("done", foreground="#19734d")
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)
        table.columnconfigure(0, weight=1)
        table.rowconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", lambda event: self.show_details())
        self.tree.bind("<Double-1>", lambda event: self.result())
        ttk.Label(container, text="Detalle del archivo seleccionado", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(12, 4))
        self.detail = tk.Text(container, height=4, wrap="word", relief="flat", background="#f0f3f6", font=("Segoe UI", 10))
        self.detail.pack(fill="x")
        self.detail.configure(state="disabled")
        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=10)
        self.result_button = ttk.Button(actions, text="Abrir transcripción", command=self.result)
        self.result_button.pack(side="left", padx=(0, 8))
        self.retry_button = ttk.Button(actions, text="Reintentar archivo", command=self.retry)
        self.retry_button.pack(side="left")
        ttk.Button(actions, text="Carpeta de resultados", command=lambda: self.open(Path(self.config.output_dir))).pack(side="right")
        ttk.Button(actions, text="Ver registro", command=lambda: self.open(Path(self.config.data_dir) / "audioscribe.log")).pack(side="right", padx=8)
        self.footer = tk.StringVar()
        ttk.Label(container, textvariable=self.footer, wraplength=990, style="Muted.TLabel").pack(anchor="w")
        # Keep controls visible on smaller screens: only the job table gives up height.
        layout = [(widget, widget.pack_info()) for widget in container.winfo_children()]
        for widget, options in layout:
            widget.pack_forget()
        for row_index, (widget, options) in enumerate(layout):
            widget.grid(row=row_index, column=0, sticky="nsew" if widget is table else "ew",
                        pady=options.get("pady", 0))
            if widget is table:
                container.rowconfigure(row_index, weight=1, minsize=70)
        container.columnconfigure(0, weight=1)
        def resize(event):
            for widget in container.winfo_children():
                if isinstance(widget, ttk.Label) and int(widget.cget("wraplength") or 0):
                    widget.configure(wraplength=max(300, event.width - 8))
        container.bind("<Configure>", resize)
        self.refresh()

    def refresh(self):
        try:
            self.config = Config.load(self.config_path)
            view = self.reader(self.config)
            self.last = view
            state = view["state"]
            self.state.set(STATES.get(state, state))
            runtime = view["runtime"]
            if state == "paused":
                text = "Procesamiento pausado. Los nuevos audios siguen entrando en la cola. Pulsa Reanudar para continuar."
            elif state == "pausing":
                text = "Esperando al siguiente punto de pausa. Puede tardar durante la carga de modelos o una operación de voz."
            elif state == "stopping":
                text = "Finalizando la operación actual. Los bloques ya guardados se conservan para el próximo inicio."
            elif state == "legacy":
                text = "El servicio anterior está activo. Instala la actualización para habilitar la pausa y el seguimiento en vivo."
            elif state == "stopped":
                text = "No hay un servicio activo. Pulsa Iniciar para vigilar la carpeta y procesar la cola."
                if view["pause_requested"]:
                    text += " La pausa está guardada; pulsa Reanudar para quitarla."
            elif state == "unresponsive":
                text = "El proceso mantiene su bloqueo, pero no ha actualizado su señal de actividad. Consulta el registro."
            else:
                text = "Servicio activo. La actividad se actualiza automáticamente cada segundo."
            if runtime.get("worker_error"):
                text += " Error del servicio: " + runtime["worker_error"]
            if view.get("startup_error") and not view["active"]:
                text += " Último error de inicio: " + view["startup_error"]
            if runtime.get("scanner_error"):
                text += " " + runtime["scanner_error"]
            self.message.set(text)
            counts = view["counts"]
            self.summary.set(f"Pendientes: {counts.get('pending', 0)}   ·   Procesando: {counts.get('processing', 0)}   ·   Completados: {counts.get('done', 0)}   ·   Con error: {counts.get('error', 0)}")
            self.buttons["start"].configure(state="disabled" if view["active"] or time.monotonic() < self.pending_start_until else "normal")
            self.buttons["pause"].configure(state="normal" if view["active"] and state not in ("legacy", "stopping", "paused", "pausing") else "disabled")
            self.buttons["resume"].configure(state="normal" if view["pause_requested"] else "disabled")
            self.buttons["stop"].configure(state="normal" if view["active"] and state != "stopping" else "disabled")
            self.rows = {str(row["id"]): row for row in view["jobs"]}
            for iid in self.tree.get_children():
                if iid not in self.rows:
                    self.tree.delete(iid)
            for index, (iid, row) in enumerate(self.rows.items()):
                label = JOBS[row["state"]]
                if row["state"] == "processing":
                    label = "En pausa" if state == "paused" else label
                    if not view["active"]:
                        label = "Por recuperar"
                if row["state"] == "pending" and row["error"]:
                    label = "Reintento previsto"
                values = (Path(row["source"]).name, label, row["progress"], time.strftime("%d/%m %H:%M:%S", time.localtime(row["updated"])))
                if self.tree.exists(iid):
                    self.tree.item(iid, values=values, tags=(row["state"],))
                    self.tree.move(iid, "", index)
                else:
                    self.tree.insert("", index, iid=iid, values=values, tags=(row["state"],))
            active = next((r for r in view["jobs"] if r["state"] == "processing"), None)
            if active:
                self.progress_text.set(Path(active["source"]).name + " — " + active["progress"])
                match = re.search(r"(\d+)% del texto", active["progress"])
                self.progress["value"] = int(match.group(1)) if match else 0
            else:
                self.progress_text.set("Sin trabajo activo" if view["jobs"] else "Todavía no hay trabajos. Añade un nuevo MP3 o MP4 a la carpeta de entrada.")
                self.progress["value"] = 0
            self.footer.set(f"Entrada: {self.config.input_dir}\nEsperando estabilidad: {view['waiting']} · Preexistentes excluidos: {view['ignored']} · Modelo: {self.config.model} / {self.config.device} · Se muestran hasta 300 trabajos")
            self.show_details()
        except (OSError, sqlite3.Error, ValueError) as error:
            self.message.set(f"No se pudo actualizar el panel: {error}")
        self.after_id = self.root.after(1000, self.refresh)

    def selected(self):
        selection = self.tree.selection()
        return self.rows.get(selection[0]) if selection else None

    def show_details(self):
        row = self.selected()
        lines = ["Selecciona un audio para ver su ruta, intentos, errores y resultado."]
        if row:
            lines = [f"Origen: {row['source']}", f"Intentos: {row['attempts']} · {row['progress']}"]
            if row["output"]:
                lines.append("Resultado: " + row["output"])
            if row["error"]:
                lines.append("Último error: " + row["error"])
            if row["state"] == "pending" and row["retry_at"] > time.time():
                lines.append("Reintento automático: " + time.strftime("%H:%M:%S", time.localtime(row["retry_at"])))
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", "\n".join(lines))
        self.detail.configure(state="disabled")
        self.result_button.configure(state="normal" if row and row["output"] else "disabled")
        self.retry_button.configure(state="normal" if row and row["state"] == "error" else "disabled")

    def action(self, action):
        try:
            if action == "start":
                from .autostart import start
                if not service_active(Path(self.config.data_dir)):
                    start(Path(sys.executable), self.config_path)
                    self.pending_start_until = time.monotonic() + 3
            else:
                request(Path(self.config.data_dir), action)
        except Exception as error:
            messagebox.showerror("AudioScribe", str(error), parent=self.root)

    def retry(self):
        row = self.selected()
        if row:
            store = Store(self.config.database)
            try:
                store.retry(row["id"])
            except Exception as error:
                messagebox.showerror("No se pudo reintentar", str(error), parent=self.root)
            finally:
                store.close()

    def result(self):
        row = self.selected()
        if row and row["output"]:
            self.open(Path(row["output"]))

    def open(self, path):
        try:
            open_path(path)
        except Exception as error:
            messagebox.showerror("No se pudo abrir", str(error), parent=self.root)

    def configure(self):
        if self.last.get("active"):
            messagebox.showinfo("Configuración", "Pulsa Detener y espera a que el servicio se detenga antes de cambiar su configuración.", parent=self.root)
            return
        executable = Path(sys.executable)
        if sys.platform == "win32":
            executable = executable.with_name("pythonw.exe")
        subprocess.Popen([str(executable), "-m", "audioscribe", "--config", str(self.config_path), "setup"],
                         creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)

    def close(self):
        if self.after_id:
            self.root.after_cancel(self.after_id)
        self.root.destroy()


def launch(config_path: Path):
    prepare_tk()
    root = tk.Tk()
    Dashboard(root, config_path.resolve())
    root.mainloop()
