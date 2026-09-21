from __future__ import annotations

import argparse
import json
import os
import queue
import sys
import tempfile
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import messagebox, scrolledtext, ttk
from typing import Any

import requests

from ip_total_core import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_REPORT_DIR,
    TotalReconEngine,
    build_html_report,
    display_value,
    save_reports,
)


BG = "#08111f"
PANEL = "#101d30"
PANEL_ALT = "#17263d"
BORDER = "#263a55"
TEXT = "#e8f0fa"
MUTED = "#9db0c8"
CYAN = "#20c7e9"
GREEN = "#34d399"
RED = "#fb7185"
AMBER = "#fbbf24"


def pretty(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


class IPTotalApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title(f"{APP_NAME} {APP_VERSION} | IP ↔ URL, OS, WHOIS, DNS y puertos")
        self.root.geometry("1380x890")
        self.root.minsize(1060, 700)
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.engine: TotalReconEngine | None = None
        self.worker: threading.Thread | None = None
        self.result: dict[str, Any] | None = None
        self.report_paths: dict[str, str] = {}
        self.event_queue: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self.closing = False

        self.target_var = tk.StringVar()
        self.profile_var = tk.StringVar(value="Equilibrado (Top 1000)")
        self.traceroute_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Listo. Ingrese una IP, dominio o URL.")
        self.progress_var = tk.DoubleVar(value=0)

        self._configure_styles()
        self._build_ui()
        self.target_entry.focus_set()
        self.root.after(75, self._drain_events)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("App.TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background=PANEL,
            foreground=MUTED,
            padding=(15, 8),
            font=("Segoe UI", 9, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", PANEL_ALT)],
            foreground=[("selected", CYAN)],
        )
        style.configure(
            "Treeview",
            background="#0b1728",
            foreground=TEXT,
            fieldbackground="#0b1728",
            bordercolor=BORDER,
            rowheight=27,
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=PANEL_ALT,
            foreground=CYAN,
            relief="flat",
            font=("Segoe UI", 9, "bold"),
        )
        style.map("Treeview", background=[("selected", "#17425d")], foreground=[("selected", "white")])
        style.configure(
            "Horizontal.TProgressbar",
            troughcolor="#0b1728",
            background=CYAN,
            lightcolor=CYAN,
            darkcolor=CYAN,
            bordercolor="#0b1728",
        )
        style.configure(
            "TCombobox",
            fieldbackground="#0b1728",
            background=PANEL_ALT,
            foreground=TEXT,
            arrowcolor=CYAN,
        )
        style.map("TCombobox", fieldbackground=[("readonly", "#0b1728")], foreground=[("readonly", TEXT)])

    def _build_ui(self) -> None:
        header = tk.Frame(self.root, bg="#0b1830", height=72, highlightbackground=BORDER, highlightthickness=1)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        title_box = tk.Frame(header, bg="#0b1830")
        title_box.pack(side=tk.LEFT, padx=22, pady=11)
        tk.Label(
            title_box,
            text="IP TOTAL",
            bg="#0b1830",
            fg="white",
            font=("Segoe UI Semibold", 20),
        ).pack(anchor="w")
        tk.Label(
            title_box,
            text="IP ↔ URL · DNS · WHOIS/RDAP · OS · puertos · web · TLS · OSINT",
            bg="#0b1830",
            fg=MUTED,
            font=("Segoe UI", 9),
        ).pack(anchor="w")
        tk.Label(
            header,
            text=f"v{APP_VERSION}\nEvidencia local HTML + JSON",
            justify=tk.RIGHT,
            bg="#0b1830",
            fg=CYAN,
            font=("Segoe UI", 9, "bold"),
        ).pack(side=tk.RIGHT, padx=22)

        control = tk.Frame(self.root, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
        control.pack(fill=tk.X, padx=16, pady=(14, 8))

        target_group = tk.Frame(control, bg=PANEL)
        target_group.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(14, 8), pady=12)
        tk.Label(
            target_group,
            text="OBJETIVO ÚNICO",
            bg=PANEL,
            fg=CYAN,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w")
        entry_frame = tk.Frame(target_group, bg="#0b1728", highlightbackground="#34506f", highlightthickness=1)
        entry_frame.pack(fill=tk.X, pady=(4, 0))
        self.target_entry = tk.Entry(
            entry_frame,
            textvariable=self.target_var,
            bg="#0b1728",
            fg="white",
            insertbackground=CYAN,
            selectbackground="#21607c",
            relief=tk.FLAT,
            font=("Consolas", 12),
        )
        self.target_entry.pack(fill=tk.X, padx=11, pady=9)
        self.target_entry.bind("<Return>", lambda _event: self.start_scan())

        profile_group = tk.Frame(control, bg=PANEL)
        profile_group.pack(side=tk.LEFT, padx=8, pady=12)
        tk.Label(profile_group, text="ALCANCE DE PUERTOS", bg=PANEL, fg=CYAN, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.profile_combo = ttk.Combobox(
            profile_group,
            textvariable=self.profile_var,
            values=("Rápido (Top 100)", "Equilibrado (Top 1000)", "Completo (1-65535)"),
            state="readonly",
            width=23,
        )
        self.profile_combo.pack(pady=(5, 0), ipady=4)

        option_group = tk.Frame(control, bg=PANEL)
        option_group.pack(side=tk.LEFT, padx=8, pady=12)
        tk.Label(option_group, text="RUTA", bg=PANEL, fg=CYAN, font=("Segoe UI", 8, "bold")).pack(anchor="w")
        self.trace_check = tk.Checkbutton(
            option_group,
            text="Incluir traceroute",
            variable=self.traceroute_var,
            bg=PANEL,
            fg=TEXT,
            activebackground=PANEL,
            activeforeground=TEXT,
            selectcolor="#0b1728",
            font=("Segoe UI", 9),
        )
        self.trace_check.pack(pady=(7, 0))

        actions = tk.Frame(control, bg=PANEL)
        actions.pack(side=tk.RIGHT, padx=(8, 14), pady=12)
        self.scan_button = self._button(actions, "ANALIZAR TODO", self.start_scan, "#0d7f68")
        self.scan_button.pack(side=tk.LEFT, padx=4)
        self.stop_button = self._button(actions, "DETENER", self.stop_scan, "#8f2439", state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=4)
        self.clear_button = self._button(actions, "LIMPIAR", self.clear_results, "#33465f")
        self.clear_button.pack(side=tk.LEFT, padx=4)

        status_frame = tk.Frame(self.root, bg=BG)
        status_frame.pack(fill=tk.X, padx=18, pady=(0, 7))
        self.status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            bg=BG,
            fg=MUTED,
            anchor="w",
            font=("Segoe UI", 9),
        )
        self.status_label.pack(fill=tk.X)
        self.progress = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress.pack(fill=tk.X, pady=(4, 0))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 8))

        self.summary_tab = tk.Frame(self.notebook, bg=BG)
        self.ports_tab = tk.Frame(self.notebook, bg=BG)
        self.dns_tab = tk.Frame(self.notebook, bg=BG)
        self.whois_tab = tk.Frame(self.notebook, bg=BG)
        self.console_tab = tk.Frame(self.notebook, bg=BG)
        self.notebook.add(self.summary_tab, text="Resumen")
        self.notebook.add(self.ports_tab, text="Puertos y servicios")
        self.notebook.add(self.dns_tab, text="DNS · URL · TLS")
        self.notebook.add(self.whois_tab, text="WHOIS · OSINT")
        self.notebook.add(self.console_tab, text="Consola técnica")

        self._build_summary_tab()
        self._build_ports_tab()
        self.dns_text = self._make_text_tab(self.dns_tab)
        self.whois_text = self._make_text_tab(self.whois_tab)
        self.console = self._make_text_tab(self.console_tab, console=True)

        footer = tk.Frame(self.root, bg=BG)
        footer.pack(fill=tk.X, padx=16, pady=(0, 12))
        self.open_report_button = self._button(footer, "ABRIR INFORME HTML", self.open_report, "#126c88", state=tk.DISABLED)
        self.open_report_button.pack(side=tk.LEFT, padx=(0, 6))
        self.open_folder_button = self._button(footer, "ABRIR EVIDENCIAS", self.open_reports_folder, "#33465f")
        self.open_folder_button.pack(side=tk.LEFT)
        self.report_label = tk.Label(footer, text="", bg=BG, fg=MUTED, anchor="e", font=("Segoe UI", 8))
        self.report_label.pack(side=tk.RIGHT, fill=tk.X, expand=True)

    def _button(self, parent: tk.Widget, text: str, command, color: str, state: str = tk.NORMAL) -> tk.Button:
        return tk.Button(
            parent,
            text=text,
            command=command,
            state=state,
            bg=color,
            fg="white",
            activebackground=CYAN,
            activeforeground="#06101c",
            disabledforeground="#6f829a",
            relief=tk.FLAT,
            cursor="hand2",
            padx=12,
            pady=9,
            font=("Segoe UI", 8, "bold"),
        )

    def _build_summary_tab(self) -> None:
        frame = tk.Frame(self.summary_tab, bg=BG)
        frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.summary_tree = ttk.Treeview(frame, columns=("campo", "valor"), show="headings")
        self.summary_tree.heading("campo", text="Dato")
        self.summary_tree.heading("valor", text="Resultado")
        self.summary_tree.column("campo", width=235, minwidth=180, stretch=False)
        self.summary_tree.column("valor", width=900, minwidth=500, stretch=True)
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.summary_tree.yview)
        self.summary_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.summary_tree.pack(fill=tk.BOTH, expand=True)
        self.summary_tree.tag_configure("section", background=PANEL_ALT, foreground=CYAN, font=("Segoe UI", 9, "bold"))
        self.summary_tree.tag_configure("ok", foreground=GREEN)
        self.summary_tree.tag_configure("warn", foreground=AMBER)

    def _build_ports_tab(self) -> None:
        frame = tk.Frame(self.ports_tab, bg=BG)
        frame.pack(fill=tk.BOTH, expand=True, pady=5)
        columns = ("port", "state", "service", "product", "version", "reason", "evidence")
        self.ports_tree = ttk.Treeview(frame, columns=columns, show="headings")
        headings = {
            "port": "Puerto",
            "state": "Estado",
            "service": "Servicio",
            "product": "Producto",
            "version": "Versión / detalle",
            "reason": "Evidencia",
            "evidence": "Scripts / CPE",
        }
        widths = {"port": 80, "state": 90, "service": 120, "product": 190, "version": 230, "reason": 120, "evidence": 360}
        for column in columns:
            self.ports_tree.heading(column, text=headings[column])
            self.ports_tree.column(column, width=widths[column], anchor=tk.W)
        yscroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.ports_tree.yview)
        xscroll = ttk.Scrollbar(frame, orient=tk.HORIZONTAL, command=self.ports_tree.xview)
        self.ports_tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.ports_tree.pack(fill=tk.BOTH, expand=True)
        self.ports_tree.tag_configure("open", foreground=GREEN)
        self.ports_tree.tag_configure("filtered", foreground=AMBER)

    def _make_text_tab(self, parent: tk.Widget, console: bool = False) -> scrolledtext.ScrolledText:
        widget = scrolledtext.ScrolledText(
            parent,
            bg="#07101c",
            fg="#cfe2f7",
            insertbackground=CYAN,
            selectbackground="#17425d",
            relief=tk.FLAT,
            wrap=tk.WORD if not console else tk.NONE,
            font=("Consolas", 9),
            padx=12,
            pady=12,
            state=tk.DISABLED,
        )
        widget.pack(fill=tk.BOTH, expand=True, pady=5)
        if console:
            widget.tag_configure("success", foreground=GREEN)
            widget.tag_configure("warning", foreground=AMBER)
            widget.tag_configure("error", foreground=RED)
            widget.tag_configure("command", foreground=CYAN)
            widget.tag_configure("nmap", foreground="#aac4df")
            widget.tag_configure("info", foreground="#cfe2f7")
        return widget

    def append_log(self, message: str, level: str = "info") -> None:
        if not self.root.winfo_exists():
            return
        self.console.configure(state=tk.NORMAL)
        stamp = __import__("datetime").datetime.now().strftime("%H:%M:%S")
        self.console.insert(tk.END, f"[{stamp}] {message}\n", level if level in self.console.tag_names() else "info")
        self.console.see(tk.END)
        self.console.configure(state=tk.DISABLED)

    def queue_log(self, message: str, level: str = "info") -> None:
        self.event_queue.put(("log", message, level))

    def queue_progress(self, value: int, message: str) -> None:
        self.event_queue.put(("progress", value, message))

    def _drain_events(self) -> None:
        if self.closing:
            return
        try:
            while True:
                event = self.event_queue.get_nowait()
                if event[0] == "log":
                    self.append_log(event[1], event[2])
                elif event[0] == "progress":
                    self._set_progress(event[1], event[2])
                elif event[0] == "finish":
                    self._finish_scan(event[1], event[2])
        except queue.Empty:
            pass
        self.root.after(75, self._drain_events)

    def _set_progress(self, value: int, message: str) -> None:
        self.progress_var.set(value)
        self.status_var.set(message)

    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        target = self.target_var.get().strip()
        if not target:
            messagebox.showwarning(APP_NAME, "Ingrese una IP, dominio o URL.")
            self.target_entry.focus_set()
            return
        try:
            TotalReconEngine.normalize_target(target)
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return

        self.clear_results(keep_target=True)
        self._set_busy(True)
        self.engine = TotalReconEngine(self.queue_log, self.queue_progress)
        profile = self.profile_var.get()
        trace = self.traceroute_var.get()
        self.append_log(f"=== INICIO {APP_NAME} {APP_VERSION} ===", "command")
        self.append_log(f"Entrada: {target} | Perfil: {profile}", "command")
        self.worker = threading.Thread(
            target=self._scan_worker,
            args=(target, profile, trace),
            daemon=True,
            name="ip-total-scan",
        )
        self.worker.start()

    def _scan_worker(self, target: str, profile: str, trace: bool) -> None:
        assert self.engine is not None
        result = self.engine.analyze(target, profile, trace)
        paths: dict[str, str] = {}
        if result.get("objetivo"):
            try:
                paths = save_reports(result)
                self.queue_log(f"HTML: {paths['html']}", "success")
                self.queue_log(f"JSON: {paths['json']}", "success")
            except OSError as exc:
                self.queue_log(f"No se pudo guardar evidencia: {exc}", "error")
        self.event_queue.put(("finish", result, paths))

    def _finish_scan(self, result: dict[str, Any], paths: dict[str, str]) -> None:
        self.result = result
        self.report_paths = paths
        self._populate_results(result)
        self._set_busy(False)
        state = result.get("meta", {}).get("estado")
        duration = result.get("meta", {}).get("duracion_segundos", 0)
        if state == "completado":
            self.status_var.set(f"Análisis completado en {duration} s. Evidencia HTML y JSON generada.")
            self.status_label.configure(fg=GREEN)
        elif state == "detenido":
            self.status_var.set(f"Análisis detenido. Evidencia parcial guardada ({duration} s).")
            self.status_label.configure(fg=AMBER)
        else:
            self.status_var.set("El análisis terminó con error; revise la consola técnica.")
            self.status_label.configure(fg=RED)
        if paths:
            self.open_report_button.configure(state=tk.NORMAL)
            self.report_label.configure(text=paths["html"])

    def _set_busy(self, busy: bool) -> None:
        state = tk.DISABLED if busy else tk.NORMAL
        self.scan_button.configure(state=state)
        self.clear_button.configure(state=state)
        self.target_entry.configure(state=state)
        self.profile_combo.configure(state=tk.DISABLED if busy else "readonly")
        self.trace_check.configure(state=state)
        self.stop_button.configure(state=tk.NORMAL if busy else tk.DISABLED)
        if busy:
            self.status_label.configure(fg=MUTED)

    def stop_scan(self) -> None:
        if self.engine:
            self.status_var.set("Deteniendo análisis y proceso activo…")
            self.status_label.configure(fg=AMBER)
            self.engine.stop()
            self.stop_button.configure(state=tk.DISABLED)

    def clear_results(self, keep_target: bool = False) -> None:
        if not keep_target:
            self.target_var.set("")
        self.result = None
        self.report_paths = {}
        self.progress_var.set(0)
        self.status_var.set("Listo. Ingrese una IP, dominio o URL.")
        self.status_label.configure(fg=MUTED)
        self.report_label.configure(text="")
        self.open_report_button.configure(state=tk.DISABLED)
        for tree in (getattr(self, "summary_tree", None), getattr(self, "ports_tree", None)):
            if tree:
                for item in tree.get_children():
                    tree.delete(item)
        for widget in (getattr(self, "dns_text", None), getattr(self, "whois_text", None), getattr(self, "console", None)):
            if widget:
                widget.configure(state=tk.NORMAL)
                widget.delete("1.0", tk.END)
                widget.configure(state=tk.DISABLED)

    def _summary_row(self, field: str, value: Any, tag: str = "") -> None:
        self.summary_tree.insert("", tk.END, values=(field, display_value(value)), tags=(tag,) if tag else ())

    def _summary_section(self, text: str) -> None:
        self.summary_tree.insert("", tk.END, values=(text, ""), tags=("section",))

    def _populate_results(self, result: dict[str, Any]) -> None:
        target = result.get("objetivo", {})
        resolution = result.get("resolucion", {})
        geo = result.get("geolocalizacion", {})
        os_data = result.get("sistema_operativo", {})
        web = result.get("urls_verificadas", [])
        ports = result.get("puertos", [])

        self._summary_section("OBJETIVO Y RESOLUCIÓN")
        self._summary_row("Entrada", target.get("entrada"))
        self._summary_row("Tipo detectado", target.get("tipo"))
        self._summary_row("Host normalizado", target.get("host"))
        self._summary_row("URL ingresada", target.get("url_original"))
        self._summary_row("Dominio registrable", target.get("dominio_registrable"))
        self._summary_row("IP primaria", resolution.get("ip_primaria"), "ok")
        self._summary_row("Todas las direcciones", [item.get("ip") for item in resolution.get("direcciones", [])])
        self._summary_row("DNS inverso / PTR", resolution.get("dns_inverso"))
        self._summary_row("Dominios verificados para la IP", result.get("dominios_verificados_para_ip"))

        self._summary_section("SISTEMA Y EXPOSICIÓN")
        self._summary_row("Sistema operativo", os_data.get("nombre"), "ok" if os_data.get("nombre") != "No concluyente" else "warn")
        self._summary_row("Método / precisión", f"{display_value(os_data.get('metodo'))} / {display_value(os_data.get('precision'))}")
        self._summary_row("TTL / saltos estimados", result.get("icmp_ttl"))
        self._summary_row("Estado Nmap", result.get("nmap", {}).get("estado_host"))
        self._summary_row("Puertos abiertos", [item.get("puerto") for item in ports if item.get("estado") == "open"], "ok")
        self._summary_row("Resumen restantes", result.get("nmap", {}).get("resumen_puertos"))

        self._summary_section("WEB, ASN Y UBICACIÓN")
        self._summary_row("URLs verificadas", [item.get("url_final") for item in web], "ok" if web else "warn")
        self._summary_row("Títulos web", [item.get("titulo") for item in web if item.get("titulo")])
        self._summary_row("Tecnologías", sorted({tech for item in web for tech in item.get("tecnologias", [])}))
        self._summary_row("ASN", geo.get("asn"))
        self._summary_row("Organización / ISP", [geo.get("organizacion"), geo.get("isp")])
        self._summary_row("País / región / ciudad", [geo.get("pais"), geo.get("region"), geo.get("ciudad")])
        self._summary_row("Duración", f"{result.get('meta', {}).get('duracion_segundos')} segundos")

        for item in ports:
            service = item.get("servicio", {})
            scripts = " | ".join(
                f"{entry.get('id')}: {entry.get('salida')}" for entry in item.get("scripts", [])
            )
            cpes = ", ".join(service.get("cpes", []))
            evidence = " | ".join(value for value in (cpes, scripts) if value)
            version = " ".join(str(service.get(key, "")) for key in ("version", "extrainfo")).strip()
            tag = "open" if item.get("estado") == "open" else "filtered" if item.get("estado") == "filtered" else ""
            self.ports_tree.insert(
                "",
                tk.END,
                values=(
                    f"{item.get('puerto')}/{item.get('protocolo')}",
                    item.get("estado"),
                    service.get("name"),
                    service.get("product"),
                    version,
                    item.get("razon"),
                    evidence,
                ),
                tags=(tag,) if tag else (),
            )

        dns_sections = [
            ("RESOLUCIÓN", resolution),
            ("REGISTROS DNS", result.get("dns", {})),
            ("URLS WEB VERIFICADAS", result.get("urls_verificadas", [])),
            ("CERTIFICADOS TLS", result.get("tls", [])),
            ("ROBOTS.TXT", result.get("robots", [])),
            ("TRACEROUTE", result.get("traceroute", {})),
        ]
        whois_sections = [
            ("GEOLOCALIZACIÓN Y ASN", result.get("geolocalizacion", {})),
            ("WHOIS / RDAP DE IP", result.get("whois_ip", {})),
            ("WHOIS / RDAP DE DOMINIO", result.get("whois_dominio", {})),
            ("WHOIS TCP/43 SIN PROCESAR", result.get("whois_dominio_raw", {})),
            ("TRANSPARENCIA DE CERTIFICADOS / SUBDOMINIOS", result.get("crt_sh", {})),
            ("FINGERPRINT DE SISTEMA", result.get("sistema_operativo", {})),
        ]
        self._set_sections(self.dns_text, dns_sections)
        self._set_sections(self.whois_text, whois_sections)

    @staticmethod
    def _set_sections(widget: scrolledtext.ScrolledText, sections: list[tuple[str, Any]]) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        for title, value in sections:
            widget.insert(tk.END, f"{'=' * 9} {title} {'=' * 9}\n")
            widget.insert(tk.END, pretty(value) + "\n\n")
        widget.configure(state=tk.DISABLED)

    def open_report(self) -> None:
        path = self.report_paths.get("html")
        if path and Path(path).exists():
            webbrowser.open(Path(path).resolve().as_uri())
        else:
            messagebox.showwarning(APP_NAME, "Todavía no existe un informe HTML.")

    @staticmethod
    def open_reports_folder() -> None:
        DEFAULT_REPORT_DIR.mkdir(parents=True, exist_ok=True)
        if os.name == "nt":
            os.startfile(str(DEFAULT_REPORT_DIR))
        else:
            webbrowser.open(DEFAULT_REPORT_DIR.resolve().as_uri())

    def on_close(self) -> None:
        self.closing = True
        if self.engine:
            self.engine.stop()
        self.root.destroy()


def run_self_test() -> int:
    engine = TotalReconEngine()
    ip = engine.normalize_target("8.8.8.8")
    domain = engine.normalize_target("example.com")
    url = engine.normalize_target("https://example.com:8443/ruta?q=1")
    assert ip["tipo"] == "IP" and ip["version_ip"] == 4
    assert domain["tipo"] == "Dominio/host" and domain["host"] == "example.com"
    assert url["tipo"] == "URL" and url["puerto_explicito"] == 8443
    assert engine.profile_key("Rápido (Top 100)") == "rapido"
    assert engine.profile_key("Completo (1-65535)") == "completo"
    xml_sample = """<?xml version='1.0'?>
    <nmaprun><host><status state='up' reason='echo-reply'/><hostnames><hostname name='test.local'/></hostnames>
    <ports><port protocol='tcp' portid='443'><state state='open' reason='syn-ack'/>
    <service name='https' product='Test Server' version='1.0' tunnel='ssl'><cpe>cpe:/a:test</cpe></service>
    <script id='ssl-cert' output='CN=test.local'/></port></ports>
    <os><osmatch name='Test OS' accuracy='95'><osclass type='general purpose' vendor='Test' osfamily='TestOS' accuracy='95'/></osmatch></os>
    </host></nmaprun>"""
    parsed_nmap = engine.parse_nmap_xml(xml_sample)
    assert parsed_nmap["estado_host"] == "up"
    assert parsed_nmap["puertos"][0]["puerto"] == 443
    assert parsed_nmap["puertos"][0]["servicio"]["product"] == "Test Server"
    assert parsed_nmap["os_matches"][0]["precision"] == 95
    sample = {
        "meta": {"inicio": "test", "perfil": "Rápido", "duracion_segundos": 0, "estado": "completado"},
        "objetivo": ip,
        "resolucion": {"ip_primaria": "8.8.8.8", "direcciones": [{"ip": "8.8.8.8", "familia": "IPv4", "publica": True}], "dns_inverso": {"8.8.8.8": "dns.google"}},
        "sistema_operativo": {"nombre": "No concluyente", "metodo": "test"},
        "puertos": [],
        "urls_verificadas": [],
    }
    rendered = build_html_report(sample)
    assert "<!doctype html>" in rendered and "8.8.8.8" in rendered
    with tempfile.TemporaryDirectory(prefix="ip_total_selftest_") as temporary:
        paths = save_reports(sample, temporary)
        assert Path(paths["html"]).is_file() and Path(paths["json"]).is_file()
        json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
    print("SELFTEST_OK")
    return 0


def run_ui_smoke() -> int:
    root = tk.Tk()
    root.withdraw()
    app = IPTotalApp(root)
    root.update_idletasks()
    assert app.profile_var.get().startswith("Equilibrado")
    assert app.target_entry.winfo_exists()
    root.destroy()
    print("UI_SMOKE_OK")
    return 0


def run_cli_scan(target: str, profile: str, include_traceroute: bool, output: str | None) -> int:
    def logger(message: str, level: str) -> None:
        print(f"[{level.upper():7}] {message}", flush=True)

    def progress(value: int, message: str) -> None:
        print(f"[{value:3}%] {message}", flush=True)

    engine = TotalReconEngine(logger, progress)
    try:
        result = engine.analyze(target, profile, include_traceroute)
    except KeyboardInterrupt:
        engine.stop()
        print("Análisis interrumpido", file=sys.stderr)
        return 130
    paths = save_reports(result, output or DEFAULT_REPORT_DIR) if result.get("objetivo") else {}
    print(json.dumps({"estado": result.get("meta", {}).get("estado"), "reportes": paths}, ensure_ascii=False, indent=2))
    return 0 if result.get("meta", {}).get("estado") == "completado" else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="IP Total: IP ↔ URL, OS, WHOIS, DNS, puertos, web y TLS")
    parser.add_argument("--scan", metavar="OBJETIVO", help="ejecuta un análisis desde consola")
    parser.add_argument("--profile", choices=("rapido", "equilibrado", "completo"), default="equilibrado")
    parser.add_argument("--no-traceroute", action="store_true", help="omite traceroute")
    parser.add_argument("--output", help="directorio de reportes para modo CLI")
    parser.add_argument("--self-test", action="store_true", help="valida núcleo, normalización y reportes")
    parser.add_argument("--ui-smoke", action="store_true", help="valida que la GUI pueda construirse")
    return parser.parse_args()


def main() -> int:
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    args = parse_args()
    if args.self_test:
        return run_self_test()
    if args.ui_smoke:
        return run_ui_smoke()
    if args.scan:
        return run_cli_scan(args.scan, args.profile, not args.no_traceroute, args.output)
    root = tk.Tk()
    IPTotalApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
