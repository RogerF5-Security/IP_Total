import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import re
import platform
import socket
import csv
import os
import json
import webbrowser
import ipaddress
import time
import random
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class IPtoOS:
    def __init__(self, root):
        self.root = root
        self.root.title("IP to OS - Professional Network Auditor | Roger F5")
        self.root.geometry("1300x850")
        self.root.configure(bg="#121212")
        
        # Flags de control
        self.stop_event = threading.Event()
        self.is_scanning = False
        
        # Puertos por defecto (si no se especifica rango)
        self.default_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 
            443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL", 
            3389: "RDP", 5432: "PostgreSQL", 8080: "HTTP-Alt"
        }
        
        self.results_data = []
        self.setup_ui()
        self.apply_styles()

    def apply_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("Treeview", background="#1e1e1e", foreground="#e0e0e0", fieldbackground="#1e1e1e", borderwidth=0, font=('Segoe UI', 9))
        style.configure("Treeview.Heading", background="#333333", foreground="white", font=('Segoe UI', 10, 'bold'))
        style.map("Treeview", background=[('selected', '#0078d7')])
        style.configure("TProgressbar", thickness=10, troughcolor="#121212", background="#0078d7")

    def setup_ui(self):
        # --- Header ---
        header = tk.Frame(self.root, bg="#0078d7", height=70)
        header.pack(fill=tk.X)
        tk.Label(header, text="🔍 IP to OS: Professional Auditor Edition", bg="#0078d7", fg="white", font=('Segoe UI', 18, 'bold')).pack(pady=15)

        # --- Panel de Controles ---
        ctrl_frame = tk.Frame(self.root, bg="#121212", padx=20, pady=10)
        ctrl_frame.pack(fill=tk.X)

        # Entrada de Objetivos
        input_group = tk.LabelFrame(ctrl_frame, text=" Configuración de Objetivos & Red ", bg="#121212", fg="#0078d7", font=('Segoe UI', 9, 'bold'), padx=10, pady=10)
        input_group.pack(fill=tk.X, side=tk.TOP, pady=5)

        # Línea 1: IPs y Archivo
        line1 = tk.Frame(input_group, bg="#121212")
        line1.pack(fill=tk.X, pady=2)
        tk.Label(line1, text="Objetivos (IP, URL, CIDR):", bg="#121212", fg="#aaaaaa", width=22, anchor="w").pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(line1)
        self.target_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.target_entry.insert(0, "192.168.1.0/24")
        tk.Button(line1, text="📁 TXT", command=self.load_file, bg="#444444", fg="white", relief=tk.FLAT, padx=10).pack(side=tk.LEFT)

        # Línea 2: Puertos Personalizados
        line2 = tk.Frame(input_group, bg="#121212")
        line2.pack(fill=tk.X, pady=2)
        tk.Label(line2, text="Puertos (ej: 80,443 o 21-100):", bg="#121212", fg="#aaaaaa", width=22, anchor="w").pack(side=tk.LEFT)
        self.port_entry = ttk.Entry(line2)
        self.port_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.port_entry.insert(0, "Common (Default)")

        # Opciones de Ejecución
        opt_group = tk.Frame(ctrl_frame, bg="#121212", pady=10)
        opt_group.pack(fill=tk.X)

        tk.Label(opt_group, text="Perfil de Auditoría:", bg="#121212", fg="#aaaaaa").pack(side=tk.LEFT, padx=5)
        self.scan_mode = tk.StringVar(value="Normal")
        self.mode_combo = ttk.Combobox(opt_group, textvariable=self.scan_mode, values=["Stealth (SOC-Safe)", "Normal", "Aggressive"], state="readonly", width=15)
        self.mode_combo.pack(side=tk.LEFT, padx=5)

        # Botones
        self.scan_btn = tk.Button(opt_group, text="🚀 INICIAR", command=self.start_scan, bg="#28a745", fg="white", font=('Segoe UI', 9, 'bold'), padx=15, relief=tk.FLAT)
        self.scan_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = tk.Button(opt_group, text="🛑 DETENER", command=self.stop_scan, state=tk.DISABLED, bg="#dc3545", fg="white", font=('Segoe UI', 9, 'bold'), padx=15, relief=tk.FLAT)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = tk.Button(opt_group, text="🧹 LIMPIAR", command=self.clear_screen, bg="#6c757d", fg="white", font=('Segoe UI', 9, 'bold'), padx=15, relief=tk.FLAT)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        self.report_btn = tk.Button(opt_group, text="📊 REPORTE HTML", command=self.generate_html_report, state=tk.DISABLED, bg="#17a2b8", fg="white", font=('Segoe UI', 9, 'bold'), padx=15, relief=tk.FLAT)
        self.report_btn.pack(side=tk.LEFT, padx=5)
        
        self.json_btn = tk.Button(opt_group, text="💾 JSON", command=self.export_json, state=tk.DISABLED, bg="#6f42c1", fg="white", font=('Segoe UI', 9, 'bold'), padx=15, relief=tk.FLAT)
        self.json_btn.pack(side=tk.LEFT, padx=5)

        # --- Progreso ---
        self.status_label = tk.Label(self.root, text="Listo para auditoría", bg="#121212", fg="#0078d7", font=('Segoe UI', 9))
        self.status_label.pack(anchor="w", padx=20)
        self.progress = ttk.Progressbar(self.root, orient=tk.HORIZONTAL, mode='determinate')
        self.progress.pack(fill=tk.X, padx=20, pady=5)

        # --- Tabla Principal ---
        table_frame = tk.Frame(self.root, bg="#121212")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        cols = ("IP", "HOSTNAME", "TTL", "OS", "HOPS", "SERVICES", "REASON")
        self.tree = ttk.Treeview(table_frame, columns=cols, show='headings')
        
        headers = {
            "IP": "Dirección IP", "HOSTNAME": "Reverse DNS", "TTL": "TTL",
            "OS": "OS Estimado", "HOPS": "Hops", "SERVICES": "Servicios Detectados", "REASON": "Estado/Evidencia"
        }
        for col, text in headers.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, anchor=tk.W, width=110)
        
        self.tree.column("SERVICES", width=350)
        self.tree.column("REASON", width=150)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(fill=tk.BOTH, expand=True)

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, 'r') as f:
                content = ",".join([line.strip() for line in f if line.strip()])
                self.target_entry.delete(0, tk.END)
                self.target_entry.insert(0, content)

    def clear_screen(self):
        for item in self.tree.get_children(): self.tree.delete(item)
        self.results_data = []
        self.progress["value"] = 0
        self.status_label.config(text="Memoria limpia")
        self.report_btn.config(state=tk.DISABLED)
        self.json_btn.config(state=tk.DISABLED)

    def stop_scan(self):
        if self.is_scanning:
            self.stop_event.set()
            self.status_label.config(text="🛑 Deteniendo hilos activos... por favor espere.")

    def parse_ports(self):
        p_input = self.port_entry.get().strip().lower()
        if "common" in p_input or not p_input:
            return self.default_ports
        
        custom_ports = {}
        try:
            for part in p_input.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    for p in range(start, end + 1):
                        custom_ports[p] = socket.getservbyport(p) if p < 1024 else f"Unk-{p}"
                else:
                    p = int(part)
                    custom_ports[p] = socket.getservbyport(p) if p < 1024 else f"Unk-{p}"
        except:
            pass
        return custom_ports if custom_ports else self.default_ports

    def get_reverse_dns(self, ip):
        try:
            host, _, _ = socket.gethostbyaddr(ip)
            return host
        except:
            return "N/A"

    def grab_banner(self, ip, port):
        if self.stop_event.is_set(): return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.2)
                s.connect((ip, port))
                # Payload específico por puerto para forzar banners
                if port in [80, 8080]:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 443:
                    # Intento de SSL (Básico)
                    return "SSL/TLS Service"
                else:
                    s.sendall(b"\r\n")
                
                banner = s.recv(1024).decode(errors='ignore').strip()
                banner = re.sub(r'[^a-zA-Z0-9\/\.\_\-\s]', '', banner)
                return banner[:50] if banner else "Open (No Banner)"
        except:
            return "Open"

    def scan_port(self, ip, port, port_name, timeout):
        if self.stop_event.is_set(): return None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((ip, port)) == 0:
                    info = self.grab_banner(ip, port)
                    return f"{port}/{port_name} [{info}]"
        except:
            pass
        return None

    def audit_target(self, target, workers, p_timeout, s_delay, port_list):
        if self.stop_event.is_set(): return None
        
        target = target.strip()
        try:
            resolved_ip = socket.gethostbyname(target)
            hostname = self.get_reverse_dns(resolved_ip)
        except:
            return (target, "Unresolved", "N/A", "N/A", "N/A", "---", "❌ DNS Error")

        if s_delay > 0:
            time.sleep(random.uniform(s_delay * 0.8, s_delay * 1.2))

        # Fingerprinting Pasivo (TTL)
        param = "-n" if platform.system().lower() == "windows" else "-c"
        ttl_rec, os_guess, hops = "N/A", "Unknown", "N/A"
        
        try:
            output = subprocess.check_output(["ping", param, "1", "-w", "1000", resolved_ip], 
                                           stderr=subprocess.STDOUT, universal_newlines=True)
            match = re.search(r"ttl=(\d+)", output.lower())
            if match:
                ttl_rec = int(match.group(1))
                if ttl_rec <= 64: base, os_guess = 64, "Linux/Unix/IoT"
                elif ttl_rec <= 128: base, os_guess = 128, "Windows"
                else: base, os_guess = 255, "Network Device"
                hops = base - ttl_rec
        except:
            # Si el ping falla, intentamos marcar como activo si hay puertos abiertos luego
            pass

        # Port Scan
        open_services = []
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [executor.submit(self.scan_port, resolved_ip, p, name, p_timeout) for p, name in port_list.items()]
            for f in futures:
                if self.stop_event.is_set(): break
                res = f.result()
                if res: open_services.append(res)

        status = "✅ Active" if (open_services or ttl_rec != "N/A") else "⚠️ No Response"
        return (resolved_ip, hostname, ttl_rec, os_guess, hops, 
                " | ".join(open_services) if open_services else "No common ports found", status)

    def run_scan_thread(self):
        self.is_scanning = True
        self.stop_event.clear()
        
        # Preparación de objetivos
        raw_input = self.target_entry.get().split(',')
        targets = []
        for item in raw_input:
            item = item.strip()
            if "/" in item:
                try:
                    for ip in ipaddress.ip_network(item, strict=False): targets.append(str(ip))
                except: targets.append(item)
            else: targets.append(item)

        total = len(targets)
        self.progress["maximum"] = total
        port_list = self.parse_ports()
        
        # Modos
        mode = self.scan_mode.get()
        if "Stealth" in mode: workers, p_timeout, s_delay = 1, 1.5, 3.0
        elif "Aggressive" in mode: workers, p_timeout, s_delay = 40, 0.4, 0.0
        else: workers, p_timeout, s_delay = 15, 0.8, 0.0

        for i, t in enumerate(targets):
            if self.stop_event.is_set(): break
            self.status_label.config(text=f"Auditing ({i+1}/{total}): {t}")
            res = self.audit_target(t, workers, p_timeout, s_delay, port_list)
            if res:
                self.results_data.append(res)
                self.root.after(0, self.update_tree, res)
                self.root.after(0, self.update_progress, i + 1)

        self.is_scanning = False
        self.root.after(0, self.finish_scan)

    def update_tree(self, res):
        self.tree.insert("", tk.END, values=res)
        self.tree.see(self.tree.get_children()[-1])

    def update_progress(self, val):
        self.progress["value"] = val

    def finish_scan(self):
        self.scan_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_label.config(text="Auditoría Completada" if not self.stop_event.is_set() else "Escaneo interrumpido.")
        if self.results_data:
            self.report_btn.config(state=tk.NORMAL)
            self.json_btn.config(state=tk.NORMAL)

    def start_scan(self):
        if not self.target_entry.get().strip(): return
        self.scan_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        threading.Thread(target=self.run_scan_thread, daemon=True).start()

    def export_json(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if file_path:
            keys = ["ip", "hostname", "ttl", "os", "hops", "services", "status"]
            data = [dict(zip(keys, r)) for r in self.results_data]
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=4)
            messagebox.showinfo("Export", "Datos exportados en JSON exitosamente.")

    def generate_html_report(self):
        if not self.results_data: return
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""
        <html><head><meta charset='UTF-8'><title>Audit Report</title>
        <style>
            body {{ font-family: 'Segoe UI', sans-serif; background: #0f172a; color: #f1f5f9; padding: 40px; }}
            .container {{ max-width: 1200px; margin: auto; }}
            .header {{ border-bottom: 2px solid #38bdf8; padding-bottom: 10px; margin-bottom: 30px; }}
            .card {{ background: #1e293b; padding: 25px; border-radius: 12px; margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th {{ background: #38bdf8; color: #0f172a; padding: 12px; text-align: left; }}
            td {{ padding: 12px; border-bottom: 1px solid #334155; font-size: 14px; }}
            .badge {{ padding: 4px 10px; border-radius: 15px; font-size: 11px; font-weight: bold; }}
            .win {{ background: #0ea5e9; }} .linux {{ background: #f97316; }} .net {{ background: #64748b; }}
        </style></head>
        <body><div class='container'>
            <div class='header'><h1>Network Audit Report</h1><p>Generated by Roger F5 Tool</p></div>
            <div class='card'><strong>Scan Time:</strong> {timestamp} | <strong>Hosts:</strong> {len(self.results_data)}</div>
            <table><thead><tr><th>IP / Host</th><th>OS</th><th>TTL/Hops</th><th>Services</th></tr></thead><tbody>"""
        
        for r in self.results_data:
            cls = "win" if "Windows" in r[3] else "linux" if "Linux" in r[3] else "net"
            html += f"<tr><td><b>{r[0]}</b><br><small>{r[1]}</small></td>"
            html += f"<td><span class='badge {cls}'>{r[3]}</span></td>"
            html += f"<td>TTL: {r[2]} | Hops: {r[4]}</td>"
            html += f"<td style='font-family: monospace; color: #94a3b8;'>{r[5]}</td></tr>"
            
        html += "</tbody></table></div></body></html>"
        
        path = filedialog.asksaveasfilename(defaultextension=".html", initialfile="Audit_Report.html")
        if path:
            with open(path, 'w', encoding='utf-8') as f: f.write(html)
            webbrowser.open(f"file:///{os.path.abspath(path)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = IPtoOS(root)
    root.mainloop()