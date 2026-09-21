import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import subprocess
import threading
import platform
import socket
import ssl
import requests
import json
import re

class NetReconOSINT:
    def __init__(self, root):
        self.root = root
        self.root.title("NetRecon v4 - Infra + OSINT | Roger F5")
        self.root.geometry("1100x800")
        self.root.configure(bg="#0f0f0f")
        
        self.current_process = None
        self.stop_requested = False

        # --- Top Panel ---
        top_frame = tk.Frame(root, bg="#1a1a1a", pady=10, padx=10)
        top_frame.pack(fill=tk.X)

        tk.Label(top_frame, text="TARGET >", bg="#1a1a1a", fg="#00ff00", font=("Consolas", 12, "bold")).pack(side=tk.LEFT)
        self.target_entry = tk.Entry(top_frame, width=30, font=("Consolas", 12), bg="#333", fg="white", insertbackground="white")
        self.target_entry.pack(side=tk.LEFT, padx=10)

        # Botones Principales
        btn_frame = tk.Frame(top_frame, bg="#1a1a1a")
        btn_frame.pack(side=tk.LEFT, padx=20)
        
        tk.Button(btn_frame, text="▶ EJECUTAR TODO", command=self.start_full_scan, bg="#006400", fg="white", font=("Consolas", 10, "bold"), relief="flat").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="⏹ DETENER", command=self.stop_process, bg="#8b0000", fg="white", font=("Consolas", 10), relief="flat").pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="LIMPIAR", command=self.clear_console, bg="#444", fg="white", font=("Consolas", 10), relief="flat").pack(side=tk.LEFT, padx=5)

        # --- Tabs para organizar ---
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Pestaña 1: Infraestructura (Lo que ya tenías)
        self.tab_infra = tk.Frame(self.notebook, bg="#0f0f0f")
        self.notebook.add(self.tab_infra, text="Infraestructura (Net/System)")
        
        # Pestaña 2: OSINT & Web (Lo nuevo)
        self.tab_osint = tk.Frame(self.notebook, bg="#0f0f0f")
        self.notebook.add(self.tab_osint, text="OSINT & Web Recon")

        # --- Configuración Tab Infra ---
        infra_opts = tk.Frame(self.tab_infra, bg="#0f0f0f")
        infra_opts.pack(fill=tk.X, pady=5)
        self.chk_nslookup = tk.BooleanVar(value=True)
        self.chk_nmap = tk.BooleanVar(value=True)
        self.chk_traceroute = tk.BooleanVar(value=False)
        self.create_check(infra_opts, "Nslookup (Raw)", self.chk_nslookup)
        self.create_check(infra_opts, "Nmap (Fast Scan)", self.chk_nmap)
        self.create_check(infra_opts, "Traceroute", self.chk_traceroute)

        # --- Configuración Tab OSINT ---
        osint_opts = tk.Frame(self.tab_osint, bg="#0f0f0f")
        osint_opts.pack(fill=tk.X, pady=5)
        self.chk_ssl = tk.BooleanVar(value=True)
        self.chk_subs = tk.BooleanVar(value=True)
        self.chk_robots = tk.BooleanVar(value=True)
        self.create_check(osint_opts, "SSL Analysis (SANs)", self.chk_ssl)
        self.create_check(osint_opts, "Subdominios (Crt.sh)", self.chk_subs)
        self.create_check(osint_opts, "Robots.txt Hunting", self.chk_robots)

        # Consola Única
        self.console = scrolledtext.ScrolledText(root, bg="#000000", fg="#cccccc", font=("Consolas", 10), height=20, state='disabled')
        self.console.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.setup_tags()

    def create_check(self, parent, text, var):
        tk.Checkbutton(parent, text=text, variable=var, bg="#0f0f0f", fg="#ddd", selectcolor="#333", activebackground="#0f0f0f", font=("Consolas", 9)).pack(side=tk.LEFT, padx=10)

    def setup_tags(self):
        self.console.tag_config("header", foreground="#00ffff", font=("Consolas", 11, "bold"))
        self.console.tag_config("success", foreground="#00ff00")
        self.console.tag_config("alert", foreground="#ff00ff") # Magenta para hallazgos importantes
        self.console.tag_config("error", foreground="#ff5555")

    def log(self, text, tag=None):
        self.console.config(state='normal')
        self.console.insert(tk.END, text + "\n", tag)
        self.console.see(tk.END)
        self.console.config(state='disabled')

    def clear_console(self):
        self.console.config(state='normal')
        self.console.delete(1.0, tk.END)
        self.console.config(state='disabled')

    def stop_process(self):
        self.stop_requested = True
        if self.current_process:
            try: self.current_process.kill()
            except: pass

    # --- Funciones OSINT Nuevas ---
    
    def scan_ssl_sans(self, target):
        self.log(f"\n[*] Analizando Certificado SSL en: {target}", "header")
        try:
            # Limpiar input
            host = target.replace("http://", "").replace("https://", "").split("/")[0]
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE # Para aceptar self-signed en auditoría

            with socket.create_connection((host, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Si el cert es vacío (común en self-signed con CERT_NONE sin parsear manual), intentamos obtener binario
                    # Nota: getpeercert() devuelve dict solo si se valida, sino devuelve binario o nada.
                    # Para simplificar en auditoría, usamos un truco para obtener datos básicos
                    
                    self.log(f" -> Cipher: {ssock.cipher()}")
                    self.log(f" -> Version: {ssock.version()}")
                    
                    # Intentamos recuperar SANs si el cert fue parseado
                    if cert and 'subjectAltName' in cert:
                        self.log(" -> [!] Nombres Alternativos (SANs) Detectados:", "alert")
                        for item in cert['subjectAltName']:
                            self.log(f"    - {item[1]}")
                    else:
                        self.log(" -> No se pudo parsear SANs (Posible Self-Signed o sin validación completa).")

        except Exception as e:
            self.log(f" [-] Error SSL: {e}", "error")

    def scan_subdomains_crt(self, target):
        self.log(f"\n[*] Buscando Subdominios (Passive - crt.sh): {target}", "header")
        domain = target.replace("http://", "").replace("https://", "").split("/")[0]
        # Intentar extraer dominio raíz si es subdominio (simple heuristic)
        parts = domain.split('.')
        if len(parts) > 2:
            domain = f"{parts[-2]}.{parts[-1]}" # apuntas a claro.com.gt

        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            headers = {'User-Agent': 'Mozilla/5.0 (Audit-Tool)'}
            resp = requests.get(url, headers=headers, timeout=10)
            
            if resp.status_code == 200:
                data = resp.json()
                subs = set()
                for entry in data:
                    name_value = entry['name_value']
                    # crt.sh devuelve strings multi-linea a veces
                    for sub in name_value.split('\n'):
                        if "*" not in sub: # Ignorar wildcards
                            subs.add(sub)
                
                self.log(f" -> Se encontraron {len(subs)} subdominios únicos en registros históricos.", "success")
                count = 0
                for s in subs:
                    if count < 15: # Limitar output visual
                        self.log(f"    {s}")
                    count += 1
                if len(subs) > 15:
                    self.log(f"    ... y {len(subs)-15} más.")
            else:
                self.log(f" [-] Error API crt.sh: {resp.status_code}", "error")
        except Exception as e:
            self.log(f" [-] Excepción conectando a crt.sh: {e}", "error")

    def check_robots(self, target):
        self.log(f"\n[*] Buscando Fugas en robots.txt: {target}", "header")
        if not target.startswith("http"):
            target = f"http://{target}" # Default to HTTP
        
        try:
            resp = requests.get(f"{target}/robots.txt", timeout=5, verify=False)
            if resp.status_code == 200:
                self.log(" -> [!] robots.txt ENCONTRADO:", "alert")
                lines = resp.text.split('\n')
                for line in lines:
                    if "Disallow" in line or "Allow" in line:
                        self.log(f"    {line.strip()}")
            else:
                self.log(f" -> Sin robots.txt (Status: {resp.status_code})")
        except Exception as e:
            self.log(f" [-] Error HTTP: {e}", "error")

    # --- Lógica de Sistema (Infra) ---
    def run_sys_cmd(self, cmd, desc):
        if self.stop_requested: return
        self.log(f"\n[*] Ejecutando: {desc}", "header")
        self.log(f"CMD > {' '.join(cmd)}")
        
        try:
            startupinfo = None
            if platform.system() == "Windows":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            self.current_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, startupinfo=startupinfo)
            while True:
                line = self.current_process.stdout.readline()
                if not line and self.current_process.poll() is not None: break
                if line: self.log(line.strip())
                if self.stop_requested: 
                    self.current_process.kill()
                    break
        except Exception as e:
            self.log(f"Error: {e}", "error")

    def execution_logic(self):
        target = self.target_entry.get().strip()
        if not target: return
        
        self.stop_requested = False

        # --- FASE 1: INFRAESTRUCTURA ---
        if self.chk_nslookup.get():
            self.run_sys_cmd(["nslookup", target], "DNS Lookup")
        
        if self.chk_nmap.get() and not self.stop_requested:
            host = target.replace("http://", "").replace("https://", "").split("/")[0]
            self.run_sys_cmd(["nmap", "-F", "-Pn", host], "Nmap Fast Scan")
            
        if self.chk_traceroute.get() and not self.stop_requested:
            host = target.replace("http://", "").replace("https://", "").split("/")[0]
            cmd = "tracert" if platform.system() == "Windows" else "traceroute"
            self.run_sys_cmd([cmd, "-d", host], "Traceroute (Fast)")

        # --- FASE 2: OSINT / WEB ---
        if self.chk_ssl.get() and not self.stop_requested:
            self.scan_ssl_sans(target)

        if self.chk_subs.get() and not self.stop_requested:
            self.scan_subdomains_crt(target)

        if self.chk_robots.get() and not self.stop_requested:
            self.scan_robots(target)

        self.log("\n[--- AUDITORÍA FINALIZADA ---]", "success")

    def start_full_scan(self):
        threading.Thread(target=self.execution_logic, daemon=True).start()

    # Wrapper por si el método se llama diferente en la lógica
    def scan_robots(self, target):
        self.check_robots(target)

if __name__ == "__main__":
    # Ignorar warnings de SSL verify=False
    requests.packages.urllib3.disable_warnings()
    root = tk.Tk()
    app = NetReconOSINT(root)
    root.mainloop()