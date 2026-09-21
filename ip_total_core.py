from __future__ import annotations

import html
import ipaddress
import json
import locale
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit, urlunsplit

import requests

try:
    import dns.resolver
except ImportError:  # pragma: no cover - degradacion controlada
    dns = None

try:
    import tldextract
except ImportError:  # pragma: no cover - degradacion controlada
    tldextract = None

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:  # pragma: no cover - degradacion controlada
    x509 = None


APP_NAME = "IP Total"
APP_VERSION = "1.0.0"
USER_AGENT = f"{APP_NAME}/{APP_VERSION} (Network Audit)"
DEFAULT_REPORT_DIR = Path(__file__).resolve().parent / "audit_reports"

LogCallback = Callable[[str, str], None]
ProgressCallback = Callable[[int, str], None]


class ScanCancelled(RuntimeError):
    pass


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(item) for item in value]
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def display_value(value: Any) -> str:
    if value in (None, "", [], {}):
        return "No disponible"
    if isinstance(value, (list, tuple, set)):
        return ", ".join(display_value(item) for item in value)
    if isinstance(value, dict):
        return json.dumps(json_safe(value), ensure_ascii=False, indent=2)
    return str(value)


def safe_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._")
    return cleaned[:80] or "objetivo"


def format_url(scheme: str, host: str, port: int | None = None, path: str = "/") -> str:
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = (scheme == "http" and port in (None, 80)) or (scheme == "https" and port in (None, 443))
    netloc = rendered_host if default else f"{rendered_host}:{port}"
    return urlunsplit((scheme, netloc, path or "/", "", ""))


def _rdap_vcard(entity: dict[str, Any]) -> dict[str, Any]:
    data: dict[str, Any] = {
        "handle": entity.get("handle"),
        "roles": entity.get("roles", []),
    }
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list):
        for row in vcard[1]:
            if not isinstance(row, list) or len(row) < 4:
                continue
            name, value = str(row[0]), row[3]
            if name in {"fn", "org", "email", "tel", "adr"}:
                data.setdefault(name, []).append(value)
    return {key: value for key, value in data.items() if value not in (None, "", [])}


def summarize_rdap(payload: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "handle",
        "ldhName",
        "unicodeName",
        "name",
        "type",
        "country",
        "parentHandle",
        "startAddress",
        "endAddress",
        "ipVersion",
        "port43",
        "status",
    )
    summary = {key: payload.get(key) for key in keys if payload.get(key) not in (None, "", [])}
    events = []
    for event in payload.get("events", []):
        if isinstance(event, dict):
            events.append({
                "accion": event.get("eventAction"),
                "fecha": event.get("eventDate"),
            })
    if events:
        summary["eventos"] = events
    nameservers = []
    for item in payload.get("nameservers", []):
        if isinstance(item, dict) and item.get("ldhName"):
            nameservers.append(item["ldhName"])
    if nameservers:
        summary["nameservers"] = sorted(set(nameservers))
    entities = [_rdap_vcard(entity) for entity in payload.get("entities", []) if isinstance(entity, dict)]
    if entities:
        summary["entidades"] = entities
    remarks = []
    for remark in payload.get("remarks", []):
        if isinstance(remark, dict):
            title = remark.get("title")
            description = remark.get("description", [])
            remarks.append({"titulo": title, "detalle": description})
    if remarks:
        summary["observaciones"] = remarks
    notices = []
    for notice in payload.get("notices", []):
        if isinstance(notice, dict) and notice.get("title"):
            notices.append(notice.get("title"))
    if notices:
        summary["avisos"] = notices
    return summary


class TotalReconEngine:
    """Motor de reconocimiento para IP, dominio o URL.

    Todas las llamadas externas tienen timeout y los procesos se invocan sin shell.
    Los callbacks permiten reutilizar el motor tanto desde GUI como desde CLI.
    """

    PROFILE_MAP = {
        "rapido": {
            "label": "Rápido (Top 100)",
            "ports": ["--top-ports", "100"],
            "timeout": "12m",
            "version": "--version-light",
        },
        "equilibrado": {
            "label": "Equilibrado (Top 1000)",
            "ports": ["--top-ports", "1000"],
            "timeout": "30m",
            "version": "--version-light",
        },
        "completo": {
            "label": "Completo (1-65535)",
            "ports": ["-p-"],
            "timeout": "75m",
            "version": "--version-all",
        },
    }

    TLS_PORTS = {443, 465, 636, 853, 989, 990, 992, 993, 994, 995, 8443, 9443, 10443}
    HTTP_PORTS = {80, 81, 3000, 5000, 7001, 8000, 8008, 8080, 8081, 8088, 8888, 9000}

    def __init__(
        self,
        log_callback: LogCallback | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        self.log_callback = log_callback or (lambda _message, _level="info": None)
        self.progress_callback = progress_callback or (lambda _value, _message: None)
        self.stop_event = threading.Event()
        self.current_process: subprocess.Popen[str] | None = None
        self.nmap_path = shutil.which("nmap")

    def log(self, message: str, level: str = "info") -> None:
        self.log_callback(message, level)

    def progress(self, value: int, message: str) -> None:
        self.progress_callback(max(0, min(100, value)), message)

    def check_cancelled(self) -> None:
        if self.stop_event.is_set():
            raise ScanCancelled("Análisis detenido por el usuario")

    def stop(self) -> None:
        self.stop_event.set()
        process = self.current_process
        if process and process.poll() is None:
            try:
                process.terminate()
            except OSError:
                pass

    @staticmethod
    def profile_key(profile: str) -> str:
        lowered = profile.lower()
        if "completo" in lowered:
            return "completo"
        if "rápido" in lowered or "rapido" in lowered:
            return "rapido"
        return "equilibrado"

    @staticmethod
    def normalize_target(raw_target: str) -> dict[str, Any]:
        raw = raw_target.strip()
        if not raw:
            raise ValueError("Ingrese una IP, dominio o URL")
        if any(char.isspace() for char in raw):
            raise ValueError("El objetivo no puede contener espacios")

        explicit_url = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw))
        parsed = urlsplit(raw if explicit_url else f"//{raw}", scheme="http")
        if explicit_url and parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Solo se admiten URL http:// o https://")

        host = parsed.hostname
        if not host:
            raise ValueError("No se pudo extraer un host válido")
        host = host.rstrip(".")
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("El nombre de host no es válido") from exc

        try:
            ip_obj = ipaddress.ip_address(ascii_host)
        except ValueError:
            ip_obj = None
            if len(ascii_host) > 253 or not re.fullmatch(r"(?=.{1,253}$)[A-Za-z0-9_.-]+", ascii_host):
                raise ValueError("El dominio o nombre de host no es válido")
            labels = ascii_host.split(".")
            if any(not label or len(label) > 63 or label.startswith("-") or label.endswith("-") for label in labels):
                raise ValueError("El dominio o nombre de host no es válido")

        if explicit_url:
            scheme = parsed.scheme.lower()
            path = parsed.path or "/"
            port = parsed.port
            input_url = urlunsplit((scheme, parsed.netloc, path, parsed.query, ""))
            target_type = "URL"
        else:
            scheme = None
            path = "/"
            port = parsed.port
            input_url = None
            target_type = "IP" if ip_obj else "Dominio/host"

        return {
            "entrada": raw,
            "tipo": target_type,
            "host": str(ip_obj) if ip_obj else ascii_host.lower(),
            "es_ip": ip_obj is not None,
            "version_ip": ip_obj.version if ip_obj else None,
            "es_privada": bool(ip_obj and not ip_obj.is_global),
            "url_original": input_url,
            "esquema": scheme,
            "puerto_explicito": port,
            "ruta": path,
        }

    @staticmethod
    def registrable_domain(host: str) -> str | None:
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        if tldextract is not None:
            # Se usa el snapshot incluido por la libreria; no hace una descarga oculta.
            extracted = tldextract.TLDExtract(suffix_list_urls=())(host)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}".lower()
        parts = host.lower().split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return None

    def resolve_target(self, target: dict[str, Any]) -> dict[str, Any]:
        host = target["host"]
        addresses: list[dict[str, Any]] = []
        if target["es_ip"]:
            ip_obj = ipaddress.ip_address(host)
            addresses.append({
                "ip": host,
                "familia": f"IPv{ip_obj.version}",
                "publica": ip_obj.is_global,
                "privada": ip_obj.is_private,
                "loopback": ip_obj.is_loopback,
                "reservada": ip_obj.is_reserved,
            })
        else:
            seen: set[str] = set()
            for family, _socktype, _proto, _canonname, sockaddr in socket.getaddrinfo(host, None):
                ip = sockaddr[0]
                if ip in seen:
                    continue
                seen.add(ip)
                ip_obj = ipaddress.ip_address(ip)
                addresses.append({
                    "ip": ip,
                    "familia": "IPv6" if family == socket.AF_INET6 else "IPv4",
                    "publica": ip_obj.is_global,
                    "privada": ip_obj.is_private,
                    "loopback": ip_obj.is_loopback,
                    "reservada": ip_obj.is_reserved,
                })
        if not addresses:
            raise RuntimeError("El objetivo no resolvió ninguna dirección IP")

        reverse: dict[str, str] = {}
        for item in addresses:
            try:
                reverse[item["ip"]] = socket.gethostbyaddr(item["ip"])[0].rstrip(".")
            except (socket.herror, socket.gaierror, OSError):
                reverse[item["ip"]] = "No disponible"
        return {"direcciones": addresses, "dns_inverso": reverse}

    def dns_records(self, hosts: list[str]) -> dict[str, Any]:
        records: dict[str, Any] = {}
        if dns is None:
            return {"aviso": "dnspython no está instalado"}
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = 3.0
        resolver.lifetime = 6.0
        for host in dict.fromkeys(item for item in hosts if item):
            host_records: dict[str, list[str]] = {}
            for record_type in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"):
                self.check_cancelled()
                try:
                    answers = resolver.resolve(host, record_type, lifetime=6.0, raise_on_no_answer=False)
                    values = sorted({answer.to_text().strip() for answer in answers}) if answers.rrset else []
                    if values:
                        host_records[record_type] = values
                except Exception:
                    continue
            records[host] = host_records
        return records

    def ping_fingerprint(self, ip: str) -> dict[str, Any]:
        command = ["ping", "-n" if platform.system() == "Windows" else "-c", "1"]
        if platform.system() == "Windows":
            command += ["-w", "1800", ip]
        else:
            command += ["-W", "2", ip]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding=locale.getpreferredencoding(False),
                errors="replace",
                timeout=5,
                check=False,
                creationflags=subprocess.CREATE_NO_WINDOW if platform.system() == "Windows" else 0,
            )
            output = (completed.stdout or "") + (completed.stderr or "")
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"estado": "No disponible", "error": str(exc)}

        ttl_match = re.search(r"ttl[=:\s]+(\d+)", output, re.IGNORECASE)
        time_match = re.search(r"(?:tiempo|time)[=<]\s*([0-9.]+)\s*ms", output, re.IGNORECASE)
        if not ttl_match:
            return {
                "estado": "Sin respuesta ICMP",
                "codigo_salida": completed.returncode,
                "salida": output.strip()[-1200:],
            }
        ttl = int(ttl_match.group(1))
        if ttl <= 64:
            base, guess = 64, "Linux/Unix/IoT (estimación TTL)"
        elif ttl <= 128:
            base, guess = 128, "Windows (estimación TTL)"
        else:
            base, guess = 255, "Dispositivo de red/Unix (estimación TTL)"
        return {
            "estado": "Responde",
            "ttl": ttl,
            "saltos_estimados": max(0, base - ttl),
            "sistema_estimado": guess,
            "latencia_ms": float(time_match.group(1)) if time_match else None,
        }

    def _run_process(self, command: list[str]) -> tuple[int, str]:
        startupinfo = None
        creationflags = 0
        if platform.system() == "Windows":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW
        self.log(f"CMD > {subprocess.list2cmdline(command)}", "command")
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding=locale.getpreferredencoding(False),
            errors="replace",
            startupinfo=startupinfo,
            creationflags=creationflags,
        )
        self.current_process = process
        lines: list[str] = []
        assert process.stdout is not None
        try:
            for line in iter(process.stdout.readline, ""):
                clean = line.rstrip()
                if clean:
                    lines.append(clean)
                    self.log(clean, "nmap")
                if self.stop_event.is_set() and process.poll() is None:
                    process.terminate()
                    break
            return_code = process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait()
        finally:
            self.current_process = None
        return return_code, "\n".join(lines)

    def nmap_scan(self, host: str, ip: str, profile: str) -> dict[str, Any]:
        if not self.nmap_path:
            return {
                "disponible": False,
                "error": "Nmap no está instalado o no se encuentra en PATH",
                "puertos": self.socket_fallback_scan(ip),
            }
        key = self.profile_key(profile)
        spec = self.PROFILE_MAP[key]
        descriptor, xml_path = tempfile.mkstemp(prefix="ip_total_", suffix=".xml")
        os.close(descriptor)
        command = [
            self.nmap_path,
            "-Pn",
            "-n",
            "-T4",
            "--reason",
            "--stats-every",
            "5s",
            "-sV",
            spec["version"],
            "-O",
            "--osscan-guess",
            "--script",
            "banner,http-title,http-headers,ssl-cert,ssl-enum-ciphers",
            "--script-timeout",
            "20s",
            "--host-timeout",
            spec["timeout"],
            *spec["ports"],
            "-oX",
            xml_path,
        ]
        if ipaddress.ip_address(ip).version == 6:
            command.append("-6")
        command.append(host)
        output = ""
        return_code = -1
        try:
            return_code, output = self._run_process(command)
            self.check_cancelled()
            xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            privilege_error = re.search(
                r"requires root privileges|failed to open device|raw socket|dnet:.*failed",
                output,
                re.IGNORECASE,
            )
            if (return_code != 0 or "<host" not in xml_text) and privilege_error:
                self.log("Nmap no pudo ejecutar OS fingerprinting; reintento seguro sin -O.", "warning")
                command = [item for item in command if item not in {"-O", "--osscan-guess"}]
                return_code, output_retry = self._run_process(command)
                output = f"{output}\n{output_retry}".strip()
                self.check_cancelled()
                xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            parsed = self.parse_nmap_xml(xml_text)
            parsed.update({
                "disponible": True,
                "perfil": spec["label"],
                "codigo_salida": return_code,
                "comando": subprocess.list2cmdline(command),
                "salida": output[-15000:],
            })
            if return_code != 0 and not parsed.get("puertos"):
                parsed["error"] = "Nmap terminó con error; revise la consola incluida"
            return parsed
        except ET.ParseError as exc:
            return {
                "disponible": True,
                "perfil": spec["label"],
                "codigo_salida": return_code,
                "comando": subprocess.list2cmdline(command),
                "salida": output[-15000:],
                "error": f"Nmap no produjo XML válido: {exc}",
                "puertos": [],
            }
        finally:
            try:
                Path(xml_path).unlink(missing_ok=True)
            except OSError:
                pass

    @staticmethod
    def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
        root = ET.fromstring(xml_text)
        host_node = root.find("host")
        result: dict[str, Any] = {
            "estado_host": "desconocido",
            "hostnames": [],
            "puertos": [],
            "resumen_puertos": [],
            "os_matches": [],
            "uptime": {},
            "distancia": None,
            "traza_nmap": [],
        }
        if host_node is None:
            return result
        status = host_node.find("status")
        if status is not None:
            result["estado_host"] = status.get("state", "desconocido")
            result["razon_estado"] = status.get("reason")
        result["hostnames"] = sorted({
            node.get("name", "")
            for node in host_node.findall("./hostnames/hostname")
            if node.get("name")
        })
        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            service: dict[str, Any] = {}
            if service_node is not None:
                for key in ("name", "product", "version", "extrainfo", "tunnel", "method", "conf", "ostype", "devicetype"):
                    if service_node.get(key):
                        service[key] = service_node.get(key)
                cpes = [node.text for node in service_node.findall("cpe") if node.text]
                if cpes:
                    service["cpes"] = cpes
            scripts = []
            for script in port_node.findall("script"):
                scripts.append({"id": script.get("id"), "salida": script.get("output", "")})
            result["puertos"].append({
                "puerto": int(port_node.get("portid", "0")),
                "protocolo": port_node.get("protocol", "tcp"),
                "estado": state,
                "razon": state_node.get("reason") if state_node is not None else None,
                "servicio": service,
                "scripts": scripts,
            })
        for extra in host_node.findall("./ports/extraports"):
            reasons = [
                {"razon": node.get("reason"), "cantidad": int(node.get("count", "0"))}
                for node in extra.findall("extrareasons")
            ]
            result["resumen_puertos"].append({
                "estado": extra.get("state"),
                "cantidad": int(extra.get("count", "0")),
                "razones": reasons,
            })
        for os_match in host_node.findall("./os/osmatch"):
            classes = []
            for os_class in os_match.findall("osclass"):
                classes.append({
                    "tipo": os_class.get("type"),
                    "fabricante": os_class.get("vendor"),
                    "familia": os_class.get("osfamily"),
                    "generacion": os_class.get("osgen"),
                    "precision": os_class.get("accuracy"),
                    "cpes": [node.text for node in os_class.findall("cpe") if node.text],
                })
            result["os_matches"].append({
                "nombre": os_match.get("name"),
                "precision": int(os_match.get("accuracy", "0")),
                "clases": classes,
            })
        uptime = host_node.find("uptime")
        if uptime is not None:
            result["uptime"] = {"segundos": uptime.get("seconds"), "ultimo_arranque": uptime.get("lastboot")}
        distance = host_node.find("distance")
        if distance is not None:
            result["distancia"] = distance.get("value")
        for hop in host_node.findall("./trace/hop"):
            result["traza_nmap"].append({
                "ttl": hop.get("ttl"),
                "rtt": hop.get("rtt"),
                "ip": hop.get("ipaddr"),
                "host": hop.get("host"),
            })
        return result

    def socket_fallback_scan(self, ip: str) -> list[dict[str, Any]]:
        common = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443]
        found = []
        family = socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET
        for port in common:
            self.check_cancelled()
            try:
                with socket.socket(family, socket.SOCK_STREAM) as sock:
                    sock.settimeout(0.6)
                    if sock.connect_ex((ip, port)) == 0:
                        try:
                            service = socket.getservbyport(port, "tcp")
                        except OSError:
                            service = "desconocido"
                        found.append({
                            "puerto": port,
                            "protocolo": "tcp",
                            "estado": "open",
                            "razon": "connect",
                            "servicio": {"name": service},
                            "scripts": [],
                        })
            except OSError:
                continue
        return found

    def rdap_lookup(self, resource_type: str, value: str) -> dict[str, Any]:
        url = f"https://rdap.org/{resource_type}/{value}"
        try:
            response = requests.get(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
                timeout=(5, 15),
                allow_redirects=True,
            )
            if response.status_code >= 400:
                return {"error": f"RDAP respondió HTTP {response.status_code}", "url": response.url}
            payload = response.json()
            return {
                "fuente": response.url,
                "resumen": summarize_rdap(payload),
                "respuesta_rdap": json_safe(payload),
            }
        except (requests.RequestException, ValueError) as exc:
            if resource_type == "ip":
                try:
                    from ipwhois import IPWhois

                    payload = IPWhois(value).lookup_rdap(depth=1)
                    return {
                        "fuente": "ipwhois/RDAP",
                        "resumen": {
                            "asn": payload.get("asn"),
                            "descripcion_asn": payload.get("asn_description"),
                            "pais_asn": payload.get("asn_country_code"),
                            "red": payload.get("network", {}),
                        },
                        "respuesta_rdap": json_safe(payload),
                    }
                except Exception as fallback_exc:
                    return {"error": f"RDAP no disponible: {exc}; fallback: {fallback_exc}"}
            return {"error": f"RDAP no disponible: {exc}"}

    @staticmethod
    def _whois_query(server: str, query: str, timeout: float = 7.0) -> str:
        chunks: list[bytes] = []
        with socket.create_connection((server, 43), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((query + "\r\n").encode("utf-8"))
            while True:
                try:
                    chunk = sock.recv(8192)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
                if sum(map(len, chunks)) >= 512_000:
                    break
        return b"".join(chunks).decode("utf-8", errors="replace")

    def raw_domain_whois(self, domain: str) -> dict[str, Any]:
        try:
            bootstrap = self._whois_query("whois.iana.org", domain)
            referral_match = re.search(r"^(?:refer|whois):\s*(\S+)", bootstrap, re.IGNORECASE | re.MULTILINE)
            referral = referral_match.group(1).strip() if referral_match else None
            authoritative = self._whois_query(referral, domain) if referral else ""
            return {
                "servidor": referral or "whois.iana.org",
                "respuesta": authoritative or bootstrap,
                "bootstrap_iana": bootstrap if authoritative else None,
            }
        except OSError as exc:
            return {"error": f"WHOIS TCP/43 no disponible: {exc}"}

    def geolocation(self, ip: str) -> dict[str, Any]:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_global:
            return {
                "aplica": False,
                "motivo": "Dirección no pública; no tiene geolocalización/ASN público aplicable",
            }
        try:
            response = requests.get(
                f"https://ipwho.is/{ip}",
                headers={"User-Agent": USER_AGENT},
                timeout=(5, 12),
            )
            payload = response.json()
            if not payload.get("success", True):
                return {"error": payload.get("message", "Servicio de geolocalización sin resultado")}
            connection = payload.get("connection", {})
            timezone_data = payload.get("timezone", {})
            return {
                "fuente": "ipwho.is",
                "continente": payload.get("continent"),
                "pais": payload.get("country"),
                "codigo_pais": payload.get("country_code"),
                "region": payload.get("region"),
                "ciudad": payload.get("city"),
                "latitud": payload.get("latitude"),
                "longitud": payload.get("longitude"),
                "zona_horaria": timezone_data.get("id") if isinstance(timezone_data, dict) else timezone_data,
                "asn": connection.get("asn"),
                "organizacion": connection.get("org"),
                "isp": connection.get("isp"),
                "dominio_red": connection.get("domain"),
            }
        except (requests.RequestException, ValueError) as exc:
            return {"error": f"Geolocalización no disponible: {exc}"}

    def crt_subdomains(self, domain: str) -> dict[str, Any]:
        try:
            response = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                headers={"User-Agent": USER_AGENT},
                timeout=(5, 20),
            )
            if response.status_code >= 400:
                return {"error": f"crt.sh respondió HTTP {response.status_code}", "subdominios": []}
            payload = response.json()
            names: set[str] = set()
            for entry in payload:
                for name in str(entry.get("name_value", "")).splitlines():
                    normalized = name.strip().lower().rstrip(".")
                    if normalized.startswith("*."):
                        normalized = normalized[2:]
                    if normalized == domain or normalized.endswith(f".{domain}"):
                        names.add(normalized)
            ordered = sorted(names)
            limited = len(ordered) > 1000
            return {
                "fuente": response.url,
                "cantidad": len(ordered),
                "limitado": limited,
                "subdominios": ordered[:1000],
            }
        except (requests.RequestException, ValueError) as exc:
            return {"error": f"crt.sh no disponible: {exc}", "subdominios": []}

    def tls_info(self, connect_host: str, port: int, server_name: str | None) -> dict[str, Any]:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((connect_host, port), timeout=6) as raw_socket:
                with context.wrap_socket(raw_socket, server_hostname=server_name) as tls_socket:
                    der = tls_socket.getpeercert(binary_form=True)
                    result: dict[str, Any] = {
                        "host_conexion": connect_host,
                        "sni": server_name,
                        "puerto": port,
                        "version_tls": tls_socket.version(),
                        "cifrado": tls_socket.cipher(),
                        "alpn": tls_socket.selected_alpn_protocol(),
                    }
                    if der:
                        result["sha256"] = __import__("hashlib").sha256(der).hexdigest()
                    if der and x509 is not None:
                        certificate = x509.load_der_x509_certificate(der)
                        result.update({
                            "sujeto": certificate.subject.rfc4514_string(),
                            "emisor": certificate.issuer.rfc4514_string(),
                            "serie": format(certificate.serial_number, "X"),
                            "valido_desde": certificate.not_valid_before_utc.isoformat(),
                            "valido_hasta": certificate.not_valid_after_utc.isoformat(),
                            "firma": certificate.signature_hash_algorithm.name if certificate.signature_hash_algorithm else None,
                        })
                        try:
                            san_ext = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                            result["sans_dns"] = sorted(set(san_ext.value.get_values_for_type(x509.DNSName)))
                            result["sans_ip"] = sorted(str(item) for item in san_ext.value.get_values_for_type(x509.IPAddress))
                        except x509.ExtensionNotFound:
                            result["sans_dns"] = []
                            result["sans_ip"] = []
                        try:
                            common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                            result["common_name"] = common_names[0].value if common_names else None
                        except Exception:
                            pass
                    return result
        except (OSError, ssl.SSLError, ValueError) as exc:
            return {"host_conexion": connect_host, "sni": server_name, "puerto": port, "error": str(exc)}

    @staticmethod
    def detect_technologies(headers: dict[str, str], body: str) -> list[str]:
        detected: set[str] = set()
        server = headers.get("server", "")
        powered = headers.get("x-powered-by", "")
        generator_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
        for value in (server, powered, generator_match.group(1) if generator_match else ""):
            if value:
                detected.add(value.strip())
        patterns = {
            "WordPress": r"wp-content|wp-includes",
            "Drupal": r"Drupal\.settings|sites/(?:default|all)/files",
            "Joomla": r"/media/system/js/|option=com_",
            "Laravel": r"laravel_session",
            "ASP.NET": r"__VIEWSTATE|ASP\.NET",
            "React": r"data-reactroot|__NEXT_DATA__",
            "Vue.js": r"data-v-|__NUXT__",
            "Angular": r"ng-version|<app-root",
            "Cloudflare": r"__cf_bm|cf-ray",
        }
        combined = body[:250_000] + "\n" + "\n".join(f"{key}: {value}" for key, value in headers.items())
        for technology, pattern in patterns.items():
            if re.search(pattern, combined, re.I):
                detected.add(technology)
        cookies = headers.get("set-cookie", "")
        if "PHPSESSID" in cookies:
            detected.add("PHP")
        if "JSESSIONID" in cookies:
            detected.add("Java/JSP")
        return sorted(detected)

    def probe_url(self, url: str) -> dict[str, Any]:
        try:
            with requests.get(
                url,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
                timeout=(5, 10),
                verify=False,
                allow_redirects=True,
                stream=True,
            ) as response:
                chunks: list[bytes] = []
                size = 0
                for chunk in response.iter_content(chunk_size=16384):
                    if not chunk:
                        continue
                    chunks.append(chunk)
                    size += len(chunk)
                    if size >= 300_000:
                        break
                raw = b"".join(chunks)
                encoding = response.encoding or "utf-8"
                body = raw.decode(encoding, errors="replace")
                headers = {key.lower(): value for key, value in response.headers.items()}
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                title = html.unescape(re.sub(r"\s+", " ", title_match.group(1))).strip() if title_match else None
                security_names = (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                    "x-content-type-options",
                    "referrer-policy",
                    "permissions-policy",
                )
                return {
                    "url_solicitada": url,
                    "existe": True,
                    "estado_http": response.status_code,
                    "url_final": response.url,
                    "titulo": title,
                    "servidor": response.headers.get("Server"),
                    "tipo_contenido": response.headers.get("Content-Type"),
                    "tecnologias": self.detect_technologies(headers, body),
                    "cabeceras_seguridad": {name: headers.get(name) for name in security_names},
                    "cabeceras": dict(response.headers),
                }
        except requests.RequestException as exc:
            return {"url_solicitada": url, "existe": False, "error": str(exc)}

    def robots_lookup(self, web_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        robots: list[dict[str, Any]] = []
        origins: set[str] = set()
        for item in web_results:
            if not item.get("existe"):
                continue
            parsed = urlsplit(item.get("url_final") or item["url_solicitada"])
            origin = urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))
            if origin in origins:
                continue
            origins.add(origin)
            try:
                response = requests.get(
                    f"{origin}/robots.txt",
                    headers={"User-Agent": USER_AGENT},
                    timeout=(4, 8),
                    verify=False,
                )
                entry: dict[str, Any] = {"url": response.url, "estado_http": response.status_code}
                if response.status_code == 200:
                    interesting = [
                        line.strip()
                        for line in response.text.splitlines()
                        if line.strip().lower().startswith(("allow:", "disallow:", "sitemap:"))
                    ]
                    entry["directivas"] = interesting[:500]
                robots.append(entry)
            except requests.RequestException as exc:
                robots.append({"url": f"{origin}/robots.txt", "error": str(exc)})
        return robots

    def verify_domains_for_ip(self, domains: list[str], ip: str) -> list[str]:
        verified = []
        for domain in dict.fromkeys(item.lower().lstrip("*.") for item in domains if item):
            if len(verified) >= 20:
                break
            try:
                resolved = {entry[4][0] for entry in socket.getaddrinfo(domain, None)}
                if ip in resolved:
                    verified.append(domain)
            except socket.gaierror:
                continue
        return verified

    def web_and_tls(
        self,
        target: dict[str, Any],
        resolution: dict[str, Any],
        ports: list[dict[str, Any]],
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
        primary_ip = resolution["direcciones"][0]["ip"]
        original_host = target["host"]
        ptr_names = [
            name for name in resolution["dns_inverso"].values()
            if name and name != "No disponible"
        ]
        sni = None if target["es_ip"] else original_host
        if not sni and ptr_names:
            sni = ptr_names[0]

        open_ports = [item for item in ports if item.get("estado") == "open"]
        tls_ports: set[int] = set()
        web_port_schemes: set[tuple[int, str]] = set()
        for item in open_ports:
            port = int(item.get("puerto", 0))
            service = item.get("servicio", {})
            name = str(service.get("name", "")).lower()
            tunnel = str(service.get("tunnel", "")).lower()
            if port in self.TLS_PORTS or tunnel == "ssl" or "https" in name:
                tls_ports.add(port)
                if "http" in name or port in self.TLS_PORTS:
                    web_port_schemes.add((port, "https"))
            elif port in self.HTTP_PORTS or "http" in name:
                web_port_schemes.add((port, "http"))
        if not open_ports:
            tls_ports.add(target.get("puerto_explicito") or 443)
            web_port_schemes.update({(80, "http"), (443, "https")})

        tls_results = []
        discovered_domains = list(ptr_names)
        for port in sorted(tls_ports)[:12]:
            self.check_cancelled()
            info = self.tls_info(primary_ip, port, sni)
            tls_results.append(info)
            discovered_domains.extend(info.get("sans_dns", []))
            if info.get("common_name"):
                discovered_domains.append(info["common_name"])
        verified_domains = self.verify_domains_for_ip(discovered_domains, primary_ip)

        candidate_urls: list[str] = []
        if target.get("url_original"):
            candidate_urls.append(target["url_original"])
        preferred_hosts = [original_host]
        if target["es_ip"]:
            preferred_hosts.extend(verified_domains[:10])
        for candidate_host in dict.fromkeys(preferred_hosts):
            for port, scheme in sorted(web_port_schemes):
                candidate_urls.append(format_url(scheme, candidate_host, port))
        if not web_port_schemes:
            for candidate_host in dict.fromkeys(preferred_hosts):
                candidate_urls.extend([format_url("https", candidate_host, 443), format_url("http", candidate_host, 80)])

        web_results = []
        for url in list(dict.fromkeys(candidate_urls))[:30]:
            self.check_cancelled()
            self.log(f"Verificando URL: {url}", "info")
            web_results.append(self.probe_url(url))
        return web_results, tls_results, verified_domains

    def traceroute(self, ip: str) -> dict[str, Any]:
        if platform.system() == "Windows":
            command = ["tracert", "-d", "-h", "18", "-w", "700", ip]
        else:
            executable = shutil.which("traceroute")
            if not executable:
                return {"error": "traceroute no está instalado"}
            command = [executable, "-n", "-m", "18", "-w", "1", ip]
        try:
            return_code, output = self._run_process(command)
            return {
                "comando": subprocess.list2cmdline(command),
                "codigo_salida": return_code,
                "salida": output,
            }
        except OSError as exc:
            return {"error": str(exc), "comando": subprocess.list2cmdline(command)}

    def analyze(self, raw_target: str, profile: str = "equilibrado", include_traceroute: bool = True) -> dict[str, Any]:
        self.stop_event.clear()
        started = time.monotonic()
        result: dict[str, Any] = {
            "meta": {
                "aplicacion": APP_NAME,
                "version": APP_VERSION,
                "inicio": now_iso(),
                "perfil": self.PROFILE_MAP[self.profile_key(profile)]["label"],
            },
            "errores": [],
        }
        try:
            self.progress(2, "Normalizando objetivo")
            target = self.normalize_target(raw_target)
            result["objetivo"] = target
            self.log(f"Objetivo detectado: {target['tipo']} | {target['host']}", "success")

            self.check_cancelled()
            self.progress(8, "Resolviendo IP y DNS inverso")
            resolution = self.resolve_target(target)
            result["resolucion"] = resolution
            primary_ip = next(
                (item["ip"] for item in resolution["direcciones"] if item["familia"] == "IPv4"),
                resolution["direcciones"][0]["ip"],
            )
            result["resolucion"]["ip_primaria"] = primary_ip
            self.log(f"IP primaria: {primary_ip}", "success")
            reverse_names = [name for name in resolution["dns_inverso"].values() if name != "No disponible"]
            if reverse_names:
                self.log(f"DNS inverso: {', '.join(reverse_names)}", "success")

            candidate_domain = self.registrable_domain(target["host"])
            if not candidate_domain and reverse_names:
                candidate_domain = self.registrable_domain(reverse_names[0])
            result["objetivo"]["dominio_registrable"] = candidate_domain

            self.check_cancelled()
            self.progress(15, "Consultando registros DNS")
            dns_hosts = [] if target["es_ip"] else [target["host"]]
            if candidate_domain and candidate_domain not in dns_hosts:
                dns_hosts.append(candidate_domain)
            result["dns"] = self.dns_records(dns_hosts)

            self.check_cancelled()
            self.progress(22, "Estimando sistema por ICMP/TTL")
            result["icmp_ttl"] = self.ping_fingerprint(primary_ip)

            self.check_cancelled()
            self.progress(28, "Consultando WHOIS/RDAP y ASN")
            primary_ip_obj = ipaddress.ip_address(primary_ip)
            if primary_ip_obj.is_global:
                result["whois_ip"] = self.rdap_lookup("ip", primary_ip)
            else:
                result["whois_ip"] = {"aplica": False, "motivo": "IP no pública"}
            result["geolocalizacion"] = self.geolocation(primary_ip)
            if candidate_domain:
                result["whois_dominio"] = self.rdap_lookup("domain", candidate_domain)
                result["whois_dominio_raw"] = self.raw_domain_whois(candidate_domain)
            else:
                result["whois_dominio"] = {"aplica": False, "motivo": "No se identificó dominio"}
                result["whois_dominio_raw"] = {"aplica": False}

            self.check_cancelled()
            self.progress(38, "Escaneando puertos, servicios y sistema operativo")
            nmap_target = target["host"] if not target["es_ip"] else primary_ip
            result["nmap"] = self.nmap_scan(nmap_target, primary_ip, profile)
            ports = result["nmap"].get("puertos", [])
            result["puertos"] = ports
            open_count = sum(1 for item in ports if item.get("estado") == "open")
            self.log(f"Puertos abiertos detectados: {open_count}", "success" if open_count else "warning")

            self.check_cancelled()
            self.progress(68, "Verificando web, URL y certificados TLS")
            web, tls, verified_domains = self.web_and_tls(target, resolution, ports)
            result["web"] = web
            result["tls"] = tls
            result["dominios_verificados_para_ip"] = verified_domains
            result["robots"] = self.robots_lookup(web)

            if not candidate_domain and verified_domains:
                candidate_domain = self.registrable_domain(verified_domains[0])
                result["objetivo"]["dominio_registrable"] = candidate_domain
                if candidate_domain:
                    result["whois_dominio"] = self.rdap_lookup("domain", candidate_domain)
                    result["whois_dominio_raw"] = self.raw_domain_whois(candidate_domain)

            self.check_cancelled()
            self.progress(82, "Consultando transparencia de certificados")
            result["crt_sh"] = self.crt_subdomains(candidate_domain) if candidate_domain else {
                "aplica": False,
                "subdominios": [],
            }

            self.check_cancelled()
            if include_traceroute:
                self.progress(90, "Trazando ruta de red")
                result["traceroute"] = self.traceroute(primary_ip)
            else:
                result["traceroute"] = {"omitido": True}

            self.check_cancelled()
            result["sistema_operativo"] = self.select_os(result)
            result["urls_verificadas"] = [item for item in web if item.get("existe")]
            result["meta"]["estado"] = "completado"
            self.progress(98, "Generando evidencia")
        except ScanCancelled as exc:
            result["meta"]["estado"] = "detenido"
            result["errores"].append(str(exc))
            self.log(str(exc), "warning")
        except Exception as exc:
            result["meta"]["estado"] = "error"
            result["errores"].append(f"{type(exc).__name__}: {exc}")
            self.log(f"Error: {type(exc).__name__}: {exc}", "error")
        finally:
            result["meta"]["fin"] = now_iso()
            result["meta"]["duracion_segundos"] = round(time.monotonic() - started, 2)
            self.progress(100, "Análisis finalizado")
        return json_safe(result)

    @staticmethod
    def select_os(result: dict[str, Any]) -> dict[str, Any]:
        matches = result.get("nmap", {}).get("os_matches", [])
        if matches:
            best = sorted(matches, key=lambda item: item.get("precision", 0), reverse=True)[0]
            return {
                "nombre": best.get("nombre"),
                "precision": best.get("precision"),
                "metodo": "Nmap OS fingerprint",
                "alternativas": matches[:8],
            }
        service_os = []
        for port in result.get("puertos", []):
            ostype = port.get("servicio", {}).get("ostype")
            if ostype:
                service_os.append(ostype)
        if service_os:
            return {
                "nombre": ", ".join(sorted(set(service_os))),
                "precision": "indirecta",
                "metodo": "Banners de servicios Nmap",
            }
        ttl = result.get("icmp_ttl", {})
        if ttl.get("sistema_estimado"):
            return {
                "nombre": ttl["sistema_estimado"],
                "precision": "heurística",
                "metodo": "TTL ICMP",
            }
        return {
            "nombre": "No concluyente",
            "precision": "sin evidencia suficiente",
            "metodo": "Nmap/TTL sin fingerprint",
        }


def _h(value: Any) -> str:
    return html.escape(display_value(value), quote=True)


def _pretty(value: Any) -> str:
    return html.escape(json.dumps(json_safe(value), ensure_ascii=False, indent=2), quote=False)


def build_html_report(result: dict[str, Any]) -> str:
    target = result.get("objetivo", {})
    resolution = result.get("resolucion", {})
    meta = result.get("meta", {})
    os_data = result.get("sistema_operativo", {})
    geo = result.get("geolocalizacion", {})
    verified_urls = result.get("urls_verificadas", [])
    ports = result.get("puertos", [])
    open_ports = [item for item in ports if item.get("estado") == "open"]

    url_rows = "".join(
        "<tr>"
        f"<td><a href='{_h(item.get('url_final') or item.get('url_solicitada'))}'>{_h(item.get('url_final') or item.get('url_solicitada'))}</a></td>"
        f"<td>{_h(item.get('estado_http'))}</td>"
        f"<td>{_h(item.get('titulo'))}</td>"
        f"<td>{_h(item.get('servidor'))}</td>"
        f"<td>{_h(item.get('tecnologias'))}</td>"
        "</tr>"
        for item in verified_urls
    ) or "<tr><td colspan='5'>No se verificó un servicio web accesible en los puertos examinados.</td></tr>"

    port_rows = "".join(
        "<tr>"
        f"<td>{_h(item.get('puerto'))}/{_h(item.get('protocolo'))}</td>"
        f"<td><span class='badge {'open' if item.get('estado') == 'open' else 'other'}'>{_h(item.get('estado'))}</span></td>"
        f"<td>{_h(item.get('servicio', {}).get('name'))}</td>"
        f"<td>{_h(' '.join(str(item.get('servicio', {}).get(k, '')) for k in ('product', 'version', 'extrainfo')).strip())}</td>"
        f"<td>{_h(item.get('razon'))}</td>"
        "</tr>"
        for item in ports
    ) or "<tr><td colspan='5'>Sin puertos individuales reportados.</td></tr>"

    address_rows = "".join(
        f"<tr><td>{_h(item.get('ip'))}</td><td>{_h(item.get('familia'))}</td><td>{_h(item.get('publica'))}</td>"
        f"<td>{_h(resolution.get('dns_inverso', {}).get(item.get('ip')))}</td></tr>"
        for item in resolution.get("direcciones", [])
    )

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>IP Total - {_h(target.get('entrada'))}</title>
<style>
:root{{--bg:#08111f;--panel:#111d30;--panel2:#17263d;--text:#e8f0fa;--muted:#9db0c8;--cyan:#20c7e9;--green:#34d399;--amber:#fbbf24;--border:#263a55}}
*{{box-sizing:border-box}}body{{margin:0;background:linear-gradient(145deg,#07101c,#0c1930);color:var(--text);font:14px/1.5 "Segoe UI",Arial,sans-serif}}
.wrap{{max-width:1400px;margin:auto;padding:28px}}header{{display:flex;justify-content:space-between;align-items:end;border-bottom:1px solid var(--border);padding-bottom:20px;margin-bottom:22px}}
h1{{margin:0;font-size:30px}}h2{{font-size:18px;color:var(--cyan);margin:0 0 14px}}h3{{font-size:15px;color:#cfe2f7}}
.muted{{color:var(--muted)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px;margin-bottom:18px}}
.card,.section{{background:rgba(17,29,48,.96);border:1px solid var(--border);border-radius:12px;padding:18px;box-shadow:0 12px 28px #0004}}.section{{margin:16px 0}}
.metric{{font-size:22px;font-weight:700;color:white;word-break:break-word}}table{{width:100%;border-collapse:collapse}}th,td{{text-align:left;padding:10px;border-bottom:1px solid var(--border);vertical-align:top}}th{{color:var(--cyan);background:#0d1829}}
.badge{{display:inline-block;padding:2px 9px;border-radius:99px;font-weight:700}}.open{{background:#123f35;color:#69efc1}}.other{{background:#3b3014;color:#ffd970}}
pre{{white-space:pre-wrap;word-break:break-word;background:#08111f;border:1px solid var(--border);border-radius:8px;padding:14px;max-height:600px;overflow:auto;color:#cfe2f7}}
a{{color:#69dcf1}}details{{margin:10px 0}}summary{{cursor:pointer;color:#d8e8f9;font-weight:600}}footer{{padding:24px 0;color:var(--muted);text-align:center}}
@media print{{body{{background:white;color:#111}}.card,.section{{box-shadow:none;background:white;color:#111}}pre{{color:#111;background:#f7f7f7}}}}
</style>
</head>
<body><div class="wrap">
<header><div><div class="muted">EVIDENCIA DE RECONOCIMIENTO</div><h1>IP Total</h1></div><div class="muted">{_h(meta.get('inicio'))}<br>{_h(meta.get('perfil'))}</div></header>
<div class="grid">
  <div class="card"><div class="muted">Objetivo</div><div class="metric">{_h(target.get('entrada'))}</div><div>{_h(target.get('tipo'))}</div></div>
  <div class="card"><div class="muted">IP primaria</div><div class="metric">{_h(resolution.get('ip_primaria'))}</div><div>{_h(target.get('dominio_registrable'))}</div></div>
  <div class="card"><div class="muted">Sistema operativo</div><div class="metric">{_h(os_data.get('nombre'))}</div><div>{_h(os_data.get('metodo'))} · {_h(os_data.get('precision'))}</div></div>
  <div class="card"><div class="muted">Exposición observada</div><div class="metric">{len(open_ports)} puertos</div><div>{len(verified_urls)} URL verificadas</div></div>
</div>
<section class="section"><h2>Resolución IP ↔ nombre</h2><table><thead><tr><th>IP</th><th>Familia</th><th>Pública</th><th>DNS inverso / PTR</th></tr></thead><tbody>{address_rows}</tbody></table></section>
<section class="section"><h2>URLs web verificadas</h2><table><thead><tr><th>URL final</th><th>HTTP</th><th>Título</th><th>Servidor</th><th>Tecnologías</th></tr></thead><tbody>{url_rows}</tbody></table></section>
<section class="section"><h2>Puertos y servicios</h2><table><thead><tr><th>Puerto</th><th>Estado</th><th>Servicio</th><th>Producto / versión</th><th>Evidencia</th></tr></thead><tbody>{port_rows}</tbody></table>
<details><summary>Resumen de puertos no listados</summary><pre>{_pretty(result.get('nmap', {}).get('resumen_puertos', []))}</pre></details></section>
<section class="section"><h2>Sistema operativo y red</h2><div class="grid"><div><h3>Fingerprint</h3><pre>{_pretty(os_data)}</pre></div><div><h3>ICMP / TTL</h3><pre>{_pretty(result.get('icmp_ttl', {}))}</pre></div><div><h3>Geolocalización / ASN</h3><pre>{_pretty(geo)}</pre></div></div></section>
<section class="section"><h2>DNS</h2><pre>{_pretty(result.get('dns', {}))}</pre></section>
<section class="section"><h2>TLS y certificados</h2><pre>{_pretty(result.get('tls', []))}</pre></section>
<section class="section"><h2>WHOIS / RDAP de IP</h2><pre>{_pretty(result.get('whois_ip', {}))}</pre></section>
<section class="section"><h2>WHOIS / RDAP de dominio</h2><pre>{_pretty(result.get('whois_dominio', {}))}</pre><details><summary>WHOIS TCP/43 sin procesar</summary><pre>{_h(result.get('whois_dominio_raw', {}).get('respuesta'))}</pre></details></section>
<section class="section"><h2>OSINT web</h2><h3>Transparencia de certificados / subdominios</h3><pre>{_pretty(result.get('crt_sh', {}))}</pre><h3>robots.txt</h3><pre>{_pretty(result.get('robots', []))}</pre></section>
<section class="section"><h2>Traceroute</h2><pre>{_h(result.get('traceroute', {}).get('salida') or result.get('traceroute', {}))}</pre></section>
<section class="section"><h2>Trazabilidad técnica</h2><details><summary>Comando y salida de Nmap</summary><pre>{_h(result.get('nmap', {}).get('comando'))}\n\n{_h(result.get('nmap', {}).get('salida'))}</pre></details><details><summary>Errores y observaciones</summary><pre>{_pretty(result.get('errores', []))}</pre></details></section>
<footer>Generado localmente por IP Total {APP_VERSION} · Duración: {_h(meta.get('duracion_segundos'))} s</footer>
</div></body></html>"""


def save_reports(result: dict[str, Any], output_dir: str | Path = DEFAULT_REPORT_DIR) -> dict[str, str]:
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    target = result.get("objetivo", {}).get("host", "objetivo")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"IP_Total_{safe_filename(str(target))}_{stamp}"
    json_path = destination / f"{base}.json"
    html_path = destination / f"{base}.html"
    json_path.write_text(json.dumps(json_safe(result), ensure_ascii=False, indent=2), encoding="utf-8")
    html_path.write_text(build_html_report(result), encoding="utf-8")
    return {"json": str(json_path), "html": str(html_path)}
