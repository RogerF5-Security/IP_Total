# IP Total

Herramienta unificada para ingresar **una IP, un dominio o una URL** y ejecutar todo el reconocimiento desde un único botón.

Las herramientas anteriores `IPtoOS.py` e `IPtoURL.py` permanecen intactas.

## Inicio rápido

1. Abra `IP_Total.bat` con doble clic.
2. Escriba un objetivo, por ejemplo:
   - `8.8.8.8`
   - `ejemplo.com`
   - `https://ejemplo.com/ruta`
3. Elija el alcance de puertos:
   - **Rápido:** Top 100 TCP.
   - **Equilibrado:** Top 1000 TCP; recomendado.
   - **Completo:** TCP 1-65535; puede tardar bastante.
4. Pulse **ANALIZAR TODO**.

Los resultados aparecen en cinco pestañas y se guardan automáticamente como HTML y JSON dentro de `audit_reports`.

## Información obtenida

- Normalización automática de IP, dominio o URL.
- Resolución directa A/AAAA y DNS inverso/PTR.
- Registros DNS A, AAAA, CNAME, MX, NS, TXT, SOA y CAA.
- Dominio registrable y nombres vinculados a una IP mediante PTR y certificados TLS.
- WHOIS/RDAP completo de IP y dominio, ASN, organización, ISP y geolocalización aproximada.
- Puertos TCP, estado, razón, servicio, producto, versión, CPE y evidencia de scripts Nmap.
- Sistema operativo por fingerprint Nmap; respaldo heurístico mediante TTL.
- Servicios web reales, URL final, redirecciones, HTTP status, título, servidor y tecnologías.
- Cabeceras HTTP y controles de seguridad observados.
- Certificado TLS, emisor, vigencia, hash SHA-256, versión, cifrado y SANs.
- `robots.txt`, transparencia de certificados y subdominios pasivos de `crt.sh`.
- Traceroute opcional.
- Evidencia HTML legible y JSON técnico por cada ejecución.

## Requisitos

- Windows con Python 3.10 o superior.
- Nmap en `PATH` para el análisis completo de puertos/servicios/OS.
- Acceso a Internet para RDAP, ASN/geolocalización y `crt.sh`.

Instalación de librerías, si fuera necesaria:

```powershell
py -3 -m pip install -r requirements.txt
```

Si Nmap no está disponible, la aplicación mantiene un escaneo de respaldo sobre puertos TCP comunes, pero no tendrá la misma precisión.

## Uso por consola

```powershell
python .\IP_Total.py --scan 8.8.8.8 --profile rapido --no-traceroute
python .\IP_Total.py --scan https://ejemplo.com --profile equilibrado
python .\IP_Total.py --scan 10.0.0.10 --profile completo
```

Validaciones incluidas:

```powershell
python .\IP_Total.py --self-test
python .\IP_Total.py --ui-smoke
```

## Lectura correcta de resultados

- Una IP solo tendrá una URL asociable si existe PTR, un nombre en el certificado o un servicio web verificable. No existe una relación universal uno-a-uno entre IP y dominio.
- El sistema operativo es concluyente cuando Nmap obtiene un fingerprint con precisión; TTL se etiqueta como estimación.
- WHOIS/RDAP y geolocalización no aplican a direcciones privadas, loopback o reservadas.
- Un resultado depende de lo observable desde el equipo y del filtrado/firewall situado entre el auditor y el objetivo.

