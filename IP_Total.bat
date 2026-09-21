@echo off
setlocal
cd /d "%~dp0"

where pyw >nul 2>&1
if %errorlevel%==0 (
    start "IP Total" pyw -3 "%~dp0IP_Total.py"
    exit /b 0
)

where pythonw >nul 2>&1
if %errorlevel%==0 (
    start "IP Total" pythonw "%~dp0IP_Total.py"
    exit /b 0
)

echo No se encontro Python 3 en el equipo.
echo Instale Python 3 y ejecute de nuevo este archivo.
pause
exit /b 1

