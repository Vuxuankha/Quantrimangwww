@echo off
setlocal EnableExtensions
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator permission...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
  exit /b
)

if not exist ".venv\Scripts\python.exe" (
  echo [ERROR] Chua co .venv. Hay chay INSTALL_WEB.bat truoc.
  pause
  exit /b 1
)

echo =====================================================
echo NetworkAutomation Cybersecurity - Repair/Install Service
echo =====================================================
".venv\Scripts\python.exe" SERVICE_INSTALLER.py
set "RC=%ERRORLEVEL%"
if "%RC%"=="0" (
  echo.
  echo SERVICE INSTALL/REPAIR OK.
) else (
  echo.
  echo SERVICE INSTALL/REPAIR FAILED. Xem chan doan o tren.
)
if not defined NA_NO_PAUSE pause
exit /b %RC%
