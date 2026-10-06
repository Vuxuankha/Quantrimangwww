@echo off
setlocal
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
  exit /b
)
sc stop NetworkAutomationWeb >nul 2>&1
sc delete NetworkAutomationWeb
if exist "service_config.json" del /q "service_config.json" >nul 2>&1
echo Service removed. runtime_data was preserved.
if not defined NA_NO_PAUSE pause
