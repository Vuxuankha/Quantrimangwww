@echo off
setlocal EnableExtensions
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
  exit /b
)
sc start NetworkAutomationWeb
set "RC=%ERRORLEVEL%"
timeout /t 3 /nobreak >nul
sc query NetworkAutomationWeb
sc query NetworkAutomationWeb | findstr /C:"RUNNING" >nul
if errorlevel 1 (
  echo.
  echo Service khong RUNNING. Chay INSTALL_WEB_SERVICE.bat de tu sua va cai lai.
  if exist "service_logs\web_service_bootstrap.log" type "service_logs\web_service_bootstrap.log"
  if exist "service_logs\web_service.log" type "service_logs\web_service.log"
  if exist "service_logs\web_service_child.log" type "service_logs\web_service_child.log"
  set "RC=1"
)
if not defined NA_NO_PAUSE pause
exit /b %RC%
