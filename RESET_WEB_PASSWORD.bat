@echo off
setlocal EnableExtensions
cd /d "%~dp0"
net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator permission...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
  exit /b
)
sc stop NetworkAutomationWeb >nul 2>&1
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" stop_web.py >nul 2>&1
) else (
  py -3 stop_web.py >nul 2>&1
)
timeout /t 2 /nobreak >nul
if not exist ".venv\Scripts\python.exe" (
  echo Run INSTALL_WEB.bat first.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" "reset_web_password.py"
set RC=%ERRORLEVEL%
if "%RC%"=="0" (
  ".venv\Scripts\python.exe" "RESET_LOGIN_MFA_SAFE.py"
  sc start NetworkAutomationWeb >nul 2>&1
)
if not "%RC%"=="0" pause
endlocal
exit /b %RC%
