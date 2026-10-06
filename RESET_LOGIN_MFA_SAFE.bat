@echo off
setlocal EnableExtensions
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator permission...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
  exit /b
)

echo [1/4] Stopping NetworkAutomation Web service...
sc stop NetworkAutomationWeb >nul 2>&1
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" stop_web.py >nul 2>&1
) else (
  py -3 stop_web.py >nul 2>&1
)
timeout /t 2 /nobreak >nul

set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY where py >nul 2>&1 && set "PY=py -3"
if not defined PY where python >nul 2>&1 && set "PY=python"
if not defined PY (
  echo Python 3 not found.
  pause
  exit /b 1
)

echo [2/4] Repairing local Admin login and MFA...
%PY% RESET_LOGIN_MFA_SAFE.py
if errorlevel 1 (
  echo.
  echo Repair failed. Database was not deleted or recreated.
  pause
  exit /b 1
)

echo [3/4] Starting Web service...
sc query NetworkAutomationWeb >nul 2>&1
if not errorlevel 1 (
  sc start NetworkAutomationWeb >nul 2>&1
  timeout /t 3 /nobreak >nul
) else (
  start "" /min "%COMSPEC%" /c START_WEB.bat
  timeout /t 3 /nobreak >nul
)

echo [4/4] Opening Web...
start "" http://127.0.0.1:8765/
echo.
echo LOGIN/MFA REPAIR OK.
echo Use the EXISTING Admin password. MFA setup should no longer be forced.
pause
exit /b 0
