@echo off
setlocal EnableExtensions
cd /d "%~dp0"

net session >nul 2>&1
if errorlevel 1 (
  echo Requesting Administrator permission...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

set "PY="
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
if not defined PY (
  where py >nul 2>&1 && set "PY=py -3"
)
if not defined PY (
  where python >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo Python 3 was not found. Install Python 3 and run this file again.
  pause
  exit /b 1
)

%PY% ONECLICK_SETUP.py
set RC=%ERRORLEVEL%
if not "%RC%"=="0" (
  echo.
  echo ONECLICK FAILED. Existing runtime/database/key were not reset.
  pause
  exit /b %RC%
)

echo.
echo ================================================
echo  NETWORKAUTOMATION UI 6.9.0 QA HOTFIX16 LAN DISCOVERY FAST/ACCURATE + INTEGRITY FIX
echo ================================================
echo Dependencies bootstrapped before runtime import. Existing data preserved.
pause
exit /b 0
