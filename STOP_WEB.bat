@echo off
setlocal
cd /d "%~dp0"
set "NETWORK_AUTOMATION_DATA_DIR="
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" stop_web.py
) else (
  py -3 stop_web.py
)
echo.
pause
endlocal
