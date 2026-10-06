@echo off
setlocal
cd /d "%~dp0"
REM v4.3.2: ignore stale inherited data-root environment variable.
set "NETWORK_AUTOMATION_DATA_DIR="
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" VERIFY_WEB_DATA.py
) else (
  py -3 VERIFY_WEB_DATA.py
)
echo.
pause
endlocal
