@echo off
setlocal
cd /d "%~dp0"
set "NETWORK_AUTOMATION_DATA_DIR="
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" VERIFY_WEB_DATA.py --external-data
) else (
  py -3 VERIFY_WEB_DATA.py --external-data
)
echo.
pause
endlocal
