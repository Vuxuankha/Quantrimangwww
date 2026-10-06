@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Run INSTALL_WEB.bat first.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" "VERIFY_WEB_DATA.py"
if errorlevel 1 exit /b 1
set "NETWORK_AUTOMATION_DATA_DIR=%~dp0runtime_data"
echo Do not run competing Desktop and Web collectors on the same targets.
".venv\Scripts\python.exe" main.py
if errorlevel 1 pause
