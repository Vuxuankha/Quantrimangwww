@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Run INSTALL_WEB.bat first.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" CREATE_EMPTY_RUNTIME.py
pause
