@echo off
setlocal
cd /d "%~dp0"
echo Install Web at current user logon. Loopback only. Review the PS1 before running.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0INSTALL_WEB_AUTOSTART.ps1"
if errorlevel 1 echo Not installed. Check account permission and local policy above.
pause
