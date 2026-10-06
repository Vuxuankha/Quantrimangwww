@echo off
setlocal
schtasks /Delete /F /TN "NetworkAutomation Web"
if errorlevel 1 echo Khong tim thay task hoac khong co quyen xoa.
pause
endlocal
