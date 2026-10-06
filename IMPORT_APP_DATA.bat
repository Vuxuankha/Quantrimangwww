@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
 echo Chay INSTALL_WEB.bat truoc.
 pause
 exit /b 1
)
".venv\Scripts\python.exe" "IMPORT_APP_DATA.py"
set "RESULT=%ERRORLEVEL%"
pause
exit /b %RESULT%
