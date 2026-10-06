@echo off
setlocal
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" VERIFY_RELEASE.py
) else (
  py -3 VERIFY_RELEASE.py
)
set "RC=%ERRORLEVEL%"
pause
exit /b %RC%
