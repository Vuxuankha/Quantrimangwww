@echo off
setlocal
cd /d "%~dp0"
set "PY=.venv\Scripts\python.exe"
if not exist "%PY%" (
  where py >nul 2>&1 && set "PY=py -3"
)
if not defined PY (
  echo Python 3 not found.
  pause
  exit /b 1
)
%PY% SELF_CHECK.py %*
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" echo NetworkAutomation self-check: READY
if not "%RC%"=="0" echo NetworkAutomation self-check: NEEDS ATTENTION
pause
exit /b %RC%
