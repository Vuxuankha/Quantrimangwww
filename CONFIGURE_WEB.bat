@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Run INSTALL_WEB.bat first.
  pause
  exit /b 1
)
echo CHU Y: START_WEB.bat luon dung runtime_data an toan.
echo Cau hinh nay CHI duoc dung khi ban chay START_WEB_EXTERNAL_DATA.bat.
echo.
".venv\Scripts\python.exe" "configure_web.py"
if errorlevel 1 pause
endlocal
