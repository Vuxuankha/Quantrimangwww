@echo off
setlocal
cd /d "%~dp0"
set "NETWORK_AUTOMATION_DATA_DIR="
if not exist ".venv\Scripts\python.exe" (
  echo Chua co moi truong Web. Hay chay INSTALL_WEB.bat truoc.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" "VERIFY_WEB_DATA.py" --external-data
if errorlevel 1 (
  echo.
  echo External database khong hop le hoac chua cau hinh.
  echo Chay CONFIGURE_WEB.bat, hoac dung START_WEB.bat de dung runtime_data an toan.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" "run_web.py" --external-data
if errorlevel 1 pause
endlocal
