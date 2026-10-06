@echo off
setlocal EnableExtensions
cd /d "%~dp0"
set "NETWORK_AUTOMATION_DATA_DIR="

if not exist ".venv\Scripts\python.exe" (
  echo Chua co moi truong Web. Dang chay OneClick de tu cai dat va giu du lieu cu...
  call "ONECLICK_UPDATE.bat"
  if errorlevel 1 exit /b 1
)

".venv\Scripts\python.exe" "VERIFY_RELEASE.py"
if errorlevel 1 (
  echo Code/asset bi thieu hoac da thay doi. GIU NGUYEN runtime_data va khoa.
  echo Ap dung lai dung goi update; khong reset database.
  pause
  exit /b 1
)

".venv\Scripts\python.exe" "VERIFY_WEB_DATA.py"
if errorlevel 1 (
  echo.
  echo [AUTO DATA] runtime_data chua san sang. Dang tu tim du lieu NetworkAutomation cu...
  ".venv\Scripts\python.exe" "AUTO_PREPARE_RUNTIME.py"
  if errorlevel 1 (
    echo.
    echo Khong tu tim thay runtime hop le. Web KHONG duoc khoi dong de bao ve du lieu.
    echo Database/key cu KHONG bi reset. Giu thu muc Web cu tren may va chay lai ONECLICK_UPDATE.bat.
    pause
    exit /b 1
  )
  echo [AUTO DATA] Kiem tra lai runtime sau khi tu phuc hoi...
  ".venv\Scripts\python.exe" "VERIFY_WEB_DATA.py"
  if errorlevel 1 (
    echo Runtime vua phuc hoi van khong dat kiem tra. Web KHONG duoc khoi dong.
    echo Database/key cu KHONG bi reset.
    pause
    exit /b 1
  )
)

".venv\Scripts\python.exe" "run_web.py"
if errorlevel 1 pause
endlocal
