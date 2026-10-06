@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  py -3 -m venv .venv
  if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" VERIFY_RELEASE.py
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip install -r requirements.txt -r requirements-web.txt
if errorlevel 1 goto failed
".venv\Scripts\python.exe" -m pip check
if errorlevel 1 goto failed
echo INSTALL OK.
echo - Nang cap: chay IMPORT_APP_DATA.bat va chon du lieu app/Web cu.
echo - Cai moi hoan toan: CREATE_EMPTY_RUNTIME.bat, khong dung khi nang cap.
echo - Chay START_WEB.bat de mo NetworkAutomation Cybersecurity.
echo - Chi chay CONFIGURE_WEB.bat neu ban chu dong muon dung data root khac.
pause
exit /b 0
:failed
echo INSTALL FAILED. Do not start the application until this is fixed.
pause
exit /b 1
