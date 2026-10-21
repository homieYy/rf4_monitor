@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
pushd "%~dp0" || exit /b 1
if exist ".venv\Scripts\python.exe" goto install
where py >nul 2>nul
if not errorlevel 1 (
    py -3 -m venv .venv
) else (
    python -m venv .venv
)
if errorlevel 1 goto failed
:install
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
echo Python dependencies installed. Live capture also requires Npcap from https://npcap.com/
popd
pause
exit /b 0
:failed
echo Installation failed. Install Python 3.10 or newer and check your network.
popd
pause
exit /b 1
