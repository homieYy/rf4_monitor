@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
pushd "%~dp0" || exit /b 1
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>nul
    if not errorlevel 1 (
        ".venv\Scripts\python.exe" bootstrap.py %*
        goto finish
    )
)
py -3 -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>nul
if not errorlevel 1 (
    py -3 bootstrap.py %*
    goto finish
)
python -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>nul
if not errorlevel 1 (
    python bootstrap.py %*
    goto finish
)
echo Please install Python 3.10 or newer, then double-click this file again.
echo Enable "Add Python to PATH" in the Python installer.
start "" "https://www.python.org/downloads/windows/"
set "EXIT_CODE=1"
goto done
:finish
set "EXIT_CODE=%ERRORLEVEL%"
:done
if not "%EXIT_CODE%"=="0" pause
popd
exit /b %EXIT_CODE%
