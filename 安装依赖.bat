@echo off
setlocal
call "%~dp0rf4_monitor.bat" --setup-only
set "EXIT_CODE=%ERRORLEVEL%"
if "%EXIT_CODE%"=="0" pause
exit /b %EXIT_CODE%
