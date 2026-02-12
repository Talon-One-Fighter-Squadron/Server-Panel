@echo off
setlocal EnableExtensions
cd /d "%~dp0"

:: Nuclear Option Server Panel - Start (Admin)
:: This panel needs Administrator privileges to manage Windows Firewall rules.

:: Check for admin (net session requires elevation)
net session >nul 2>&1
if %errorlevel%==0 goto :RUN

:: Relaunch self as admin (will trigger UAC)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process -FilePath '%ComSpec%' -ArgumentList '/c','\"%~f0\"' -Verb RunAs" >nul 2>&1
exit /b

:RUN
set "PYEXE="
if exist "%~dp0venv\Scripts\python.exe" set "PYEXE=%~dp0venv\Scripts\python.exe"

if not defined PYEXE (
  where py >nul 2>&1 && set "PYEXE=py -3"
)

if not defined PYEXE (
  where python >nul 2>&1 && set "PYEXE=python"
)

if not defined PYEXE (
  echo [start-panel] ERROR: Python was not found.
  echo [start-panel] Install Python 3.x or ensure 'py' or 'python' is on PATH.
  pause
  exit /b 1
)

echo [start-panel] Running as Administrator: OK
echo [start-panel] Launching panel from: %CD%
echo.

%PYEXE% "%~dp0app.py"

set "EC=%errorlevel%"
echo.
echo [start-panel] Panel exited with code %EC%.
pause
exit /b %EC%
