@echo off
setlocal
cd /d "%~dp0"
title Network IDS Console
echo ============================================================
echo  AI-Driven Network Traffic Analysis and Intrusion Detection System
echo ============================================================
set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY (
  where python >nul 2>nul && set "PY=python"
)
if not defined PY (
  echo.
  echo Python was not found on this computer.
  echo 1. Download Python 3.10 or newer from https://www.python.org/downloads/
  echo 2. In the installer, TICK "Add python.exe to PATH", then click Install Now.
  echo 3. Double-click this file again.
  echo.
  pause
  exit /b 1
)
%PY% -c "import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)"
if errorlevel 1 (
  echo.
  echo Your Python is older than 3.10. Install a newer version from https://www.python.org/downloads/
  echo.
  pause
  exit /b 1
)
if not exist ".venv\Scripts\python.exe" (
  echo Creating a private Python environment. This happens only once...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo Could not create the environment.
    pause
    exit /b 1
  )
)
if not exist ".venv\deps_installed.txt" (
  echo Installing the required packages. This happens only once and needs internet. It can take a few minutes...
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
  if errorlevel 1 (
    echo.
    echo Package installation failed. Check your internet connection, then double-click this file again.
    pause
    exit /b 1
  )
  echo done> ".venv\deps_installed.txt"
)
echo.
echo Starting the dashboard. Your web browser will open by itself.
echo If it does not, open  http://127.0.0.1:8000  in your browser.
echo Keep this window open while you use the dashboard. Close it to stop.
echo.
".venv\Scripts\python.exe" app.py
echo.
pause
