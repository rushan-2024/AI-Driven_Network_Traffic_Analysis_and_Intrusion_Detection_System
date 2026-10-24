#!/usr/bin/env bash
# One-step launcher for macOS and Linux:  bash run.sh
cd "$(dirname "$0")" || exit 1
echo "============================================================"
echo " AI-Driven Network Traffic Analysis and Intrusion Detection System"
echo "============================================================"
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info>=(3,10) else 1)' 2>/dev/null; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  echo "Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/ and run this again."
  exit 1
fi
if [ ! -x ".venv/bin/python" ]; then
  echo "Creating a private Python environment (first run only)..."
  "$PY" -m venv .venv || { echo "Could not create the environment. On Ubuntu/Debian try: sudo apt install python3-venv"; exit 1; }
fi
if [ ! -f ".venv/deps_installed.txt" ]; then
  echo "Installing the required packages (first run only, needs internet, can take a few minutes)..."
  .venv/bin/python -m pip install --disable-pip-version-check -r requirements.txt || { echo "Package installation failed. Check your internet connection and run this again."; exit 1; }
  echo done > .venv/deps_installed.txt
fi
echo
echo "Starting the dashboard. Your browser will open by itself."
echo "If it does not, open http://127.0.0.1:8000 . Press Ctrl+C here to stop."
exec .venv/bin/python app.py "$@"
