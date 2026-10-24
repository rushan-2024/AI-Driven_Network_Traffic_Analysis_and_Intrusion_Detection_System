"""AI-Driven Network Traffic Analysis and Intrusion Detection System - launcher.

Easiest way to start: double-click run_windows.bat (Windows) or run run.sh (macOS/Linux).
Manual start from the repository root:  python app.py
"""
import sys

if sys.version_info < (3, 10):
    sys.exit("Python 3.10 or newer is required. Download it from https://www.python.org/downloads/")

try:
    from src.web.server import main
except ImportError as exc:  # missing pandas / numpy / scikit-learn
    sys.exit(f"A required package is missing ({exc}).\n"
             "Fix: run run_windows.bat (Windows) or run.sh (macOS/Linux), or run:  pip install -r requirements.txt")

if __name__ == "__main__":
    sys.exit(main())
