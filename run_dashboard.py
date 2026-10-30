"""Helper script to launch the RansomWatch Streamlit Dashboard."""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DASHBOARD_PATH = PROJECT_ROOT / "dashboard" / "app.py"

if __name__ == "__main__":
    print(f"[*] Launching RansomWatch Dashboard from {DASHBOARD_PATH}...")
    subprocess.run([sys.executable, "-m", "streamlit", "run", str(DASHBOARD_PATH)])
