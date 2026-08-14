#!/usr/bin/env python3
"""Simple launcher — works without pip install.

Usage:
  python run.py status
  python run.py anomaly
  python run.py kev
  python run.py logs
  python run.py report
  python run.py dashboard
  python run.py about
"""

import sys
from pathlib import Path

# Put src/ on path so "melisa" is importable
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from melisa.cli import main

if __name__ == "__main__":
    main()
