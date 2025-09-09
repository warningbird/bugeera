#!/usr/bin/env python3
import argparse
import json
import os
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception as exc:  # pragma: no cover
    print("Missing dependency: PyYAML. Run: pip install -r requirements.txt", file=sys.stderr)
    raise

try:
    import requests  # type: ignore
except Exception:
    requests = None

# Reuse core analyzer by importing from tools if available
ROOT = Path(__file__).resolve().parents[3]
TOOLS = ROOT / "tools"
if TOOLS.exists():
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(TOOLS))

from tools.qg_analyzer import main as core_main  # type: ignore

if __name__ == "__main__":
    sys.exit(core_main())


