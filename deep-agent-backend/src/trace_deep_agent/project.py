"""Locate the host project and make its source package importable."""
from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[3]
CORE_SRC = PROJECT_ROOT / "src"


def ensure_core_importable() -> None:
    """Add the existing trace engine source tree to this process only."""
    core_src = str(CORE_SRC)
    if core_src not in sys.path:
        sys.path.insert(0, core_src)

