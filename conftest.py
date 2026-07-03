"""pytest 根配置：保证本仓 src/ 内核优先于全局安装的同名包。"""
import sys
from pathlib import Path

_SRC = str(Path(__file__).resolve().parent / "src")
if _SRC in sys.path:
    sys.path.remove(_SRC)
sys.path.insert(0, _SRC)
