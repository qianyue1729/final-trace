"""trace-engine 服务启动器（仓库根目录运行，无需设置 PYTHONPATH）。

Usage:
    python scripts/serve_engine.py                       # 默认配置 :8100
    python scripts/serve_engine.py --config configs/engine.yaml --port 8100
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trace_engine.serve import main

if __name__ == "__main__":
    main()
