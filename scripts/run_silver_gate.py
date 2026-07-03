#!/usr/bin/env python3
"""Silver-solid release gate (T31)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trace_agent.eval.silver_gate import report_markdown, run_silver_gate  # noqa: E402


def main() -> int:
    gate = run_silver_gate()
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    (out / "silver_gate_report.json").write_text(json.dumps(gate, indent=2), encoding="utf-8")
    (out / "silver_gate_report.md").write_text(report_markdown(gate), encoding="utf-8")
    print(f"Silver gate: {gate['status']} ({len(gate['blockers'])} blockers)")
    return 0 if gate["status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
