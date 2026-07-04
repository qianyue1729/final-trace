#!/usr/bin/env python3
"""Phase 3 auxiliary MCP tools smoke test."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.config import EngineConfig
from trace_engine.transports import build_mcp_transport


def load_env() -> None:
    for line in (ROOT / "host-client.env").read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())


def ok_result(raw: object) -> bool:
    if not isinstance(raw, dict):
        return False
    if raw.get("isError"):
        return False
    content = raw.get("content") or []
    if not content:
        return False
    text = ""
    if isinstance(content[0], dict):
        text = (content[0].get("text") or "").lower()
    return "error" not in text[:200] or "affected_items" in text


def main() -> int:
    load_env()
    cfg = EngineConfig.load(ROOT / "configs" / "engine.yaml")
    t = build_mcp_transport(cfg.soar_mcp)
    t._ensure_initialized()
    cases = [
        ("3.1", "get_wazuh_alerts", {"limit": 10}),
        ("3.2", "get_wazuh_alert_summary", {"time_range": "30d", "group_by": "rule.id"}),
        ("3.3", "analyze_alert_patterns", {"time_range": "30d", "min_frequency": 3}),
        ("3.4", "analyze_security_threat", {"indicator": "10.0.3.11", "indicator_type": "ip"}),
        ("3.5", "check_ioc_reputation", {"indicator": "10.0.3.11", "indicator_type": "ip"}),
        ("3.6", "generate_security_report", {"report_type": "incident", "time_range": "7d"}),
        ("3.7", "perform_risk_assessment", {"agent_id": "004", "time_range": "7d"}),
        ("3.8", "get_top_security_threats", {"time_range": "7d"}),
        ("3.9", "run_compliance_check", {"framework": "pci_dss"}),
    ]
    results = []
    try:
        for cid, tool, args in cases:
            try:
                raw = t._rpc("tools/call", {"name": tool, "arguments": args})
                passed = ok_result(raw)
                detail = "ok" if passed else str(raw)[:120]
            except Exception as exc:  # noqa: BLE001
                passed = False
                detail = str(exc)[:120]
            results.append({"id": cid, "tool": tool, "passed": passed, "detail": detail})
            print(f"[{'PASS' if passed else 'FAIL'}] {cid} {tool}")
    finally:
        t.close()
    out = ROOT / "reports" / "phase3_aux_tools.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    return 2 if any(not r["passed"] for r in results) else 0


if __name__ == "__main__":
    raise SystemExit(main())
