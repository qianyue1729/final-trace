#!/usr/bin/env python3
"""Windows-side acceptance for real_trace_01 (真实 Wazuh 形态)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.config import EngineConfig
from trace_engine.normalizer import EventNormalizer
from trace_engine.runner import InvestigationRunner
from trace_engine.transports import _extract_mcp_records, build_mcp_transport

SRCIP = "203.0.113.50"
DST_IP = "198.51.100.77"
GROUP = "real_trace"


def mcp_search(cfg: EngineConfig, query: str, *, limit: int = 10) -> tuple[int, list[dict]]:
    t = build_mcp_transport(cfg.soar_mcp)
    try:
        t._ensure_initialized()
        raw = t._rpc(
            "tools/call",
            {
                "name": "search_security_events",
                "arguments": {
                    "query": query,
                    "time_range": cfg.soar_mcp.wazuh_time_range,
                    "limit": limit,
                    "compact": False,
                },
            },
        )
        recs = _extract_mcp_records(raw)
        return len(recs), recs
    finally:
        t.close()


def main() -> int:
    cfg_path = ROOT / "configs" / "engine.real_trace.yaml"
    if len(sys.argv) > 1:
        cfg_path = Path(sys.argv[1])
    cfg = EngineConfig.load(cfg_path)
    normalizer = EventNormalizer(cfg.normalizer)
    report: dict = {"config": str(cfg_path), "checks": []}

    # v2: 种子按 dst_ip 定位；回溯链按 pivot 字段逐跳（非一次拉满）
    queries = [
        (
            "seed_t1048_dstip",
            f'rule.mitre.id:T1048 AND data.dst_ip:"{DST_IP}"',
            1,
        ),
        (
            "pivot_collected_file",
            'data.collected_file:"/tmp/collected_7f3a2c.dat" AND rule.mitre.id:T1005',
            1,
        ),
    ]
    all_ok = True
    for name, query, expected in queries:
        count, recs = mcp_search(cfg, query, limit=max(10, expected))
        # Wazuh 单逻辑事件可能有多条告警，>=expected 即视为链存在
        ok = count >= expected
        all_ok &= ok
        techniques = []
        for r in recs:
            ev = normalizer.normalize(r)
            if ev.get("technique"):
                techniques.append(str(ev["technique"]))
        report["checks"].append(
            {
                "name": name,
                "query": query,
                "expected": expected,
                "count": count,
                "passed": ok,
                "techniques": techniques,
            }
        )
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {count}/{expected}  mitre={techniques}")

    payload = {
        "technique": "T1048",
        "tactic": "exfiltration",
        "asset": "wazuh.manager",
        "log_source": "wazuh",
        "attributes": {"dst_ip": DST_IP},
    }
    runner = InvestigationRunner(cfg)
    live = runner.run(payload, max_rounds=cfg.budget.total_rounds)
    g = live.get("graph") or {}
    nodes = g.get("nodes") or []
    edges = g.get("edges") or []
    usage = live.get("usage") or {}
    bootstrap = (usage.get("soar_fetch") or {}).get("bootstrap") or {}
    node_count_ok = len(nodes) >= 6
    edge_count_ok = len(edges) >= 5
    completed = live.get("status") == "completed"
    e2e_ok = completed and node_count_ok and edge_count_ok
    all_ok &= e2e_ok
    report["e2e"] = {
        "status": live.get("status"),
        "nodes": len(nodes),
        "edges": len(edges),
        "bootstrap": bootstrap,
        "mcp_errors": (usage.get("soar_fetch") or {}).get("errors", 0),
        "passed": e2e_ok,
    }
    print(
        f"[{'PASS' if e2e_ok else 'FAIL'}] e2e: status={live.get('status')} "
        f"nodes={len(nodes)} edges={len(edges)} bootstrap={bootstrap.get('case_prefetch_events')}"
    )

    out = ROOT / "reports" / "real_trace_01_windows.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"Report: {out}")
    return 0 if all_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
