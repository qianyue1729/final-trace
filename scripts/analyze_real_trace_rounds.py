#!/usr/bin/env python3
"""Report LOCK round count and per-round diagnostics for real_trace_01."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.config import EngineConfig
from trace_engine.runner import InvestigationRunner

PAYLOAD = {
    "technique": "T1048",
    "tactic": "exfiltration",
    "asset": "wazuh.manager",
    "log_source": "wazuh",
    "attributes": {"dst_ip": "198.51.100.77"},
}


def main() -> int:
    cfg = EngineConfig.load(ROOT / "configs" / "engine.real_trace.yaml")
    print("=== real_trace LOCK 轮次分析 ===")
    print(f"配置上限: total_rounds={cfg.budget.total_rounds}, "
          f"total_probes={cfg.budget.total_probes}, "
          f"fanout={cfg.budget.fanout_per_round}")
    print()

    report = InvestigationRunner(cfg).run(PAYLOAD)
    usage = report.get("usage") or {}
    decision = report.get("decision") or {}
    graph = report.get("graph") or {}
    rounds = usage.get("rounds", 0)
    stop = decision.get("stop_reason", "?")
    probes = usage.get("probes_used", 0)
    bootstrap = (usage.get("soar_fetch") or {}).get("bootstrap") or {}

    print(f"实际执行轮数: {rounds}")
    print(f"停止原因: {stop}")
    print(f"探针消耗: {probes}/{cfg.budget.total_probes}")
    print(f"Bootstrap 预取: {bootstrap.get('case_prefetch_events', 0)} 条")
    print(f"图: {len(graph.get('nodes') or [])} 节点 / {len(graph.get('edges') or [])} 边")
    print(f"决策: {decision.get('action')}")
    print()

    diag = usage.get("round_diagnostics") or []
    if not diag:
        print("(无 round_diagnostics)")
    else:
        print("逐轮 K 拍摘要:")
        for d in diag:
            r = d.get("round", "?")
            stop_flag = d.get("stop", False)
            reason = d.get("stop_reason") or d.get("reason") or ""
            nodes = d.get("graph_nodes") or d.get("node_count")
            edges = d.get("graph_edges") or d.get("edge_count")
            voi = d.get("best_voi")
            probes_r = d.get("probes_this_round") or d.get("probes_executed")
            line = f"  R{r}: stop={stop_flag}"
            if reason:
                line += f" reason={reason}"
            if nodes is not None:
                line += f" nodes={nodes}"
            if edges is not None:
                line += f" edges={edges}"
            if voi is not None:
                line += f" voi={voi}"
            if probes_r is not None:
                line += f" probes={probes_r}"
            print(line)

    print()
    if rounds <= 1:
        print("[WARN] 仅 1 轮即结束 — 对 6 步真实链而言不合理，需排查早停条件。")
        ok = False
    elif rounds < 3:
        print(f"[WARN] 仅 {rounds} 轮 — 偏少，可能 bootstrap 已覆盖全链 + 早停。")
        ok = rounds >= 3
    else:
        print(f"[OK] 执行 {rounds} 轮 LOCK 循环，符合多轮调查预期。")
        ok = True

    out = ROOT / "reports" / "real_trace_round_analysis.json"
    out.write_text(
        json.dumps(
            {
                "config_budget": {
                    "total_rounds": cfg.budget.total_rounds,
                    "total_probes": cfg.budget.total_probes,
                    "fanout_per_round": cfg.budget.fanout_per_round,
                },
                "actual_rounds": rounds,
                "stop_reason": stop,
                "probes_used": probes,
                "bootstrap": bootstrap,
                "graph_nodes": len(graph.get("nodes") or []),
                "graph_edges": len(graph.get("edges") or []),
                "round_diagnostics": diag,
                "logical_ok": ok,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"\nReport: {out}")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
