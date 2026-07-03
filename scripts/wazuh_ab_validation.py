#!/usr/bin/env python3
"""Remote Wazuh A/B validation for production vs eval bootstrap paths."""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_engine.config import EngineConfig, eval_attacks_only_allowed
from trace_engine.runner import InvestigationRunner
from trace_engine.transports import build_mcp_transport


def _entry_payload(scenario_id: str) -> dict:
    data, spec = load_scenario(scenario_id)
    entry = find_entry_event(data, spec)
    alert = build_alert_event(entry)
    return {
        "technique": alert.technique_id,
        "asset": alert.asset_id,
        "tactic": alert.tactic,
        "timestamp": alert.timestamp,
        "log_source": alert.log_source or "alert",
        "anomaly_score": alert.anomaly_score or 0.8,
        "attributes": dict(alert.attributes or {}),
    }


def _probe_query(cfg: EngineConfig, scenario_id: str) -> dict:
    transport = build_mcp_transport(cfg.soar_mcp)
    captured: dict = {}

    def fake_rpc(_method, payload):
        captured.update(payload.get("arguments") or {})
        return {"content": [{"type": "text", "text": 'Security Events:\n{"data":{"affected_items":[]}}'}]}

    transport._ensure_initialized = lambda: None  # type: ignore[method-assign]
    transport._rpc = fake_rpc  # type: ignore[method-assign]
    transport.query(query="*", from_ms=0, to_ms=0, limit=1)
    query = str(captured.get("query") or "")
    return {
        "query": query,
        "contains_is_attack": "data.is_attack:true" in query,
        "contains_scenario_scope": f'data.scenario:"{scenario_id}"' in query,
    }


def _run_matrix(
    *,
    label: str,
    scenario_id: str,
    attacks_only: bool,
    eval_flag: str | None,
    max_rounds: int,
) -> dict:
    if eval_flag is None:
        os.environ.pop("TRACE_ENGINE_EVAL_ATTACKS_ONLY", None)
    else:
        os.environ["TRACE_ENGINE_EVAL_ATTACKS_ONLY"] = eval_flag

    base = EngineConfig.load(ROOT / "configs" / "engine.yaml")
    cfg = replace(
        base,
        backend="soar_mcp",
        soar_mcp=replace(
            base.soar_mcp,
            wazuh_attacks_only=attacks_only,
            wazuh_incident_prefix=scenario_id,
        ),
    )
    runner = InvestigationRunner(cfg)
    query_probe = _probe_query(cfg, scenario_id)
    payload = _entry_payload(scenario_id)

    t0 = time.time()
    try:
        report = runner.run(payload, scenario_id=scenario_id, max_rounds=max_rounds)
        status = report.get("status", "error")
        error = report.get("error")
    except Exception as exc:
        status = "error"
        error = str(exc)
        report = {}

    elapsed = round(time.time() - t0, 2)
    graph = report.get("graph") or {}
    graph_nodes = graph.get("nodes") or []
    graph_edges = graph.get("edges") or []
    decision = report.get("decision") or {}
    coverage = report.get("trace_coverage") or {}
    bootstrap = coverage.get("bootstrap") or {}
    candidate = coverage.get("candidate_chain") or {}
    fetch = coverage.get("soar_fetch") or {}

    attack_prefix_hits = 0
    wazuh_ref_hits = 0
    events_cached = coverage.get("events_cached")

    return {
        "label": label,
        "status": status,
        "error": error,
        "elapsed_seconds": elapsed,
        "eval_attacks_only_allowed": eval_attacks_only_allowed(),
        "effective_wazuh_attacks_only": cfg.soar_mcp.wazuh_attacks_only,
        "query_probe": query_probe,
        "bootstrap": {
            "case_prefetch_events": bootstrap.get("case_prefetch_events"),
            "entry_prefetch_events": bootstrap.get("entry_prefetch_events"),
            "attack_chain_events": bootstrap.get("attack_chain_events"),
            "discovered_hosts": bootstrap.get("discovered_hosts"),
        },
        "candidate_chain": candidate,
        "graph": {
            "node_count": len(graph_nodes),
            "edge_count": len(graph_edges),
            "attack_node_count": graph.get("attack_node_count"),
        },
        "decision": {
            "action": decision.get("action"),
            "guardrail_flags": decision.get("guardrail_flags"),
            "confidence": decision.get("confidence"),
        },
        "soar_fetch": {
            "records": fetch.get("records"),
            "coverage_truncated": fetch.get("coverage_truncated"),
            "errors": fetch.get("errors"),
        },
        "cached_event_refs": {
            "attack_prefix": attack_prefix_hits,
            "wazuh_prefix": wazuh_ref_hits,
            "total_cached": events_cached,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--max-rounds", type=int, default=3)
    parser.add_argument("--out", type=Path, default=ROOT / "reports" / "wazuh_ab_validation.json")
    args = parser.parse_args()

    results = {
        "scenario_id": args.scenario,
        "max_rounds": args.max_rounds,
        "runs": [
            _run_matrix(
                label="A_production_default",
                scenario_id=args.scenario,
                attacks_only=False,
                eval_flag=None,
                max_rounds=args.max_rounds,
            ),
            _run_matrix(
                label="B_explicit_eval_shortcut",
                scenario_id=args.scenario,
                attacks_only=True,
                eval_flag="1",
                max_rounds=args.max_rounds,
            ),
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(results, ensure_ascii=False, indent=2))
    print(f"\nSaved: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
