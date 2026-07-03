#!/usr/bin/env python3
"""Collect P0 evidence for Deep Agent production trace demo (read-only)."""
from __future__ import annotations

import json
import os
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_engine.config import EngineConfig
from trace_engine.decision_guardrails import collect_guardrail_flags
from trace_engine.runner import InvestigationRunner


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


def _summarize_report(label: str, report: dict, *, query_hint: str = "") -> dict:
    decision = report.get("decision") or {}
    usage = report.get("usage") or {}
    graph = report.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    coverage = report.get("trace_coverage") or {}
    planner = usage.get("model_planner") or []
    voi = usage.get("voi_audit") or []
    rounds: dict[int, dict] = {}
    for item in voi:
        rnd = int(item.get("round") or 0)
        rounds.setdefault(rnd, {"voi_events": 0, "operators": []})
        rounds[rnd]["voi_events"] += 1
        op = item.get("operator")
        if op:
            rounds[rnd]["operators"].append(op)
    return {
        "label": label,
        "query_hint": query_hint,
        "status": report.get("status"),
        "decision": {
            "action": decision.get("action"),
            "original_action": decision.get("original_action"),
            "stop_reason": decision.get("stop_reason"),
            "confidence": decision.get("confidence"),
            "confidence_status": decision.get("confidence_status"),
            "investigation_score": decision.get("investigation_score"),
            "guardrail_flags": decision.get("guardrail_flags"),
            "require_human_review": decision.get("require_human_review"),
            "incomplete": decision.get("incomplete"),
        },
        "usage": {
            "rounds": usage.get("rounds"),
            "probes_used": usage.get("probes_used"),
            "elapsed_seconds": usage.get("elapsed_seconds"),
        },
        "graph": {"nodes": len(nodes), "edges": len(edges)},
        "bootstrap": coverage.get("bootstrap"),
        "candidate_chain": coverage.get("candidate_chain"),
        "soar_fetch_summary": {
            k: (usage.get("soar_fetch") or {}).get(k)
            for k in ("records", "queries", "errors", "coverage_truncated")
        },
        "planner_audit": planner,
        "voi_rounds": rounds,
        "posterior_constant_check": _posterior_constant(planner),
    }


def _posterior_constant(planner_audit: list) -> dict:
    margins = [entry.get("margin") for entry in planner_audit if "margin" in entry]
    if not margins:
        return {"checked": False}
    return {
        "checked": True,
        "unique_margins": len(set(round(m, 6) for m in margins if m is not None)),
        "first_margin": margins[0] if margins else None,
        "last_margin": margins[-1] if margins else None,
    }


def _run_path_with_report(
    label: str,
    *,
    backend: str,
    scenario_id: str,
    attacks_only: bool,
    eval_flag: str | None,
    max_rounds: int,
) -> tuple[dict, dict]:
    if eval_flag is None:
        os.environ.pop("TRACE_ENGINE_EVAL_ATTACKS_ONLY", None)
    else:
        os.environ["TRACE_ENGINE_EVAL_ATTACKS_ONLY"] = eval_flag

    base = EngineConfig.load(ROOT / "configs" / "engine.yaml")
    cfg = replace(base, backend=backend)
    if backend == "soar_mcp":
        cfg = replace(
            cfg,
            soar_mcp=replace(
                cfg.soar_mcp,
                wazuh_attacks_only=attacks_only,
                wazuh_incident_prefix=scenario_id,
            ),
        )
    runner = InvestigationRunner(cfg)
    payload = _entry_payload(scenario_id)
    report = runner.run(payload, scenario_id=scenario_id, max_rounds=max_rounds)
    query = ""
    if backend == "soar_mcp":
        from trace_engine.transports import build_mcp_transport

        transport = build_mcp_transport(cfg.soar_mcp)
        captured: dict = {}

        def fake_rpc(_method, payload_in):
            captured.update(payload_in.get("arguments") or {})
            return {"content": [{"type": "text", "text": 'Security Events:\n{"data":{"affected_items":[]}}'}]}

        transport._ensure_initialized = lambda: None  # type: ignore[method-assign]
        transport._rpc = fake_rpc  # type: ignore[method-assign]
        transport.query(query="*", from_ms=0, to_ms=0, limit=1)
        query = str(captured.get("query") or "")
    return _summarize_report(label, report, query_hint=query), report


def _guardrail_breakdown(report: dict) -> list[dict]:
    decision = report.get("decision") or {}
    usage = report.get("usage") or {}
    graph = report.get("graph") or {}
    flags = collect_guardrail_flags(decision=decision, usage=usage, graph=graph)
    details = []
    soar = usage.get("soar_fetch") or {}
    planner = usage.get("model_planner") or []
    for flag in flags:
        row = {"flag": flag}
        if flag == "planner_non_functional":
            row["trigger"] = "all planner audit entries abstained or accepted=0"
            row["planner_audit_len"] = len(planner)
            row["sample"] = planner[:2]
        elif flag == "telemetry_coverage_insufficient":
            row["trigger"] = "soar_fetch.coverage_truncated=true"
            row["coverage_truncated"] = soar.get("coverage_truncated")
        elif flag == "confidence_unavailable":
            row["trigger"] = "decision.confidence_status=unavailable"
            row["confidence_status"] = decision.get("confidence_status")
            row["calibration_path"] = EngineConfig.load(ROOT / "configs" / "engine.yaml").calibration.artifact_path
        elif flag == "investigation_budget_exhausted":
            row["trigger"] = "stop_reason=budget AND action in affirmative set"
            row["stop_reason"] = decision.get("stop_reason")
            row["action"] = decision.get("action")
        elif flag == "score_action_mismatch":
            row["trigger"] = "affirmative action with investigation_score < 0.5"
            row["investigation_score"] = decision.get("investigation_score")
            row["action"] = decision.get("action")
        details.append(row)
    return details


def _config_diff() -> dict:
    import yaml

    engine = yaml.safe_load((ROOT / "configs" / "engine.yaml").read_text(encoding="utf-8"))
    shadow = json.loads(
        (ROOT / "src" / "trace_engine" / "config_production_shadow.json").read_text(
            encoding="utf-8"
        )
    )
    keys = [
        "backend",
        ("soar_mcp", "wazuh_attacks_only"),
        ("soar_mcp", "page_limit"),
        ("soar_mcp", "wazuh_time_range"),
        ("budget", "total_rounds"),
        ("budget", "total_probes"),
        ("budget", "fanout_per_round"),
        ("budget", "min_rounds_before_robust"),
        ("model_planner", "mode"),
        ("model_judgement", "mode"),
        ("calibration", "artifact_path"),
    ]

    def dig(d, path):
        if isinstance(path, str):
            return d.get(path)
        cur = d
        for part in path:
            cur = (cur or {}).get(part)
        return cur

    diff = {}
    for key in keys:
        path = key if isinstance(key, tuple) else (key,)
        name = ".".join(path)
        diff[name] = {"engine.yaml": dig(engine, path), "production_shadow": dig(shadow, path)}
    defaults = EngineConfig.load()
    diff["defaults.model_planner.mode"] = defaults.model_planner.mode
    diff["defaults.model_judgement.mode"] = defaults.model_judgement.mode
    diff["defaults.calibration.artifact_path"] = defaults.calibration.artifact_path
    return diff


def main() -> int:
    scenario_id = "pipeline_18"
    max_rounds = int(os.environ.get("EVIDENCE_MAX_ROUNDS", "25"))
    paths = {
        "A_production": None,
        "B_eval": None,
        "C_local_scenario": None,
    }
    full_reports: dict[str, dict] = {}
    for key, kwargs in (
        ("A_production", dict(label="A_production", backend="soar_mcp", scenario_id=scenario_id, attacks_only=False, eval_flag=None, max_rounds=max_rounds)),
        ("B_eval", dict(label="B_eval", backend="soar_mcp", scenario_id=scenario_id, attacks_only=True, eval_flag="1", max_rounds=max_rounds)),
        ("C_local_scenario", dict(label="C_local_scenario", backend="scenario", scenario_id=scenario_id, attacks_only=False, eval_flag=None, max_rounds=max_rounds)),
    ):
        summary, full = _run_path_with_report(**kwargs)
        paths[key] = summary
        full_reports[key] = full

    out = {
        "scenario_id": scenario_id,
        "max_rounds": max_rounds,
        "paths": paths,
        "config_diff": _config_diff(),
        "guardrail_breakdown": _guardrail_breakdown(full_reports["A_production"]),
        "deep_agent_tool_simulation": _simulate_deep_agent_tool(full_reports["A_production"]),
    }

    dest = ROOT / "reports" / "deep_agent_production_trace_evidence.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2, default=str))
    print(f"\nSaved: {dest}")
    return 0


def _simulate_deep_agent_tool(report: dict) -> dict:
    """Simulate run_production_trace compact output shape (not via LangGraph UI)."""
    graph = report.get("graph") or {}
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    decision = report.get("decision") or {}
    return {
        "note": "Simulated _compact_report(); not collected from LangGraph UI session",
        "input_equivalent": {
            "technique": (report.get("alert") or {}).get("technique_id"),
            "asset": (report.get("alert") or {}).get("asset_id"),
            "scenario_id": "pipeline_18",
            "max_rounds": (report.get("usage") or {}).get("rounds"),
        },
        "compact_output": {
            "status": report.get("status"),
            "decision": decision,
            "guardrail_flags": decision.get("guardrail_flags"),
            "graph": {
                "node_count": len(nodes),
                "edge_count": len(edges),
            },
            "usage": report.get("usage"),
            "ground_truth_eval": report.get("ground_truth_eval"),
        },
        "ui_fields_missing_in_compact_report": [
            "trace_coverage",
            "original_action visible only inside decision dict",
            "candidate_chain not in compact_report",
        ],
    }


if __name__ == "__main__":
    raise SystemExit(main())
