"""Narrow, auditable tools exposed to the trace deep agent.

All black-box one-shot tools (run_trace_scenario, run_production_trace,
list_trace_scenarios) have been removed in favour of the fine-grained
phase-level tools that expose every LOCK step and LLM reasoning to the
frontend.  See phase_tools.py for the canonical workflow.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from .project import PROJECT_ROOT, ensure_core_importable

ensure_core_importable()

from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.prior_v2 import PriorManager
from trace_engine.config import EngineConfig
from trace_engine.runner import InvestigationRunner

from .phase_tools import PHASE_TOOLS
from .query_tools import QUERY_TOOLS
from .control_tools import CONTROL_TOOLS


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


@lru_cache(maxsize=1)
def _scenario_runner() -> InvestigationRunner:
    config = EngineConfig()
    config.backend = "scenario"
    return InvestigationRunner(config)


def _production_runner() -> InvestigationRunner:
    """Fresh runner per call so demo-profile / strict config switches apply without restart."""
    default_config = (
        "configs/engine_demo_wazuh.yaml"
        if os.getenv("TRACE_ENGINE_DEMO_PROFILE", "0") == "1"
        else "configs/engine.yaml"
    )
    config_path = Path(
        os.getenv(
            "TRACE_AGENT_ENGINE_CONFIG",
            str(PROJECT_ROOT / default_config),
        )
    )
    if not config_path.is_absolute():
        config_path = (PROJECT_ROOT / config_path).resolve()
    config = EngineConfig.load(config_path)
    if config.backend != "soar_mcp":
        raise RuntimeError(
            f"Production config must use backend=soar_mcp, got {config.backend!r}"
        )
    return InvestigationRunner(config)


from .presentation import derive_investigation_presentation


def _compact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Keep the decision evidence while bounding tool output size."""
    if report.get("status") != "completed":
        return {
            "status": report.get("status", "error"),
            "error": report.get("error", "investigation failed"),
            "elapsed_seconds": report.get("elapsed_seconds"),
        }

    graph = report.get("graph") or {}
    nodes = list(graph.get("nodes") or [])
    edges = list(graph.get("edges") or [])
    decision = report.get("decision") or {}
    usage = report.get("usage") or {}
    trace_coverage = report.get("trace_coverage") or {}
    candidate_chain = trace_coverage.get("candidate_chain") or {}
    soar_fetch = trace_coverage.get("soar_fetch") or usage.get("soar_fetch") or {}
    round_diag = list(usage.get("round_diagnostics") or [])
    model_judgement = dict(usage.get("model_judgement") or {"mode": "off"})
    model_planner = list(usage.get("model_planner") or [])
    model_mcp_compiler = dict(
        usage.get("model_mcp_compiler") or {"mode": "off"}
    )
    presentation = derive_investigation_presentation(report)
    lock_loop = dict(presentation["lock_loop"] or {})
    lock_loop["mcp_compiler_audit"] = list(
        model_mcp_compiler.get("audit") or []
    )[:50]

    return {
        "status": "completed",
        "investigation_status": presentation["investigation_status"],
        "display_headline": presentation["display_headline"],
        "is_demo_success": presentation["is_demo_success"],
        "chain_build_status": presentation["chain_build_status"],
        "chain_build_label": presentation["chain_build_label"],
        "attribution_status": presentation["attribution_status"],
        "attribution_label": presentation["attribution_label"],
        "chain_metrics": presentation["chain_metrics"],
        "lock_loop": lock_loop,
        "presentation_notes": presentation["presentation_notes"],
        "alert": report.get("alert"),
        "decision": decision,
        "usage": {
            "rounds": usage.get("rounds"),
            "probes_used": usage.get("probes_used"),
            "elapsed_seconds": usage.get("elapsed_seconds"),
            "events_processed": usage.get("events_processed"),
        },
        "ground_truth_eval": report.get("ground_truth_eval"),
        "demo_profile": report.get("demo_profile"),
        "original_action": decision.get("original_action"),
        "guardrail_flags": decision.get("guardrail_flags"),
        "guardrail_warnings": decision.get("guardrail_warnings"),
        "require_human_review": decision.get("require_human_review"),
        "trace_coverage": {
            "candidate_chain_mode": candidate_chain.get("candidate_chain_mode"),
            "candidate_chain_events": candidate_chain.get("candidate_chain_events"),
            "candidate_chain_selected": candidate_chain.get("candidate_chain_selected"),
            "anchor_host": candidate_chain.get("anchor_host"),
            "anchor_confidence": candidate_chain.get("anchor_confidence"),
            "coverage_truncated": soar_fetch.get("coverage_truncated"),
        },
        "round_diagnostics_summary": {
            "rounds_recorded": len(round_diag),
            "final_p_atk": round_diag[-1].get("p_atk_after") if round_diag else None,
            "posterior_plateau": (
                len({d.get("p_atk_after") for d in round_diag[-5:]}) <= 1
                if len(round_diag) >= 5
                else None
            ),
            "last_round": round_diag[-1] if round_diag else None,
            "rounds": round_diag[:25],
        },
        "model_processing": {
            "planner": model_planner[:25],
            "judgement": {
                "mode": model_judgement.get("mode", "off"),
                "provider_status": model_judgement.get(
                    "provider_status", "disabled"
                ),
                "l3_llm_calls": model_judgement.get("l3_llm_calls", 0),
                "provider_errors": model_judgement.get("provider_errors", 0),
                "shadow_summary": model_judgement.get("shadow_summary") or {},
                "audit": list(model_judgement.get("audit") or [])[:50],
            },
            "mcp_compiler": {
                "mode": model_mcp_compiler.get("mode", "off"),
                "provider_status": model_mcp_compiler.get(
                    "provider_status", "disabled"
                ),
                "calls_used": model_mcp_compiler.get("calls_used", 0),
                "audit": list(model_mcp_compiler.get("audit") or [])[:50],
            },
        },
        "graph": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "attack_node_count": graph.get("attack_node_count"),
            "nodes": nodes[:120],
            "edges": edges[:160],
            "truncated": len(nodes) > 120 or len(edges) > 160,
        },
    }


@tool
def inspect_trace_prior(
    technique: str,
    tactic: str = "",
    platform: str = "Windows",
    log_source: str = "alert",
) -> str:
    """Inspect the competing prior explanations for one ATT&CK technique.

    This is an offline operation. It does not query SOAR or Wazuh.
    """
    bundle = load_prior_bundle()
    manager = PriorManager(bundle)
    alert = AlertEvent(
        technique_id=technique,
        tactic=tactic or "execution",
        platform=platform,
        log_source=log_source,
        asset_id="prior-inspection",
        anomaly_score=0.5,
    )
    seed = DecisionLedger(manager).seed(alert)
    return _json(seed.to_dict())


TRACE_TOOLS = [
    inspect_trace_prior,
    # Phase-level tools — each step visible to frontend
    *PHASE_TOOLS,
    # Control tools — adjust loss / budget / force stop
    *CONTROL_TOOLS,
    # Query tools — inspect LOCK ledgers in real time
    *QUERY_TOOLS,
]
