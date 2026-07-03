"""Narrow, auditable tools exposed to the trace deep agent."""
from __future__ import annotations

import json
import os
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from .project import PROJECT_ROOT, ensure_core_importable

ensure_core_importable()

from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_agent.prior_v2 import PriorManager
from trace_engine.config import EngineConfig
from trace_engine.runner import InvestigationRunner


_RUN_LOCK = threading.Lock()


def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


@lru_cache(maxsize=1)
def _scenario_runner() -> InvestigationRunner:
    config = EngineConfig()
    config.backend = "scenario"
    return InvestigationRunner(config)


def _production_runner() -> InvestigationRunner:
    """Fresh runner per call so demo/strict config switches apply without restart."""
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
    presentation = derive_investigation_presentation(report)

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
        "lock_loop": presentation["lock_loop"],
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
def list_trace_scenarios() -> str:
    """List the local, non-production trace scenarios available for debugging."""
    return _json({"scenarios": _scenario_runner().list_scenarios()})


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


@tool
def run_trace_scenario(
    scenario_id: str,
    max_rounds: int = 50,
) -> str:
    """Run the complete LOCK trace loop against a local ground-truth scenario.

    Valid scenario IDs can be obtained with list_trace_scenarios. This tool is
    safe for debugging and never contacts the production SOAR/Wazuh backend.
    """
    if max_rounds < 1 or max_rounds > 100:
        return _json({"status": "error", "error": "max_rounds must be 1..100"})

    try:
        scenario_data, spec = load_scenario(scenario_id)
        entry = find_entry_event(scenario_data, spec)
        alert = build_alert_event(entry)
    except Exception as exc:
        return _json(
            {
                "status": "error",
                "error": f"Unable to load scenario {scenario_id!r}: {exc}",
            }
        )

    payload = {
        "technique": alert.technique_id,
        "asset": alert.asset_id,
        "tactic": alert.tactic,
        "timestamp": alert.timestamp,
        "log_source": alert.log_source,
        "anomaly_score": alert.anomaly_score,
        "attributes": alert.attributes,
    }
    with _RUN_LOCK:
        report = _scenario_runner().run(
            payload,
            scenario_id=scenario_id,
            max_rounds=max_rounds,
        )
    return _json(_compact_report(report))


@tool
def run_production_trace(
    technique: str,
    asset: str,
    scenario_id: str = "",
    raw_log_ref: str = "",
    tactic: str = "",
    timestamp: str = "",
    log_source: str = "alert",
    anomaly_score: float = 0.5,
    max_rounds: int = 30,
) -> str:
    """Run a real SOAR/Wazuh investigation when production access is enabled.

    For indexed scenarios such as pipeline_18, pass scenario_id to apply registry
    Wazuh scope (e.g. INC-PIPELINE_18 + is_attack). Pass raw_log_ref when anchoring
    on a specific alert.

    Returns compact report with investigation_status, chain_build_label,
    attribution_label, and lock_loop round-by-round diagnostics.

    This may perform external queries. It is denied unless the backend process
    has TRACE_AGENT_ALLOW_PRODUCTION=1.
    """
    if os.getenv("TRACE_AGENT_ALLOW_PRODUCTION", "0") != "1":
        return _json(
            {
                "status": "denied",
                "error": (
                    "Production tracing is disabled. Set "
                    "TRACE_AGENT_ALLOW_PRODUCTION=1 in the backend process."
                ),
            }
        )
    if not technique.strip() or not asset.strip():
        return _json(
            {"status": "error", "error": "technique and asset are required"}
        )
    if not 0.0 <= anomaly_score <= 1.0:
        return _json(
            {"status": "error", "error": "anomaly_score must be between 0 and 1"}
        )
    if max_rounds < 1 or max_rounds > 100:
        return _json({"status": "error", "error": "max_rounds must be 1..100"})

    payload = {
        "technique": technique.strip(),
        "asset": asset.strip(),
        "tactic": tactic.strip() or None,
        "timestamp": timestamp.strip() or None,
        "log_source": log_source,
        "anomaly_score": anomaly_score,
        "attributes": (
            {"raw_log_ref": raw_log_ref.strip()}
            if raw_log_ref.strip()
            else {}
        ),
    }
    sid = scenario_id.strip() or None
    with _RUN_LOCK:
        report = _production_runner().run(
            payload,
            scenario_id=sid,
            max_rounds=max_rounds,
        )
    return _json(_compact_report(report))


TRACE_TOOLS = [
    list_trace_scenarios,
    inspect_trace_prior,
    run_trace_scenario,
    run_production_trace,
]

