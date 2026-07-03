"""Tests for investigation presentation semantics."""
from __future__ import annotations

import sys
from pathlib import Path

BACKEND_SRC = Path(__file__).resolve().parents[2] / "deep-agent-backend" / "src"
if str(BACKEND_SRC) not in sys.path:
    sys.path.insert(0, str(BACKEND_SRC))

from trace_deep_agent.presentation import derive_investigation_presentation  # noqa: E402


def _attack_nodes(count: int) -> list[dict]:
    return [
        {"id": f"n{i}", "attributes": {"raw_log_ref": f"attack:{i}"}}
        for i in range(count)
    ]


def _pipeline_18_report(*, action: str = "escalate_incomplete") -> dict:
    nodes = _attack_nodes(19)
    return {
        "decision": {
            "action": action,
            "stop_reason": "evidence_plateau_partial_chain",
            "require_human_review": True,
            "boundary_decisions": {
                "initial_access": "contested",
                "execution": "contested",
                "lateral_movement": "contested",
            },
        },
        "usage": {
            "rounds": 5,
            "probes_used": 12,
            "elapsed_seconds": 42.5,
            "round_diagnostics": [
                {
                    "round": i,
                    "probes_selected": [f"probe_{i}"],
                    "probe_results_count": 3,
                    "attach_bucket_count": 2,
                    "new_graph_nodes": 4 if i == 1 else 0,
                    "new_graph_edges": 3 if i == 1 else 0,
                    "graph_nodes": 19 if i >= 1 else 0,
                    "graph_edges": 17 if i >= 1 else 0,
                    "p_atk_before": 0.457,
                    "p_atk_after": 0.457,
                    "delta_p_atk": 0.0,
                    "stop_reason_candidate": "evidence_plateau_partial_chain" if i == 5 else None,
                }
                for i in range(1, 6)
            ],
            "voi_audit": [{"round": 1, "operator": "temporal_correlation"}],
            "model_planner": [{"round": 1, "mode": "shadow", "abstained": True}],
        },
        "graph": {"nodes": nodes, "edges": [{"source": "n0", "target": "n1"}] * 17},
        "trace_coverage": {
            "candidate_chain": {
                "candidate_chain_events": 18,
                "candidate_chain_mode": "eval_attack_prefix",
                "noise_refs": 0,
            }
        },
    }


def test_escalate_incomplete_with_full_chain_is_needs_review_not_failure():
    result = derive_investigation_presentation(_pipeline_18_report())

    assert result["investigation_status"] == "completed_needs_review"
    assert result["display_headline"] == "调查完成 · 建议人工复核"
    assert result["is_demo_success"] is True
    assert result["chain_build_status"] == "success"
    assert result["chain_build_label"] == "建链成功"
    assert result["attribution_status"] == "contested"
    assert result["attribution_label"] == "归因待确认"


def test_inconclusive_is_failed_inconclusive():
    report = _pipeline_18_report(action="inconclusive")
    report["decision"]["stop_reason"] = "budget"
    result = derive_investigation_presentation(report)

    assert result["investigation_status"] == "failed_inconclusive"
    assert result["is_demo_success"] is False


def test_lock_loop_summary_has_five_rounds():
    result = derive_investigation_presentation(_pipeline_18_report())
    lock = result["lock_loop"]

    assert lock["rounds_used"] == 5
    assert len(lock["rounds"]) == 5
    assert lock["final_stop_reason"] == "evidence_plateau_partial_chain"
    assert lock["rounds"][0]["phase_flow"] == "L → Veto → O → C → K"
    assert lock["voi_operators_by_round"][1] == ["temporal_correlation"]
