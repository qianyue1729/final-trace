"""Demo profile guardrails — escalate_incomplete preserved when config gaps only."""
from trace_engine.decision_guardrails import apply_decision_guardrails


def _pipeline18_like_report(*, action: str = "escalate_incomplete", stop_reason: str = "evidence_plateau_partial_chain") -> dict:
    nodes = [{"id": str(i)} for i in range(9)]
    edges = [{"source": str(i), "target": str(i + 1)} for i in range(7)]
    return {
        "status": "completed",
        "decision": {
            "action": action,
            "investigation_score": -0.0856,
            "confidence": None,
            "confidence_status": "unavailable",
            "stop_reason": stop_reason,
            "incomplete": True,
            "unresolved_obligations": [
                {
                    "id": "probe_gap_1",
                    "type": "coverage",
                    "hard": True,
                    "overdue": False,
                    "attempts": 2,
                    "resolved": False,
                }
            ],
        },
        "usage": {
            "rounds": 5,
            "soar_fetch": {
                "queries": 20,
                "errors": 0,
                "coverage_truncated": True,
            },
            "model_planner": [
                {"round": i, "mode": "shadow", "abstained": True, "accepted": 0, "provider_status": "disabled"}
                for i in range(1, 6)
            ],
        },
        "graph": {"nodes": nodes, "edges": edges},
    }


def test_demo_profile_preserves_escalate_incomplete():
    report = apply_decision_guardrails(
        _pipeline18_like_report(),
        demo_profile=True,
    )
    decision = report["decision"]
    assert decision["action"] == "escalate_incomplete"
    assert decision.get("original_action") is None
    assert decision["require_human_review"] is True
    warnings = set(decision.get("guardrail_warnings") or [])
    assert "planner_non_functional" in warnings
    assert "confidence_unavailable" in warnings
    assert "telemetry_coverage_insufficient" in warnings


def test_strict_profile_still_forces_inconclusive():
    report = apply_decision_guardrails(
        _pipeline18_like_report(stop_reason="budget"),
        demo_profile=False,
    )
    decision = report["decision"]
    assert decision["action"] == "inconclusive"
    assert decision["original_action"] == "escalate_incomplete"


def test_demo_profile_still_blocks_empty_graph():
    report = apply_decision_guardrails(
        {
            "decision": {
                "action": "escalate_incomplete",
                "investigation_score": -0.1,
                "confidence_status": "unavailable",
                "stop_reason": "evidence_plateau_partial_chain",
                "unresolved_obligations": [],
            },
            "usage": {
                "soar_fetch": {"queries": 1, "errors": 0, "coverage_truncated": False},
                "model_planner": [],
            },
            "graph": {"nodes": [{"id": "1"}], "edges": []},
        },
        demo_profile=True,
    )
    assert report["decision"]["action"] == "inconclusive"
