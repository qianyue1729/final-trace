"""Decision guardrails — prevent over-confident production actions."""
from trace_engine.decision_guardrails import apply_decision_guardrails


def _ubuntu_t1110_review_fixture() -> dict:
    """Synthetic report matching ubuntu-server T1110 production review."""
    return {
        "status": "completed",
        "decision": {
            "action": "contain_escalate",
            "investigation_score": 0.4815,
            "confidence": None,
            "confidence_status": "unavailable",
            "automation_eligible": False,
            "stop_reason": "budget",
            "reason_codes": [
                "calibrator_missing",
                "calibration_not_stable",
                "telemetry_coverage_truncated",
            ],
            "unresolved_obligations": [
                {
                    "id": "lifecycle_1",
                    "type": "initial_access",
                    "hard": True,
                    "overdue": True,
                    "attempts": 25,
                    "blocked_reason": "",
                }
            ],
        },
        "usage": {
            "rounds": 25,
            "soar_fetch": {
                "queries": 54,
                "errors": 24,
                "coverage_truncated": True,
            },
            "model_planner": [
                {"round": i, "mode": "shadow", "abstained": True, "accepted": 0}
                for i in range(1, 26)
            ],
        },
        "graph": {
            "nodes": [
                {
                    "id": "1",
                    "technique": "T1110",
                    "host": "ubuntu-server",
                    "attributed": True,
                }
            ],
            "edges": [],
        },
    }


def test_ubuntu_t1110_review_forces_inconclusive():
    report = apply_decision_guardrails(_ubuntu_t1110_review_fixture())
    decision = report["decision"]
    assert decision["action"] == "inconclusive"
    assert decision["original_action"] == "contain_escalate"
    assert decision["require_human_review"] is True
    flags = set(decision["guardrail_flags"])
    assert "data_collection_critical_failure" in flags
    assert "attack_chain_unresolved" in flags
    assert "obligation_lifecycle_1_unresolved" in flags
    assert "planner_non_functional" in flags
    assert "telemetry_coverage_insufficient" in flags
    assert "score_action_mismatch" in flags
    assert "confidence_unavailable" in flags
    assert "investigation_budget_exhausted" in flags


def test_healthy_scenario_report_unchanged():
    report = apply_decision_guardrails({
        "decision": {
            "action": "monitor",
            "investigation_score": 0.12,
            "confidence_status": "unavailable",
            "stop_reason": "voi_floor",
            "reason_codes": ["advisory_action_only"],
            "unresolved_obligations": [],
        },
        "usage": {
            "soar_fetch": {"queries": 10, "errors": 0, "coverage_truncated": False},
            "model_planner": [{"mode": "shadow", "abstained": True, "accepted": 0}],
        },
        "graph": {
            "nodes": [{"id": "1"}, {"id": "2"}],
            "edges": [{"source": "1", "target": "2"}],
        },
    })
    assert report["decision"]["action"] == "monitor"
    assert report["decision"].get("require_human_review") is not True
