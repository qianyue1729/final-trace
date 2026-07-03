"""Orchestrator demo plateau stop and round diagnostics."""
from trace_agent.agents.orchestrator import DecisionOrchestrator, BudgetState
from trace_agent.decision.types import AlertEvent
from trace_agent.loop.mock_executor import MockExecutor


def _minimal_orch(*, demo: bool = True) -> DecisionOrchestrator:
    alert = AlertEvent(
        technique_id="T1041",
        tactic="exfiltration",
        platform="Windows",
        log_source="alert",
        asset_id="db-prod-01",
        timestamp="1000.0",
        anomaly_score=0.5,
    )
    return DecisionOrchestrator(
        alert=alert,
        executor=MockExecutor([]),
        budget=BudgetState(total_rounds=20, total_probes=100, fanout_per_round=2),
        demo_profile_enabled=demo,
        demo_plateau_rounds=3,
        demo_min_graph_nodes=8,
        demo_min_graph_edges=6,
    )


def test_round_diagnostics_field_on_result():
    orch = _minimal_orch()
    orch._bootstrap()
    assert orch._round_diagnostics == []
    assert hasattr(orch, "_posterior_history")


def test_demo_plateau_stop_requires_graph_threshold():
    orch = _minimal_orch(demo=True)
    orch._bootstrap()
    orch._posterior_history = [0.457, 0.457, 0.457]
    assert orch._check_demo_plateau_stop() is None


def test_demo_partial_conclusion_monitor_to_escalate():
    orch = _minimal_orch(demo=True)
    orch._bootstrap()
    orch._demo_min_graph_nodes = 1
    orch._demo_min_graph_edges = 0
    decision, incomplete = orch._apply_demo_partial_conclusion(
        decision="monitor",
        incomplete=False,
        stop_reason="budget",
        unresolved_obligations=[{"id": "discriminative_1", "hard": False, "overdue": True}],
        leading_id="__null__",
        investigation_score=-0.086,
    )
    assert decision == "escalate_incomplete"
    assert incomplete is True
