"""Orchestrator LOCK init tests."""
from trace_agent.agents.orchestrator import TraceOrchestrator
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.prior_v2 import PriorManager


def test_orchestrator_initialize_case_with_real_prior():
    prior = PriorManager(load_prior_bundle())
    orch = TraceOrchestrator(DecisionLedger(prior))
    alert = AlertEvent(
        technique_id="T1059.001",
        tactic="execution",
        platform="windows",
        log_source="process_creation",
        anomaly_score=0.85,
    )
    state = orch.initialize_case(alert)

    assert state.phase == "L_INITIALIZED"
    assert 1 <= len(state.decision_ledger_seed.explanations) <= 6
    assert state.obligation_ledger.get("items")
    assert "candidate_edges" in state.graph_ledger
    assert isinstance(state.recommended_probes, list)
    assert state.case_metadata["has_null_anchor"] is True
