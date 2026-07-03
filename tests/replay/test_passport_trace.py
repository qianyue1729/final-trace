"""Evidence passport source_trace smoke test."""
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.prior_v2 import PriorManager


def test_passport_has_source_trace():
    seed = DecisionLedger(PriorManager(load_prior_bundle())).seed(
        AlertEvent("T1059.001", tactic="execution", platform="windows", log_source="process_creation")
    )
    passport = seed.explanations[0].support.get("evidence_passport") or {}
    trace = passport.get("source_trace") or {}
    assert "attack_flow" in trace
    assert "sigma" in trace
