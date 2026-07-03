"""Explanation card renderer smoke test."""
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.prior_v2 import PriorManager
from trace_agent.reporting.explanation_card import render_seed_cards


def test_explanation_card_renders():
    seed = DecisionLedger(PriorManager(load_prior_bundle())).seed(
        AlertEvent("T1059.001", tactic="execution", platform="windows", log_source="process_creation")
    )
    md = render_seed_cards(seed)
    assert "Why plausible" in md
    assert "Why this may be wrong" in md
    assert seed.visibility.get("observability_gap") is not None
