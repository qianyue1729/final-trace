"""Sigma visibility ablation sanity — no_sigma must not collapse causal metrics but should drop visibility."""
from trace_agent.decision.belief import DecisionLedger
from trace_agent.eval.ablation_replay import run_ablation
from trace_agent.eval.prior_replay import FIXTURES_DIR


def test_sigma_visibility_delta_gate():
    ab = run_ablation(FIXTURES_DIR)
    full = ab["modes"]["full"]
    ns = ab["modes"]["no_sigma"]
    assert abs((full["mean_max_prior"] or 0) - (ns["mean_max_prior"] or 0)) < 0.15
    assert (ns["sigma_visibility"]["mean_recommended_log_source_count"] or 0) < (
        full["sigma_visibility"]["mean_recommended_log_source_count"] or 0
    )
    assert ab["sigma_visibility_delta_gate"]["pass"] is True
