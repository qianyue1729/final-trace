"""T18-T20: probability semantics, calibration skip, flow trace."""
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.eval.calibration import run_calibration
from trace_agent.eval.prior_replay import load_fixtures, run_all
from trace_agent.prior_v2 import PriorManager


def test_investigation_prior_semantics():
    seed = DecisionLedger(PriorManager(load_prior_bundle())).seed(
        AlertEvent("T1059.001", tactic="execution", platform="windows", log_source="process_creation")
    )
    e = seed.explanations[0]
    assert e.probability_status == "uncalibrated"
    assert e.calibrated_probability is None
    assert e.investigation_prior_score == e.prior_probability
    d = seed.to_dict()
    assert "probability_semantics" in d


def test_calibration_skipped_on_synthetic_only():
    report = run_all()
    cal = run_calibration(report, load_fixtures())
    assert cal["calibration_status"] == "skipped"


def test_calibration_experimental_with_labeled():
    from trace_agent.eval.prior_replay import LABELED_DIR, load_fixtures as lf

    if not LABELED_DIR.is_dir():
        return
    labeled = lf(LABELED_DIR)
    if len(labeled) < 30:
        return
    report = run_all(LABELED_DIR)
    cal = run_calibration(report, labeled)
    assert cal["calibration_status"] in ("experimental", "stable")
    assert cal.get("brier_score") is not None


def test_attack_flow_trace_in_passport():
    seed = DecisionLedger(PriorManager(load_prior_bundle())).seed(
        AlertEvent("T1059.001", tactic="execution", platform="windows", log_source="process_creation")
    )
    trace = seed.explanations[0].support["evidence_passport"]["source_trace"]
    assert "attack_flow_trace" in trace
