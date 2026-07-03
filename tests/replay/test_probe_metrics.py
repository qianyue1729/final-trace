"""P3 probe ground-truth metrics smoke tests."""
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.eval.ablation_replay import run_ablation
from trace_agent.eval.prior_replay import FIXTURES_DIR, load_fixtures, run_case
from trace_agent.eval.probe_metrics import collect_probe_metrics, probe_ground_truth
from trace_agent.prior_v2 import PriorManager
from trace_agent.probe.voi import recommend_log_source_probes


def test_fixtures_have_probe_ground_truth():
    fixtures = load_fixtures(FIXTURES_DIR)
    with_gt = [f for f in fixtures if probe_ground_truth(f)]
    assert len(with_gt) >= 70


def test_probe_metrics_on_fixture():
    fx = next(f for f in load_fixtures(FIXTURES_DIR) if probe_ground_truth(f))
    prior = PriorManager()
    alert = AlertEvent(**{**fx["alert"], "attributes": fx["alert"].get("attributes") or {}})
    ledger = DecisionLedger(prior)
    seed = ledger.seed(alert)
    probes = recommend_log_source_probes(alert, seed.explanations[0], prior)
    m = collect_probe_metrics(probes, fx)
    assert "probe_coverage_at_k" in m
    assert m.get("probe_must_not_violation") is False


def test_no_sigma_lowers_probe_coverage():
    ab = run_ablation(FIXTURES_DIR)
    full = ab["modes"]["full"]["probe_ground_truth"]
    ns = ab["modes"]["no_sigma"]["probe_ground_truth"]
    assert (full.get("probe_coverage_at_k") or 0) >= (ns.get("probe_coverage_at_k") or 0)
