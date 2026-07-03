"""Mordor / OTRF L1 graph replay regression tests (A+)."""
from __future__ import annotations

import pytest

from trace_agent.eval.graph_fixture_builder import all_mordor_graph_fixtures, is_mordor_graph_fixture
from trace_agent.eval.graph_replay import (
    GRAPH_FIXTURES_DIR,
    load_graph_fixtures,
    load_mordor_graph_fixtures,
    run_graph_case,
)
from trace_agent.prior_v2 import PriorManager

MORDOR_CASE_IDS = [f["case_id"] for f in all_mordor_graph_fixtures()]


@pytest.fixture(scope="module")
def mordor_fixtures():
    loaded = load_mordor_graph_fixtures(GRAPH_FIXTURES_DIR)
    assert len(loaded) >= len(MORDOR_CASE_IDS)
    return loaded


@pytest.fixture(scope="module")
def mordor_report(mordor_fixtures):
    cases = [run_graph_case(f, prior_manager=PriorManager()) for f in mordor_fixtures]
    passed = sum(1 for c in cases if c["passed"])
    return {"cases": cases, "summary": {"total": len(cases), "passed": passed}}


def test_mordor_graph_cases_load(mordor_fixtures):
    ids = {f["case_id"] for f in mordor_fixtures}
    for case_id in MORDOR_CASE_IDS:
        assert case_id in ids
    assert all(is_mordor_graph_fixture(f) for f in mordor_fixtures)
    assert all(f.get("replay_driver", {}).get("pollute_queue") for f in mordor_fixtures)
    for fx in mordor_fixtures:
        for key in ("entry_alert", "world_graph", "replay_driver", "ground_truth_subgraph", "expected_decision"):
            assert key in fx


def test_mordor_builder_matches_disk(mordor_fixtures):
    built = {f["case_id"]: f for f in all_mordor_graph_fixtures()}
    for fx in mordor_fixtures:
        assert fx["case_id"] in built
        assert fx["ground_truth_subgraph"]["attack_edges"] == built[fx["case_id"]]["ground_truth_subgraph"]["attack_edges"]


def test_mordor_graph_metrics_are_computed(mordor_report):
    for case in mordor_report["cases"]:
        m = case["metrics"]
        assert m["root_cause_hit_at_k"] is True, case["case_id"]
        assert m["attack_subgraph_recall"] is not None
        fx = next(f for f in load_mordor_graph_fixtures(GRAPH_FIXTURES_DIR) if f["case_id"] == case["case_id"])
        min_recall = float((fx.get("replay_config") or {}).get("min_attack_recall", 0.6))
        assert m["attack_subgraph_recall"] >= min_recall, case["case_id"]
        assert "probes" in m["probe_cost_to_decision"]
        assert isinstance(m["decision_accuracy"], bool)


def test_mordor_graph_no_benign_pollution(mordor_report):
    for case in mordor_report["cases"]:
        m = case["metrics"]
        assert m["benign_pollution_rate"]["count"] == 0, case["case_id"]
        assert m["benign_pollution_rate"]["oos_count"] == 0, case["case_id"]
        bc = m["boundary_checks"]
        exclude = bc.get("must_exclude_ok")
        if exclude is not None:
            assert exclude is True, case["case_id"]


@pytest.mark.parametrize("case_id", MORDOR_CASE_IDS)
def test_mordor_distractors_revealed_not_wired(case_id, mordor_fixtures):
    result = run_graph_case(
        next(f for f in mordor_fixtures if f["case_id"] == case_id),
        prior_manager=PriorManager(),
    )
    revealed = set(result["metrics"]["revealed_world_nodes"])
    pollute = set(
        next(f for f in mordor_fixtures if f["case_id"] == case_id)["replay_driver"]["pollute_queue"]
    )
    assert pollute & revealed, f"expected pollute nodes revealed for {case_id}"
    assert result["metrics"]["benign_pollution_rate"]["count"] == 0


def test_mordor_probe_cost_within_budget(mordor_report):
    for case in mordor_report["cases"]:
        fx = next(f for f in load_graph_fixtures(GRAPH_FIXTURES_DIR) if f["case_id"] == case["case_id"])
        budget = int((fx.get("replay_config") or {}).get("max_probes", 60))
        assert case["metrics"]["probe_cost_to_decision"]["probes"] <= budget
