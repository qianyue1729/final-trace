"""L1 graph replay contract tests (B0)."""
from __future__ import annotations

import pytest

from trace_agent.eval.graph_replay import (
    GRAPH_FIXTURES_DIR,
    aggregate_graph_metrics,
    is_graph_fixture,
    load_graph_fixtures,
    run_all_graph_replay,
    run_graph_case,
)
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def graph_fixtures():
    return load_graph_fixtures(GRAPH_FIXTURES_DIR)


@pytest.fixture(scope="module")
def graph_report(graph_fixtures):
    return run_all_graph_replay(GRAPH_FIXTURES_DIR, prior_manager=PriorManager())


def test_graph_fixture_count(graph_fixtures):
    assert len(graph_fixtures) >= 26
    assert all(is_graph_fixture(f) for f in graph_fixtures)


def test_graph_fixture_schema_fields(graph_fixtures):
    for fx in graph_fixtures:
        assert fx.get("schema_version") == "graph_replay_v1"
        assert "world_graph" in fx
        assert "replay_driver" in fx
        assert "replay_config" in fx


@pytest.mark.parametrize(
    "case_id",
    [
        "graph_toy_powershell_chain",
        "graph_toy_benign_admin",
        "graph_toy_oos_miner",
    ],
)
def test_graph_case_runs(case_id, graph_fixtures):
    fx = next(f for f in graph_fixtures if f["case_id"] == case_id)
    result = run_graph_case(fx, prior_manager=PriorManager())
    metrics = result["metrics"]
    assert "root_cause_hit_at_k" in metrics
    assert "attack_subgraph_recall" in metrics
    assert "boundary_precision" in metrics
    assert "benign_pollution_rate" in metrics
    assert "probe_cost_to_decision" in metrics
    assert "decision_accuracy" in metrics
    assert metrics["probe_cost_to_decision"]["rounds"] >= 1


def test_powershell_chain_recovers_attack(graph_report):
    case = next(c for c in graph_report["cases"] if c["case_id"] == "graph_toy_powershell_chain")
    m = case["metrics"]
    assert m["attack_subgraph_recall"] == 1.0
    assert case["metrics"]["boundary_checks"]["must_include_ok"] is True
    assert isinstance(m["decision_accuracy"], bool)


def test_benign_case_computes_decision_metric(graph_report):
    case = next(c for c in graph_report["cases"] if c["case_id"] == "graph_toy_benign_admin")
    assert "decision_actual" in case["metrics"]
    assert isinstance(case["metrics"]["decision_accuracy"], bool)


def test_oos_exclusion_boundary(graph_report):
    case = next(c for c in graph_report["cases"] if c["case_id"] == "graph_toy_oos_miner")
    bc = case["metrics"]["boundary_checks"]
    assert bc.get("must_include_ok") is True
    assert bc.get("must_exclude_ok") is True
    assert case["metrics"]["benign_pollution_rate"]["oos_count"] == 0


def test_aggregate_metrics(graph_report):
    agg = aggregate_graph_metrics(graph_report["cases"])
    assert agg["n_cases"] >= 3
    assert agg["decision_accuracy_rate"] is not None
    assert agg["mean_probe_cost"] >= 1
