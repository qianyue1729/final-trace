"""C0 OpTC-like multi-host graph replay tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_agent.eval.graph_replay import is_graph_fixture, is_optc_multihost_toy_fixture, run_graph_case
from trace_agent.prior_v2 import PriorManager

FIXTURE_PATH = Path(__file__).resolve().parent / "graph" / "optc_multihost_lateral_toy_001.json"


@pytest.fixture(scope="module")
def multihost_fixture():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def multihost_result(multihost_fixture):
    return run_graph_case(multihost_fixture, prior_manager=PriorManager())


def test_multihost_fixture_schema(multihost_fixture):
    assert is_graph_fixture(multihost_fixture)
    assert is_optc_multihost_toy_fixture(multihost_fixture)
    gt = multihost_fixture["ground_truth_subgraph"]
    assert gt.get("attack_hosts") == ["host-a", "host-b"]
    assert gt.get("attack_event_ids")
    assert gt.get("attack_edge_ids")


def test_multihost_run_graph_case(multihost_result):
    m = multihost_result["metrics"]
    assert m["root_cause_hit_at_k"] is not None
    assert m["attack_subgraph_recall"] is not None
    assert m["benign_pollution_rate"] is not None
    mh = m.get("multihost") or {}
    assert mh, "C-specific multihost metrics expected"
    for key in (
        "cross_host_attack_recall",
        "lateral_movement_recall",
        "network_pivot_recall",
        "benign_cross_host_pollution_rate",
        "oos_host_split_accuracy",
        "hosts_over_attributed",
    ):
        assert key in mh, key


def test_multihost_no_benign_cross_host_pollution(multihost_result):
    mh = multihost_result["metrics"]["multihost"]
    assert mh["benign_cross_host_pollution_rate"]["count"] == 0
    assert multihost_result["metrics"]["benign_pollution_rate"]["count"] == 0


def test_multihost_oos_host_not_in_attack_scope(multihost_result):
    mh = multihost_result["metrics"]["multihost"]
    assert mh["oos_host_split_accuracy"] == 1.0
    assert mh["hosts_over_attributed"]["count"] == 0


def test_cross_host_edges_represented(multihost_fixture):
    edges = multihost_fixture["world_graph"]["edges"]
    cross = [e for e in edges if e.get("edge_scope") == "cross_host" and e.get("role") == "attack"]
    assert len(cross) >= 1
    assert cross[0].get("network_flow_id")
