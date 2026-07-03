"""B1 DARPA TC CADETS adapter tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_agent.eval.adapters.darpa_tc_cadets import (
    CadetsAdapterConfig,
    default_cadets_sample_path,
    load_cadets_graph_fixture,
    normalize_cadets_world_graph,
    read_cadets_events,
)
from trace_agent.eval.graph_replay import is_graph_fixture, run_graph_case
from trace_agent.prior_v2 import PriorManager

CADETS_DATA = Path(__file__).resolve().parent / "data" / "cadets" / "cadets_sample_001.json"
GRAPH_FIXTURE = Path(__file__).resolve().parent / "graph" / "darpa_cadets_sample_001.json"


@pytest.fixture(scope="module")
def cadets_fixture():
    return load_cadets_graph_fixture(
        CadetsAdapterConfig(input_path=CADETS_DATA, scenario_id="darpa_cadets_sample_001")
    )


def test_read_cadets_events():
    raw = read_cadets_events(CADETS_DATA)
    assert len(raw["events"]) >= 5
    assert raw["metadata"]["performer"] == "CADETS"


def test_normalize_world_graph():
    raw = read_cadets_events(CADETS_DATA)
    world = normalize_cadets_world_graph(raw)
    assert len(world["nodes"]) == len(raw["events"])
    attack_edges = [e for e in world["edges"] if e.get("role") == "attack"]
    assert len(attack_edges) >= 3


def test_adapter_produces_valid_graph_fixture(cadets_fixture):
    assert cadets_fixture["case_id"] == "darpa_cadets_sample_001"
    assert cadets_fixture["source"] == "darpa_tc_cadets"
    assert is_graph_fixture(cadets_fixture)
    for key in ("entry_alert", "world_graph", "replay_driver", "ground_truth_subgraph", "expected_decision"):
        assert key in cadets_fixture
    assert cadets_fixture["replay_driver"]["mode"] == "offline"
    gt = cadets_fixture["ground_truth_subgraph"]
    assert isinstance(gt["attack_edges"][0], list)


def test_committed_graph_fixture_matches_adapter(cadets_fixture):
    on_disk = json.loads(GRAPH_FIXTURE.read_text(encoding="utf-8"))
    assert on_disk["case_id"] == cadets_fixture["case_id"]
    assert on_disk["ground_truth_subgraph"]["attack_edges"] == cadets_fixture["ground_truth_subgraph"]["attack_edges"]


def test_run_graph_case_on_cadets(cadets_fixture):
    result = run_graph_case(cadets_fixture, prior_manager=PriorManager())
    m = result["metrics"]
    assert m["root_cause_hit_at_k"] is True
    assert m["attack_subgraph_recall"] is not None
    assert m["boundary_precision"] is not None
    assert m["benign_pollution_rate"]["count"] == 0
    assert m["probe_cost_to_decision"]["probes"] >= 1
    assert m["probe_cost_to_decision"]["rounds"] >= 1
    assert isinstance(m["decision_accuracy"], bool)


def test_cadets_no_auto_pollution(cadets_fixture):
    result = run_graph_case(cadets_fixture, prior_manager=PriorManager())
    pollute = set(cadets_fixture["replay_driver"]["pollute_queue"])
    revealed = set(result["metrics"]["revealed_world_nodes"])
    assert pollute & revealed
    assert result["metrics"]["benign_pollution_rate"]["count"] == 0
    bc = result["metrics"]["boundary_checks"]
    if bc.get("must_exclude_ok") is not None:
        assert bc["must_exclude_ok"] is True


def test_default_sample_path_exists():
    assert default_cadets_sample_path().is_file()
