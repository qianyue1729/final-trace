"""B2.1 THEIA adapter tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_agent.eval.adapters.darpa_tc_theia import (
    TheiaAdapter,
    TheiaAdapterConfig,
    list_theia_sample_paths,
    load_all_theia_graph_fixtures,
    load_theia_graph_fixture,
    read_theia_events,
)
from trace_agent.eval.graph_replay import is_darpa_theia_fixture, is_graph_fixture, run_graph_case
from trace_agent.prior_v2 import PriorManager

DATA_DIR = Path(__file__).resolve().parent / "data" / "theia"
GRAPH_DIR = Path(__file__).resolve().parent / "graph"
EXPECTED = 3


@pytest.fixture(scope="module")
def theia_samples():
    paths = list_theia_sample_paths()
    assert len(paths) >= EXPECTED
    return paths


@pytest.fixture(scope="module")
def theia_fixtures():
    return load_all_theia_graph_fixtures()


@pytest.fixture(scope="module")
def theia_results(theia_fixtures):
    return [run_graph_case(f, prior_manager=PriorManager()) for f in theia_fixtures]


def test_theia_adapter_protocol():
    adapter = TheiaAdapter()
    assert adapter.source_name == "darpa_tc_theia"


def test_all_theia_fixtures_valid(theia_fixtures):
    assert len(theia_fixtures) >= EXPECTED
    for fx in theia_fixtures:
        assert is_graph_fixture(fx)
        assert is_darpa_theia_fixture(fx)
        assert fx["adapter_meta"]["normalization_stats"]["source"] == "darpa_tc_theia"


def test_committed_theia_graph_fixtures(theia_fixtures):
    for fx in theia_fixtures:
        on_disk = GRAPH_DIR / f"{fx['case_id']}.json"
        assert on_disk.is_file(), fx["case_id"]
        disk = json.loads(on_disk.read_text(encoding="utf-8"))
        assert disk["source"] == "darpa_tc_theia"
        assert disk["ground_truth_subgraph"]["attack_edges"] == fx["ground_truth_subgraph"]["attack_edges"]


def test_theia_run_graph_case(theia_results):
    for result in theia_results:
        m = result["metrics"]
        assert m["root_cause_hit_at_k"] is not None
        assert m["attack_subgraph_recall"] is not None
        assert m["boundary_precision"] is not None
        assert m["benign_pollution_rate"] is not None
        assert m["probe_cost_to_decision"]["probes"] >= 1
        assert isinstance(m["decision_accuracy"], bool)


def test_theia_no_benign_pollution(theia_results):
    for result in theia_results:
        assert result["metrics"]["benign_pollution_rate"]["count"] == 0, result["case_id"]


def test_theia_read_events(theia_samples):
    raw = read_theia_events(theia_samples[0])
    assert raw["metadata"]["performer"] == "THEIA"
    assert len(raw["events"]) >= 5
