"""B2.2 TRACE adapter tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_agent.eval.adapters.darpa_tc_trace import (
    TraceAdapter,
    TraceAdapterConfig,
    list_trace_sample_paths,
    load_all_trace_graph_fixtures,
    load_trace_graph_fixture,
    read_trace_events,
)
from trace_agent.eval.graph_replay import is_darpa_trace_fixture, is_graph_fixture, run_graph_case
from trace_agent.prior_v2 import PriorManager

GRAPH_DIR = Path(__file__).resolve().parent / "graph"
EXPECTED = 2


@pytest.fixture(scope="module")
def trace_samples():
    paths = list_trace_sample_paths()
    assert len(paths) >= EXPECTED
    return paths


@pytest.fixture(scope="module")
def trace_fixtures():
    return load_all_trace_graph_fixtures()


@pytest.fixture(scope="module")
def trace_results(trace_fixtures):
    return [run_graph_case(f, prior_manager=PriorManager()) for f in trace_fixtures]


def test_trace_adapter_protocol():
    adapter = TraceAdapter()
    assert adapter.source_name == "darpa_tc_trace"


def test_all_trace_fixtures_valid(trace_fixtures):
    assert len(trace_fixtures) >= EXPECTED
    for fx in trace_fixtures:
        assert is_graph_fixture(fx)
        assert is_darpa_trace_fixture(fx)
        assert fx["adapter_meta"]["normalization_stats"]["source"] == "darpa_tc_trace"


def test_committed_trace_graph_fixtures(trace_fixtures):
    for fx in trace_fixtures:
        on_disk = GRAPH_DIR / f"{fx['case_id']}.json"
        assert on_disk.is_file(), fx["case_id"]
        disk = json.loads(on_disk.read_text(encoding="utf-8"))
        assert disk["source"] == "darpa_tc_trace"
        assert disk["ground_truth_subgraph"]["attack_edges"] == fx["ground_truth_subgraph"]["attack_edges"]


def test_trace_run_graph_case(trace_results):
    for result in trace_results:
        m = result["metrics"]
        assert m["root_cause_hit_at_k"] is not None
        assert m["attack_subgraph_recall"] is not None
        assert m["boundary_precision"] is not None
        assert m["benign_pollution_rate"] is not None
        assert m["probe_cost_to_decision"]["probes"] >= 1
        assert isinstance(m["decision_accuracy"], bool)


def test_trace_no_benign_pollution(trace_results):
    for result in trace_results:
        assert result["metrics"]["benign_pollution_rate"]["count"] == 0, result["case_id"]


def test_trace_read_events(trace_samples):
    raw = read_trace_events(trace_samples[0])
    assert raw["metadata"]["performer"] == "TRACE"
    assert len(raw["events"]) >= 5
