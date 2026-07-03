"""C1 Corrected OpTC adapter tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_agent.eval.adapters.optc_corrected import (
    OptcCorrectedAdapter,
    OptcAdapterConfig,
    list_optc_sample_paths,
    load_all_optc_graph_fixtures,
    load_optc_graph_fixture,
    read_optc_events,
)
from trace_agent.eval.graph_replay import is_graph_fixture, is_optc_fixture, run_graph_case
from trace_agent.prior_v2 import PriorManager

DATA = Path(__file__).resolve().parent / "data" / "optc" / "optc_sample_001.json"
GRAPH = Path(__file__).resolve().parent / "graph" / "optc_sample_001.json"


@pytest.fixture(scope="module")
def optc_fixture():
    return load_optc_graph_fixture(OptcAdapterConfig(input_path=DATA, scenario_id="optc_sample_001"))


@pytest.fixture(scope="module")
def optc_result(optc_fixture):
    return run_graph_case(optc_fixture, prior_manager=PriorManager())


def test_optc_adapter_protocol():
    assert OptcCorrectedAdapter().source_name == "optc_corrected"


def test_read_optc_events():
    raw = read_optc_events(DATA)
    assert raw["metadata"]["performer"] == "OpTC"
    assert len(raw["events"]) >= 5


def test_adapter_produces_valid_fixture(optc_fixture):
    assert optc_fixture["source"] == "optc_corrected"
    assert is_graph_fixture(optc_fixture)
    assert is_optc_fixture(optc_fixture)
    gt = optc_fixture["ground_truth_subgraph"]
    assert gt["attack_hosts"] == ["host-a", "host-b"]
    assert gt["attack_event_ids"]
    stats = optc_fixture["adapter_meta"]["normalization_stats"]
    assert stats["source"] == "optc_corrected"


def test_multihost_fields_preserved(optc_fixture):
    lateral = next(
        n for n in optc_fixture["world_graph"]["nodes"] if n["id"] == "optc:e_lateral"
    )
    attrs = lateral["attributes"]
    assert attrs.get("src_host") == "host-a"
    assert attrs.get("dst_host") == "host-b"
    assert attrs.get("network_flow_id") == "flow:host-a:host-b:445"


def test_committed_graph_fixture_matches(optc_fixture):
    assert GRAPH.is_file()
    on_disk = json.loads(GRAPH.read_text(encoding="utf-8"))
    assert on_disk["ground_truth_subgraph"]["attack_hosts"] == optc_fixture["ground_truth_subgraph"]["attack_hosts"]


def test_run_graph_case(optc_result):
    m = optc_result["metrics"]
    assert m["root_cause_hit_at_k"] is not None
    assert m["attack_subgraph_recall"] is not None
    assert m["benign_pollution_rate"]["count"] == 0
    mh = m.get("multihost") or {}
    assert mh.get("benign_cross_host_pollution_rate", {}).get("count") == 0


def test_load_all_optc_fixtures():
    fixtures = load_all_optc_graph_fixtures()
    assert len(fixtures) >= 1
    assert list_optc_sample_paths()
