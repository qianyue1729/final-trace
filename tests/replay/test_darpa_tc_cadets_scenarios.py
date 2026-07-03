"""B1.5 CADETS multi-scenario stability tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_agent.eval.adapters.darpa_tc_cadets import (
    CadetsAdapterConfig,
    cadets_benchmark_markdown,
    cadets_data_dir,
    cadets_scenario_summary,
    list_cadets_sample_paths,
    load_all_cadets_graph_fixtures,
    load_cadets_graph_fixture,
    select_entry_alert,
    build_ground_truth_subgraph,
    normalize_cadets_world_graph,
    read_cadets_events,
)
from trace_agent.eval.adapters.normalization_stats import collect_normalization_stats
from trace_agent.eval.graph_replay import is_darpa_cadets_fixture, is_graph_fixture, run_graph_case
from trace_agent.prior_v2 import PriorManager

GRAPH_DIR = Path(__file__).resolve().parent / "graph"
EXPECTED_SCENARIOS = 6


@pytest.fixture(scope="module")
def cadets_samples():
    paths = list_cadets_sample_paths()
    assert len(paths) >= EXPECTED_SCENARIOS
    return paths


@pytest.fixture(scope="module")
def cadets_fixtures():
    return load_all_cadets_graph_fixtures()


@pytest.fixture(scope="module")
def cadets_results(cadets_fixtures):
    return [run_graph_case(f, prior_manager=PriorManager()) for f in cadets_fixtures]


def test_cadets_sample_files_exist(cadets_samples):
    assert len(cadets_samples) >= EXPECTED_SCENARIOS


def test_all_cadets_fixtures_valid(cadets_fixtures):
    assert len(cadets_fixtures) >= EXPECTED_SCENARIOS
    for fx in cadets_fixtures:
        assert is_graph_fixture(fx)
        assert is_darpa_cadets_fixture(fx)
        stats = fx["adapter_meta"]["normalization_stats"]
        assert stats["events_in"] >= stats["events_kept"] >= 1
        assert "relations" in stats


def test_normalization_stats_shape(cadets_fixtures):
    for fx in cadets_fixtures:
        stats = fx["adapter_meta"]["normalization_stats"]
        assert stats["source"] == "darpa_tc_cadets"
        assert isinstance(stats.get("nodes"), dict)
        assert isinstance(stats.get("dropped_events"), dict)


def test_entry_alert_auto_leaf_strategy(cadets_samples):
    path = cadets_samples[0]
    raw = read_cadets_events(path)
    world = normalize_cadets_world_graph(raw)
    gt = dict(raw.get("ground_truth") or {})
    gt.pop("entry_event_id", None)
    explicit = select_entry_alert(world, gt, strategy="explicit")
    auto_leaf = select_entry_alert(world, gt, strategy="auto_leaf")
    assert explicit["event_id"]
    assert auto_leaf["event_id"]
    assert auto_leaf["event_id"] in {n["id"] for n in world["nodes"]}


def test_committed_graph_fixtures_match_adapter(cadets_fixtures):
    for fx in cadets_fixtures:
        on_disk = GRAPH_DIR / f"{fx['case_id']}.json"
        assert on_disk.is_file(), fx["case_id"]
        disk = json.loads(on_disk.read_text(encoding="utf-8"))
        assert disk["ground_truth_subgraph"]["attack_edges"] == fx["ground_truth_subgraph"]["attack_edges"]


@pytest.mark.parametrize("strategy", ["explicit", "auto_leaf", "auto_terminal"])
def test_entry_alert_strategies_produce_fixture(strategy, cadets_samples):
    path = cadets_samples[1]
    fx = load_cadets_graph_fixture(
        CadetsAdapterConfig(
            input_path=path,
            scenario_id="darpa_cadets_sample_002",
            entry_alert_strategy=strategy,
        )
    )
    assert fx["entry_alert"]["event_id"]
    assert fx["adapter_meta"]["entry_alert_strategy"] == strategy


def test_all_scenarios_run_graph_case(cadets_results):
    for result in cadets_results:
        m = result["metrics"]
        assert m["root_cause_hit_at_k"] is not None
        assert m["attack_subgraph_recall"] is not None or result["category"] == "benign"
        assert m["boundary_precision"] is not None or result["category"] == "benign"
        assert m["benign_pollution_rate"] is not None
        assert m["probe_cost_to_decision"]["probes"] >= 1
        assert isinstance(m["decision_accuracy"], bool)


def test_no_benign_oos_auto_pollution(cadets_results):
    for result in cadets_results:
        assert result["metrics"]["benign_pollution_rate"]["count"] == 0, result["case_id"]
        assert result["metrics"]["benign_pollution_rate"]["oos_count"] == 0, result["case_id"]


def test_attack_recall_report_only(cadets_results):
    for result in cadets_results:
        if result["category"] == "benign":
            continue
        recall = result["metrics"]["attack_subgraph_recall"]
        assert recall is not None
        assert recall >= 0.0


def test_cadets_scenario_summary(cadets_fixtures):
    summary = cadets_scenario_summary(cadets_fixtures)
    assert summary["n_scenarios"] >= EXPECTED_SCENARIOS
    assert len(summary["cases"]) >= EXPECTED_SCENARIOS


def test_cadets_benchmark_markdown(cadets_fixtures, cadets_results):
    md = cadets_benchmark_markdown(cadets_fixtures, cadets_results)
    assert "CADETS Provenance Graph Benchmark" in md
    assert "darpa_cadets_sample_001" in md


def test_report_markdown_groups_cadets_source(cadets_results):
    from trace_agent.eval.graph_replay import report_markdown

    passed = sum(1 for r in cadets_results if r["passed"])
    report = {
        "summary": {"total": len(cadets_results), "passed": passed, "failed": len(cadets_results) - passed},
        "cases": cadets_results,
    }
    md = report_markdown(report)
    assert "darpa_tc_cadets" in md
    assert "By source" in md


def test_dropped_events_audit():
    raw = {
        "events": [
            {"event_id": "ok", "relation": "process_spawn", "subject": {"type": "process"}, "object": {"type": "file"}},
            {"relation": "process_spawn", "subject": {"type": "process"}, "object": {"type": "file"}},
            {"event_id": "badrel", "relation": "unknown_xyz", "subject": {"type": "process"}, "object": {"type": "file"}},
        ]
    }
    kept, dropped = __import__(
        "trace_agent.eval.adapters.normalization_stats", fromlist=["audit_raw_events"]
    ).audit_raw_events(raw)
    assert len(kept) == 1
    assert dropped.get("missing_event_id", 0) >= 1
