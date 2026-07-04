"""ProvSec adapter and L1 graph replay tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from trace_agent.eval.adapters.provsec import (
    ProvSecAdapter,
    ProvSecAdapterConfig,
    default_provsec_case_path,
    load_all_provsec_fixtures,
    provsec_data_dir,
    list_provsec_case_paths,
)
from trace_agent.eval.adapters.provsec_common import (
    load_cve_map,
    read_provsec_events,
    aggregate_syscalls,
    normalize_provsec_world_graph,
)
from trace_agent.eval.graph_replay import is_graph_fixture, load_graph_fixtures, run_graph_case
from trace_agent.prior_v2 import PriorManager


FIXTURE_PATH = Path(__file__).parent / "graph" / "provsec_case_05_log4j.json"
DATA_PATH = default_provsec_case_path()


class TestProvSecDataReader:
    """Test ProvSec event reading and field mapping."""

    def test_read_provsec_events(self):
        raw = read_provsec_events(DATA_PATH, max_events=100)
        assert "events" in raw
        assert "metadata" in raw
        assert "ground_truth" in raw
        assert len(raw["events"]) == 100  # max_events cap
        # Check event has ProvSec fields
        evt = raw["events"][0]
        assert "evt.type" in evt
        assert "proc.name" in evt
        assert "role" in evt

    def test_event_count(self):
        raw = read_provsec_events(DATA_PATH, max_events=5000)
        attack = [e for e in raw["events"] if e.get("role") == "attack"]
        benign = [e for e in raw["events"] if e.get("role") == "benign"]
        assert len(attack) == 200
        assert len(benign) == 300


class TestSyscallAggregation:
    """Test syscall-to-security-event aggregation."""

    def test_aggregate_produces_events(self):
        raw = read_provsec_events(DATA_PATH, max_events=5000)
        cve_map = load_cve_map()
        aggregated = aggregate_syscalls(raw["events"], cve_map=cve_map)
        assert len(aggregated) > 0
        # Each aggregated event should have DARPA TC-compatible fields
        evt = aggregated[0]
        assert "event_id" in evt
        assert "relation" in evt
        assert "role" in evt
        assert "timestamp" in evt

    def test_aggregation_reduces_count(self):
        raw = read_provsec_events(DATA_PATH, max_events=5000)
        cve_map = load_cve_map()
        aggregated = aggregate_syscalls(raw["events"], cve_map=cve_map)
        # Aggregation should reduce 500 syscall events to fewer security events
        assert len(aggregated) <= len(raw["events"])


class TestWorldGraph:
    """Test world_graph normalization."""

    def test_normalize_world_graph(self):
        raw = read_provsec_events(DATA_PATH, max_events=5000)
        cve_map = load_cve_map()
        wg = normalize_provsec_world_graph(raw, cve_map=cve_map)
        assert "nodes" in wg
        assert "edges" in wg
        assert len(wg["nodes"]) > 0
        # Nodes should have standard fields
        node = wg["nodes"][0]
        assert "id" in node
        assert "technique" in node
        assert "tactic" in node
        assert "timestamp" in node


class TestGraphFixture:
    """Test fixture contract and graph replay."""

    def test_fixture_file_exists(self):
        assert FIXTURE_PATH.is_file(), f"Fixture not found: {FIXTURE_PATH}"

    def test_fixture_contract(self):
        fx = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        assert is_graph_fixture(fx)

    def test_fixture_metadata(self):
        fx = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        assert fx["case_id"] == "provsec_case_05"
        assert fx["source"] == "provsec"
        assert fx["schema_version"] == "graph_replay_v1"
        assert fx["entry_alert"]["technique_id"] == "T1190"
        assert fx["entry_alert"]["tactic"] == "initial-access"
        assert fx["expected_decision"]["action"] == "contain"

    def test_fixture_loads_with_others(self):
        all_fixtures = load_graph_fixtures()
        provsec = [f for f in all_fixtures if "provsec" in f.get("case_id", "")]
        assert len(provsec) >= 1

    def test_run_graph_case(self):
        """Run L1 graph replay on ProvSec fixture — the key integration test."""
        fx = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
        result = run_graph_case(fx, prior_manager=PriorManager())

        # Basic assertions
        assert result is not None
        metrics = result.get("metrics") or {}

        # The LOCK cycle should complete
        assert "probe_cost_to_decision" in metrics or "rounds_used" in result

        # Print metrics for visibility
        print(f"\n=== ProvSec L1 Graph Replay Results ===")
        print(f"  decision: {result.get('decision')}")
        print(f"  decision_accuracy: {metrics.get('decision_accuracy')}")
        print(f"  attack_subgraph_recall: {metrics.get('attack_subgraph_recall')}")
        print(f"  boundary_precision: {metrics.get('boundary_precision')}")
        print(f"  root_cause_hit@k: {metrics.get('root_cause_hit_at_k')}")
        print(f"  benign_pollution: {metrics.get('benign_pollution_rate')}")
        probes = metrics.get("probe_cost_to_decision") or {}
        print(f"  probes: {probes.get('probes')}, rounds: {probes.get('rounds')}")
