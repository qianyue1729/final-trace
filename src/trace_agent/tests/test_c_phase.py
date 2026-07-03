"""Tests for C-phase pipeline: ProbeExecutor, MockExecutor, IngestPipeline."""
from __future__ import annotations

import time
import pytest
from dataclasses import dataclass, field
from typing import Any

from trace_agent.loop.probe import Probe
from trace_agent.loop.executor import ProbeExecutor
from trace_agent.loop.mock_executor import MockExecutor
from trace_agent.loop.scenario_executor import ScenarioExecutor
from trace_agent.loop.session_graph import SessionGraph
from trace_agent.loop.ingest import (
    IngestPipeline, IngestResult,
    ROUTE_ATTACH, ROUTE_WEAK, ROUTE_PARK, ROUTE_DISCARD, ROUTE_SPAWN,
)


# ─── Helpers / Stubs ─────────────────────────────────────────────────────────


def _make_probe(target="host-A", operator="process_tree", tactic="execution", probe_id=None):
    pid = probe_id or Probe.generate_id(target, operator, tactic)
    return Probe(
        id=pid,
        target=target,
        target_type="host",
        operator=operator,
        tactic=tactic,
        source="test",
    )


def _make_event(eid="EVT-0001", technique="T1059.001", tactic="execution",
                timestamp=None, source="sysmon", target="host-A", probe_id="P-test"):
    return {
        "id": eid,
        "technique": technique,
        "tactic": tactic,
        "timestamp": timestamp or time.time(),
        "source": source,
        "target": target,
        "probe_id": probe_id,
        "raw_data": {},
        "attributes": {},
    }


@dataclass
class StubTrust:
    """Minimal trust stub for testing."""
    integrity: float = 0.9
    adversary_controllable: bool = False


class StubTrustModel:
    """Duck-typed EvidenceTrustModel for testing."""

    def __init__(self, integrity: float = 0.9, adversary_ctrl: bool = False):
        self._integrity = integrity
        self._adversary_ctrl = adversary_ctrl

    def assess(self, event: dict) -> StubTrust:
        return StubTrust(integrity=self._integrity, adversary_controllable=self._adversary_ctrl)

    def weight_likelihood(self, likelihood_base: float, evidence_id: str) -> float:
        return likelihood_base * self._integrity


@dataclass
class StubExplanation:
    id: str
    prior_probability: float = 0.5
    techniques: list = field(default_factory=list)
    expected_tactics: list = field(default_factory=list)


class StubLedger:
    """Duck-typed RuntimeDecisionLedger for testing."""

    def __init__(self, explanations=None):
        self.explanations = explanations or [
            StubExplanation(id="E-001", techniques=["T1059.001"], expected_tactics=["execution"]),
            StubExplanation(id="E-002", techniques=["T1021.001"], expected_tactics=["lateral-movement"]),
        ]

    def _log_likelihood(self, event: dict, explanation, trust) -> float:
        """Simple mock: high score if technique matches."""
        technique = event.get("technique", "")
        if technique in getattr(explanation, "techniques", []):
            return -0.5  # Good fit
        return -2.5  # Poor fit


# ─── ProbeExecutor / MockExecutor Tests ───────────────────────────────────────


class TestMockExecutor:
    def test_mock_executor_available(self):
        """MockExecutor.available() always returns True."""
        executor = MockExecutor()
        assert executor.available() is True

    def test_mock_executor_empty_probes(self):
        """Empty probe list → empty events."""
        executor = MockExecutor(seed=42)
        result = executor.execute_fanout([])
        assert result == []

    def test_mock_executor_returns_events_from_scenario(self):
        """Events looked up by (target, operator) key."""
        scenario = {
            "events": {
                "(host-A, process_tree)": [
                    {"technique": "T1059.001", "tactic": "execution",
                     "timestamp": 1000.0, "source": "sysmon"},
                ]
            },
            "hit_rate": 1.0,
            "noise_rate": 0.0,
        }
        executor = MockExecutor(scenario=scenario, seed=42)
        probe = _make_probe(target="host-A", operator="process_tree")
        results = executor.execute_fanout([probe])
        assert len(results) >= 1
        assert results[0]["technique"] == "T1059.001"

    def test_mock_executor_hit_rate(self):
        """With hit_rate=0, no events should be returned."""
        scenario = {
            "events": {
                "(host-A, process_tree)": [
                    {"technique": "T1059.001", "tactic": "execution",
                     "timestamp": 1000.0, "source": "sysmon"},
                ]
            },
            "hit_rate": 0.0,
            "noise_rate": 0.0,
        }
        executor = MockExecutor(scenario=scenario, seed=42)
        probe = _make_probe(target="host-A", operator="process_tree")
        results = executor.execute_fanout([probe])
        assert results == []

    def test_mock_executor_events_tagged_with_probe_id(self):
        """Each returned event should contain probe_id."""
        scenario = {
            "events": {
                "(host-A, process_tree)": [
                    {"technique": "T1059.001", "tactic": "execution",
                     "timestamp": 1000.0, "source": "sysmon"},
                ]
            },
            "hit_rate": 1.0,
            "noise_rate": 0.0,
        }
        executor = MockExecutor(scenario=scenario, seed=42)
        probe = _make_probe(target="host-A", operator="process_tree", probe_id="P-UNIQUE")
        results = executor.execute_fanout([probe])
        assert len(results) >= 1
        assert results[0]["probe_id"] == "P-UNIQUE"

    def test_create_attack_scenario(self):
        """create_attack_scenario returns valid multi-round scenario."""
        scenario = MockExecutor.create_attack_scenario()
        assert "events" in scenario
        assert "hit_rate" in scenario
        assert len(scenario["events"]) >= 4  # multiple (target, operator) keys
        # Check known techniques present
        all_events = []
        for evts in scenario["events"].values():
            all_events.extend(evts)
        techniques = {e["technique"] for e in all_events}
        assert "T1566.001" in techniques  # initial-access
        assert "T1059.001" in techniques  # execution
        assert "T1048.003" in techniques  # exfiltration

    def test_create_benign_scenario(self):
        """create_benign_scenario returns valid scenario with benign events."""
        scenario = MockExecutor.create_benign_scenario()
        assert "events" in scenario
        assert scenario["hit_rate"] == 1.0
        all_events = []
        for evts in scenario["events"].values():
            all_events.extend(evts)
        # All events should have benign markers
        for ev in all_events:
            assert ev["attributes"].get("benign") is True


# ─── IngestPipeline Tests ─────────────────────────────────────────────────────


class TestIngestPipeline:
    def _make_pipeline(self, trust_integrity=0.9, adversary_ctrl=False,
                       with_ledger=True, graph=None):
        """Create a pipeline with stubs."""
        g = graph or SessionGraph()
        trust = StubTrustModel(integrity=trust_integrity, adversary_ctrl=adversary_ctrl)
        ledger = StubLedger() if with_ledger else None
        return IngestPipeline(trust_model=trust, graph=g, ledger=ledger)

    def test_ingest_empty_events(self):
        """Empty input → empty result."""
        pipeline = self._make_pipeline()
        result = pipeline.triage([])
        assert result.confirmed == []
        assert all(len(v) == 0 for v in result.routed.values())

    def test_l0_dedup(self):
        """Duplicate events are filtered."""
        pipeline = self._make_pipeline()
        ev = _make_event(eid="DUP-001")
        result = pipeline.triage([ev, ev.copy()])
        # Only one event should pass through
        total_routed = sum(len(v) for v in result.routed.values())
        assert total_routed == 1

    def test_id_prefix_does_not_change_c_phase_treatment(self):
        ts = time.time()
        scenario = {
            "events": [
                {
                    "raw_log_ref": prefix,
                    "ts": "2026-07-01T00:00:00Z",
                    "technique": "T1059.001",
                    "tactic": "execution",
                    "action": "EXEC",
                    "anomaly_score": 0.8,
                    "src_entity": {"attrs": {"host_uid": "host-A"}},
                    "attributes": {"is_attack": prefix.startswith("attack:")},
                }
                for prefix in ("attack:case:evt-1", "noise:case:evt-2")
            ]
        }
        probe = _make_probe()
        raw_events = ScenarioExecutor(scenario, seed=7).execute_fanout([probe])
        assert len(raw_events) == 2
        assert all("is_attack" not in event["attributes"] for event in raw_events)

        graph = SessionGraph()
        graph.add_events([{
            "id": "root",
            "technique": "T1566.001",
            "tactic": "initial-access",
            "timestamp": ts,
            "source": "sysmon",
            "attributes": {"target": "host-A"},
        }])
        for event in raw_events:
            event["timestamp"] = ts + 30
        result = self._make_pipeline(graph=graph).triage(
            raw_events,
            probes=[probe],
        )
        by_id = {event["id"]: event for event in result.all_events}
        attack = by_id["attack:case:evt-1"]
        noise = by_id["noise:case:evt-2"]
        compared = (
            "_l1_attachable",
            "_l1_temporal_fit",
            "_l2_trust_tier",
            "_l3_best_explanation",
            "_route_bucket",
            "_graph_eligible",
        )
        assert {key: attack.get(key) for key in compared} == {
            key: noise.get(key) for key in compared
        }

    def test_l0_malformed_filtered(self):
        """Events missing required fields are discarded."""
        pipeline = self._make_pipeline()
        malformed = {"id": "BAD-001"}  # missing technique, tactic, etc.
        good = _make_event(eid="GOOD-001")
        result = pipeline.triage([malformed, good])
        total_routed = sum(len(v) for v in result.routed.values())
        assert total_routed == 1

    def test_l1_structural_attachable(self):
        """Events near existing nodes should be marked attachable."""
        graph = SessionGraph()
        ts = time.time()
        graph.add_events([{
            "technique": "T1566.001",
            "tactic": "initial-access",
            "timestamp": ts,
            "source": "sysmon",
            "attributes": {"target": "host-A"},
        }])
        pipeline = self._make_pipeline(graph=graph)
        ev = _make_event(eid="ATT-001", tactic="execution", timestamp=ts + 30, target="host-A")
        result = pipeline.triage([ev])
        # Should be routed (not discarded), and marked attachable
        total = sum(len(v) for v in result.routed.values())
        assert total == 1
        routed_ev = None
        for bucket_events in result.routed.values():
            for e in bucket_events:
                if e["id"] == "ATT-001":
                    routed_ev = e
                    break
        assert routed_ev is not None
        assert routed_ev["_l1_attachable"] is True

    def test_l1_structural_not_attachable(self):
        """Isolated events with no graph neighbors are not attachable."""
        graph = SessionGraph()  # empty graph
        pipeline = self._make_pipeline(graph=graph)
        ev = _make_event(eid="ISO-001", timestamp=time.time())
        result = pipeline.triage([ev])
        routed_ev = None
        for bucket_events in result.routed.values():
            for e in bucket_events:
                if e["id"] == "ISO-001":
                    routed_ev = e
                    break
        assert routed_ev is not None
        assert routed_ev["_l1_attachable"] is False

    def test_l2_trust_annotation(self):
        """Trust tier is assigned based on trust model."""
        pipeline = self._make_pipeline(trust_integrity=0.9, adversary_ctrl=False)
        ev = _make_event(eid="TRUST-001")
        result = pipeline.triage([ev])
        assert len(result.trust_annotations) == 1
        ann = result.trust_annotations[0]
        assert ann["trust_tier"] == "forge_resistant"
        assert ann["integrity"] == 0.9

    def test_l3_attribution_with_ledger(self):
        """Explanation scores are computed when ledger is present."""
        pipeline = self._make_pipeline(with_ledger=True)
        # Event with technique T1059.001 should match E-001
        ev = _make_event(eid="ATTR-001", technique="T1059.001")
        result = pipeline.triage([ev])
        assert len(result.attribution_scores) == 1
        attr = result.attribution_scores[0]
        assert attr["best_explanation"] == "E-001"
        assert attr["scores"]["E-001"] > attr["scores"]["E-002"]

    def test_l3_attribution_without_ledger(self):
        """Graceful when no ledger is present."""
        pipeline = self._make_pipeline(with_ledger=False)
        ev = _make_event(eid="NOLEDGER-001")
        result = pipeline.triage([ev])
        # Should still route without error
        total_routed = sum(len(v) for v in result.routed.values())
        assert total_routed == 1

    def test_l4_route_attach(self):
        """High quality + attachable + clear attribution → ATTACH."""
        graph = SessionGraph()
        ts = time.time()
        graph.add_events([{
            "technique": "T1566.001",
            "tactic": "initial-access",
            "timestamp": ts,
            "source": "sysmon",
            "attributes": {"target": "host-A"},
        }])
        pipeline = self._make_pipeline(trust_integrity=0.9, adversary_ctrl=False, graph=graph)
        ev = _make_event(eid="ATTACH-001", technique="T1059.001",
                         tactic="execution", timestamp=ts + 30, target="host-A")
        result = pipeline.triage([ev])
        assert len(result.routed[ROUTE_ATTACH]) == 1
        assert len(result.confirmed) == 1

    def test_l4_route_discard(self):
        """Malformed events don't make it through L0 → effectively DISCARD."""
        pipeline = self._make_pipeline()
        malformed = {"id": "MAL-001", "technique": "T1059"}  # missing fields
        result = pipeline.triage([malformed])
        # Malformed is filtered at L0, nothing routed
        total = sum(len(v) for v in result.routed.values())
        assert total == 0

    def test_l4_route_park(self):
        """Inconclusive event → PARK."""
        graph = SessionGraph()  # empty
        # Low trust, not attachable, no attribution → PARK
        pipeline = self._make_pipeline(trust_integrity=0.2, adversary_ctrl=True, graph=graph)
        ev = _make_event(eid="PARK-001", technique="T9999")
        result = pipeline.triage([ev])
        assert len(result.routed[ROUTE_PARK]) == 1

    def test_l4_route_spawn(self):
        """Not attachable + looks real + no explanation → SPAWN."""
        graph = SessionGraph()  # empty
        # Medium trust, not attachable, boundary (all scores low)
        pipeline = self._make_pipeline(trust_integrity=0.5, adversary_ctrl=False, graph=graph)
        ev = _make_event(eid="SPAWN-001", technique="T9999")
        ev["attributes"]["independent_sources"] = ["edr", "network"]
        result = pipeline.triage([ev])
        # Should be SPAWN (not attachable, integrity >= 0.3, no attribution)
        assert len(result.routed[ROUTE_SPAWN]) == 1

    def test_full_pipeline_integration(self):
        """End-to-end with MockExecutor feeding IngestPipeline."""
        # Setup scenario
        scenario = MockExecutor.create_attack_scenario()
        executor = MockExecutor(scenario=scenario, seed=42)

        # Create probes matching scenario
        probes = [
            _make_probe(target="host-A", operator="email_log", tactic="initial-access"),
            _make_probe(target="host-A", operator="process_tree", tactic="execution"),
        ]

        # Execute
        raw_events = executor.execute_fanout(probes)

        # Setup graph with a root node
        graph = SessionGraph()
        ts = time.time() - 100
        graph.add_events([{
            "technique": "T1566.001",
            "tactic": "initial-access",
            "timestamp": ts,
            "source": "sysmon",
            "attributes": {"target": "host-A"},
        }])

        # Ingest
        trust = StubTrustModel(integrity=0.85)
        ledger = StubLedger()
        pipeline = IngestPipeline(trust_model=trust, graph=graph, ledger=ledger)
        result = pipeline.triage(raw_events, probes=probes)

        # Verify structure
        assert isinstance(result, IngestResult)
        total_routed = sum(len(v) for v in result.routed.values())
        assert total_routed >= 1  # At least some events got through
        assert len(result.trust_annotations) >= 1
