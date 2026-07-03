"""Tests for L-phase: Probe, CandidatePool, generators."""
from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from trace_agent.loop.probe import Probe
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.loop.generators import (
    prior_generator,
    rule_gap_generator,
    TACTIC_TO_OPERATORS,
    TACTIC_TO_TARGET_TYPE,
)
from trace_agent.loop.session_graph import SessionGraph


# ──── Probe Tests ────


def test_probe_learning_key_format():
    """learning_key 格式: '{operator}|{target_type}|{tactic}'"""
    p = Probe(
        id="P-1", target="host-A", target_type="host",
        operator="process_tree", tactic="execution", source="prior",
    )
    key = p.learning_key()
    assert key == "process_tree|host|execution"
    # Handles whitespace/case normalization
    p2 = Probe(
        id="P-2", target="x", target_type=" Host ",
        operator=" Auth_Log ", tactic=" Lateral-Movement ", source="prior",
    )
    assert p2.learning_key() == "auth_log|host|lateral-movement"


def test_probe_dedup_key():
    """Same target + operator + tactic = same dedup key."""
    p1 = Probe(id="P-1", target="host-A", target_type="host",
               operator="auth_log", tactic="initial-access", source="prior")
    p2 = Probe(id="P-2", target="host-A", target_type="network",
               operator="auth_log", tactic="initial-access", source="rule_gap")
    assert p1.dedup_key() == p2.dedup_key()

    p3 = Probe(id="P-3", target="host-B", target_type="host",
               operator="auth_log", tactic="initial-access", source="prior")
    assert p1.dedup_key() != p3.dedup_key()


def test_probe_generate_id_deterministic():
    """Same inputs = same ID."""
    id1 = Probe.generate_id("host-A", "process_tree", "execution")
    id2 = Probe.generate_id("host-A", "process_tree", "execution")
    assert id1 == id2
    assert id1.startswith("P-")
    assert len(id1) == 10  # "P-" + 8 hex chars

    # Different inputs = different ID
    id3 = Probe.generate_id("host-B", "process_tree", "execution")
    assert id1 != id3


# ──── CandidatePool Tests ────


def _make_probe(target: str, operator: str, tactic: str,
                priority: float = 0.0, explanation_ids: list[str] | None = None) -> Probe:
    """Helper to create Probe with auto-generated ID."""
    return Probe(
        id=Probe.generate_id(target, operator, tactic),
        target=target, target_type="host", operator=operator,
        tactic=tactic, source="prior",
        explanation_ids=explanation_ids or [],
        priority_hint=priority,
    )


def test_pool_add_dedup():
    """Duplicate probes are deduplicated."""
    pool = CandidatePool()
    p1 = _make_probe("host-A", "auth_log", "initial-access", priority=0.5)
    p2 = _make_probe("host-A", "auth_log", "initial-access", priority=0.3)
    added = pool.add([p1, p2])
    assert added == 1  # only first is truly new
    assert pool.size() == 1


def test_pool_add_merges_explanations():
    """explanation_ids are merged on dedup."""
    pool = CandidatePool()
    p1 = _make_probe("host-A", "auth_log", "execution", explanation_ids=["E1"])
    p2 = _make_probe("host-A", "auth_log", "execution", explanation_ids=["E2"])
    pool.add([p1])
    pool.add([p2])
    probes = pool.peek()
    assert len(probes) == 1
    assert "E1" in probes[0].explanation_ids
    assert "E2" in probes[0].explanation_ids


def test_pool_keeps_higher_priority():
    """Higher priority_hint is kept on dedup."""
    pool = CandidatePool()
    p1 = _make_probe("host-A", "dns_query", "discovery", priority=0.2)
    p2 = _make_probe("host-A", "dns_query", "discovery", priority=0.8)
    pool.add([p1])
    pool.add([p2])
    probes = pool.peek()
    assert probes[0].priority_hint == 0.8


def test_pool_drain_clears():
    """drain empties pool."""
    pool = CandidatePool()
    pool.add([_make_probe("A", "op1", "execution"), _make_probe("B", "op2", "persistence")])
    assert pool.size() == 2
    drained = pool.drain()
    assert len(drained) == 2
    assert pool.size() == 0


def test_pool_drain_ordered():
    """drain returns probes ordered by priority desc."""
    pool = CandidatePool()
    pool.add([
        _make_probe("A", "op1", "t1", priority=0.1),
        _make_probe("B", "op2", "t2", priority=0.9),
        _make_probe("C", "op3", "t3", priority=0.5),
    ])
    drained = pool.drain()
    priorities = [p.priority_hint for p in drained]
    assert priorities == sorted(priorities, reverse=True)


def test_pool_remove():
    """removes specified probes."""
    pool = CandidatePool()
    p1 = _make_probe("A", "op1", "t1")
    p2 = _make_probe("B", "op2", "t2")
    pool.add([p1, p2])
    removed = pool.remove([p1.id])
    assert removed == 1
    assert pool.size() == 1
    remaining = pool.peek()
    assert remaining[0].id == p2.id


# ──── Generator Tests ────


def _build_graph_with_frontier() -> SessionGraph:
    """Build a small graph with frontier nodes."""
    g = SessionGraph()
    g.add_events([
        {"technique": "T1566.001", "tactic": "initial-access",
         "timestamp": 1000.0, "source": "email_gateway",
         "attributes": {"asset_id": "host-victim"}},
    ])
    g.add_events([
        {"technique": "T1059.001", "tactic": "execution",
         "timestamp": 1010.0, "source": "sysmon",
         "parent_id": "N1",
         "attributes": {"asset_id": "host-victim"}},
    ])
    return g


def test_prior_generator_empty_graph():
    """Returns empty on empty graph."""
    g = SessionGraph()
    mock_ledger = MagicMock()
    mock_ledger.leading.return_value = ""
    mock_ledger.explanations = []
    mock_prior = MagicMock()
    result = prior_generator(g, mock_ledger, mock_prior)
    assert result == []


def test_prior_generator_with_frontier():
    """Generates probes from frontier nodes."""
    g = _build_graph_with_frontier()
    mock_ledger = MagicMock()
    mock_ledger.leading.return_value = "H1"
    mock_ledger.explanations = []

    mock_prior = MagicMock()
    mock_prior.technique_neighbors.return_value = [
        {"src": "T1053.005", "src_node": {"tactic": "persistence"}, "probability": 0.7},
        {"src": "T1078", "src_node": {"tactic": "privilege-escalation"}, "probability": 0.5},
    ]
    mock_prior.recommended_log_sources.return_value = []

    result = prior_generator(g, mock_ledger, mock_prior)
    assert len(result) > 0
    # All probes should have source "prior"
    for p in result:
        assert p.source == "prior"
        assert p.tactic  # tactic should be set


def test_prior_generator_uses_explanations():
    """References leading explanation."""
    g = _build_graph_with_frontier()

    mock_expl = MagicMock()
    mock_expl.id = "H1"
    mock_expl.stage = "execution"
    mock_expl.current_technique = "T1059.001"

    mock_ledger = MagicMock()
    mock_ledger.leading.return_value = "H1"
    mock_ledger.explanations = [mock_expl]

    mock_prior = MagicMock()
    mock_prior.technique_neighbors.return_value = [
        {"src": "T1053", "src_node": {"tactic": "persistence"}, "probability": 0.6},
    ]
    mock_prior.predecessor_tactics.return_value = []
    mock_prior.recommended_log_sources.return_value = [
        {"log_source": "process_creation", "available": True, "trust": 0.9}
    ]

    result = prior_generator(g, mock_ledger, mock_prior)
    assert len(result) > 0
    # At least one probe should reference H1
    has_h1 = any("H1" in p.explanation_ids for p in result)
    assert has_h1


def test_rule_gap_orphan_detection():
    """Detects orphan (disconnected root) nodes."""
    g = SessionGraph()
    # Create two disconnected components → two roots
    g.add_events([
        {"technique": "T1566", "tactic": "initial-access",
         "timestamp": 1000.0, "source": "email"},
    ])
    g.add_events([
        {"technique": "T1078", "tactic": "persistence",
         "timestamp": 1050.0, "source": "sysmon"},
    ])
    # Both are roots and frontiers (no edges between them)
    result = rule_gap_generator(g, {})
    orphan_probes = [p for p in result if p.metadata.get("gap_type") == "orphan"]
    assert len(orphan_probes) >= 1


def test_rule_gap_tactic_gaps():
    """Detects missing tactics in kill chain."""
    g = SessionGraph()
    # initial-access and lateral-movement with gap in between
    g.add_events([
        {"technique": "T1566", "tactic": "initial-access",
         "timestamp": 1000.0, "source": "email"},
    ])
    g.add_events([
        {"technique": "T1021", "tactic": "lateral-movement",
         "timestamp": 1100.0, "source": "auth_log", "parent_id": "N1"},
    ])
    result = rule_gap_generator(g, {})
    gap_probes = [p for p in result if p.metadata.get("gap_type") == "tactic_gap"]
    # Should detect gaps between initial-access and lateral-movement
    assert len(gap_probes) >= 1
    gap_tactics = [p.metadata["missing_tactic"] for p in gap_probes]
    assert "execution" in gap_tactics


def test_generators_produce_valid_probes():
    """All probes have required fields set."""
    g = _build_graph_with_frontier()
    mock_ledger = MagicMock()
    mock_ledger.leading.return_value = "H1"
    mock_ledger.explanations = []

    mock_prior = MagicMock()
    mock_prior.technique_neighbors.return_value = [
        {"dst": "T1053", "dst_node": {"tactic": "persistence"}, "probability": 0.5},
    ]
    mock_prior.recommended_log_sources.return_value = []

    prior_probes = prior_generator(g, mock_ledger, mock_prior)
    gap_probes = rule_gap_generator(g, {})

    all_probes = prior_probes + gap_probes
    for p in all_probes:
        assert p.id, "Probe must have an id"
        assert p.target, "Probe must have a target"
        assert p.target_type, "Probe must have a target_type"
        assert p.operator, "Probe must have an operator"
        assert p.tactic, "Probe must have a tactic"
        assert p.source in ("prior", "rule_gap", "obligation", "llm_scout")
