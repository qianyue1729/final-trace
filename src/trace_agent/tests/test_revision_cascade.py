"""Tests for RevisionCascade — RFC-004-02 §5/§8 证据修订级联"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

import pytest

from trace_agent.loop.revision_cascade import RevisionCascade, CascadeResult


# ---------------------------------------------------------------------------
# Stubs / Mocks
# ---------------------------------------------------------------------------


@dataclass
class FakeTrust:
    integrity: float = 0.9
    adversary_controllable: bool = False
    anti_forensics_indicator: bool = False

    def effective_integrity(self) -> float:
        return self.integrity

    def is_forge_resistant(self, tau_hard: float = 0.8) -> bool:
        return self.integrity >= tau_hard and not self.adversary_controllable


@dataclass
class FakeRevision:
    evidence_id: str = "ev1"
    round: int = 1
    old_trust: FakeTrust = field(default_factory=lambda: FakeTrust(integrity=0.9))
    new_trust: FakeTrust = field(default_factory=lambda: FakeTrust(integrity=0.5))
    reason: str = "host_compromised"
    cascading_vetos: List[str] = field(default_factory=list)


class FakeGraph:
    def __init__(self):
        self._edges_removed: list = []

    def remove_edges(self, edge_ids: list) -> None:
        self._edges_removed.extend(edge_ids)

    def get_node(self, node_id: str):
        return None

    def has_edge(self, src: str, dst: str) -> bool:
        return False


class FakeObligations:
    def __init__(self):
        self.cascade_called_with: list = []

    def cascade_on_revision(self, revisions: list) -> list:
        self.cascade_called_with = revisions
        return [f"cascade_noted:ob1:evidence_downgraded"]


class FakeLedger:
    pass


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRevisionCascade:
    def _make_cascade(self, graph=None, trust=None, obligations=None, ledger=None):
        return RevisionCascade(
            graph=graph or FakeGraph(),
            trust=trust,
            obligations=obligations or FakeObligations(),
            ledger=ledger or FakeLedger(),
        )

    def test_empty_revisions(self):
        """No revisions → empty result."""
        cascade = self._make_cascade()
        result = cascade.apply([])
        assert result.restored_edges == []
        assert result.invalidated_obligations == []
        assert result.new_obligations == []
        assert result.graph_changes == []
        assert result.veto_reassessments == []

    def test_integrity_drop_invalidates_veto(self):
        """Recorded VETO becomes invalid when evidence integrity drops below forge-resistant."""
        cascade = self._make_cascade()
        # Record a veto while evidence was forge-resistant
        cascade.record_veto("ev1", "temporal_order", "E1", 0.9)

        # Revision: integrity dropped from 0.9 to 0.5 (no longer forge-resistant)
        revision = FakeRevision(
            evidence_id="ev1",
            old_trust=FakeTrust(integrity=0.9),
            new_trust=FakeTrust(integrity=0.5),
            reason="host_compromised",
        )
        result = cascade.apply([revision])

        assert len(result.veto_reassessments) == 1
        assert result.veto_reassessments[0]["action"] == "invalidate"
        assert result.veto_reassessments[0]["edge_id"] == "E1"
        assert "E1" in result.restored_edges

    def test_integrity_rise_no_effect(self):
        """Integrity increase doesn't invalidate existing VETOs."""
        cascade = self._make_cascade()
        cascade.record_veto("ev1", "temporal_order", "E1", 0.85)

        # Revision: integrity increased (still forge-resistant)
        revision = FakeRevision(
            evidence_id="ev1",
            old_trust=FakeTrust(integrity=0.85),
            new_trust=FakeTrust(integrity=0.95),
            reason="corroboration",
        )
        result = cascade.apply([revision])

        assert len(result.veto_reassessments) == 0
        assert result.restored_edges == []

    def test_restored_edge_tracked(self):
        """Restored edges appear in result.restored_edges."""
        cascade = self._make_cascade()
        cascade.record_veto("ev1", "disconfirmed", "E5", 0.85)
        cascade.record_veto("ev1", "temporal_order", "E6", 0.85)

        revision = FakeRevision(
            evidence_id="ev1",
            old_trust=FakeTrust(integrity=0.85),
            new_trust=FakeTrust(integrity=0.4),
            reason="host_compromised",
        )
        result = cascade.apply([revision])

        assert "E5" in result.restored_edges
        assert "E6" in result.restored_edges

    def test_obligation_cascade_forwarded(self):
        """obligations.cascade_on_revision is called with revisions."""
        obligations = FakeObligations()
        cascade = self._make_cascade(obligations=obligations)

        revision = FakeRevision(evidence_id="ev1")
        cascade.apply([revision])

        assert len(obligations.cascade_called_with) == 1
        assert obligations.cascade_called_with[0].evidence_id == "ev1"

    def test_new_obligations_from_anti_forensics(self):
        """Anti-forensics revision generates new obligation."""
        cascade = self._make_cascade()
        revision = FakeRevision(
            evidence_id="ev1",
            old_trust=FakeTrust(integrity=0.9),
            new_trust=FakeTrust(integrity=0.4, anti_forensics_indicator=True),
            reason="anti_forensics_detected",
        )
        result = cascade.apply([revision])

        assert len(result.new_obligations) == 1
        assert result.new_obligations[0]["type"] == "anti_forensics"
        assert result.new_obligations[0]["hard"] is True
        assert "ev1" in result.new_obligations[0]["anchor"]

    def test_graph_edge_weakened(self):
        """Significant integrity drop (>=0.3) marks edges in graph_changes."""
        cascade = self._make_cascade()
        # Drop from 0.9 → 0.5 = drop of 0.4 (>= 0.3)
        revision = FakeRevision(
            evidence_id="ev1",
            old_trust=FakeTrust(integrity=0.9),
            new_trust=FakeTrust(integrity=0.5),
            reason="host_compromised",
        )
        result = cascade.apply([revision])

        assert len(result.graph_changes) == 1
        assert result.graph_changes[0]["action"] == "weaken"
        assert result.graph_changes[0]["drop"] == pytest.approx(0.4)

    def test_multiple_revisions(self):
        """Handles batch of revisions."""
        cascade = self._make_cascade()
        cascade.record_veto("ev1", "temporal_order", "E1", 0.9)

        revisions = [
            FakeRevision(
                evidence_id="ev1",
                old_trust=FakeTrust(integrity=0.9),
                new_trust=FakeTrust(integrity=0.4),
                reason="host_compromised",
            ),
            FakeRevision(
                evidence_id="ev2",
                old_trust=FakeTrust(integrity=0.7),
                new_trust=FakeTrust(integrity=0.85),
                reason="corroboration",
            ),
        ]
        result = cascade.apply(revisions)

        # ev1 invalidates veto, ev2 has small drop → only ev1 weakens graph
        assert "E1" in result.restored_edges
        assert len(result.graph_changes) == 1  # only ev1 had big drop

    def test_record_veto_stores_history(self):
        """Veto recording stores in history."""
        cascade = self._make_cascade()
        cascade.record_veto("ev1", "temporal_order", "E1", 0.9)
        cascade.record_veto("ev2", "disconfirmed", "E2", 0.85)

        assert len(cascade._veto_history) == 2
        assert cascade._veto_history[0]["evidence_id"] == "ev1"
        assert cascade._veto_history[1]["edge_id"] == "E2"
        assert cascade._veto_history[0]["invalidated"] is False

    def test_cascade_result_structure(self):
        """All fields populated correctly in CascadeResult."""
        cascade = self._make_cascade()
        cascade.record_veto("ev1", "temporal_order", "E1", 0.9)

        revision = FakeRevision(
            evidence_id="ev1",
            old_trust=FakeTrust(integrity=0.9),
            new_trust=FakeTrust(integrity=0.3, anti_forensics_indicator=True),
            reason="anti_forensics_detected",
        )
        result = cascade.apply([revision])

        # All fields should be populated
        assert isinstance(result.restored_edges, list)
        assert isinstance(result.invalidated_obligations, list)
        assert isinstance(result.new_obligations, list)
        assert isinstance(result.graph_changes, list)
        assert isinstance(result.veto_reassessments, list)

        # Specific checks
        assert "E1" in result.restored_edges
        assert len(result.new_obligations) >= 1
        assert len(result.graph_changes) >= 1  # drop of 0.6
        assert len(result.invalidated_obligations) >= 1  # from obligations mock
