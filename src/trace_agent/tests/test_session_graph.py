"""Tests for SessionGraph — RFC-004-02 §3.2 运行时因果图"""
import pytest

from trace_agent.loop.session_graph import GraphEdge, GraphNode, SessionGraph


def _make_event(technique="T1059.001", tactic="execution", timestamp=1000.0,
                source="sysmon", trust_tier="medium", explanation_ids=None,
                parent_id=None, relation="causes", attributes=None, id=None):
    ev = {
        "technique": technique,
        "tactic": tactic,
        "timestamp": timestamp,
        "source": source,
        "trust_tier": trust_tier,
        "explanation_ids": explanation_ids or [],
        "parent_id": parent_id,
        "relation": relation,
    }
    if attributes:
        ev["attributes"] = attributes
    if id:
        ev["id"] = id
    return ev


class TestSessionGraph:

    def test_empty_graph(self):
        g = SessionGraph()
        s = g.stats()
        assert s["node_count"] == 0
        assert s["edge_count"] == 0
        assert s["frontier_count"] == 0
        assert s["max_depth"] == 0
        assert s["tactics_seen"] == []
        assert s["techniques_seen"] == []

    def test_add_single_event(self):
        g = SessionGraph()
        ids = g.add_events([_make_event()])
        assert len(ids) == 1
        node = g.get_node(ids[0])
        assert node is not None
        assert node.technique == "T1059.001"
        assert node.tactic == "execution"
        assert node.trust_tier == "medium"

    def test_add_events_with_parent(self):
        g = SessionGraph()
        ids1 = g.add_events([_make_event(timestamp=1000.0)])
        ids2 = g.add_events([_make_event(
            technique="T1021.001", tactic="lateral_movement",
            timestamp=1010.0, parent_id=ids1[0], relation="causes"
        )])
        assert g.has_edge(ids1[0], ids2[0])

    def test_frontier_returns_leaves(self):
        g = SessionGraph()
        ids = g.add_events([_make_event(timestamp=1000.0)])
        # Single node with no children is a frontier node
        assert ids[0] in g.frontier()
        # Add child
        ids2 = g.add_events([_make_event(timestamp=1010.0, parent_id=ids[0])])
        # Parent no longer in frontier, child is
        assert ids[0] not in g.frontier()
        assert ids2[0] in g.frontier()

    def test_roots_returns_entry_points(self):
        g = SessionGraph()
        ids1 = g.add_events([_make_event(timestamp=1000.0)])
        ids2 = g.add_events([_make_event(timestamp=1010.0, parent_id=ids1[0])])
        assert ids1[0] in g.roots()
        assert ids2[0] not in g.roots()

    def test_stats_counts(self):
        g = SessionGraph()
        g.add_events([_make_event(timestamp=1000.0)])
        g.add_events([_make_event(timestamp=1010.0, technique="T1021.001",
                                  tactic="lateral_movement")])
        s = g.stats()
        assert s["node_count"] == 2
        assert s["edge_count"] == 0
        assert s["frontier_count"] == 2
        assert s["max_depth"] == 0

    def test_subgraph_for_explanation(self):
        g = SessionGraph()
        ids1 = g.add_events([_make_event(explanation_ids=["EX1"])])
        ids2 = g.add_events([_make_event(
            timestamp=1010.0, parent_id=ids1[0],
            explanation_ids=["EX1"]
        )])
        ids3 = g.add_events([_make_event(
            timestamp=1020.0, explanation_ids=["EX2"]
        )])
        sub = g.subgraph_for("EX1")
        assert ids1[0] in sub["nodes"]
        assert ids2[0] in sub["nodes"]
        assert ids3[0] not in sub["nodes"]
        assert len(sub["edges"]) == 1

    def test_has_edge(self):
        g = SessionGraph()
        ids1 = g.add_events([_make_event()])
        ids2 = g.add_events([_make_event(timestamp=1010.0, parent_id=ids1[0])])
        assert g.has_edge(ids1[0], ids2[0]) is True
        assert g.has_edge(ids2[0], ids1[0]) is False

    def test_get_node_exists_and_missing(self):
        g = SessionGraph()
        ids = g.add_events([_make_event()])
        assert g.get_node(ids[0]) is not None
        assert isinstance(g.get_node(ids[0]), GraphNode)
        assert g.get_node("NONEXIST") is None

    def test_temporal_neighbors(self):
        g = SessionGraph()
        ids1 = g.add_events([_make_event(timestamp=1000.0)])
        ids2 = g.add_events([_make_event(timestamp=1100.0)])
        ids3 = g.add_events([_make_event(timestamp=2000.0)])
        # Window 300s from ids1 → should include ids2 (100s away) but not ids3 (1000s away)
        neighbors = g.temporal_neighbors(ids1[0], window_sec=300)
        assert ids2[0] in neighbors
        assert ids3[0] not in neighbors

    def test_remove_edges(self):
        g = SessionGraph()
        ids1 = g.add_events([_make_event()])
        ids2 = g.add_events([_make_event(timestamp=1010.0, parent_id=ids1[0])])
        assert g.has_edge(ids1[0], ids2[0])
        # Find edge and remove it
        s = g.stats()
        assert s["edge_count"] == 1
        edge_ids = list(g._edges.keys())
        g.remove_edges(edge_ids)
        assert g.has_edge(ids1[0], ids2[0]) is False
        assert g.stats()["edge_count"] == 0
        # Nodes still exist
        assert g.get_node(ids1[0]) is not None
        assert g.get_node(ids2[0]) is not None

    def test_depth_calculation(self):
        g = SessionGraph()
        ids1 = g.add_events([_make_event(timestamp=1000.0)])
        ids2 = g.add_events([_make_event(timestamp=1010.0, parent_id=ids1[0])])
        ids3 = g.add_events([_make_event(timestamp=1020.0, parent_id=ids2[0])])
        assert g.depth_of(ids1[0]) == 0
        assert g.depth_of(ids2[0]) == 1
        assert g.depth_of(ids3[0]) == 2
        assert g.stats()["max_depth"] == 2

    def test_multiple_explanations(self):
        g = SessionGraph()
        ids = g.add_events([_make_event(explanation_ids=["EX1", "EX2"])])
        sub1 = g.subgraph_for("EX1")
        sub2 = g.subgraph_for("EX2")
        assert ids[0] in sub1["nodes"]
        assert ids[0] in sub2["nodes"]

    def test_duplicate_events_get_unique_ids(self):
        g = SessionGraph()
        ids = g.add_events([
            _make_event(timestamp=1000.0),
            _make_event(timestamp=1001.0),
            _make_event(timestamp=1002.0),
        ])
        assert len(ids) == 3
        assert len(set(ids)) == 3  # All unique

    def test_tactics_seen_in_stats(self):
        g = SessionGraph()
        g.add_events([
            _make_event(tactic="execution"),
            _make_event(tactic="lateral_movement", timestamp=1010.0),
            _make_event(tactic="execution", timestamp=1020.0),
        ])
        s = g.stats()
        assert "execution" in s["tactics_seen"]
        assert "lateral_movement" in s["tactics_seen"]
        assert len(s["tactics_seen"]) == 2
