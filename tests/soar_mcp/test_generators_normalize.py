"""Tests for normalize_tactic and cross_host_probe_generator."""
from __future__ import annotations

from trace_agent.loop.generators import cross_host_probe_generator, normalize_tactic, chain_follow_generator
from trace_agent.loop.session_graph import SessionGraph


def test_normalize_tactic_semantic_passthrough():
    assert normalize_tactic("initial-access") == "initial-access"


def test_cross_host_skips_alert_asset():
    graph = SessionGraph()
    graph.add_events([{
        "technique": "T1041",
        "tactic": "exfiltration",
        "timestamp": 1000.0,
        "source": "alert",
        "attributes": {"asset_id": "DB-PROD-01"},
    }])
    probes = cross_host_probe_generator(
        graph,
        ["DB-PROD-01", "WS-USER-01", "WS-USER-02"],
        alert_asset="DB-PROD-01",
    )
    targets = {p.target for p in probes}
    # 未入图主机必须被覆盖；告警主机例外允许（算子覆盖轮换），但不得独占
    assert {"WS-USER-01", "WS-USER-02"} <= targets
    assert "WS-USER-01" in targets


def test_cross_host_stops_after_initial_access_seen():
    graph = SessionGraph()
    graph.add_events([
        {
            "technique": "T1566.001",
            "tactic": "initial-access",
            "timestamp": 1000.0,
            "source": "auth",
            "attributes": {"host_uid": "WS-USER-01"},
        },
    ])
    probes = cross_host_probe_generator(
        graph,
        ["WS-USER-02"],
        alert_asset="DB-PROD-01",
    )
    assert probes == []


def test_chain_follow_fills_execution_gap_on_host():
    graph = SessionGraph()
    graph.add_events([{
        "technique": "T1566.001",
        "tactic": "initial-access",
        "timestamp": 1000.0,
        "source": "auth",
        "attributes": {"host_uid": "WS-USER-01"},
    }])
    probes = chain_follow_generator(graph)
    tactics = {p.tactic for p in probes if p.target == "WS-USER-01"}
    assert "execution" in tactics or "persistence" in tactics
