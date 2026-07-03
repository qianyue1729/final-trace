from __future__ import annotations

import json

from trace_deep_agent.tools import (
    _compact_report,
    list_trace_scenarios,
    run_production_trace,
)


def test_list_scenarios_exposes_known_debug_cases():
    payload = json.loads(list_trace_scenarios.invoke({}))
    ids = {item["id"] for item in payload["scenarios"]}
    assert {"pipeline_18", "apt_5host", "multipath_12host"} <= ids


def test_production_tool_is_denied_by_default(monkeypatch):
    monkeypatch.delenv("TRACE_AGENT_ALLOW_PRODUCTION", raising=False)
    payload = json.loads(
        run_production_trace.invoke(
            {"technique": "T1059.001", "asset": "WS-TEST-01"}
        )
    )
    assert payload["status"] == "denied"


def test_compact_report_removes_traceback_and_bounds_graph():
    report = {
        "status": "completed",
        "alert": {"technique": "T1059.001"},
        "decision": {"action": "monitor"},
        "usage": {"rounds": 2},
        "traceback": "must not escape",
        "graph": {
            "nodes": [{"id": str(i)} for i in range(130)],
            "edges": [{"source": str(i), "target": str(i + 1)} for i in range(170)],
            "attack_node_count": 5,
        },
    }
    compact = _compact_report(report)
    assert "traceback" not in compact
    assert len(compact["graph"]["nodes"]) == 120
    assert len(compact["graph"]["edges"]) == 160
    assert compact["graph"]["truncated"] is True

