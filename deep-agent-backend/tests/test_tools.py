from __future__ import annotations

import json

from trace_deep_agent.tools import (
    _compact_report,
)


def test_compact_report_removes_traceback_and_bounds_graph():
    report = {
        "status": "completed",
        "alert": {"technique": "T1059.001"},
        "decision": {"action": "monitor"},
        "usage": {
            "rounds": 2,
            "model_planner": [{"round": 1, "provider_status": "ok"}],
            "model_judgement": {
                "mode": "shadow",
                "provider_status": "ready",
                "l3_llm_calls": 2,
                "audit": [{"event_ref": "evt-1", "status": "accepted"}],
                "shadow_summary": {"total_judgements": 1},
            },
        },
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
    assert compact["model_processing"]["planner"][0]["provider_status"] == "ok"
    assert compact["model_processing"]["judgement"]["l3_llm_calls"] == 2
    assert compact["model_processing"]["judgement"]["provider_status"] == "ready"


def test_phase_progress_cb_tags_custom_events_with_tool_call_id():
    """Phase progress callback correctly wraps events."""
    from trace_deep_agent.phase_tools import _phase_progress_cb

    events = []
    runtime = type("Runtime", (), {
        "stream_writer": events.append,
        "tool_call_id": "call-123",
    })()

    emit = _phase_progress_cb(runtime, "run_l_phase")
    emit({"stage": "lock_loop", "phase": "L", "round": 1})

    assert events == [{
        "kind": "lock_progress",
        "tool_name": "run_l_phase",
        "tool_call_id": "call-123",
        "stage": "lock_loop",
        "phase": "L",
        "round": 1,
    }]


def test_phase_tools_exist():
    """拍级工具全部可导入"""
    from trace_deep_agent.phase_tools import PHASE_TOOLS
    assert len(PHASE_TOOLS) >= 7


def test_query_tools_exist():
    """查询工具全部可导入"""
    from trace_deep_agent.query_tools import QUERY_TOOLS
    assert len(QUERY_TOOLS) == 6


def test_control_tools_exist():
    """控制工具全部可导入"""
    from trace_deep_agent.control_tools import CONTROL_TOOLS
    assert len(CONTROL_TOOLS) == 3


def test_total_tool_count():
    """工具总数符合预期（无黑盒legacy工具）"""
    from trace_deep_agent.tools import TRACE_TOOLS
    # 1 inspect_trace_prior + 8 phase + 3 control + 6 query = 18
    assert len(TRACE_TOOLS) >= 18


def test_lock_session_basic():
    """LOCKSession 空实例工作正常"""
    from trace_agent.agents.lock_session import LOCKSession
    s = LOCKSession()
    assert s.stats() is not None
    assert s.to_snapshot() is not None


def test_progress_protocol():
    """进度事件协议可序列化"""
    from trace_agent.agents.progress_protocol import LPhaseEvent
    e = LPhaseEvent(kind='phase_end', event_kind='phase_end', phase='L', round=1, candidates_count=10)
    d = e.to_stream_dict()
    assert d['kind'] == 'lock_phase'
    assert d['candidates_count'] == 10


def test_modular_orchestrator_import():
    """ModularOrchestrator 可导入"""
    from trace_agent.agents.modular_orchestrator import ModularOrchestrator
    assert ModularOrchestrator is not None


