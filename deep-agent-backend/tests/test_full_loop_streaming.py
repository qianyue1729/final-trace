from __future__ import annotations

import json

from trace_deep_agent.phase_tools import init_investigation, run_full_loop


def _make_runtime(captured: list):
    return type("Runtime", (), {
        "stream_writer": captured.append,
        "tool_call_id": "test-call-full-loop",
    })()


def _init_and_run_full_loop(*, max_rounds: int = 3) -> tuple[list, dict]:
    captured: list[dict] = []
    runtime = _make_runtime(captured)

    init_payload = init_investigation.func(
        technique="T1059.001",
        asset="SRV-MAIL-01",
        scenario_id="pipeline_18",
        backend="scenario",
        max_rounds=max_rounds,
        runtime=runtime,
    )
    init_result = json.loads(init_payload)
    assert init_result["status"] == "initialized", init_result

    loop_payload = run_full_loop.func(
        session_id=init_result["session_id"],
        max_rounds=max_rounds,
        runtime=runtime,
    )
    loop_result = json.loads(loop_payload)
    return captured, loop_result


def test_full_loop_emits_rich_phase_events():
    captured, loop_result = _init_and_run_full_loop(max_rounds=3)
    assert loop_result.get("status") == "completed", loop_result

    rich_phase_ends = [
        event for event in captured
        if event.get("kind") == "lock_phase"
        and event.get("event_kind") == "phase_end"
    ]
    phases = {event.get("phase") for event in rich_phase_ends}
    assert "O" in phases
    assert "C" in phases
    assert "K" in phases


def test_full_loop_still_returns_compact_report():
    _, loop_result = _init_and_run_full_loop(max_rounds=3)
    assert "status" in loop_result
    assert "lock_loop" in loop_result
    assert loop_result["lock_loop"].get("rounds_used") is not None
