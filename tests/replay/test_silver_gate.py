"""Silver gate smoke test."""
from trace_agent.eval.silver_gate import run_silver_gate


def test_silver_gate_runs():
    gate = run_silver_gate()
    assert gate["level"] == "silver_solid"
    assert "passed" in gate
    assert "blockers" in gate
