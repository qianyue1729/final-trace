from dataclasses import replace

from trace_agent.loop.probe import Probe
from trace_agent.loop.scenario_executor import ScenarioExecutor
from trace_engine.config import EngineConfig
from trace_engine.runner import InvestigationRunner
from trace_engine.transports import LocalScenarioTransport


def test_local_scenario_without_alert_timestamp_uses_scenario_clock():
    config = replace(EngineConfig.load(), backend="scenario")
    runner = InvestigationRunner(config)
    executor, scenario = runner._build_executor("pipeline_18")

    assert isinstance(executor.transport, LocalScenarioTransport)
    timestamps = [
        ScenarioExecutor._parse_ts(event.get("ts", ""))
        for event in scenario["events"]
        if event.get("ts")
    ]
    assert executor._time_cursor == min(timestamps)

    first_event = min(
        scenario["events"],
        key=lambda event: ScenarioExecutor._parse_ts(event.get("ts", "")),
    )
    target = ScenarioExecutor._extract_host(first_event)
    probe = Probe(
        id="scenario-clock-probe",
        target=target,
        target_type="host",
        operator="file_hash_lookup",
        tactic="initial-access",
        source="test",
    )

    events = executor.execute_fanout([probe])

    assert events
    assert all(event["probe_id"] == probe.id for event in events)
