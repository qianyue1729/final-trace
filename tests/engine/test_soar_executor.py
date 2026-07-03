"""SoarMcpProbeExecutor — 增量取数 + 匹配内核复用 + 传输失败降级。"""
import json
from pathlib import Path

import pytest

from trace_agent.loop.probe import Probe
from trace_engine.config import SoarMcpConfig
from trace_engine.soar_executor import SoarMcpProbeExecutor
from trace_engine.transports import (
    GENERIC_MCP_CAPABILITIES,
    LOCAL_SCENARIO_CAPABILITIES,
    WAZUH_MCP_CAPABILITIES,
    LocalScenarioTransport,
    TransportCapabilities,
)

SCENARIO = (
    Path(__file__).resolve().parent.parent.parent
    / "soar_mcp_env" / "scenarios" / "scenario_pipeline_18steps.json"
)


@pytest.fixture(scope="module")
def scenario_data() -> dict:
    return json.loads(SCENARIO.read_text(encoding="utf-8"))


def _entry_alert_ts(scenario_data: dict) -> float:
    from trace_agent.loop.scenario_executor import ScenarioExecutor
    ts = [
        ScenarioExecutor._parse_ts(e["ts"])
        for e in scenario_data["events"]
        if e.get("raw_log_ref", "").startswith("attack:")
    ]
    return max(ts)


def _probe(target: str, operator: str = "process_tree", tactic: str = "execution") -> Probe:
    return Probe(
        id=Probe.generate_id(target, operator, tactic),
        target=target,
        target_type="host",
        operator=operator,
        tactic=tactic,
        source="test",
    )


class RecordingTransport:
    capabilities = GENERIC_MCP_CAPABILITIES

    def __init__(self, pages=None):
        self.calls = []
        self.pages = list(pages or [])

    def query(self, **kwargs):
        self.calls.append(kwargs)
        return self.pages.pop(0) if self.pages else []

    def ping(self):
        return True


def test_fanout_fetches_and_matches(scenario_data):
    executor = SoarMcpProbeExecutor(
        transport=LocalScenarioTransport(scenario_data),
    )
    executor.align_to_alert(_entry_alert_ts(scenario_data))

    hosts = {
        e["src_entity"]["attrs"]["host_uid"]
        for e in scenario_data["events"]
        if e.get("raw_log_ref", "").startswith("attack:")
        and e.get("src_entity", {}).get("attrs", {}).get("host_uid")
    }
    probes = [_probe(h) for h in sorted(hosts)][:4]
    events = executor.execute_fanout(probes)

    assert events, "扇出应返回事件"
    assert executor.fetch_stats["queries"] >= 1
    assert executor.fetch_stats["errors"] == 0
    for ev in events:
        assert ev["id"]
        assert "attributes" in ev


def test_dedup_across_rounds(scenario_data):
    executor = SoarMcpProbeExecutor(
        transport=LocalScenarioTransport(scenario_data),
    )
    executor.align_to_alert(_entry_alert_ts(scenario_data))
    probes = [_probe("SRV-MAIL-01")]

    executor.execute_fanout(probes)
    executor.execute_fanout(probes)
    # 时间窗前进可注入新事件，但同一 ref 不得重复入缓存
    refs = [e.get("raw_log_ref") for e in executor._events if e.get("raw_log_ref")]
    assert len(refs) == len(set(refs))


def test_transport_failure_does_not_raise(scenario_data):
    class BrokenTransport:
        def query(self, **kwargs):
            raise ConnectionError("SOAR down")

        def ping(self):
            return False

    executor = SoarMcpProbeExecutor(transport=BrokenTransport())
    events = executor.execute_fanout([_probe("H1")])
    assert events == []
    assert executor.fetch_stats["errors"] == 1
    assert executor.available() is False


def test_known_hosts_merges_static_and_discovered(scenario_data):
    executor = SoarMcpProbeExecutor(
        transport=LocalScenarioTransport(scenario_data),
        known_hosts=["CMDB-ONLY-HOST"],
    )
    executor.align_to_alert(_entry_alert_ts(scenario_data))
    executor.execute_fanout([_probe("SRV-MAIL-01")])
    hosts = executor.known_hosts()
    assert "CMDB-ONLY-HOST" in hosts
    assert "SRV-MAIL-01" in hosts


def test_transport_capability_contract(scenario_data):
    assert GENERIC_MCP_CAPABILITIES.exact_time_bounds is True
    assert GENERIC_MCP_CAPABILITIES.cursor_pagination is True
    assert WAZUH_MCP_CAPABILITIES.exact_time_bounds is False
    assert WAZUH_MCP_CAPABILITIES.cursor_pagination is True
    assert LocalScenarioTransport(scenario_data).capabilities == (
        LOCAL_SCENARIO_CAPABILITIES
    )


def test_same_host_different_operators_issue_distinct_queries():
    transport = RecordingTransport()
    executor = SoarMcpProbeExecutor(transport=transport)
    executor.align_to_alert(1_700_000_000)

    probes = [
        _probe("host-A", "auth_log"),
        _probe("host-A", "network_flow"),
        _probe("host-A", "process_tree"),
    ]
    executor.execute_fanout(probes)

    assert len(transport.calls) == 3
    assert {call["query"].split("source:", 1)[1] for call in transport.calls} == {
        "SIEM",
        "NDR",
        "EDR",
    }


def test_wazuh_deduplicates_dimensions_the_backend_cannot_filter():
    transport = RecordingTransport()
    transport.capabilities = WAZUH_MCP_CAPABILITIES
    executor = SoarMcpProbeExecutor(transport=transport)
    executor.align_to_alert(1_700_000_000)

    probes = [
        _probe("host-A", "auth_log"),
        _probe("host-A", "network_flow"),
        _probe("host-A", "process_tree"),
    ]
    executor.execute_fanout(probes)

    assert len(transport.calls) == 1
    assert executor.fetch_stats["deduplicated_queries"] == 2
    diagnostic = executor.fetch_stats["query_diagnostics"][0]
    assert diagnostic["operators"] == [
        "auth_log",
        "network_flow",
        "process_tree",
    ]
    assert diagnostic["datasources"] == ["SIEM", "NDR", "EDR"]


def test_canonical_source_survives_probe_conversion():
    transport = RecordingTransport(pages=[[
        {
            "raw_log_ref": "wazuh:alert-1",
            "ts": "2023-11-14T22:13:00Z",
            "technique": "T1110.001",
            "tactic": "credential-access",
            "action": "AUTH",
            "source": "syslog",
            "attributes": {
                "src_ip": "10.0.0.5",
                "user": "alice",
                "auth_outcome": "failure",
            },
            "src_entity": {"attrs": {"host_uid": "host-A"}},
        },
    ]])
    executor = SoarMcpProbeExecutor(transport=transport)
    executor.align_to_alert(1_700_000_000)

    events = executor.execute_fanout([
        _probe("host-A", "auth_log", "credential-access"),
    ])

    assert events[0]["source"] == "syslog"
    assert events[0]["attributes"]["src_ip"] == "10.0.0.5"
    assert events[0]["attributes"]["user"] == "alice"
    assert events[0]["attributes"]["auth_outcome"] == "failure"


def test_identical_queries_are_deduplicated_with_probe_attribution():
    transport = RecordingTransport()
    executor = SoarMcpProbeExecutor(transport=transport)
    executor.align_to_alert(1_700_000_000)
    probe = _probe("host-A", "auth_log")

    executor.execute_fanout([probe, probe])

    assert len(transport.calls) == 1
    assert executor.fetch_stats["deduplicated_queries"] == 1
    assert executor.fetch_stats["query_diagnostics"][0]["probe_ids"] == [
        probe.id,
        probe.id,
    ]


@pytest.mark.parametrize(
    ("alert_ts", "expected"),
    [
        (900.0, (800_000, 920_000)),
        (1_000.0, (900_000, 1_005_000)),
        (2_000.0, (905_000, 1_005_000)),
    ],
)
def test_production_windows_are_alert_anchored_and_future_capped(
    monkeypatch,
    alert_ts,
    expected,
):
    monkeypatch.setattr("trace_engine.soar_executor.time.time", lambda: 1_000.0)
    cfg = SoarMcpConfig(
        lookback_seconds=100,
        lookahead_seconds=20,
        allowed_clock_skew_seconds=5,
    )
    executor = SoarMcpProbeExecutor(
        transport=RecordingTransport(),
        config=cfg,
    )
    executor.align_to_alert(alert_ts)
    assert executor._window_ms() == expected


def test_exact_pagination_sorts_pages_and_detects_missing_cursor():
    out_of_order = RecordingTransport(pages=[[
        {
            "raw_log_ref": "r2",
            "ts": "2026-07-01T00:00:02Z",
            "src_entity": {"attrs": {"host_uid": "host-A"}},
        },
        {
            "raw_log_ref": "r1",
            "ts": "2026-07-01T00:00:01Z",
            "src_entity": {"attrs": {"host_uid": "host-A"}},
        },
    ], []])
    executor = SoarMcpProbeExecutor(
        transport=out_of_order,
        config=SoarMcpConfig(page_limit=2),
    )
    executor.align_to_alert(1_800_000_000)
    executor.execute_fanout([_probe("host-A")])
    diagnostic = executor.fetch_stats["query_diagnostics"][0]
    assert diagnostic["out_of_order"] is True
    assert diagnostic["coverage_truncated"] is False
    assert [event["raw_log_ref"] for event in executor._events] == ["r1", "r2"]

    missing_cursor = RecordingTransport(pages=[[
        {"raw_log_ref": "r3", "src_entity": {"attrs": {"host_uid": "host-A"}}},
        {"raw_log_ref": "r4", "src_entity": {"attrs": {"host_uid": "host-A"}}},
    ]])
    executor = SoarMcpProbeExecutor(
        transport=missing_cursor,
        config=SoarMcpConfig(page_limit=2),
    )
    executor.align_to_alert(1_800_000_000)
    executor.execute_fanout([_probe("host-A")])
    assert executor.fetch_stats["coverage_truncated"] is True
    assert executor.fetch_stats["truncations"][0]["reason"] == (
        "repeated_or_missing_cursor"
    )


def test_coarse_full_page_reports_truncation():
    transport = RecordingTransport(pages=[[
        {"raw_log_ref": "r1", "src_entity": {"attrs": {"host_uid": "host-A"}}},
        {"raw_log_ref": "r2", "src_entity": {"attrs": {"host_uid": "host-A"}}},
    ]])
    transport.capabilities = TransportCapabilities(
        exact_time_bounds=False,
        stable_ascending_sort=False,
        cursor_pagination=False,
        supported_query_dimensions=frozenset({"host"}),
    )
    executor = SoarMcpProbeExecutor(
        transport=transport,
        config=SoarMcpConfig(page_limit=2),
    )
    executor.align_to_alert(1_800_000_000)
    executor.execute_fanout([_probe("host-A")])

    assert len(transport.calls) == 1
    assert executor.fetch_stats["coverage_truncated"] is True
    assert executor.fetch_stats["truncations"][0]["reason"] == (
        "full_page_without_cursor"
    )
