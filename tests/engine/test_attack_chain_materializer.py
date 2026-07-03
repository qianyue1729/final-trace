"""Attack chain materializer tests."""
from types import SimpleNamespace

from trace_engine.attack_chain_materializer import (
    DiversityCaps,
    materialize_attack_chain,
    materialize_attack_chain_from_executor,
    materialize_production_candidate_chain,
    resolve_production_anchor,
)


def test_materialize_pipeline_chain_builds_cross_host_edges():
    events = [
        {
            "raw_log_ref": "attack:idx_stress:evt_001",
            "technique": "T1566.001",
            "tactic": "initial-access",
            "ts": "2026-06-10T02:15:00.000Z",
            "source": "wazuh",
            "src_entity": {"attrs": {"host_uid": "WS-USER-01", "name": "outlook.exe"}},
        },
        {
            "raw_log_ref": "attack:idx_stress:evt_010",
            "technique": "T1021.001",
            "tactic": "lateral-movement",
            "ts": "2026-06-10T03:30:00.000Z",
            "source": "wazuh",
            "src_entity": {"attrs": {"host_uid": "WS-USER-01", "name": "mstsc.exe"}},
        },
        {
            "raw_log_ref": "attack:idx_stress:evt_011",
            "technique": "T1005",
            "tactic": "collection",
            "ts": "2026-06-10T03:45:00.000Z",
            "source": "wazuh",
            "src_entity": {"attrs": {"host_uid": "WS-USER-02", "name": "cmd.exe"}},
        },
        {
            "raw_log_ref": "attack:idx_stress:evt_018",
            "technique": "T1041",
            "tactic": "exfiltration",
            "ts": "2026-06-11T06:00:00.000Z",
            "source": "wazuh",
            "src_entity": {"attrs": {"host_uid": "DB-PROD-01", "name": "sqlservr.exe"}},
        },
    ]
    graph_events = materialize_attack_chain(events, explanation_ids=["H1"])
    assert len(graph_events) == 4
    assert "parent_id" not in graph_events[0]
    assert graph_events[1]["parent_id"] == "attack:idx_stress:evt_001"
    assert graph_events[1]["relation"] == "causes"
    assert graph_events[2]["parent_id"] == "attack:idx_stress:evt_010"
    assert graph_events[2]["relation"] == "lateral_to"
    assert graph_events[3]["parent_id"] == "attack:idx_stress:evt_011"
    assert graph_events[3]["relation"] == "lateral_to"


def test_materialize_ignores_noise_events():
    events = [
        {"raw_log_ref": "noise:idx_stress:evt_0001", "technique": None},
        {
            "raw_log_ref": "attack:idx_stress:evt_001",
            "technique": "T1566.001",
            "tactic": "initial-access",
            "ts": "2026-06-10T02:15:00.000Z",
            "src_entity": {"attrs": {"host_uid": "WS-USER-01"}},
        },
    ]
    graph_events = materialize_attack_chain(events)
    assert len(graph_events) == 1


def _production_like_event(
    ref: str,
    *,
    ts: str,
    host: str,
    level: int,
    tactic: str,
    technique: str,
    src_ip: str = "",
    process: str = "",
    groups: list[str] | None = None,
    rule_id: str = "",
) -> dict:
    attrs = {
        "rule_level": level,
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "rule_groups": groups or ["authentication_failed"],
        "src_ip": src_ip,
    }
    if rule_id:
        attrs["rule_id"] = rule_id
    return {
        "raw_log_ref": ref,
        "ts": ts,
        "technique": technique,
        "tactic": tactic,
        "source": "wazuh",
        "attributes": attrs,
        "src_entity": {
            "attrs": {
                "host_uid": host,
                "name": process,
            }
        },
    }


def test_production_fallback_builds_candidate_chain():
    events = [
        _production_like_event(
            "wazuh:alert-1",
            ts="2026-07-03T08:00:00Z",
            host="prod-db-01",
            level=12,
            tactic="execution",
            technique="T1059.001",
            process="powershell.exe",
        ),
        _production_like_event(
            "wazuh:alert-2",
            ts="2026-07-03T08:05:00Z",
            host="prod-db-01",
            level=10,
            tactic="credential-access",
            technique="T1110",
            src_ip="10.0.0.5",
        ),
        _production_like_event(
            "wazuh:alert-3",
            ts="2026-07-03T08:10:00Z",
            host="prod-web-01",
            level=11,
            tactic="lateral-movement",
            technique="T1021.001",
        ),
    ]
    executor = SimpleNamespace(_events=events)
    graph_events = materialize_attack_chain_from_executor(
        executor,
        alert_context={
            "asset": "prod-db-01",
            "timestamp": 1780502400.0,
            "attributes": {"raw_log_ref": "wazuh:alert-1"},
        },
    )
    assert graph_events
    assert len(graph_events) > 1
    assert all(not str(ev["id"]).startswith("attack:") for ev in graph_events)
    assert all("is_attack" not in (ev.get("attributes") or {}) for ev in graph_events)
    assert executor._candidate_chain_diagnostics["candidate_chain_mode"] == "production_fallback"
    assert graph_events[0]["_attribution_status"] == "CONTESTED"
    assert graph_events[1]["relation"] in {"precedes", "lateral_to"}


def test_production_fallback_filters_noise_by_top_k():
    anchor = _production_like_event(
        "wazuh:alert-entry",
        ts="2026-07-03T08:00:00Z",
        host="prod-db-01",
        level=12,
        tactic="execution",
        technique="T1059.001",
    )
    related = [
        _production_like_event(
            f"wazuh:alert-related-{idx}",
            ts=f"2026-07-03T08:{idx:02d}:00Z",
            host="prod-db-01",
            level=11,
            tactic="credential-access",
            technique="T1110",
        )
        for idx in range(1, 6)
    ]
    noise = [{"raw_log_ref": f"wazuh:noise-{idx}"} for idx in range(100)]
    events = [anchor, *related, *noise]
    graph_events, diagnostics = materialize_production_candidate_chain(
        events,
        alert_context={
            "asset": "prod-db-01",
            "timestamp": 1780502400.0,
            "attributes": {"raw_log_ref": "wazuh:alert-entry"},
        },
        top_k=8,
    )
    refs = {ev["id"] for ev in graph_events}
    assert len(graph_events) <= 8
    assert "wazuh:alert-entry" in refs
    assert any(ref.startswith("wazuh:alert-related-") for ref in refs)
    assert not any(ref.startswith("wazuh:noise-") for ref in refs)
    assert diagnostics["candidate_chain_dropped_noise"] >= len(events) - 8


def test_production_fallback_sorts_by_timestamp():
    events = [
        _production_like_event(
            "wazuh:alert-3",
            ts="2026-07-03T08:20:00Z",
            host="prod-db-01",
            level=10,
            tactic="execution",
            technique="T1059.001",
        ),
        _production_like_event(
            "wazuh:alert-1",
            ts="2026-07-03T08:00:00Z",
            host="prod-db-01",
            level=10,
            tactic="execution",
            technique="T1059.001",
        ),
        _production_like_event(
            "wazuh:alert-2",
            ts="2026-07-03T08:10:00Z",
            host="prod-db-01",
            level=10,
            tactic="execution",
            technique="T1059.001",
        ),
    ]
    graph_events, _ = materialize_production_candidate_chain(
        events,
        alert_context={"asset": "prod-db-01", "timestamp": 1780502400.0},
    )
    assert [ev["id"] for ev in graph_events] == [
        "wazuh:alert-1",
        "wazuh:alert-2",
        "wazuh:alert-3",
    ]


def test_production_fallback_reports_insufficient_fields():
    events = [{"raw_log_ref": "wazuh:empty-1"}, {"raw_log_ref": "wazuh:empty-2"}]
    graph_events, diagnostics = materialize_production_candidate_chain(events)
    assert graph_events == []
    assert diagnostics["candidate_chain_mode"] == "empty"
    assert "no usable timestamp/entity/rule fields" in diagnostics["candidate_chain_empty_reason"]


def test_eval_path_takes_precedence_over_production_fallback():
    events = [
        {
            "raw_log_ref": "attack:idx_stress:evt_001",
            "technique": "T1566.001",
            "tactic": "initial-access",
            "ts": "2026-06-10T02:15:00.000Z",
            "src_entity": {"attrs": {"host_uid": "WS-USER-01"}},
        },
        _production_like_event(
            "wazuh:alert-1",
            ts="2026-07-03T08:00:00Z",
            host="prod-db-01",
            level=12,
            tactic="execution",
            technique="T1059.001",
        ),
    ]
    executor = SimpleNamespace(_events=events)
    graph_events = materialize_attack_chain_from_executor(executor)
    assert len(graph_events) == 1
    assert graph_events[0]["id"] == "attack:idx_stress:evt_001"
    assert executor._candidate_chain_diagnostics["candidate_chain_mode"] == "eval_attack_prefix"


def test_anchor_diagnostics_from_entry_alert_payload():
    events = [
        _production_like_event(
            "wazuh:alert-1",
            ts="2026-07-03T08:00:00Z",
            host="prod-db-01",
            level=12,
            tactic="execution",
            technique="T1059.001",
        )
    ]
    anchor = resolve_production_anchor(
        events,
        {
            "asset": "prod-db-01",
            "timestamp": 1780502400.0,
            "attributes": {"raw_log_ref": "wazuh:alert-1"},
        },
    )
    assert anchor["anchor_source"] == "matched_raw_log_ref"
    assert anchor["anchor_confidence"] == "high"
    assert anchor["host"] == "prod-db-01"


def test_production_fallback_emits_anchor_and_selection_diagnostics():
    events = [
        _production_like_event(
            "wazuh:alert-1",
            ts="2026-07-03T08:00:00Z",
            host="prod-db-01",
            level=12,
            tactic="execution",
            technique="T1059.001",
            rule_id="92001",
        ),
        _production_like_event(
            "wazuh:alert-2",
            ts="2026-07-03T08:05:00Z",
            host="prod-db-01",
            level=10,
            tactic="credential-access",
            technique="T1110",
            rule_id="92002",
        ),
    ]
    _, diagnostics = materialize_production_candidate_chain(
        events,
        alert_context={
            "asset": "prod-db-01",
            "timestamp": 1780502400.0,
            "attributes": {"raw_log_ref": "wazuh:alert-1"},
        },
    )
    assert diagnostics["anchor_source"] == "matched_raw_log_ref"
    assert diagnostics["anchor_confidence"] == "high"
    assert diagnostics["candidate_chain_total_usable"] == 2
    assert diagnostics["candidate_chain_selected"] == 2
    assert "92001" in diagnostics["top_rule_ids"]


def test_diversity_cap_limits_same_rule_id():
    events = [
        _production_like_event(
            f"wazuh:dup-{idx}",
            ts=f"2026-07-03T08:{idx:02d}:00Z",
            host=f"host-{idx % 3}",
            level=10,
            tactic="execution",
            technique="T1059.001",
            rule_id="92001",
        )
        for idx in range(20)
    ]
    _, diagnostics = materialize_production_candidate_chain(
        events,
        alert_context={"asset": "host-0", "timestamp": 1780502400.0},
        top_k=20,
        diversity_caps=DiversityCaps(per_rule_id=3, per_host=20, per_rule_group=20, per_minute=20, per_decoder=20),
    )
    assert diagnostics["candidate_chain_selected"] <= 20
    assert diagnostics["candidate_chain_dropped_by_diversity"] > 0
    assert diagnostics["top_rule_ids"].count("92001") == 1
    assert diagnostics["top_rule_ids"][0] == "92001"
