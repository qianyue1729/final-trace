"""EventNormalizer — 字段映射 / 透传 / 合成去重键。"""
from trace_engine.config import NormalizerConfig
from trace_engine.normalizer import EventNormalizer


def test_passthrough_scenario_event():
    ev = {
        "raw_log_ref": "attack:x:evt_1",
        "ts": "2026-06-10T00:00:00Z",
        "src_entity": {"attrs": {"host_uid": "H1"}},
        "action": "EXEC",
        "attributes": {"is_attack": True, "sensor": "edr"},
        "ground_truth": {"label": "attack"},
    }
    out = EventNormalizer().normalize(ev)
    assert out is not ev
    assert "ground_truth" not in out
    assert out["attributes"] == {"sensor": "edr"}
    assert ev["attributes"]["is_attack"] is True


def test_custom_field_map_foreign_record():
    """模拟第三方 SOAR 记录格式（扁平字段）。"""
    cfg = NormalizerConfig(field_map={
        "ref": "event_id",
        "timestamp": "occurred_at",
        "technique": "mitre.technique_id",
        "tactic": "mitre.tactic",
        "action": "activity",
        "source": "log_source",
        "anomaly_score": "risk_score",
        "host": "device.hostname",
        "host_fallback": "device.ip",
        "process_name": "process.name",
        "ocsf_class_uid": "class_uid",
    })
    record = {
        "event_id": "SIEM-88771",
        "occurred_at": "2026-07-01T08:30:00Z",
        "mitre": {"technique_id": "T1059.001", "tactic": "execution"},
        "activity": "EXEC",
        "log_source": "auditd",
        "risk_score": 0.87,
        "device": {"hostname": "WS-FIN-07"},
        "process": {"name": "powershell.exe"},
        "class_uid": 2001,
    }
    out = EventNormalizer(cfg).normalize(record)
    assert out["raw_log_ref"] == "SIEM-88771"
    assert out["ts"] == "2026-07-01T08:30:00Z"
    assert out["technique"] == "T1059.001"
    assert out["tactic"] == "execution"
    assert out["action"] == "EXEC"
    assert out["source"] == "auditd"
    assert out["anomaly_score"] == 0.87
    assert out["src_entity"]["attrs"]["host_uid"] == "WS-FIN-07"
    assert out["src_entity"]["attrs"]["name"] == "powershell.exe"
    assert out["ocsf_class_uid"] == 2001


def test_mitre_display_tactic_is_normalized():
    cfg = NormalizerConfig(field_map={
        "ref": "id",
        "timestamp": "timestamp",
        "technique": "mitre_technique",
        "tactic": "mitre_tactic",
        "host": "host",
    })
    out = EventNormalizer(cfg).normalize({
        "id": "alert-1",
        "timestamp": "2026-07-03T08:00:00Z",
        "host": "prod-db-01",
        "mitre_technique": "T1110.001",
        "mitre_tactic": "Credential Access",
        "src_ip": "10.0.0.5",
        "user": "alice",
        "auth_outcome": "failure",
        "rule": {"id": "5503", "level": 5},
    })
    assert out["tactic"] == "credential-access"
    assert out["attributes"] == {
        "src_ip": "10.0.0.5",
        "user": "alice",
        "auth_outcome": "failure",
        "rule_id": "5503",
        "rule_level": 5,
    }


def test_synth_ref_stable():
    n = EventNormalizer(NormalizerConfig(field_map={"ref": "missing_key"}))
    record = {"foo": "bar", "ts": "2026-01-01T00:00:00Z"}
    a = n.normalize(dict(record))["raw_log_ref"]
    b = n.normalize(dict(record))["raw_log_ref"]
    assert a == b and a.startswith("soar:")


def test_id_prefix_is_preserved_but_not_classified():
    out = EventNormalizer().normalize({
        "raw_log_ref": "attack:idx:evt_9",
        "ts": "2026-06-10T00:00:00Z",
        "src_entity": {"attrs": {"host_uid": "H1"}},
    })
    assert out["raw_log_ref"] == "attack:idx:evt_9"
    assert not hasattr(EventNormalizer(), "is_attack_ref")
