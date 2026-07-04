#!/usr/bin/env python3
"""ProvSec case JSON → LOCK scenario JSON + NDJSON converter.

Reads a ProvSec provenance case file, aggregates syscalls via
``provsec_common``, and emits:
  1. soar_mcp_env/scenarios/scenario_provsec_case_05.json  (scenario format)
  2. wazuh_ingest/provsec_case_05.ndjson                   (flat ingest lines)

Usage:
  cd "f:/cursor all/final trace"
  $env:PYTHONPATH="src"
  python scripts/provsec_to_scenario.py
"""
from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trace_agent.eval.adapters.provsec_common import (  # noqa: E402
    aggregate_syscalls,
    load_cve_map,
    read_provsec_events,
)

# ── paths ───────────────────────────────────────────────────────────────
INPUT_PATH = ROOT / "data" / "provsec" / "provsec_case_05_log4j.json"
SCENARIO_OUT = ROOT / "soar_mcp_env" / "scenarios" / "scenario_provsec_case_05.json"
NDJSON_OUT = ROOT / "wazuh_ingest" / "provsec_case_05.ndjson"

SCENARIO_ID = "provsec_case_05"
INCIDENT_ID = "INC-PROVSEC-C05-001"

# Relation → OCSF class uid
_RELATION_OCSF: dict[str, int] = {
    "process_spawn": 2001,
    "execve": 2001,
    "network_connect": 4001,
    "file_read": 6001,
    "file_write": 6001,
}

# Technique prefix → MITRE tactic
_TECHNIQUE_TACTIC: dict[str, str] = {
    "T1190": "initial-access",
    "T1059": "execution",
    "T1021": "lateral-movement",
    "T1552": "credential-access",
    "T1071": "command-and-control",
    "T1005": "collection",
    "T1105": "command-and-control",
    "T1068": "privilege-escalation",
    "T1548": "privilege-escalation",
    "T1070": "defense-evasion",
    "T1036": "defense-evasion",
    "T1543": "persistence",
    "T1546": "persistence",
    "T1505": "persistence",
    "T1078": "defense-evasion",
    "T1611": "privilege-escalation",
    "T1041": "exfiltration",
    "T0000": "unknown",
}


def _technique_to_tactic(technique: str | None) -> str | None:
    if not technique:
        return None
    prefix = technique.split(".")[0]
    return _TECHNIQUE_TACTIC.get(prefix)


def _ts_to_iso(ts: Any) -> str:
    """Convert a numeric timestamp to ISO 8601 UTC string."""
    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (TypeError, ValueError, OSError):
        return str(ts)


def _build_src_entity(agg: dict) -> dict:
    subj = agg["subject"]
    host = agg.get("host_id", "provsec-host")
    return {
        "type": "process",
        "id": f"{host}:{subj.get('name', 'unknown')}:{subj.get('pid', 0)}",
        "resolution": "resolved",
        "attrs": {
            "name": subj.get("name", "unknown"),
            "host_uid": host,
            "ip": "10.0.1.5",
        },
    }


def _build_dst_entity(agg: dict) -> dict:
    obj = agg["object"]
    host = agg.get("host_id", "provsec-host")
    obj_type = obj.get("type", "process")

    if obj_type == "network":
        ip = obj.get("ip", "0.0.0.0")
        port = obj.get("port", 0)
        return {
            "type": "netconn",
            "id": f"{host}:ext:{ip}:{port}",
            "resolution": "resolved",
            "attrs": {"ip": ip, "dst_port": port, "external": True},
        }
    elif obj_type == "file":
        path = obj.get("path", "")
        return {
            "type": "file",
            "id": f"{host}:{path}",
            "resolution": "resolved",
            "attrs": {"path": path, "host_uid": host},
        }
    else:
        return {
            "type": "process",
            "id": f"{host}:{obj.get('name', 'unknown')}:{obj.get('pid', 0)}",
            "resolution": "resolved",
            "attrs": {
                "name": obj.get("name", "unknown"),
                "host_uid": host,
                "ip": "10.0.1.5",
            },
        }


def _anomaly_score(role: str) -> float:
    if role == "attack":
        return round(random.uniform(0.85, 0.95), 2)
    return round(random.uniform(0.05, 0.20), 2)


def convert() -> None:
    random.seed(42)

    # 1. Load & aggregate
    raw = read_provsec_events(INPUT_PATH)
    cve_map = load_cve_map()
    metadata = raw.get("metadata", {})
    default_host = str(
        metadata.get("default_host") or metadata.get("host") or "provsec-ubuntu-01"
    )
    # Inject default_host into events so aggregate_syscalls picks it up
    for evt in raw["events"]:
        evt.setdefault("default_host", default_host)
    aggregated = aggregate_syscalls(raw["events"], cve_map=cve_map)
    gt_raw = raw.get("ground_truth", {})
    host = default_host
    platform = str(metadata.get("platform") or "linux")

    # 2. Build scenario events
    scenario_events: list[dict] = []
    attack_edge_refs: list[str] = []
    evt_counter = 0

    for agg in aggregated:
        evt_counter += 1
        role = agg.get("role", "benign")
        ref_prefix = "attack" if role == "attack" else "noise"
        raw_log_ref = f"{ref_prefix}:provsec:evt_{evt_counter:03d}"

        technique = agg.get("technique") if role == "attack" else None
        tactic = agg.get("tactic") if role == "attack" else None
        if technique and not tactic:
            tactic = _technique_to_tactic(technique)

        if role == "attack":
            attack_edge_refs.append(raw_log_ref)

        relation = agg.get("relation", "process_spawn")
        ocsf = _RELATION_OCSF.get(relation, 2001)

        evt = {
            "ts": _ts_to_iso(agg.get("timestamp")),
            "src_entity": _build_src_entity(agg),
            "dst_entity": _build_dst_entity(agg),
            "action": agg.get("_action", "UNKNOWN"),
            "raw_log_ref": raw_log_ref,
            "anomaly_score": _anomaly_score(role),
            "technique": technique,
            "tactic": tactic,
            "ocsf_class_uid": ocsf,
        }
        scenario_events.append(evt)

    # 3. Primary technique from CVE map
    c05_info = cve_map.get("mappings", {}).get("C05", {})
    primary_technique = c05_info.get("technique_id", "T1190")

    # 4. Build scenario JSON
    scenario: dict[str, Any] = {
        "meta": {
            "name": f"ProvSec C05: {c05_info.get('name', 'Log4j JNDI Injection')}",
            "entry_alert_ref": attack_edge_refs[0] if attack_edge_refs else "attack:provsec:evt_001",
            "cmdb": {
                host: {
                    "ip": "10.0.1.5",
                    "platform": platform,
                    "criticality": "high",
                    "business_role": "web_server",
                }
            },
            "internal_cidrs": ["10.0.0.0/8"],
            "iam": {},
            "nat_sessions": [],
            "dhcp_leases": [],
        },
        "events": scenario_events,
        "ground_truth": {
            "attack_edge_refs": attack_edge_refs,
            "root_cause_entity_id": host,
            "root_cause_technique": primary_technique,
        },
    }

    SCENARIO_OUT.parent.mkdir(parents=True, exist_ok=True)
    SCENARIO_OUT.write_text(json.dumps(scenario, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[OK] Scenario JSON: {SCENARIO_OUT}  ({len(scenario_events)} events)")

    # 5. Build NDJSON
    NDJSON_OUT.parent.mkdir(parents=True, exist_ok=True)
    with NDJSON_OUT.open("w", encoding="utf-8") as fh:
        for ev in scenario_events:
            src = ev.get("src_entity", {})
            dst = ev.get("dst_entity", {})
            src_attrs = src.get("attrs", {})
            dst_attrs = dst.get("attrs", {})
            row: dict[str, Any] = {
                "timestamp": ev["ts"],
                "scenario": SCENARIO_ID,
                "incident_id": INCIDENT_ID,
                "raw_log_ref": ev["raw_log_ref"],
                "action": ev["action"],
                "anomaly_score": ev["anomaly_score"],
                "host": src_attrs.get("host_uid", host),
                "process_name": src_attrs.get("name"),
                "src_ip": src_attrs.get("ip"),
                "ingest_source": "provsec",
            }
            if ev.get("technique"):
                row["technique"] = ev["technique"]
            dst_ip = dst_attrs.get("ip")
            if dst_ip:
                row["dst_ip"] = dst_ip
            if ev.get("ocsf_class_uid"):
                row["ocsf_class_uid"] = ev["ocsf_class_uid"]
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"[OK] NDJSON:        {NDJSON_OUT}  ({len(scenario_events)} lines)")


if __name__ == "__main__":
    convert()
