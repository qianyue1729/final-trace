#!/usr/bin/env python3
"""Validate pipeline_18 query contract vs engine configuration."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.runner import InvestigationRunner
from trace_engine.config import EngineConfig
from trace_engine.scenario_registry import resolve_wazuh_scope
from trace_engine.transports import WazuhMcpTransport

REF_DIR = ROOT / "reference" / "pipeline_18"


def _check_registry() -> list[str]:
    errors: list[str] = []
    scope = resolve_wazuh_scope("pipeline_18")
    if scope is None:
        return ["registry: pipeline_18 wazuh_scope missing"]
    if scope.incident_prefix != "INC-PIPELINE_18":
        errors.append(f"registry incident_prefix={scope.incident_prefix!r}")
    if not scope.attacks_only:
        errors.append("registry attacks_only must be true")
    if scope.scope_field != "incident":
        errors.append(f"registry scope_field={scope.scope_field!r}")
    return errors


def _check_compose_queries() -> list[str]:
    errors: list[str] = []
    t = WazuhMcpTransport(
        endpoint="http://localhost/mcp",
        incident_prefix="INC-PIPELINE_18",
        scope_field="incident",
        attacks_only=True,
        scenario_slug="pipeline_18",
    )
    bootstrap = t._compose_wazuh_query("*")
    if 'data.incident_id:"INC-PIPELINE_18"' not in bootstrap:
        errors.append("bootstrap missing incident_id tag")
    if "data.is_attack:true" not in bootstrap:
        errors.append("bootstrap missing is_attack filter")
    if "data.scenario:pipeline_18" in bootstrap:
        errors.append("bootstrap must not use scenario-only scope")

    seed = t._compose_wazuh_query("ref:attack:idx_stress:evt_018")
    if 'data.incident_id:"INC-PIPELINE_18"' not in seed:
        errors.append("seed ref missing incident_id disambiguation")
    if 'data.raw_log_ref:"attack:idx_stress:evt_018"' not in seed:
        errors.append("seed ref missing raw_log_ref")

    host = t._compose_wazuh_query("host:DB-PROD-01")
    if "data.is_attack:true" not in host:
        errors.append("host probe must inherit is_attack when attacks_only set")
    return errors


def _check_reference_files() -> list[str]:
    notes: list[str] = []
    for name in ("attack_chain_18_events.json", "attack_chain_18_compact.json"):
        path = REF_DIR / name
        if not path.is_file():
            notes.append(f"missing reference file: {name} (run scp download)")
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if name.startswith("attack_chain_18_events"):
            count = len(data) if isinstance(data, list) else len(data.get("events", []))
            if count != 18:
                notes.append(f"{name}: expected 18 events, got {count}")
        if name.endswith("compact.json") and isinstance(data, list):
            if len(data) != 18:
                notes.append(f"{name}: expected 18 compact rows, got {len(data)}")
    return notes


def _entry_payload(scenario_id: str) -> dict:
    from trace_agent.eval.soar_integration_runner import (
        build_alert_event,
        find_entry_event,
        load_scenario,
    )

    data, spec = load_scenario(scenario_id)
    entry = find_entry_event(data, spec)
    alert = build_alert_event(entry)
    return {
        "technique": alert.technique_id,
        "asset": alert.asset_id,
        "tactic": alert.tactic,
        "timestamp": alert.timestamp,
        "log_source": alert.log_source or "alert",
        "anomaly_score": alert.anomaly_score or 0.8,
        "attributes": dict(alert.attributes or {}),
    }


def _check_live_run() -> dict | None:
    """Optional Wazuh run when credentials present."""
    try:
        cfg = EngineConfig.load(ROOT / "configs" / "engine_demo_wazuh.yaml")

        r = InvestigationRunner(cfg).run(
            _entry_payload("pipeline_18"),
            scenario_id="pipeline_18",
            max_rounds=6,
        )
        if r.get("status") != "completed":
            return {"error": r.get("error")}
        g = r.get("graph") or {}
        nodes = g.get("nodes") or []
        refs = [
            str((n.get("attributes") or {}).get("raw_log_ref") or n.get("id") or "")
            for n in nodes
        ]
        return {
            "nodes": len(nodes),
            "edges": len(g.get("edges") or []),
            "attack_refs": sum(1 for r in refs if r.startswith("attack:")),
            "noise_refs": sum(1 for r in refs if r.startswith("noise:")),
            "action": (r.get("decision") or {}).get("action"),
            "stop_reason": (r.get("decision") or {}).get("stop_reason"),
        }
    except Exception as exc:  # noqa: BLE001
        return {"skipped": str(exc)}


def main() -> int:
    errors = _check_registry() + _check_compose_queries()
    notes = _check_reference_files()

    print("=== pipeline_18 Query Contract Validation ===")
    if errors:
        print("FAIL:")
        for item in errors:
            print(f"  - {item}")
    else:
        print("PASS: registry + compose queries match contract")

    if notes:
        print("NOTES:")
        for item in notes:
            print(f"  - {item}")

    live = _check_live_run()
    if live:
        print("LIVE (if MCP available):", json.dumps(live, ensure_ascii=False))

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
