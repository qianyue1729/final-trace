#!/usr/bin/env python3
"""Run WINDOWS_DEEPAGENTUI_WAZUH_TEST_CHECKLIST phases 0-2, 6 (scriptable)."""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.config import EngineConfig
from trace_engine.normalizer import EventNormalizer
from trace_engine.transports import WazuhMcpTransport, build_mcp_transport


@dataclass
class Check:
    phase: str
    item_id: str
    name: str
    level: str
    passed: bool | None  # None = skip
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


def load_host_env() -> None:
    env_path = ROOT / "host-client.env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())


def health_check(ca_path: Path) -> tuple[bool, str]:
    url = os.environ.get("WAZUH_MCP_HEALTH", "https://192.144.151.189/health")
    ctx = None
    if ca_path.is_file():
        import ssl

        ctx = ssl.create_default_context(cafile=str(ca_path))
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status == 200, body[:200]
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def count_hits(transport: WazuhMcpTransport, query: str, **kwargs: Any) -> tuple[int, list[dict]]:
    recs = transport.query(query=query, from_ms=0, to_ms=0, limit=kwargs.get("limit", 50))
    return len(recs), recs


def run_phase0() -> list[Check]:
    checks: list[Check] = []
    env_ok = (ROOT / "host-client.env").is_file()
    checks.append(
        Check("0", "0.1", "host-client.env", "P0", env_ok, "exists" if env_ok else "missing")
    )
    ca = ROOT / "mcp-ca.crt"
    checks.append(Check("0", "0.2", "mcp-ca.crt", "P0", ca.is_file()))
    ref = ROOT / "reference" / "pipeline_18" / "attack_chain_18_events.json"
    checks.append(
        Check("0", "0.3", "reference pipeline_18", "P1", ref.is_file() if ref.is_file() else None,
              "skip/missing" if not ref.is_file() else "ok")
    )
    proxy_clear = not os.environ.get("HTTP_PROXY") and not os.environ.get("HTTPS_PROXY")
    checks.append(Check("0", "0.4", "no proxy", "P0", proxy_clear))
    cfg = EngineConfig.load(ROOT / "configs" / "engine.yaml")
    cfg_ok = cfg.backend == "soar_mcp" and cfg.soar_mcp.tool_name == "search_security_events"
    checks.append(
        Check("0", "0.5", "engine.yaml", "P0", cfg_ok,
              f"backend={cfg.backend} tool={cfg.soar_mcp.tool_name}")
    )
    token_ok = bool(os.environ.get("WAZUH_MCP_TOKEN") or os.environ.get("TRACE_ENGINE_MCP_TOKEN"))
    checks.append(Check("0", "0.6", "env loaded", "P0", token_ok, "token present" if token_ok else "no token"))
    return checks


def run_phase1(cfg: EngineConfig) -> list[Check]:
    checks: list[Check] = []
    ca = ROOT / "mcp-ca.crt"
    ok, detail = health_check(ca)
    checks.append(Check("1", "1.1", "TLS health", "P0", ok, detail))

    transport = build_mcp_transport(cfg.soar_mcp)
    try:
        transport._ensure_initialized()
        tools_result = transport._rpc("tools/list", {})
        tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []
        names = [str(t.get("name")) for t in tools if isinstance(t, dict)]
        checks.append(
            Check("1", "1.4", "tools/list count", "P0", len(names) >= 48,
                  f"{len(names)} tools", {"count": len(names)})
        )
        required = {
            "search_security_events",
            "get_wazuh_alerts",
            "analyze_security_threat",
            "generate_security_report",
        }
        missing = sorted(required - set(names))
        checks.append(
            Check("1", "1.5", "core tools", "P0", not missing,
                  f"missing: {missing}" if missing else "all present")
        )
        # rate limit 1.6
        errors = 0
        for _ in range(10):
            try:
                transport.query(query="*", from_ms=0, to_ms=0, limit=1)
            except Exception:  # noqa: BLE001
                errors += 1
        checks.append(
            Check("1", "1.6", "rate limit 10 calls", "P0", errors == 0, f"errors={errors}")
        )
    finally:
        close = getattr(transport, "close", None)
        if callable(close):
            close()
    return checks


def run_phase2(cfg: EngineConfig) -> list[Check]:
    checks: list[Check] = []
    waz = WazuhMcpTransport(
        endpoint=cfg.soar_mcp.endpoint,
        headers=dict(cfg.soar_mcp.headers),
        verify_tls=cfg.soar_mcp.verify_tls,
        ca_bundle=cfg.soar_mcp.ca_bundle,
        incident_prefix=cfg.soar_mcp.wazuh_incident_prefix,
        scope_field=cfg.soar_mcp.wazuh_scope_field,
        attacks_only=cfg.soar_mcp.wazuh_attacks_only,
        scenario_slug="pipeline_18",
        default_time_range=cfg.soar_mcp.wazuh_time_range,
        compact=cfg.soar_mcp.wazuh_compact,
    )
    normalizer = EventNormalizer(cfg.normalizer)
    cases = [
        ("2.1.1", "Bootstrap attack chain",
         'data.incident_id:INC-PIPELINE_18 AND data.is_attack:true', 20, 18, "P0"),
        ("2.1.2", "Seed evt_018",
         'data.raw_log_ref:"attack:idx_stress:evt_018" AND data.incident_id:INC-PIPELINE_18 AND data.is_attack:true',
         5, 1, "P0"),
        ("2.1.3", "Host WS-USER-01",
         'data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.hostname:WS-USER-01',
         15, 10, "P1"),
        ("2.1.4", "Host DB-PROD-01",
         'data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.hostname:DB-PROD-01',
         5, 2, "P1"),
        ("2.1.5", "Technique T1041",
         'data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.mitre_technique:T1041',
         5, 1, "P1"),
        ("2.1.6", "apt_5host",
         "data.scenario:apt_5host AND data.is_attack:true", 30, 1, "P1", True),
        ("2.1.7", "multipath",
         "data.scenario:multipath_12host AND data.is_attack:true", 40, 1, "P1", True),
    ]
    try:
        for row in cases:
            cid, name, query, limit, expected, level = row[:6]
            ge = row[6] if len(row) > 6 else False
            count, recs = count_hits(waz, query, limit=limit)
            if ge:
                passed = count >= expected
            else:
                passed = count == expected
            checks.append(
                Check("2", cid, name, level, passed,
                      f"got {count}, expected {'>=' if ge else ''}{expected}")
            )
            if cid == "2.1.2" and recs:
                data = recs[0].get("data") or recs[0]
                if isinstance(data, dict) and "data" in data:
                    data = data["data"]
                fields = {
                    "raw_log_ref": data.get("raw_log_ref"),
                    "mitre_technique": data.get("mitre_technique") or data.get("technique"),
                    "hostname": data.get("hostname") or data.get("host"),
                    "incident_id": data.get("incident_id"),
                    "is_attack": data.get("is_attack"),
                }
                evt_ok = (
                    fields["raw_log_ref"] == "attack:idx_stress:evt_018"
                    and fields.get("mitre_technique") == "T1041"
                    and fields.get("hostname") == "DB-PROD-01"
                )
                checks.append(
                    Check("2", "2.2", "evt_018 fields", "P0", evt_ok, json.dumps(fields, ensure_ascii=False))
                )

        # 2.3 bootstrap field completeness
        _, bootstrap_recs = count_hits(
            waz,
            'data.incident_id:INC-PIPELINE_18 AND data.is_attack:true',
            limit=20,
        )
        norm = normalizer.normalize_batch(bootstrap_recs)
        bad = []
        for ev in norm:
            if not ev.get("technique") or not ev.get("tactic"):
                bad.append(ev.get("raw_log_ref"))
        checks.append(
            Check("2", "2.3", "bootstrap normalization", "P0", len(bad) == 0,
                  f"discard candidates: {bad[:5]}" if bad else f"{len(norm)} events ok")
        )

        # 2.6 negative queries
        neg_cases = [
            ("2.6.1", "scenario only noise", "data.scenario:pipeline_18", lambda c: c > 18),
            ("2.6.2", "host only no attack", "data.hostname:DB-PROD-01", lambda c: c == 0),
            ("2.6.3", "ref without incident", 'data.raw_log_ref:"attack:idx_stress:evt_018"', lambda c: c == 3),
        ]
        for cid, name, query, pred in neg_cases:
            c, _ = count_hits(waz, query, limit=50)
            checks.append(Check("2", cid, name, "P0", pred(c), f"count={c}"))
    finally:
        waz.close()
    return checks


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


def run_phase6(cfg: EngineConfig) -> list[Check]:
    from trace_engine.runner import InvestigationRunner

    checks: list[Check] = []
    try:
        demo_cfg = EngineConfig.load(ROOT / "configs" / "engine_demo_wazuh.yaml")
        demo_cfg.soar_mcp.endpoint = cfg.soar_mcp.endpoint
        demo_cfg.soar_mcp.headers = dict(cfg.soar_mcp.headers)
        demo_cfg.soar_mcp.verify_tls = cfg.soar_mcp.verify_tls
        demo_cfg.soar_mcp.ca_bundle = cfg.soar_mcp.ca_bundle
        runner = InvestigationRunner(demo_cfg)
        t0 = time.time()
        report = runner.run(_entry_payload("pipeline_18"), scenario_id="pipeline_18", max_rounds=12)
        elapsed = time.time() - t0
        status_ok = report.get("status") == "completed"
        checks.append(
            Check("6", "6.0", "investigation completed", "P0", status_ok,
                  report.get("error") or f"{elapsed:.1f}s")
        )
        if not status_ok:
            return checks
        g = report.get("graph") or {}
        nodes = g.get("nodes") or []
        edges = g.get("edges") or []
        refs = [
            str((n.get("attributes") or {}).get("raw_log_ref") or "")
            for n in nodes
        ]
        attack_refs = [r for r in refs if r.startswith("attack:idx_stress:evt_")]
        noise = [r for r in refs if r.startswith("noise:")]
        checks.append(
            Check("6", "6.2.1", "attack nodes >=18", "P0", len(attack_refs) >= 18,
                  f"attack_refs={len(attack_refs)}")
        )
        checks.append(
            Check("6", "6.2.2", "edges >=17", "P0", len(edges) >= 17, f"edges={len(edges)}")
        )
        anchor = any("evt_018" in r for r in attack_refs)
        checks.append(Check("6", "6.2.3", "anchor evt_018", "P0", anchor))
        checks.append(
            Check("6", "6.2.5", "no noise in graph", "P0", len(noise) == 0,
                  f"noise_refs={len(noise)}")
        )
        usage = report.get("usage") or {}
        checks.append(
            Check("6", "6.1.1", "MCP usage", "P0", True,
                  json.dumps(usage.get("soar_fetch", {}), ensure_ascii=False))
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(Check("6", "6.x", "e2e run", "P0", False, str(exc)))
    return checks


def summarize(checks: list[Check]) -> dict[str, Any]:
    p0 = [c for c in checks if c.level == "P0"]
    p0_fail = [c for c in p0 if c.passed is False]
    return {
        "total": len(checks),
        "p0_pass": sum(1 for c in p0 if c.passed is True),
        "p0_fail": len(p0_fail),
        "p0_skip": sum(1 for c in p0 if c.passed is None),
        "blocked": len(p0_fail) > 0,
        "failed_items": [f"{c.item_id} {c.name}: {c.detail}" for c in checks if c.passed is False],
    }


def main() -> int:
    load_host_env()
    os.environ.setdefault("NO_PROXY", "192.144.151.189")
    all_checks: list[Check] = []
    all_checks.extend(run_phase0())
    cfg = EngineConfig.load(ROOT / "configs" / "engine.yaml")
    all_checks.extend(run_phase1(cfg))
    all_checks.extend(run_phase2(cfg))
    all_checks.extend(run_phase6(cfg))
    summary = summarize(all_checks)
    out = {
        "summary": summary,
        "checks": [
            {
                "phase": c.phase,
                "id": c.item_id,
                "name": c.name,
                "level": c.level,
                "passed": c.passed,
                "detail": c.detail,
                **({"data": c.data} if c.data else {}),
            }
            for c in all_checks
        ],
    }
    report_path = ROOT / "reports" / "wazuh_checklist_result.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(out, ensure_ascii=False, indent=2))
    print(f"\nReport: {report_path}")
    print("BLOCKED" if summary["blocked"] else "P0 PASS — eligible for production trace")
    return 2 if summary["blocked"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
