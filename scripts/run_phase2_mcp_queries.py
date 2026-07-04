#!/usr/bin/env python3
"""Phase 2 checklist queries via direct MCP tools/call."""
from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.config import EngineConfig
from trace_engine.normalizer import EventNormalizer
from trace_engine.transports import build_mcp_transport, _extract_mcp_records


def load_env() -> None:
    env_path = ROOT / "host-client.env"
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip())


def parse_total(text: str) -> int | None:
    for pat in (
        r"total_affected_items[\"']?\s*[:=]\s*(\d+)",
        r'"total_affected_items"\s*:\s*(\d+)',
        r'"total"\s*:\s*(\d+)',
    ):
        m = re.search(pat, text, re.I)
        if m:
            return int(m.group(1))
    return None


def main() -> int:
    load_env()
    cfg = EngineConfig.load(ROOT / "configs" / "engine.yaml")
    normalizer = EventNormalizer(cfg.normalizer)
    t = build_mcp_transport(cfg.soar_mcp)
    t._ensure_initialized()
    results = []
    cases = [
        ("2.1.1", "P0", "data.incident_id:INC-PIPELINE_18 AND data.is_attack:true", 20, 18, "eq"),
        ("2.1.2", "P0", 'data.raw_log_ref:"attack:idx_stress:evt_018" AND data.incident_id:INC-PIPELINE_18 AND data.is_attack:true', 5, 1, "eq"),
        ("2.1.3", "P1", "data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.hostname:WS-USER-01", 15, 10, "eq"),
        ("2.1.4", "P1", "data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.hostname:DB-PROD-01", 5, 2, "eq"),
        ("2.1.5", "P1", "data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.mitre_technique:T1041", 5, 1, "eq"),
        ("2.1.6", "P1", "data.scenario:apt_5host AND data.is_attack:true", 30, 1, "ge"),
        ("2.1.7", "P1", "data.scenario:multipath_12host AND data.is_attack:true", 40, 1, "ge"),
        ("2.6.1", "P0", "data.scenario:pipeline_18", 50, 18, "gt"),
        ("2.6.2", "P0", "data.hostname:DB-PROD-01", 50, 0, "attack_eq"),
        ("2.6.3", "P0", 'data.raw_log_ref:"attack:idx_stress:evt_018"', 50, 3, "eq"),
    ]
    try:
        for cid, level, query, limit, expected, mode in cases:
            raw = t._rpc(
                "tools/call",
                {
                    "name": "search_security_events",
                    "arguments": {
                        "query": query,
                        "time_range": "30d",
                        "limit": limit,
                        "compact": False,
                    },
                },
            )
            text = ""
            if isinstance(raw, dict):
                content = raw.get("content") or []
                if content and isinstance(content[0], dict):
                    text = content[0].get("text") or ""
            count = parse_total(text)
            if count is None:
                count = text.lower().count("security event")
            if mode == "attack_eq":
                recs = _extract_mcp_records(raw)
                norm = normalizer.normalize_batch(recs)
                attack_refs = [
                    e.get("raw_log_ref", "")
                    for e in norm
                    if str((e.get("attributes") or {}).get("is_attack", "")).lower() == "true"
                    or str(e.get("raw_log_ref", "")).startswith("attack:")
                ]
                count = len(attack_refs)
                mode = "eq"
            if mode == "ge":
                passed = count >= expected
            elif mode == "gt":
                passed = count > expected
            else:
                passed = count == expected
            results.append(
                {
                    "id": cid,
                    "level": level,
                    "passed": passed,
                    "count": count,
                    "expected": expected,
                    "mode": mode,
                }
            )
            print(f"[{'PASS' if passed else 'FAIL'}] {cid} count={count} expected({mode})={expected}")
    finally:
        t.close()
    out = ROOT / "reports" / "phase2_mcp_queries.json"
    out.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    p0_fail = [r for r in results if r["level"] == "P0" and not r["passed"]]
    return 2 if p0_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
