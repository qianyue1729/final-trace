#!/usr/bin/env python3
"""将 soar_mcp_env 场景导出为扁平 NDJSON，供 scp 到 Wazuh 服务器 ingest。

Wazuh MCP 无日志写入工具；须先 scp 到 soar-logs/incoming/ 再跑 ingest 脚本。
字段必须扁平，禁止嵌套 data/agent 对象（见服务器 soar-logs/SCHEMA.md）。

Usage:
  python scripts/export_scenario_ndjson.py pipeline_18 --out pipeline_18.ndjson
  python scripts/export_scenario_ndjson.py --all --out-dir wazuh_ingest/

scp + ingest（在 Windows 本机执行，需 SSH 密钥或密码）:
  scp wazuh_ingest/*.ndjson ubuntu@192.144.151.189:/home/ubuntu/soar-logs/incoming/
  ssh ubuntu@192.144.151.189 "/home/ubuntu/scripts/ingest_soar_incoming.sh"
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOAR_ENV = ROOT / "soar_mcp_env"
sys.path.insert(0, str(ROOT / "src"))


def _load_registry() -> dict:
    return json.loads((SOAR_ENV / "registry.json").read_text(encoding="utf-8"))


def _incident_id(scenario_id: str) -> str:
    slug = scenario_id.upper().replace("_", "-")
    return f"INC-{slug}-001"


def _entity_host(entity: dict | None) -> str | None:
    if not entity:
        return None
    attrs = entity.get("attrs") or {}
    return attrs.get("host_uid") or attrs.get("host")


def flatten_event(ev: dict, scenario_id: str) -> dict[str, Any]:
    """EntityEvent → Wazuh 扁平 ingest 行（Indexer 检索时用 data.<field>）。"""
    src = ev.get("src_entity") or {}
    dst = ev.get("dst_entity") or {}
    src_attrs = src.get("attrs") or {}
    dst_attrs = dst.get("attrs") or {}
    host = _entity_host(src) or _entity_host(dst)

    row: dict[str, Any] = {
        "timestamp": ev.get("ts"),
        "scenario": scenario_id,
        "incident_id": _incident_id(scenario_id),
        "raw_log_ref": ev.get("raw_log_ref"),
        "action": ev.get("action"),
        "technique": ev.get("technique"),
        "tactic": ev.get("tactic"),
        "anomaly_score": ev.get("anomaly_score"),
        "host": host,
        "process_name": src_attrs.get("name"),
        "src_ip": src_attrs.get("ip"),
        "dst_ip": dst_attrs.get("ip"),
        "ingest_source": "soar_mcp_env",
    }
    ocsf = ev.get("ocsf_class_uid")
    if ocsf is not None:
        row["ocsf_class_uid"] = ocsf
    return {k: v for k, v in row.items() if v is not None}


def export_scenario(scenario_id: str, out_path: Path) -> int:
    reg = _load_registry()
    spec = reg["scenarios"][scenario_id]
    data = json.loads((SOAR_ENV / spec["file"]).read_text(encoding="utf-8"))
    events = data.get("events", [])
    count = 0
    with out_path.open("w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(flatten_event(ev, scenario_id), ensure_ascii=False) + "\n")
            count += 1
    print(f"{scenario_id}: {count} events -> {out_path}")
    return count


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", nargs="?", help="场景 ID")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--out", type=Path, help="输出 NDJSON 文件")
    parser.add_argument("--out-dir", type=Path, default=Path("wazuh_ingest"))
    args = parser.parse_args()

    reg = _load_registry()
    ids = list(reg["scenarios"]) if args.all else [args.scenario]
    if not ids or (not args.all and not args.scenario):
        parser.error("指定 scenario 或 --all")

    if args.all:
        args.out_dir.mkdir(parents=True, exist_ok=True)
        total = 0
        for sid in ids:
            total += export_scenario(sid, args.out_dir / f"{sid}.ndjson")
        print(f"合计 {total} 条 -> {args.out_dir.resolve()}")
        print(
            "scp: scp wazuh_ingest/*.ndjson "
            "ubuntu@192.144.151.189:/home/ubuntu/soar-logs/incoming/"
        )
        print("ingest: ssh ubuntu@192.144.151.189 /home/ubuntu/scripts/ingest_soar_incoming.sh")
    else:
        out = args.out or Path(f"{args.scenario}.ndjson")
        export_scenario(args.scenario, out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
