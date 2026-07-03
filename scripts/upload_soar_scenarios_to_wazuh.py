#!/usr/bin/env python3
"""将本地 soar_mcp_env 场景对接到 Wazuh MCP 环境。

Wazuh MCP **没有**日志上传类工具 — `upload` 子命令会尝试 MCP 导入但通常失败。
场景数据应走 NDJSON 导出 + scp（见 export / ingest-guide）。

用法:
  python scripts/wazuh_auth.py --api-key wazuh_xxx --set-env
  python scripts/upload_soar_scenarios_to_wazuh.py probe
  python scripts/upload_soar_scenarios_to_wazuh.py query-test --host WS-USER-01
  python scripts/upload_soar_scenarios_to_wazuh.py export --scenario pipeline_18
  python scripts/upload_soar_scenarios_to_wazuh.py ingest-guide

环境变量:
  WAZUH_MCP_ENDPOINT  默认 http://192.144.151.189/mcp
  WAZUH_MCP_TOKEN     Bearer JWT（勿写入 git）
  WAZUH_UPLOAD_TOOL   强制指定 MCP 工具名（自动探测失败时）
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SOAR_ENV = ROOT / "soar_mcp_env"
sys.path.insert(0, str(ROOT / "src"))

DEFAULT_ENDPOINT = os.environ.get("WAZUH_MCP_ENDPOINT", "http://192.144.151.189/mcp")
DEFAULT_TOKEN = os.environ.get("WAZUH_MCP_TOKEN", "")

# 按常见命名尝试自动匹配的上传类工具
UPLOAD_TOOL_CANDIDATES = (
    "import_scenario",
    "upload_scenario",
    "load_scenario",
    "scenario_upsert",
    "ingest_scenario",
    "soar_import_scenario",
    "wazuh_import_scenario",
    "put_scenario",
)


def _client(endpoint: str, token: str):
    from trace_engine.transports import McpHttpTransport

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return McpHttpTransport(endpoint=endpoint, tool_name="soar_query", headers=headers)


def _list_tools(transport) -> list[dict[str, Any]]:
    transport._ensure_initialized()
    result = transport._rpc("tools/list", {})
    tools = result.get("tools", []) if isinstance(result, dict) else []
    return tools if isinstance(tools, list) else []


def _call_tool(transport, name: str, arguments: dict[str, Any]) -> Any:
    transport._ensure_initialized()
    return transport._rpc("tools/call", {"name": name, "arguments": arguments})


def cmd_probe(args: argparse.Namespace) -> int:
    token = args.token or DEFAULT_TOKEN
    if not token:
        print("警告: 未设置 WAZUH_MCP_TOKEN，部分服务端会拒绝连接。", file=sys.stderr)

    try:
        transport = _client(args.endpoint, token)
        transport._ensure_initialized()
        print(f"OK 已连接 {args.endpoint}")
        print(f"    session={transport._session_id}")
    except Exception as exc:
        err = str(exc)
        print(f"连接失败: {exc}", file=sys.stderr)
        if "401" in err or "Unauthorized" in err:
            print("原因: JWT 无效或已过期，请重新生成 WAZUH_MCP_TOKEN。", file=sys.stderr)
        elif "10060" in err or "timeout" in err.lower():
            print(
                "排查: 1) URL 是否为 http://192.144.151.189/mcp（无 :3000）  "
                "2) 防火墙/安全组  3) JWT 是否有效",
                file=sys.stderr,
            )
        return 1

    tools = _list_tools(transport)
    print(f"\n可用 MCP 工具 ({len(tools)}):")
    upload_like: list[str] = []
    query_like: list[str] = []
    for t in tools:
        name = t.get("name", "")
        desc = (t.get("description") or "")[:120]
        schema = t.get("inputSchema") or {}
        props = list((schema.get("properties") or {}).keys())
        print(f"  - {name}: {desc}")
        if props:
            print(f"      params: {', '.join(props)}")
        low = name.lower()
        if any(k in low for k in ("import", "upload", "scenario", "ingest", "load", "put")):
            upload_like.append(name)
        if any(k in low for k in ("query", "search", "soar")):
            query_like.append(name)

    print("\n推测上传类工具:", upload_like or "(无 — Wazuh 正常情况，请用 export + scp)")
    print("推测查询类工具:", query_like or "(无)")
    for name in query_like:
        if "search_security" in name.lower():
            print(f"\n推荐 trace-engine 配置: tool_profile=wazuh, tool_name={name}")
    transport.close()
    return 0


def cmd_query_test(args: argparse.Namespace) -> int:
    """用 search_security_events 试查一条。"""
    token = args.token or DEFAULT_TOKEN
    if not token:
        print("错误: 请设置 WAZUH_MCP_TOKEN", file=sys.stderr)
        return 1
    from trace_engine.transports import WazuhMcpTransport

    transport = WazuhMcpTransport(
        endpoint=args.endpoint,
        headers={"Authorization": f"Bearer {token}"},
        incident_prefix=args.incident or "",
        compact=False,
        attacks_only=bool(args.incident),
    )
    try:
        q = f"host:{args.host}"
        recs = transport.query(query=q, from_ms=0, to_ms=0, limit=args.limit)
        print(f"query={q!r} incident={args.incident!r} -> {len(recs)} records")
        if recs:
            print("sample keys:", list(recs[0].keys())[:12])
    except Exception as exc:
        print(f"查询失败: {exc}", file=sys.stderr)
        return 1
    finally:
        transport.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    import subprocess
    cmd = [sys.executable, str(ROOT / "scripts" / "export_scenario_ndjson.py")]
    if args.scenario:
        cmd.append(args.scenario)
    if args.all:
        cmd.append("--all")
    if args.out_dir:
        cmd.extend(["--out-dir", str(args.out_dir)])
    return subprocess.call(cmd)


def cmd_ingest_guide(_args: argparse.Namespace) -> int:
    print("""
=== soar_mcp_env → Wazuh 真实场景接入（MCP 只读，日志需先入库）===

1. 换 JWT
   python scripts/wazuh_auth.py --api-key wazuh_<MCP_API_KEY> --set-env

2. 导出场景 NDJSON
   python scripts/export_scenario_ndjson.py --all --out-dir wazuh_ingest

3. 传到 Wazuh 服务器
   scp wazuh_ingest/*.ndjson ubuntu@192.144.151.189:/home/ubuntu/soar-logs/incoming/
   ssh ubuntu@192.144.151.189 "/home/ubuntu/scripts/ingest_soar_incoming.sh"

4. 验证 MCP 查询（扁平字段 → Indexer 中为 data.*）
   python scripts/upload_soar_scenarios_to_wazuh.py query-test --host WS-USER-01 --incident pipeline_18

5. 启动 trace-engine
   copy configs\\engine.wazuh.example.yaml configs\\engine.yaml
   # 设置 wazuh_incident_prefix: pipeline_18
   python scripts/serve_engine.py --config configs/engine.yaml
""")
    return 0


def _load_registry() -> dict[str, Any]:
    return json.loads((SOAR_ENV / "registry.json").read_text(encoding="utf-8"))


def _scenario_ids(selected: list[str] | None) -> list[str]:
    reg = _load_registry()
    all_ids = list(reg.get("scenarios", {}).keys())
    if not selected:
        return all_ids
    missing = [s for s in selected if s not in all_ids]
    if missing:
        raise SystemExit(f"未知场景 ID: {missing}；可选: {all_ids}")
    return selected


def _chunk_events(events: list[dict], batch_size: int) -> list[list[dict]]:
    if batch_size <= 0:
        return [events]
    return [events[i : i + batch_size] for i in range(0, len(events), batch_size)]


def _pick_upload_tool(tools: list[dict], forced: str | None) -> tuple[str, dict]:
    if forced:
        for t in tools:
            if t.get("name") == forced:
                return forced, t.get("inputSchema") or {}
        raise SystemExit(f"未找到指定工具: {forced}")

    by_name = {t.get("name"): t for t in tools}
    for cand in UPLOAD_TOOL_CANDIDATES:
        if cand in by_name:
            return cand, by_name[cand].get("inputSchema") or {}

    for t in tools:
        name = (t.get("name") or "").lower()
        if any(k in name for k in ("import", "upload", "scenario")):
            return t["name"], t.get("inputSchema") or {}

    names = [t.get("name") for t in tools]
    raise SystemExit(
        "无法自动识别上传工具。请先运行 probe，再设置:\n"
        f"  WAZUH_UPLOAD_TOOL=<工具名>\n  当前工具列表: {names}"
    )


def _build_upload_args(
    tool_name: str,
    schema: dict,
    *,
    scenario_id: str,
    spec: dict,
    meta: dict,
    ground_truth: dict,
    events_batch: list[dict],
    batch_index: int,
    batch_total: int,
    full_payload: dict | None = None,
) -> dict[str, Any]:
    """根据工具 inputSchema 构造参数（兼容多种服务端约定）。"""
    props = set((schema.get("properties") or {}).keys())

    if "scenario_json" in props or "payload" in props:
        body = full_payload or {
            "meta": meta,
            "events": events_batch,
            "ground_truth": ground_truth,
        }
        key = "scenario_json" if "scenario_json" in props else "payload"
        return {
            "scenario_id": scenario_id,
            key: json.dumps(body, ensure_ascii=False),
            **({"replace": True} if "replace" in props else {}),
        }

    if "content" in props and "filename" in props:
        rel = spec.get("file", f"scenarios/{scenario_id}.json")
        return {
            "filename": rel.replace("/", "_"),
            "content": json.dumps(full_payload or {"meta": meta, "events": events_batch, "ground_truth": ground_truth}, ensure_ascii=False),
            "scenario_id": scenario_id,
        }

    # 通用分片上传
    args: dict[str, Any] = {
        "scenario_id": scenario_id,
        "meta": meta,
        "ground_truth": ground_truth,
        "events": events_batch,
        "batch_index": batch_index,
        "batch_total": batch_total,
        "registry_name": spec.get("name", scenario_id),
        "entry_alert_ref": spec.get("entry_alert_ref") or meta.get("entry_alert_ref"),
    }
    if "events_batch" in props:
        args = {k: v for k, v in args.items() if k in props or k == "events_batch"}
        args["events_batch"] = events_batch
    return {k: v for k, v in args.items() if k in props or not props}


def cmd_upload(args: argparse.Namespace) -> int:
    token = args.token or DEFAULT_TOKEN
    if args.dry_run:
        registry = _load_registry()
        scenario_ids = _scenario_ids(args.scenario or None)
        for sid in scenario_ids:
            spec = registry["scenarios"][sid]
            path = SOAR_ENV / spec["file"]
            data = json.loads(path.read_text(encoding="utf-8"))
            events = data.get("events", [])
            batches = _chunk_events(events, args.batch_size)
            print(f"{sid}: {path.name} events={len(events)} batches={len(batches)}")
        return 0

    if not token:
        print("错误: 请设置环境变量 WAZUH_MCP_TOKEN", file=sys.stderr)
        return 1

    transport = _client(args.endpoint, token)
    try:
        transport._ensure_initialized()
    except Exception as exc:
        print(f"连接失败: {exc}", file=sys.stderr)
        return 1

    tools = _list_tools(transport)
    forced = args.tool or os.environ.get("WAZUH_UPLOAD_TOOL")
    tool_name, schema = _pick_upload_tool(tools, forced)
    print(f"使用上传工具: {tool_name}")

    registry = _load_registry()
    scenario_ids = _scenario_ids(args.scenario or None)

    # 可选：先上传 registry
    if args.with_registry and any(t.get("name") == "import_registry" for t in tools):
        print("上传 registry.json …")
        _call_tool(
            transport,
            "import_registry",
            {"registry_json": (SOAR_ENV / "registry.json").read_text(encoding="utf-8")},
        )

    for sid in scenario_ids:
        spec = registry["scenarios"][sid]
        path = SOAR_ENV / spec["file"]
        if not path.is_file():
            print(f"跳过 {sid}: 文件不存在 {path}", file=sys.stderr)
            continue

        print(f"\n=== {sid} ({path.name}, {path.stat().st_size / 1024 / 1024:.1f} MB) ===")
        data = json.loads(path.read_text(encoding="utf-8"))
        meta = data.get("meta", {})
        gt = data.get("ground_truth", {})
        events = data.get("events", [])
        batches = _chunk_events(events, args.batch_size)

        if args.dry_run:
            print(f"  events={len(events)} batches={len(batches)} batch_size={args.batch_size}")
            continue

        # 小场景：整包一次
        if len(batches) == 1 and not args.force_chunk:
            payload = {"meta": meta, "events": events, "ground_truth": gt}
            upload_args = _build_upload_args(
                tool_name,
                schema,
                scenario_id=sid,
                spec=spec,
                meta=meta,
                ground_truth=gt,
                events_batch=events,
                batch_index=0,
                batch_total=1,
                full_payload=payload,
            )
            print(f"  上传整包 … keys={list(upload_args.keys())}")
            result = _call_tool(transport, tool_name, upload_args)
            print(f"  完成: {str(result)[:200]}")
            continue

        for i, batch in enumerate(batches):
            upload_args = _build_upload_args(
                tool_name,
                schema,
                scenario_id=sid,
                spec=spec,
                meta=meta if i == 0 else {},
                ground_truth=gt if i == 0 else {},
                events_batch=batch,
                batch_index=i,
                batch_total=len(batches),
            )
            print(f"  批次 {i + 1}/{len(batches)} ({len(batch)} events) …")
            result = _call_tool(transport, tool_name, upload_args)
            if i == 0 or i == len(batches) - 1:
                print(f"    → {str(result)[:160]}")

    transport.close()
    print("\n全部完成。可用 trace-engine 生产态验证:")
    print("  copy configs/engine.wazuh.example.yaml → configs/engine.yaml")
    print("  python scripts/serve_engine.py --config configs/engine.yaml")
    return 0


def cmd_pack(args: argparse.Namespace) -> int:
    out = Path(args.out)
    include = [
        SOAR_ENV / "registry.json",
        SOAR_ENV / "data_sources.json",
        SOAR_ENV / "README.md",
    ]
    include += sorted((SOAR_ENV / "scenarios").glob("*.json"))

    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for p in include:
            if p.is_file():
                arc = f"soar_mcp_env/{p.relative_to(SOAR_ENV)}"
                zf.write(p, arc)
                print(f"  + {arc} ({p.stat().st_size / 1024 / 1024:.1f} MB)")

    print(f"\n已打包: {out.resolve()} ({out.stat().st_size / 1024 / 1024:.1f} MB)")
    print("若 MCP 不可达，可将 zip 传到服务器后解压到 SOAR 数据目录。")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="上传 soar_mcp_env 到 Wazuh MCP 服务端")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="MCP HTTP 端点")
    parser.add_argument("--token", default="", help="Bearer JWT（默认读 WAZUH_MCP_TOKEN）")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_probe = sub.add_parser("probe", help="探测连通性并列出 MCP 工具")
    p_probe.set_defaults(func=cmd_probe)

    p_qt = sub.add_parser("query-test", help="试调用 search_security_events")
    p_qt.add_argument("--host", default="WS-USER-01")
    p_qt.add_argument("--incident", default="", help="incident_id 前缀，如 pipeline_18")
    p_qt.add_argument("--limit", type=int, default=5)
    p_qt.set_defaults(func=cmd_query_test)

    p_exp = sub.add_parser("export", help="导出 NDJSON 供 scp 入库")
    p_exp.add_argument("--scenario", action="append")
    p_exp.add_argument("--all", action="store_true")
    p_exp.add_argument("--out-dir", default="wazuh_ingest")
    p_exp.set_defaults(func=cmd_export)

    p_guide = sub.add_parser("ingest-guide", help="打印 Wazuh 场景入库流程")
    p_guide.set_defaults(func=cmd_ingest_guide)

    p_pack = sub.add_parser("pack", help="打包场景为 zip（离线）")
    p_pack.add_argument("--out", default="soar_mcp_env_bundle.zip")
    p_pack.set_defaults(func=cmd_pack)

    p_up = sub.add_parser("upload", help="[通常不可用] 尝试 MCP 上传场景")
    p_up.add_argument("--scenario", action="append", help="场景 ID，可重复；默认全部")
    p_up.add_argument("--all", action="store_true", help="上传 registry 中全部场景")
    p_up.add_argument("--batch-size", type=int, default=800, help="大场景分片事件数/批")
    p_up.add_argument("--force-chunk", action="store_true", help="强制分片 even 小场景")
    p_up.add_argument("--with-registry", action="store_true", help="若服务端有 import_registry 则一并上传")
    p_up.add_argument("--tool", default="", help="指定 MCP 上传工具名")
    p_up.add_argument("--dry-run", action="store_true", help="只统计不上传")
    p_up.set_defaults(func=cmd_upload)

    args = parser.parse_args()
    if getattr(args, "all", False):
        args.scenario = None
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
