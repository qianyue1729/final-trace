"""生产态资产清单 — Wazuh Agent（MCP）与 CMDB（HTTP）主机发现。

在 bootstrap 阶段补充 known_hosts，供 cross_host_probe_generator 使用。
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from .config import AssetInventoryConfig


@runtime_checkable
class McpToolCaller(Protocol):
    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any: ...


def _dig(obj: Any, dotted: str) -> Any:
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _parse_mcp_text_json(text: str) -> Any:
    blob = text.strip()
    if not blob:
        return None
    if blob.startswith("Security Events") or blob.startswith("Wazuh Agents"):
        blob = blob.split("\n", 1)[-1].strip()
    for prefix in ("Agents:", "Agent List:", "Results:"):
        if blob.startswith(prefix):
            blob = blob.split("\n", 1)[-1].strip()
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        return None


def _hostnames_from_records(records: list[Any], *fields: str) -> list[str]:
    hosts: set[str] = set()
    for rec in records:
        if isinstance(rec, str) and rec.strip():
            hosts.add(rec.strip())
            continue
        if not isinstance(rec, dict):
            continue
        for f in fields:
            val = _dig(rec, f) if "." in f else rec.get(f)
            if val:
                hosts.add(str(val).strip())
                break
    return sorted(h for h in hosts if h)


def _extract_items_from_mcp_result(result: Any) -> list[dict]:
    if result is None:
        return []
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]
    if isinstance(result, dict):
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            for key in ("agents", "affected_items", "items", "data"):
                chunk = structured.get(key)
                if isinstance(chunk, list):
                    return [r for r in chunk if isinstance(r, dict)]
                if isinstance(chunk, dict):
                    inner = chunk.get("affected_items") or chunk.get("items")
                    if isinstance(inner, list):
                        return [r for r in inner if isinstance(r, dict)]
        for item in result.get("content", []):
            if item.get("type") != "text":
                continue
            parsed = _parse_mcp_text_json(item.get("text", ""))
            if isinstance(parsed, dict):
                data = parsed.get("data", parsed)
                if isinstance(data, dict):
                    items = data.get("affected_items") or data.get("items")
                    if isinstance(items, list):
                        return [r for r in items if isinstance(r, dict)]
            if isinstance(parsed, list):
                return [r for r in parsed if isinstance(r, dict)]
    return []


def fetch_wazuh_agent_hosts(
    transport: McpToolCaller,
    cfg: AssetInventoryConfig,
) -> tuple[list[str], dict[str, Any]]:
    """通过 MCP 工具 get_wazuh_agents / get_wazuh_running_agents 拉主机名。"""
    meta: dict[str, Any] = {"source": "wazuh_agents", "tool": cfg.wazuh_agents_tool}
    if not cfg.wazuh_agents_enabled:
        return [], meta

    args: dict[str, Any] = {"limit": cfg.wazuh_agents_limit}
    if cfg.wazuh_agents_status:
        args["status"] = cfg.wazuh_agents_status

    try:
        result = transport.call_tool(cfg.wazuh_agents_tool, args)
    except Exception as exc:  # noqa: BLE001
        meta["error"] = str(exc)
        return [], meta

    items = _extract_items_from_mcp_result(result)
    hosts = _hostnames_from_records(
        items,
        cfg.wazuh_agent_name_field,
        "name",
        "agent_name",
        "hostname",
        "id",
    )
    meta["count"] = len(hosts)
    return hosts, meta


def fetch_cmdb_hosts(cfg: AssetInventoryConfig) -> tuple[list[str], dict[str, Any]]:
    """HTTP CMDB：GET url，从 JSON 指定路径取主机列表。"""
    cmdb = cfg.cmdb
    meta: dict[str, Any] = {"source": "cmdb_http", "url": cmdb.url}
    if not cmdb.enabled or not cmdb.url.strip():
        return [], meta

    try:
        import httpx
    except ImportError:
        meta["error"] = "httpx not installed"
        return [], meta

    try:
        resp = httpx.request(
            cmdb.method.upper(),
            cmdb.url,
            headers=cmdb.headers,
            timeout=cmdb.timeout_seconds,
        )
        resp.raise_for_status()
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001
        meta["error"] = str(exc)
        return [], meta

    chunk = _dig(payload, cmdb.hosts_json_path) if cmdb.hosts_json_path else payload
    if isinstance(chunk, dict):
        chunk = chunk.get("hosts") or chunk.get("items") or list(chunk.values())
    if not isinstance(chunk, list):
        meta["error"] = f"hosts_json_path {cmdb.hosts_json_path!r} not a list"
        return [], meta

    hosts = _hostnames_from_records(chunk, cmdb.hostname_field, "hostname", "name", "host")
    meta["count"] = len(hosts)
    return hosts, meta


def discover_asset_hosts(
    transport: Any,
    cfg: AssetInventoryConfig,
) -> tuple[list[str], dict[str, Any]]:
    """合并 Wazuh Agent + CMDB 主机清单（去重、保序）。"""
    report: dict[str, Any] = {"sources": {}}
    merged: list[str] = []
    seen: set[str] = set()

    def _add(hosts: list[str]) -> None:
        for h in hosts:
            key = h.lower()
            if key not in seen:
                seen.add(key)
                merged.append(h)

    if cfg.wazuh_agents_enabled and isinstance(transport, McpToolCaller):
        wazuh_hosts, wazuh_meta = fetch_wazuh_agent_hosts(transport, cfg)
        report["sources"]["wazuh_agents"] = wazuh_meta
        _add(wazuh_hosts)
    elif cfg.wazuh_agents_enabled:
        report["sources"]["wazuh_agents"] = {
            "error": "transport does not support call_tool()",
        }

    cmdb_hosts, cmdb_meta = fetch_cmdb_hosts(cfg)
    report["sources"]["cmdb"] = cmdb_meta
    _add(cmdb_hosts)

    report["total"] = len(merged)
    return merged, report
