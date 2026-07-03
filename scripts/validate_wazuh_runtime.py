#!/usr/bin/env python3
"""Preflight the real Wazuh MCP path without exposing credentials."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.config import EngineConfig
from trace_engine.normalizer import EventNormalizer
from trace_engine.transports import build_mcp_transport


def _error_code(exc: Exception) -> str:
    message = str(exc).lower()
    if "401" in message or "unauthorized" in message:
        return "auth_unauthorized"
    if "403" in message or "forbidden" in message:
        return "auth_forbidden"
    if "certificate_verify_failed" in message:
        return "tls_ca_untrusted"
    if "timeout" in message:
        return "connection_timeout"
    if any(f"{code}" in message for code in range(500, 600)):
        return "upstream_server_error"
    return "connection_failed"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="configs/engine.yaml")
    parser.add_argument("--host", default="")
    parser.add_argument("--incident", default="")
    parser.add_argument("--limit", type=int, default=5)
    args = parser.parse_args()

    cfg = EngineConfig.load(args.config)
    if args.incident:
        cfg.soar_mcp.wazuh_incident_prefix = args.incident
        # pipeline_* 等评测场景在 Indexer 中为 data.scenario；INC-* 才用 incident_id
        if cfg.soar_mcp.wazuh_scope_field == "incident" and not args.incident.upper().startswith("INC-"):
            cfg.soar_mcp.wazuh_scope_field = "auto"
    report = {
        "status": "blocked",
        "endpoint": cfg.soar_mcp.endpoint,
        "tool_profile": cfg.soar_mcp.tool_profile,
        "configured_tool": cfg.soar_mcp.tool_name,
        "verify_tls": cfg.soar_mcp.verify_tls,
        "ca_bundle": cfg.soar_mcp.ca_bundle or None,
        "credential_present": bool(cfg.soar_mcp.headers.get("Authorization")),
        "warnings": [],
        "checks": {},
    }
    if cfg.soar_mcp.endpoint.lower().startswith("http://"):
        report["warnings"].append(
            "MCP endpoint uses plaintext HTTP; use HTTPS with ca_bundle in production"
        )
    if cfg.soar_mcp.verify_tls and cfg.soar_mcp.ca_bundle:
        ca_path = Path(cfg.soar_mcp.ca_bundle)
        report["checks"]["tls_ca_bundle"] = {
            "ok": ca_path.is_file(),
            "path": str(ca_path),
        }
        if not ca_path.is_file():
            report["warnings"].append(f"CA bundle not found: {ca_path}")
    if not report["credential_present"]:
        report["checks"]["authentication"] = {
            "ok": False,
            "reason": "missing WAZUH_MCP_TOKEN/TRACE_ENGINE_MCP_TOKEN",
        }
        report["warnings"].append(
            "未加载 MCP Token：请确认项目根目录存在 host-client.env，"
            "或先执行 Get-Content host-client.env | ForEach-Object { ... }"
        )

    transport = build_mcp_transport(cfg.soar_mcp)
    try:
        transport._ensure_initialized()
        report["checks"]["mcp_initialize"] = {"ok": True}
        tools_result = transport._rpc("tools/list", {})
        tools = (
            tools_result.get("tools", [])
            if isinstance(tools_result, dict) else []
        )
        tool_names = [
            str(tool.get("name"))
            for tool in tools
            if isinstance(tool, dict)
        ]
        report["checks"]["tool_available"] = {
            "ok": cfg.soar_mcp.tool_name in tool_names,
            "available_tools": tool_names,
        }
        query = f"host:{args.host}" if args.host else "*"
        records = transport.query(
            query=query,
            from_ms=0,
            to_ms=0,
            limit=max(1, min(args.limit, 20)),
        )
        normalized = EventNormalizer(cfg.normalizer).normalize_batch(records)
        report["checks"]["telemetry_query"] = {
            "ok": bool(records),
            "record_count": len(records),
        }
        report["checks"]["normalization"] = {
            "ok": bool(normalized) and all(
                event.get("raw_log_ref")
                and event.get("ts")
                and event.get("src_entity", {}).get("attrs", {}).get("host_uid")
                for event in normalized
            ),
            "events_with_technique": sum(
                bool(event.get("technique")) for event in normalized
            ),
            "events_with_host": sum(
                bool(event.get("src_entity", {}).get("attrs", {}).get("host_uid"))
                for event in normalized
            ),
            "sample_keys": [
                sorted(event.keys()) for event in normalized[:2]
            ],
        }
        if hasattr(transport, "query_pages"):
            pages = list(
                transport.query_pages(
                    query=query,
                    from_ms=0,
                    to_ms=0,
                    limit=max(1, min(args.limit, 10)),
                    max_pages=2,
                )
            )
            report["checks"]["pagination"] = {
                "ok": bool(pages),
                "pages": len(pages),
                "first_page_records": len(pages[0].records) if pages else 0,
                "first_page_has_more": bool(
                    pages and pages[0].pagination.get("has_more")
                ),
                "pagination_mode": (
                    pages[0].pagination.get("mode") if pages else None
                ),
            }
        required = (
            report["checks"]["tool_available"]["ok"]
            and report["checks"]["telemetry_query"]["ok"]
            and report["checks"]["normalization"]["ok"]
        )
        if report["checks"].get("tls_ca_bundle"):
            required = required and report["checks"]["tls_ca_bundle"]["ok"]
        report["status"] = "ready" if required else "blocked"
    except Exception as exc:
        report["checks"]["mcp_initialize"] = {
            "ok": False,
            "reason": _error_code(exc),
        }
    finally:
        close = getattr(transport, "close", None)
        if callable(close):
            close()

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
