#!/usr/bin/env python3
"""探测 Wazuh Agent 列表与 CMDB 资产发现（bootstrap 前置检查）。

Usage:
  python scripts/probe_asset_inventory.py
  python scripts/probe_asset_inventory.py --wazuh-agents
  python scripts/probe_asset_inventory.py --cmdb-url http://cmdb/api/hosts

环境变量:
  WAZUH_MCP_TOKEN / TRACE_ENGINE_MCP_ENDPOINT
  TRACE_ENGINE_WAZUH_AGENTS=1
  TRACE_ENGINE_CMDB_URL
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trace_engine.asset_inventory import discover_asset_hosts
from trace_engine.config import AssetInventoryConfig, CmdbConfig
from trace_engine.transports import build_mcp_transport, McpHttpTransport


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--endpoint", default=os.environ.get("TRACE_ENGINE_MCP_ENDPOINT", "http://192.144.151.189/mcp"))
    parser.add_argument("--wazuh-agents", action="store_true")
    parser.add_argument("--agent-tool", default="get_wazuh_agents")
    parser.add_argument("--cmdb-url", default=os.environ.get("TRACE_ENGINE_CMDB_URL", ""))
    parser.add_argument("--cmdb-path", default="hosts", help="JSON 中主机数组路径")
    parser.add_argument("--cmdb-field", default="hostname")
    args = parser.parse_args()

    token = os.environ.get("WAZUH_MCP_TOKEN", "")
    headers = {"Authorization": f"Bearer {token}"} if token else {}

    inv = AssetInventoryConfig(
        wazuh_agents_enabled=args.wazuh_agents or os.environ.get("TRACE_ENGINE_WAZUH_AGENTS", "").lower() in ("1", "true"),
        wazuh_agents_tool=args.agent_tool,
        cmdb=CmdbConfig(
            enabled=bool(args.cmdb_url),
            url=args.cmdb_url,
            hosts_json_path=args.cmdb_path,
            hostname_field=args.cmdb_field,
        ),
    )

    transport = None
    if inv.wazuh_agents_enabled:
        from trace_engine.config import SoarMcpConfig
        cfg = SoarMcpConfig(endpoint=args.endpoint, tool_profile="wazuh", headers=headers)
        transport = build_mcp_transport(cfg)

    if inv.cmdb.enabled and transport is None:
        transport = McpHttpTransport(endpoint=args.endpoint, headers=headers)

    hosts, report = discover_asset_hosts(transport, inv)
    print(json.dumps({"hosts": hosts, "report": report}, ensure_ascii=False, indent=2))
    if transport and hasattr(transport, "close"):
        transport.close()
    return 0 if hosts or not (inv.wazuh_agents_enabled or inv.cmdb.enabled) else 1


if __name__ == "__main__":
    raise SystemExit(main())
