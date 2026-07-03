#!/usr/bin/env python3
"""从 Wazuh MCP 服务端 /auth/token 换取 JWT。

Usage:
  python scripts/wazuh_auth.py --api-key wazuh_xxx
  python scripts/wazuh_auth.py --api-key wazuh_xxx --set-env   # 打印 PowerShell set 命令

环境变量:
  WAZUH_AUTH_URL  默认 https://192.144.151.189/auth/token
"""
from __future__ import annotations

import argparse
import json
import os
import ssl
import sys
from pathlib import Path

try:
    import httpx
except ImportError:
    print("需要 httpx: pip install httpx", file=sys.stderr)
    raise


DEFAULT_AUTH_URL = os.environ.get(
    "WAZUH_AUTH_URL", "https://192.144.151.189/auth/token"
)
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def resolve_ca_bundle(ca_bundle: str | None = None) -> str | bool:
    """Resolve a client-local CA path; never silently disables verification."""
    candidates = [
        ca_bundle,
        os.environ.get("WAZUH_MCP_CA_BUNDLE"),
        str(PROJECT_ROOT / "mcp-ca.crt"),
    ]
    for raw in candidates:
        if not raw:
            continue
        path = Path(raw)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        if path.is_file():
            return str(path.resolve())
    if ca_bundle:
        raise FileNotFoundError(f"CA bundle not found: {ca_bundle}")
    return True


def fetch_token(
    api_key: str,
    auth_url: str = DEFAULT_AUTH_URL,
    *,
    ca_bundle: str | None = None,
) -> dict:
    verify = resolve_ca_bundle(ca_bundle)
    if isinstance(verify, str):
        verify = ssl.create_default_context(cafile=verify)
    resp = httpx.post(
        auth_url,
        json={"api_key": api_key},
        headers={"Content-Type": "application/json"},
        timeout=30.0,
        verify=verify,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Wazuh MCP JWT 换取")
    parser.add_argument("--api-key", required=True, help="MCP_API_KEY（wazuh_ 前缀）")
    parser.add_argument("--auth-url", default=DEFAULT_AUTH_URL)
    parser.add_argument(
        "--ca-bundle",
        default=None,
        help="MCP TLS CA PEM; defaults to WAZUH_MCP_CA_BUNDLE or project mcp-ca.crt",
    )
    parser.add_argument("--set-env", action="store_true", help="输出 PowerShell 环境变量设置命令")
    args = parser.parse_args()

    try:
        data = fetch_token(
            args.api_key,
            args.auth_url,
            ca_bundle=args.ca_bundle,
        )
    except httpx.HTTPStatusError as exc:
        print(f"HTTP {exc.response.status_code}: {exc.response.text[:300]}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"失败: {exc}", file=sys.stderr)
        return 1

    token = data.get("access_token") or data.get("token")
    if not token:
        print(f"响应无 access_token: {json.dumps(data, ensure_ascii=False)[:300]}", file=sys.stderr)
        return 1

    expires = data.get("expires_in", "?")
    if args.set_env:
        print(f'$env:WAZUH_MCP_TOKEN = "{token}"')
        print('$env:TRACE_ENGINE_MCP_ENDPOINT = "https://192.144.151.189/mcp"')
        print(f"# expires_in={expires}")
    else:
        print(json.dumps({"expires_in": expires, "access_token": token}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
