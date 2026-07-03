"""host-client.env auto-load and CA bundle resolution."""
import os
from pathlib import Path

from trace_engine.config import EngineConfig, _PROJECT_ROOT, _bootstrap_host_client_env


def test_load_auto_injects_token_from_host_client_env(monkeypatch):
    if not (_PROJECT_ROOT / "host-client.env").is_file():
        return

    monkeypatch.delenv("WAZUH_MCP_TOKEN", raising=False)
    monkeypatch.delenv("TRACE_ENGINE_MCP_TOKEN", raising=False)
    _bootstrap_host_client_env()
    assert os.environ.get("WAZUH_MCP_TOKEN")


def test_ca_bundle_falls_back_to_local_mcp_ca_crt(monkeypatch):
    local_ca = _PROJECT_ROOT / "mcp-ca.crt"
    if not local_ca.is_file():
        return

    monkeypatch.setenv("WAZUH_MCP_CA_BUNDLE", "/home/ubuntu/ssl/mcp-tls/ca.crt")
    cfg = EngineConfig.load()
    assert Path(cfg.soar_mcp.ca_bundle).is_file()
    assert cfg.soar_mcp.ca_bundle.endswith("mcp-ca.crt")
