"""Production config guards — eval-only Wazuh filters must not leak into soar_mcp."""
from dataclasses import replace

from trace_engine.config import EngineConfig, resolve_wazuh_attacks_only


def test_resolve_wazuh_attacks_only_blocks_soar_mcp_by_default(monkeypatch):
    monkeypatch.delenv("TRACE_ENGINE_EVAL_ATTACKS_ONLY", raising=False)
    assert resolve_wazuh_attacks_only(True, backend="soar_mcp") is False
    assert resolve_wazuh_attacks_only(True, backend="scenario") is True


def test_resolve_wazuh_attacks_only_allows_explicit_eval_opt_in(monkeypatch):
    monkeypatch.setenv("TRACE_ENGINE_EVAL_ATTACKS_ONLY", "1")
    assert resolve_wazuh_attacks_only(True, backend="soar_mcp") is True


def test_engine_config_sanitizes_attacks_only_on_load(monkeypatch):
    monkeypatch.delenv("TRACE_ENGINE_EVAL_ATTACKS_ONLY", raising=False)
    cfg = replace(
        EngineConfig.load(),
        backend="soar_mcp",
        soar_mcp=replace(
            EngineConfig.load().soar_mcp,
            wazuh_attacks_only=True,
        ),
    )
    cfg._sanitize_production_flags()
    assert cfg.soar_mcp.wazuh_attacks_only is False
