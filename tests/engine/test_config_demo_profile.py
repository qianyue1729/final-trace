"""Demo profile configuration."""
import os

import pytest

from trace_engine.config import EngineConfig, demo_profile_enabled


def test_demo_profile_env_flag():
    os.environ["TRACE_ENGINE_DEMO_PROFILE"] = "1"
    try:
        assert demo_profile_enabled() is True
        cfg = EngineConfig.load()
        assert cfg.demo_profile.enabled is True
    finally:
        os.environ.pop("TRACE_ENGINE_DEMO_PROFILE", None)


def test_demo_yaml_enables_profile():
    cfg = EngineConfig.load("configs/engine_demo_wazuh.yaml")
    assert cfg.demo_profile.enabled is True
    assert cfg.demo_profile.plateau_rounds == 5
    assert cfg.demo_profile.diversity_per_rule_id_cap == 20
    assert cfg.soar_mcp.wazuh_attacks_only is False


def test_strict_engine_yaml_demo_off():
    cfg = EngineConfig.load("configs/engine.yaml")
    assert cfg.demo_profile.enabled is False
