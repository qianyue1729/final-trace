"""Unified SOAR MCP multi-source benchmark / demo data environment."""
from __future__ import annotations

from soar_mcp_env.paths import (
    LOCAL_MCP_SERVER,
    PKG_ROOT,
    PROJECT_ROOT,
    REGISTRY_PATH,
    SCENARIOS_DIR,
    SOAR_MCP_SERVER,
    STRESS_TEST_RUNNER,
)
from soar_mcp_env.setup import (
    SOAR_DATA_SOURCES,
    build_scenario_api_info,
    create_soar_toolbox,
    get_run_config,
    list_scenario_ids,
    load_registry,
    resolve_entry_ref,
    scenario_path,
)

__all__ = [
    "SOAR_DATA_SOURCES",
    "PKG_ROOT",
    "PROJECT_ROOT",
    "REGISTRY_PATH",
    "SCENARIOS_DIR",
    "LOCAL_MCP_SERVER",
    "SOAR_MCP_SERVER",
    "STRESS_TEST_RUNNER",
    "build_scenario_api_info",
    "create_soar_toolbox",
    "get_run_config",
    "list_scenario_ids",
    "load_registry",
    "resolve_entry_ref",
    "scenario_path",
]
