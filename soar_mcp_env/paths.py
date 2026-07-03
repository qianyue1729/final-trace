"""Paths for unified SOAR MCP multi-source test environment."""
from __future__ import annotations

from pathlib import Path

PKG_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PKG_ROOT.parent

SCENARIOS_DIR = PKG_ROOT / "scenarios"
RESULTS_DIR = PKG_ROOT / "results"
REGISTRY_PATH = PKG_ROOT / "registry.json"
DATA_SOURCES_PATH = PKG_ROOT / "data_sources.json"

# MCP simulator scripts (canonical copies under benchmarks/)
LOCAL_MCP_SERVER = PROJECT_ROOT / "benchmarks" / "local_mcp_server.py"
SOAR_MCP_SERVER = PROJECT_ROOT / "benchmarks" / "soar_mcp_server.py"
STRESS_TEST_RUNNER = PROJECT_ROOT / "benchmarks" / "stress_test_runner.py"
