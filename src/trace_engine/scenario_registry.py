"""Local scenario registry → Wazuh query scope for indexed attack-chain demos."""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_REGISTRY_PATH = _PROJECT_ROOT / "soar_mcp_env" / "registry.json"


@dataclass(frozen=True)
class WazuhScenarioScope:
    """Wazuh MCP query partition for a known indexed scenario."""

    incident_prefix: str
    scope_field: str = "incident"
    attacks_only: bool = False
    indexed_attack_chain: bool = False
    scenario_slug: str = ""


@lru_cache(maxsize=1)
def _load_registry() -> dict[str, Any]:
    if not _REGISTRY_PATH.is_file():
        return {}
    return json.loads(_REGISTRY_PATH.read_text(encoding="utf-8"))


def resolve_wazuh_scope(scenario_id: str | None) -> WazuhScenarioScope | None:
    """Map scenario_id to Wazuh incident/is_attack scope when registry defines it."""
    if not scenario_id:
        return None
    spec = (_load_registry().get("scenarios") or {}).get(scenario_id) or {}
    raw = spec.get("wazuh_scope") or spec.get("wazuh") or {}
    if not raw:
        return None
    incident_prefix = str(
        raw.get("incident_prefix")
        or raw.get("incident_id")
        or ""
    ).strip()
    if not incident_prefix:
        return None
    scope_field = str(raw.get("scope_field") or "incident").strip().lower()
    if scope_field not in ("auto", "scenario", "incident"):
        scope_field = "incident"
    attacks_only = bool(raw.get("attacks_only", False))
    indexed = bool(raw.get("indexed_attack_chain", attacks_only))
    return WazuhScenarioScope(
        incident_prefix=incident_prefix,
        scope_field=scope_field,
        attacks_only=attacks_only,
        indexed_attack_chain=indexed,
        scenario_slug=str(raw.get("scenario_slug") or scenario_id),
    )
