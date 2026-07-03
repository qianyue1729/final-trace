"""Unified SOAR MCP multi-source test data environment."""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable

from trace_agent.datasource.store import LogStore
from trace_agent.mcp_tools.toolbox import Toolbox
from trace_agent.resolution import EntityResolver

from .paths import (
    DATA_SOURCES_PATH,
    PKG_ROOT,
    PROJECT_ROOT,
    REGISTRY_PATH,
    SCENARIOS_DIR,
)

if str(PROJECT_ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(PROJECT_ROOT))


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def load_registry() -> dict[str, Any]:
    return _load_json(REGISTRY_PATH)


@lru_cache(maxsize=1)
def load_data_sources() -> tuple[str, ...]:
    raw = _load_json(DATA_SOURCES_PATH)
    return tuple(raw.get("data_sources", []))


SOAR_DATA_SOURCES: tuple[str, ...] = load_data_sources()


def _scenario_spec(scenario_id: str) -> dict[str, Any]:
    reg = load_registry()
    scenarios = reg.get("scenarios", {})
    if scenario_id not in scenarios:
        raise KeyError(scenario_id)
    return scenarios[scenario_id]


def scenario_path(scenario_id: str) -> Path:
    spec = _scenario_spec(scenario_id)
    path = PKG_ROOT / spec["file"]
    if not path.is_file():
        raise FileNotFoundError(f"场景文件不存在: {path}")
    return path


def list_scenario_ids() -> list[str]:
    return list(load_registry().get("scenarios", {}).keys())


def resolve_entry_ref(scenario_id: str, meta: dict[str, Any]) -> str:
    override = _scenario_spec(scenario_id).get("entry_alert_ref")
    entry = override or meta.get("entry_alert_ref", "")
    if not entry:
        raise ValueError(f"场景 {scenario_id} 缺少 entry_alert_ref")
    return entry


def get_run_config(scenario_id: str) -> dict[str, Any]:
    return dict(_scenario_spec(scenario_id).get("run", {}))


def _make_soar_query_bridge(data_path: str) -> Callable[..., list[dict]]:
    """与 benchmarks/stress_test_runner 一致的 SOAR 查询桥（读场景 JSON）。"""

    def query_fn(
        from_ms: int,
        to_ms: int,
        query: str = "*",
        limit: int = 100,
        **kwargs: Any,
    ) -> list[dict]:
        if not hasattr(query_fn, "_store"):
            from benchmarks.local_mcp_server import LocalLogStore

            query_fn._store = LocalLogStore(data_path)
        return query_fn._store.query(from_ms, to_ms, query, limit)

    return query_fn


def create_soar_toolbox(scenario_id: str) -> tuple[Toolbox, EntityResolver, LogStore]:
    """加载场景并启用 soar:global 多源路由（与 run-soar 压力测试一致）。"""
    path = scenario_path(scenario_id)
    store = LogStore.from_scenario(path)
    meta = store.meta
    resolver = EntityResolver(
        nat_sessions=meta.get("nat_sessions", []),
        dhcp_leases=meta.get("dhcp_leases", []),
        cmdb=meta.get("cmdb", {}),
        iam=meta.get("iam", {}),
        internal_cidrs=meta.get("internal_cidrs", []),
    )
    toolbox = Toolbox(store, resolver)
    toolbox.enable_multi_source(
        {
            "soar:global": {
                "source_type": "soar",
                "host_uid": None,
                "query_fn": _make_soar_query_bridge(str(path)),
            }
        }
    )
    if toolbox.router and (meta.get("cmdb") or meta.get("hosts")):
        toolbox.router.build_capability_matrix_from_scenario(meta)
    return toolbox, resolver, store


@lru_cache(maxsize=8)
def _load_scenario_file(scenario_id: str) -> dict[str, Any]:
    path = scenario_path(scenario_id)
    return json.loads(path.read_text(encoding="utf-8"))


def build_scenario_api_info(scenario_id: str) -> dict[str, Any]:
    """供 /api/scenarios 使用的场景摘要（带缓存）。"""
    spec = _scenario_spec(scenario_id)
    raw = _load_scenario_file(scenario_id)
    meta = raw.get("meta", {})
    gt = raw.get("ground_truth", {})
    attack_refs: list[str] = gt.get("attack_edge_refs", [])
    events = raw.get("events", [])
    events_by_ref = {e.get("raw_log_ref"): e for e in events if e.get("raw_log_ref")}

    kill_chain: list[str] = []
    for ref in attack_refs:
        ev = events_by_ref.get(ref)
        if ev and ev.get("technique") and ev["technique"] not in kill_chain:
            kill_chain.append(ev["technique"])

    cmdb = meta.get("cmdb") or {}
    entry = resolve_entry_ref(scenario_id, meta)
    present_refs = [r for r in attack_refs if r in events_by_ref]
    reg = load_registry()
    return {
        "id": scenario_id,
        "name": spec["name"],
        "description": spec["description"],
        "tags": spec.get("tags", []),
        "mcp_mode": reg.get("mcp_mode", "soar"),
        "data_sources": list(SOAR_DATA_SOURCES),
        "source_count": meta.get("source_count"),
        "multi_source": meta.get("multi_source", True),
        "scenario_key": meta.get("scenario", scenario_id),
        "entry_alert_ref": entry,
        "entry_alert_ref_raw": meta.get("entry_alert_ref", ""),
        "num_events": len(events),
        "attack_chain_len": len(present_refs),
        "attack_chain_len_gt": len(attack_refs),
        "kill_chain": kill_chain[:12],
        "attack_edge_refs": present_refs,
        "root_cause_technique": gt.get("root_cause_technique"),
        "host_count": len(cmdb) if isinstance(cmdb, dict) else 0,
        "run_profile": get_run_config(scenario_id),
    }


def webapp_scenario_paths() -> dict[str, str]:
    """scenario_id → repo-relative path string (legacy WEBAPP_SCENARIOS.path)."""
    reg = load_registry()
    out: dict[str, str] = {}
    for sid, spec in reg.get("scenarios", {}).items():
        rel = (PKG_ROOT / spec["file"]).relative_to(PROJECT_ROOT)
        out[sid] = str(rel).replace("\\", "/")
    return out
