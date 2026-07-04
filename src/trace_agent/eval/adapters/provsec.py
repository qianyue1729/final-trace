"""ProvSec → L1 graph replay fixture adapter (B2.0).

Reads ProvSec syscall-level provenance data (sysdig format) and normalizes
into the graph replay contract consumed by ``run_graph_case()``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trace_agent.eval.adapters.base import ProvenanceAdapterConfig, ProvenanceGraphAdapter
from trace_agent.eval.adapters import provsec_common as common

SOURCE = "provsec"
PERFORMER = "provsec"
DEFAULT_HOST = "provsec-ubuntu-01"


@dataclass
class ProvSecAdapterConfig(ProvenanceAdapterConfig):
    """ProvSec adapter config (extends common protocol)."""

    scenario_id: str = "provsec_case_05"
    dataset: str = "provsec"


class ProvSecAdapter:
    source_name = SOURCE

    def load_graph_fixture(self, config: ProvenanceAdapterConfig) -> dict[str, Any]:
        return load_provsec_graph_fixture(config)


# -- Delegate functions (mirror cadets pattern) --------------------------------


def read_provsec_events(input_path: Path, *, max_events: int = 5000) -> dict[str, Any]:
    return common.read_provsec_events(input_path, max_events=max_events)


def normalize_provsec_world_graph(raw: dict[str, Any], *, cve_map: dict | None = None) -> dict[str, Any]:
    return common.normalize_provsec_world_graph(raw, cve_map=cve_map)


def load_provsec_graph_fixture(config: ProvenanceAdapterConfig) -> dict[str, Any]:
    return common.load_provsec_graph_fixture(config)


def provsec_data_dir() -> Path:
    return common.repo_root() / "data" / "provsec"


def list_provsec_case_paths() -> list[Path]:
    """List all ProvSec case JSON files."""
    d = provsec_data_dir()
    if not d.is_dir():
        return []
    return sorted(d.glob("provsec_case_*.json"))


def load_all_provsec_fixtures(*, entry_alert_strategy: str = "explicit") -> list[dict[str, Any]]:
    """Load all ProvSec cases as graph replay fixtures."""
    fixtures: list[dict[str, Any]] = []
    for path in list_provsec_case_paths():
        case_id = path.stem
        fixtures.append(
            load_provsec_graph_fixture(
                ProvSecAdapterConfig(
                    input_path=path,
                    scenario_id=case_id,
                    entry_strategy=entry_alert_strategy,
                )
            )
        )
    return fixtures


def default_provsec_case_path() -> Path:
    """Default test case: Log4j JNDI injection."""
    return provsec_data_dir() / "provsec_case_05_log4j.json"


def provsec_scenario_summary(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    """Summary of all loaded ProvSec fixtures."""
    cases = []
    for fx in fixtures:
        stats = (fx.get("adapter_meta") or {}).get("normalization_stats") or {}
        cases.append({
            "case_id": fx["case_id"],
            "category": fx.get("category"),
            "primary_tactic": fx.get("primary_tactic"),
            "events_in": stats.get("events_in"),
            "events_kept": stats.get("events_kept"),
            "graph_edges": stats.get("graph_edges"),
        })
    return {"source": SOURCE, "n_scenarios": len(fixtures), "cases": cases}


def provsec_benchmark_markdown(
    fixtures: list[dict[str, Any]],
    results: list[dict[str, Any]] | None = None,
) -> str:
    """Benchmark markdown table for ProvSec cases."""
    by_id = {r["case_id"]: r for r in (results or [])}
    lines = [
        "# ProvSec Provenance Graph Benchmark",
        "",
        "| case_id | category | events_in | kept | edges | root@k | recall | pollution | probes |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for fx in fixtures:
        stats = (fx.get("adapter_meta") or {}).get("normalization_stats") or {}
        r = by_id.get(fx["case_id"])
        m = (r or {}).get("metrics") or {}
        lines.append(
            f"| {fx['case_id']} | {fx.get('category')} | {stats.get('events_in')} | "
            f"{stats.get('events_kept')} | {stats.get('graph_edges')} | "
            f"{m.get('root_cause_hit_at_k', '—')} | {m.get('attack_subgraph_recall', '—')} | "
            f"{m.get('benign_pollution_rate', {}).get('count', '—')} | "
            f"{m.get('probe_cost_to_decision', {}).get('probes', '—')} |"
        )
    lines.append("")
    summary = provsec_scenario_summary(fixtures)
    lines.append(f"**Scenarios:** {summary['n_scenarios']}")
    return "\n".join(lines)
