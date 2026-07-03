"""DARPA TC CADETS → L1 graph replay fixture adapter (B1/B1.5).

Reads a small CADETS provenance subset and normalizes into the graph replay
contract consumed by ``run_graph_case()``.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trace_agent.eval.adapters.base import ProvenanceAdapterConfig, ProvenanceGraphAdapter
from trace_agent.eval.adapters import darpa_tc_common as common

SOURCE = "darpa_tc_cadets"
PERFORMER = "CADETS"
DEFAULT_HOST = "cadets-host-1"


@dataclass
class CadetsAdapterConfig(ProvenanceAdapterConfig):
    """CADETS adapter config (extends common protocol)."""

    scenario_id: str = "darpa_cadets_sample_001"


class CadetsAdapter:
    source_name = SOURCE

    def load_graph_fixture(self, config: ProvenanceAdapterConfig) -> dict[str, Any]:
        return load_cadets_graph_fixture(config)


def read_cadets_events(input_path: Path, *, max_events: int = 5000) -> dict[str, Any]:
    return common.read_provenance_events(input_path, max_events=max_events)


def normalize_cadets_world_graph(raw: dict[str, Any]) -> dict[str, Any]:
    return common.normalize_darpa_tc_world_graph(raw, performer=PERFORMER, default_host=DEFAULT_HOST)


def select_entry_alert(world_graph: dict[str, Any], ground_truth: dict[str, Any], *, strategy: str = "explicit") -> dict[str, Any]:
    return common.select_entry_alert(world_graph, ground_truth, strategy=strategy)


def build_ground_truth_subgraph(world_graph: dict[str, Any], ground_truth: dict[str, Any]) -> dict[str, Any]:
    return common.build_ground_truth_subgraph(world_graph, ground_truth)


def build_replay_driver(
    world_graph: dict[str, Any],
    entry_alert: dict[str, Any],
    ground_truth_subgraph: dict[str, Any],
) -> dict[str, Any]:
    return common.build_replay_driver(world_graph, entry_alert, ground_truth_subgraph)


def infer_expected_decision(ground_truth_subgraph: dict[str, Any], *, category: str = "attack-like") -> dict[str, Any]:
    return common.infer_expected_decision(ground_truth_subgraph, category=category)


def load_cadets_graph_fixture(config: ProvenanceAdapterConfig) -> dict[str, Any]:
    return common.load_darpa_tc_graph_fixture(
        config,
        source=SOURCE,
        performer=PERFORMER,
        default_host=DEFAULT_HOST,
        title_prefix="CADETS",
    )


def cadets_data_dir() -> Path:
    return common.performer_data_dir("cadets")


def list_cadets_sample_paths() -> list[Path]:
    return common.list_sample_paths("cadets", "cadets_sample_*.json")


def load_all_cadets_graph_fixtures(*, entry_alert_strategy: str = "explicit") -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    for path in list_cadets_sample_paths():
        case_id = f"darpa_{path.stem}"
        fixtures.append(
            load_cadets_graph_fixture(
                CadetsAdapterConfig(
                    input_path=path,
                    scenario_id=case_id,
                    entry_strategy=entry_alert_strategy,
                )
            )
        )
    return fixtures


def cadets_scenario_summary(fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    cases = []
    for fx in fixtures:
        stats = (fx.get("adapter_meta") or {}).get("normalization_stats") or {}
        cases.append(
            {
                "case_id": fx["case_id"],
                "category": fx.get("category"),
                "primary_tactic": fx.get("primary_tactic"),
                "events_in": stats.get("events_in"),
                "events_kept": stats.get("events_kept"),
                "graph_edges": stats.get("graph_edges"),
                "relations": stats.get("relations"),
            }
        )
    return {"source": SOURCE, "n_scenarios": len(fixtures), "cases": cases}


def cadets_benchmark_markdown(fixtures: list[dict[str, Any]], results: list[dict[str, Any]] | None = None) -> str:
    by_id = {r["case_id"]: r for r in (results or [])}
    lines = [
        "# CADETS Provenance Graph Benchmark (B1.5)",
        "",
        "| case_id | category | events_in | kept | edges | root@k | recall | pollution | probes | dec_acc |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
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
            f"{m.get('probe_cost_to_decision', {}).get('probes', '—')} | "
            f"{m.get('decision_accuracy', '—')} |"
        )
    lines.append("")
    summary = cadets_scenario_summary(fixtures)
    lines.append(f"**Scenarios:** {summary['n_scenarios']}")
    return "\n".join(lines)


def default_cadets_sample_path() -> Path:
    return cadets_data_dir() / "cadets_sample_001.json"


write_graph_fixture = common.write_graph_fixture

# Backward-compatible re-exports
RELATION_TECHNIQUE_MAP = common.RELATION_TECHNIQUE_MAP
DEFAULT_REPLAY_CONFIG = common.DEFAULT_REPLAY_CONFIG
