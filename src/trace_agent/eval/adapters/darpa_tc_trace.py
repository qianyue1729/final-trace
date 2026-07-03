"""DARPA TC TRACE → L1 graph replay fixture adapter (B2.2)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trace_agent.eval.adapters.base import ProvenanceAdapterConfig, ProvenanceGraphAdapter
from trace_agent.eval.adapters import darpa_tc_common as common

SOURCE = "darpa_tc_trace"
PERFORMER = "TRACE"
DEFAULT_HOST = "trace-host-1"


@dataclass
class TraceAdapterConfig(ProvenanceAdapterConfig):
    scenario_id: str = "darpa_trace_sample_001"


class TraceAdapter:
    source_name = SOURCE

    def load_graph_fixture(self, config: ProvenanceAdapterConfig) -> dict[str, Any]:
        return load_trace_graph_fixture(config)


def read_trace_events(input_path: Path, *, max_events: int = 5000) -> dict[str, Any]:
    return common.read_provenance_events(input_path, max_events=max_events)


def normalize_trace_world_graph(raw: dict[str, Any]) -> dict[str, Any]:
    return common.normalize_darpa_tc_world_graph(raw, performer=PERFORMER, default_host=DEFAULT_HOST)


def load_trace_graph_fixture(config: ProvenanceAdapterConfig) -> dict[str, Any]:
    return common.load_darpa_tc_graph_fixture(
        config,
        source=SOURCE,
        performer=PERFORMER,
        default_host=DEFAULT_HOST,
        title_prefix="TRACE",
    )


def trace_data_dir() -> Path:
    return common.performer_data_dir("trace")


def list_trace_sample_paths() -> list[Path]:
    return common.list_sample_paths("trace", "trace_sample_*.json")


def load_all_trace_graph_fixtures(*, entry_strategy: str = "explicit") -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    for path in list_trace_sample_paths():
        case_id = f"darpa_{path.stem}"
        fixtures.append(
            load_trace_graph_fixture(
                TraceAdapterConfig(
                    input_path=path,
                    scenario_id=case_id,
                    entry_strategy=entry_strategy,
                )
            )
        )
    return fixtures


write_graph_fixture = common.write_graph_fixture
