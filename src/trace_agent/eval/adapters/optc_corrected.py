"""Corrected OpTC → L1 multi-host graph replay adapter (C1)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from trace_agent.eval.adapters.base import ProvenanceAdapterConfig, ProvenanceGraphAdapter
from trace_agent.eval.adapters import darpa_tc_common as common

SOURCE = "optc_corrected"
PERFORMER = "OpTC"
DEFAULT_HOST = "host-a"


@dataclass
class OptcAdapterConfig(ProvenanceAdapterConfig):
    scenario_id: str = "optc_sample_001"


class OptcCorrectedAdapter:
    source_name = SOURCE

    def load_graph_fixture(self, config: ProvenanceAdapterConfig) -> dict[str, Any]:
        return load_optc_graph_fixture(config)


def read_optc_events(input_path: Path, *, max_events: int = 5000) -> dict[str, Any]:
    return common.read_provenance_events(input_path, max_events=max_events)


def normalize_optc_world_graph(raw: dict[str, Any]) -> dict[str, Any]:
    return common.normalize_darpa_tc_world_graph(raw, performer=PERFORMER, default_host=DEFAULT_HOST)


def load_optc_graph_fixture(config: ProvenanceAdapterConfig) -> dict[str, Any]:
    return common.load_darpa_tc_graph_fixture(
        config,
        source=SOURCE,
        performer=PERFORMER,
        default_host=DEFAULT_HOST,
        title_prefix="Corrected OpTC",
    )


def optc_data_dir() -> Path:
    return common.performer_data_dir("optc")


def list_optc_sample_paths() -> list[Path]:
    return common.list_sample_paths("optc", "optc_sample_*.json")


def load_all_optc_graph_fixtures(*, entry_strategy: str = "explicit") -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    for path in list_optc_sample_paths():
        case_id = path.stem
        fixtures.append(
            load_optc_graph_fixture(
                OptcAdapterConfig(
                    input_path=path,
                    scenario_id=case_id,
                    entry_strategy=entry_strategy,
                )
            )
        )
    return fixtures


write_graph_fixture = common.write_graph_fixture
