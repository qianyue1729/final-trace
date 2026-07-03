"""Common provenance adapter protocol for L1 graph replay (B2.0)."""
from __future__ import annotations

from dataclasses import InitVar, dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@dataclass
class ProvenanceAdapterConfig:
    input_path: Path
    ground_truth_path: Path | None = None
    max_events: int = 5000
    scenario_id: str = "sample_001"
    entry_strategy: str = "explicit"  # explicit | auto_leaf | auto_terminal
    entry_alert_strategy: InitVar[str | None] = None

    def __post_init__(self, entry_alert_strategy: str | None) -> None:
        if entry_alert_strategy is not None:
            object.__setattr__(self, "entry_strategy", entry_alert_strategy)


@runtime_checkable
class ProvenanceGraphAdapter(Protocol):
    source_name: str

    def load_graph_fixture(self, config: ProvenanceAdapterConfig) -> dict[str, Any]:
        ...
