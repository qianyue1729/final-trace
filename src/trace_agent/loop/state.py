"""LOCK loop state."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from trace_agent.decision.types import AlertEvent, SeedPayload


@dataclass
class LockState:
    alert: AlertEvent
    phase: str
    decision_ledger_seed: SeedPayload
    graph_ledger: dict[str, Any] = field(default_factory=dict)
    beta_ledger: dict[str, Any] = field(default_factory=dict)
    obligation_ledger: dict[str, Any] = field(default_factory=dict)
    recommended_probes: list[dict[str, Any]] = field(default_factory=list)
    case_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert": self.alert.to_dict(),
            "phase": self.phase,
            "decision_ledger_seed": self.decision_ledger_seed.to_dict(),
            "graph_ledger": self.graph_ledger,
            "beta_ledger": self.beta_ledger,
            "obligation_ledger": self.obligation_ledger,
            "recommended_probes": self.recommended_probes,
            "case_metadata": self.case_metadata,
        }
