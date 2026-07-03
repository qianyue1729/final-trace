"""Typed, conservative one-step probe outcome model."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class OutcomePrediction:
    probabilities: dict[str, float]
    likelihoods: dict[str, dict[str, float]]
    version: str
    status: str
    target_edge_id: str | None = None
    audit: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        total = sum(self.probabilities.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError("outcome probabilities must sum to one")
        if any(value < 0.0 for value in self.probabilities.values()):
            raise ValueError("outcome probabilities must be non-negative")


class ConservativeOutcomeModel:
    """Deterministic baseline; it learns no probabilities from scenario labels."""

    version = "conservative-outcome-v1"
    status = "baseline"

    @staticmethod
    def _beta_mean(entry: dict[str, float] | None) -> tuple[float, float]:
        entry = entry or {}
        alpha = float(entry.get("alpha", 1.0))
        beta = float(entry.get("beta", 1.0))
        total = max(alpha + beta, 1e-9)
        return alpha / total, max(0.0, total - 2.0)

    def _signal_probability(self, probe: dict, beta: dict) -> float:
        key = probe.get("learning_key") or ""
        target_type = str(probe.get("target_type") or "").lower()
        tenant = str(probe.get("tenant_id") or "global").lower()
        levels = [
            (beta.get("__global__"), 1.0),
            (beta.get(f"__tenant__:{tenant}"), 2.0),
            (beta.get(f"__target_type__:{target_type}"), 3.0),
            (beta.get(key), 5.0),
        ]
        weighted = 0.0
        weight_total = 0.0
        for entry, level_weight in levels:
            if not entry:
                continue
            mean, samples = self._beta_mean(entry)
            weight = level_weight * max(1.0, min(samples, 20.0))
            weighted += mean * weight
            weight_total += weight
        return weighted / weight_total if weight_total else 0.5

    def predict(self, probe: dict, ledger, beta: dict) -> OutcomePrediction:
        probabilities = ledger._get_probabilities()
        signal_probability = max(
            0.05,
            min(0.95, self._signal_probability(probe, beta)),
        )
        p_no_data = 1.0 - signal_probability

        tactic = str(probe.get("tactic") or "").lower()
        structural_fit = max(
            0.0, min(1.0, float(probe.get("structural_fit", 0.5)))
        )
        visibility = max(
            0.0, min(1.0, float(probe.get("visibility", 0.5)))
        )
        conditional: dict[str, float] = {}
        for explanation in ledger.explanations:
            expected = {
                str(value).lower()
                for value in getattr(explanation, "expected_tactics", [])
            }
            stage = getattr(explanation, "stage", None)
            if stage:
                expected.add(str(stage).lower())
            for predecessor in getattr(
                explanation, "predecessor_tactics", []
            ):
                if isinstance(predecessor, dict):
                    value = predecessor.get("tactic") or predecessor.get("name")
                    if value:
                        expected.add(str(value).lower())
            tactic_fit = 1.0 if tactic and tactic in expected else 0.35
            fit = 0.4 * tactic_fit + 0.3 * structural_fit + 0.3 * visibility
            conditional[f"attributable:{explanation.id}"] = (
                probabilities.get(explanation.id, 0.0) * max(0.1, fit)
            )

        p_null = probabilities.get("__null__", 0.0)
        null_anchor = getattr(ledger, "null_anchor", None)
        benign_ratio = 0.6
        if null_anchor is not None:
            total = float(null_anchor.benign + null_anchor.oos) or 1.0
            benign_ratio = float(null_anchor.benign) / total
        conditional["benign"] = p_null * benign_ratio
        conditional["oos"] = p_null * (1.0 - benign_ratio)
        total_conditional = sum(conditional.values())
        if total_conditional <= 0:
            conditional = {"benign": 0.6, "oos": 0.4}
            total_conditional = 1.0

        outcome_probabilities = {
            outcome: signal_probability * weight / total_conditional
            for outcome, weight in conditional.items()
        }
        outcome_probabilities["no_data"] = p_no_data
        likelihoods = {
            outcome: ledger.probe_outcome_likelihoods(probe, outcome)
            for outcome in outcome_probabilities
        }
        metadata = probe.get("metadata") or {}
        target_edge_id = metadata.get("edge_id") or metadata.get(
            "contested_edge_id"
        )
        return OutcomePrediction(
            probabilities=outcome_probabilities,
            likelihoods=likelihoods,
            version=self.version,
            status=self.status,
            target_edge_id=target_edge_id,
            audit={
                "operator": probe.get("operator", ""),
                "target_type": probe.get("target_type", ""),
                "tactic": tactic,
                "tenant_id": probe.get("tenant_id", "global"),
                "structural_fit": structural_fit,
                "visibility": visibility,
                "p_no_data": p_no_data,
            },
        )
