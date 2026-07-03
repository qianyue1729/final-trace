"""Decision ledger seed types."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AlertEvent:
    technique_id: str
    tactic: str | None = None
    platform: str | None = None
    log_source: str | None = None
    asset_id: str | None = None
    timestamp: str | None = None
    anomaly_score: float = 0.5
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Explanation:
    id: str
    title: str
    current_technique: str
    stage: str | None
    lifecycle_template: str | None
    predecessor_tactics: list[dict[str, Any]]
    technique_context: list[dict[str, Any]]
    raw_score: float
    prior_probability: float
    features: dict[str, float]
    support: dict[str, Any]
    recommended_log_sources: list[dict[str, Any]]
    caveats: list[str]
    investigation_prior_score: float = 0.0
    calibrated_probability: float | None = None
    probability_status: str = "uncalibrated"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # ponytail: prior_probability kept for compat; score is investigation prior until calibrated
        if d.get("investigation_prior_score", 0) == 0 and d.get("prior_probability"):
            d["investigation_prior_score"] = d["prior_probability"]
        return d


@dataclass
class NullAnchor:
    benign: float
    oos: float
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ContestedEdge:
    src: str
    dst: str
    boundary_prior: dict[str, float]
    support: dict[str, Any]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SeedPayload:
    alert: AlertEvent
    explanations: list[Explanation]
    branch_null_anchor: NullAnchor
    contested_edges: list[ContestedEdge]
    lifecycle_template_candidates: list[dict[str, Any]]
    score_v3_initial_scores: dict[str, float]
    loss_baseline: dict[str, float]
    evidence_trust_defaults: dict[str, Any]
    prior_manifest: dict[str, Any] | None
    visibility: dict[str, Any] = field(default_factory=dict)
    confidence_state: dict[str, Any] = field(default_factory=dict)
    risk_profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert": self.alert.to_dict(),
            "explanations": [x.to_dict() for x in self.explanations],
            "branch_null_anchor": self.branch_null_anchor.to_dict(),
            "contested_edges": [x.to_dict() for x in self.contested_edges],
            "lifecycle_template_candidates": self.lifecycle_template_candidates,
            "score_v3_initial_scores": self.score_v3_initial_scores,
            "loss_baseline": self.loss_baseline,
            "evidence_trust_defaults": self.evidence_trust_defaults,
            "prior_manifest": self.prior_manifest,
            "visibility": self.visibility,
            "confidence_state": self.confidence_state,
            "risk_profile": self.risk_profile,
            "probability_semantics": {
                "prior_probability": "legacy alias of investigation_prior_score",
                "investigation_prior_score": "normalized ranking prior — not calibrated probability",
                "calibrated_probability": "null until labeled replay + Brier/ECE",
            },
        }
