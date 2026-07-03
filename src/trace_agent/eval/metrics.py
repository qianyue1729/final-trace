"""Prior replay metrics."""
from __future__ import annotations

import math
from typing import Any

from trace_agent.decision.types import SeedPayload


def seed_entropy(seed: SeedPayload) -> float:
    probs = [e.prior_probability for e in seed.explanations if e.prior_probability > 0]
    if not probs:
        return 0.0
    return -sum(p * math.log(p) for p in probs)


def normalized_entropy(entropy: float, explanation_count: int) -> float:
    """entropy / log(n) — comparable when explanation_count varies (ablation sanity)."""
    if explanation_count <= 1:
        return 0.0
    denom = math.log(explanation_count)
    return round(entropy / denom, 4) if denom > 0 else 0.0


def collect_metrics(seed: SeedPayload) -> dict[str, Any]:
    priors = [e.prior_probability for e in seed.explanations]
    max_prior = max(priors) if priors else 0.0
    log_sources = {
        s["log_source"]
        for e in seed.explanations
        for s in e.recommended_log_sources
    }
    ec = len(seed.explanations)
    ent = round(seed_entropy(seed), 4)
    return {
        "max_prior": round(max_prior, 4),
        "entropy": ent,
        "explanation_count": ec,
        "normalized_entropy": normalized_entropy(ent, ec),
        "null_benign": seed.branch_null_anchor.benign,
        "null_oos": seed.branch_null_anchor.oos,
        "contested_edge_count": len(seed.contested_edges),
        "log_source_count": len(log_sources),
        "log_sources": sorted(log_sources),
        "explanation_ids": [e.id for e in seed.explanations],
        "explanation_types": [e.support.get("type") for e in seed.explanations],
        "lifecycle_templates": [
            e.lifecycle_template for e in seed.explanations if e.lifecycle_template
        ],
    }
