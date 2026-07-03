"""Minimal log-source probe recommendations (MVP — no full VOI math)."""
from __future__ import annotations

from typing import Any

from trace_agent.decision.types import AlertEvent, Explanation
from trace_agent.prior_v2 import PriorManager


def recommend_log_source_probes(
    alert: AlertEvent,
    explanation: Explanation,
    prior: PriorManager,
) -> list[dict[str, Any]]:
    sources = explanation.recommended_log_sources or prior.recommended_log_sources(
        alert.technique_id, alert.platform
    )
    if not sources:
        return []

    max_sigma = max((s.get("sigma_rule_count") or 0 for s in sources), default=1) or 1
    probes: list[dict[str, Any]] = []
    for s in sources:
        avail = 1.0 if s.get("available") else 0.0
        trust = float(s.get("trust", 0.5))
        sigma_cov = float(s.get("sigma_rule_count") or 0) / max_sigma
        score = 0.45 * avail + 0.35 * trust + 0.20 * sigma_cov
        reason = (
            f"{'available' if avail else 'unavailable'} "
            f"{'high-trust' if trust >= 0.7 else 'medium-trust'} source "
            f"for {alert.technique_id}"
        )
        probes.append(
            {
                "probe_type": "log_source_query",
                "log_source": s["log_source"],
                "available": bool(s.get("available")),
                "trust": trust,
                "score": round(score, 3),
                "reason": reason,
            }
        )
    probes.sort(key=lambda p: p["score"], reverse=True)
    return probes
