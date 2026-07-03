"""Probe ground-truth metrics for replay / ablation (P3 — not full VOI)."""
from __future__ import annotations

from typing import Any

DEFAULT_PROBE_COSTS: dict[str, int] = {
    "process_creation": 1,
    "script_execution": 2,
    "powershell_log": 2,
    "network_connection": 2,
    "dns_query": 2,
    "authentication": 2,
    "file_system": 3,
    "bash_history": 1,
    "web_application_log": 4,
    "cloudtrail": 3,
    "full_disk_scan": 10,
}

DEFAULT_MUST_NOT = ("bash_history", "full_disk_scan", "file_system_timestamp")


def probe_ground_truth(fixture: dict[str, Any]) -> dict[str, Any] | None:
    gt = fixture.get("probe_ground_truth")
    return gt if isinstance(gt, dict) and gt.get("expected_probe_sources") else None


def collect_probe_metrics(
    probes: list[dict[str, Any]],
    fixture: dict[str, Any],
    *,
    top_k: int = 3,
) -> dict[str, Any]:
    pg = probe_ground_truth(fixture)
    if not pg:
        return {}

    expected = [str(x).lower() for x in pg["expected_probe_sources"]]
    must_not = {str(x).lower() for x in pg.get("must_not_probe") or []}
    costs = {**DEFAULT_PROBE_COSTS, **(pg.get("probe_cost_profile") or {})}
    top = [str(p["log_source"]).lower() for p in probes[:top_k] if p.get("log_source")]
    all_sources = [str(p["log_source"]).lower() for p in probes if p.get("log_source")]

    out: dict[str, Any] = {"probe_top_k": top_k}
    if expected:
        hit_count = sum(1 for e in expected if e in top)
        out["probe_source_hit"] = hit_count == len(expected)
        out["probe_coverage_at_k"] = round(hit_count / len(expected), 3)
        weights = [1.0 / max(float(costs.get(e, 5)), 1.0) for e in expected]
        hit_w = sum(w for e, w in zip(expected, weights) if e in top)
        out["probe_cost_weighted_hit"] = round(hit_w / sum(weights), 3) if weights else 0.0
        noise = [p for p in top if p not in expected]
        out["probe_noise_rate"] = round(len(noise) / max(len(top), 1), 3)

    if must_not:
        out["probe_must_not_violation"] = any(m in all_sources for m in must_not)

    return out


def _pool_rate(pool: list[dict[str, Any]], key: str, *, invert: bool = False) -> float | None:
    eligible = [c for c in pool if c.get("metrics", {}).get(key) is not None]
    if not eligible:
        return None
    if invert:
        return round(sum(1 for c in eligible if not c["metrics"][key]) / len(eligible), 3)
    return round(sum(1 for c in eligible if c["metrics"][key]) / len(eligible), 3)


def aggregate_probe_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not cases:
        return {}

    def rate(key: str, *, invert: bool = False) -> float | None:
        return _pool_rate(cases, key, invert=invert)

    def mean(key: str) -> float | None:
        vals = [c["metrics"][key] for c in cases if c.get("metrics", {}).get(key) is not None]
        return round(sum(vals) / len(vals), 3) if vals else None

    def _annotation(case: dict[str, Any]) -> str:
        pg = probe_ground_truth(case) or {}
        return str(pg.get("annotation_source") or "unknown")

    by_ann: dict[str, dict[str, Any]] = {}
    for src in sorted({_annotation(c) for c in cases if probe_ground_truth(c)}):
        pool = [c for c in cases if _annotation(c) == src]
        by_ann[src] = {
            "case_count": len(pool),
            "probe_source_hit_rate": _pool_rate(pool, "probe_source_hit"),
            "probe_must_not_violation_rate": _pool_rate(pool, "probe_must_not_violation", invert=True),
        }

    return {
        "cases_with_probe_ground_truth": sum(1 for c in cases if probe_ground_truth(c)),
        "probe_source_hit_rate": rate("probe_source_hit"),
        "probe_must_not_violation_rate": rate("probe_must_not_violation", invert=True),
        "probe_cost_weighted_hit_rate": mean("probe_cost_weighted_hit"),
        "probe_coverage_at_k": mean("probe_coverage_at_k"),
        "probe_noise_rate": mean("probe_noise_rate"),
        "by_annotation_source": by_ann,
        "interpretation": (
            "probe metrics on derived_from_visibility_expectation validate behavioral-suite consistency; "
            "they do not claim SOC probe accuracy or optimal probe selection"
        ),
    }
