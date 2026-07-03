"""Sigma-specific visibility / probe metrics for replay and ablation."""
from __future__ import annotations

from typing import Any

from trace_agent.decision.types import SeedPayload


def _recommended_sources(seed: SeedPayload) -> set[str]:
    out = {s["log_source"].lower() for e in seed.explanations for s in e.recommended_log_sources}
    for name in (seed.visibility or {}).get("expected_log_sources") or []:
        out.add(str(name).lower())
    return out


def _probe_sources(probes: list[dict[str, Any]]) -> set[str]:
    return {str(p["log_source"]).lower() for p in probes if p.get("log_source")}


def _sigma_active(seed: SeedPayload) -> bool:
    for e in seed.explanations:
        if any(s.get("source") == "sigma" or (s.get("sigma_rule_count") or 0) > 0 for s in e.recommended_log_sources):
            return True
    return False


def _sigma_trace_present(seed: SeedPayload) -> bool:
    for e in seed.explanations:
        passport = e.support.get("evidence_passport") or {}
        trace = passport.get("source_trace") or {}
        if trace.get("sigma"):
            return True
        roles = passport.get("source_roles") or {}
        if roles.get("sigma") == "visibility_only":
            return True
    return False


def _evidence_debt_caveat(seed: SeedPayload) -> bool:
    vis = seed.visibility or {}
    if vis.get("missing_log_sources") and "negative evidence" in (vis.get("interpretation") or "").lower():
        return True
    blob = " ".join(
        c.lower() for e in seed.explanations for c in e.caveats
    ) + " " + " ".join((seed.confidence_state or {}).get("reason") or []).lower()
    return "missing" in blob or "sparse" in blob or "negative evidence" in blob


def collect_visibility_metrics(
    seed: SeedPayload,
    fixture: dict[str, Any],
    probes: list[dict[str, Any]],
) -> dict[str, Any]:
    exp = dict(fixture.get("expected_behavior") or fixture.get("expect") or {})
    gt = fixture.get("ground_truth") or {}
    expected = exp.get("expected_log_sources") or exp.get("log_source_contains_any") or gt.get("expected_log_sources") or []
    expected_probes = exp.get("expected_probe_sources") or expected
    missing_expected = exp.get("missing_expected_log_sources") or []

    recommended = _recommended_sources(seed)
    vis = seed.visibility or {}
    missing = {m.lower() for m in (vis.get("missing_log_sources") or [])}

    out: dict[str, Any] = {
        "recommended_log_source_count": len(recommended),
        "visibility_missing_count": len(missing),
        "sigma_visibility_active": _sigma_active(seed),
    }

    if expected:
        out["log_source_hit"] = any(str(x).lower() in recommended for x in expected)
    if expected_probes:
        out["probe_hit"] = any(str(x).lower() in _probe_sources(probes) for x in expected_probes)
    if missing_expected:
        out["visibility_gap_reported"] = all(str(m).lower() in missing for m in missing_expected)
    elif expected and missing:
        out["visibility_gap_reported"] = any(str(x).lower() in missing for x in expected)

    if fixture.get("category") == "telemetry-gap" or missing_expected:
        out["evidence_debt_caveat"] = _evidence_debt_caveat(seed)

    if _sigma_active(seed) or (seed.explanations and any(e.recommended_log_sources for e in seed.explanations)):
        out["sigma_trace_present"] = _sigma_trace_present(seed)

    return out


def aggregate_visibility_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not cases:
        return {}

    def rate(bool_key: str, *, category: str | None = None, pool: list[dict[str, Any]] | None = None) -> float | None:
        base = pool if pool is not None else cases
        if category:
            base = [c for c in base if c.get("category") == category]
        eligible = [c for c in base if c.get("metrics", {}).get(bool_key) is not None]
        if not eligible:
            return None
        return round(sum(1 for c in eligible if c["metrics"][bool_key]) / len(eligible), 3)

    def _annotation_source(case: dict[str, Any]) -> str:
        ev = case.get("evaluation") or {}
        exp = case.get("expected_behavior") or case.get("expect") or {}
        return (
            ev.get("visibility_annotation_source")
            or exp.get("visibility_annotation_source")
            or "unknown"
        )

    n = len(cases)
    mean_count = round(
        sum(c.get("metrics", {}).get("recommended_log_source_count", 0) for c in cases) / n, 3
    )

    by_source: dict[str, dict[str, Any]] = {}
    for src in sorted({_annotation_source(c) for c in cases}):
        pool = [c for c in cases if _annotation_source(c) == src]
        by_source[src] = {
            "case_count": len(pool),
            "log_source_hit_rate": rate("log_source_hit", pool=pool),
            "probe_recommendation_hit_rate": rate("probe_hit", pool=pool),
        }

    return {
        "log_source_hit_rate": rate("log_source_hit"),
        "probe_recommendation_hit_rate": rate("probe_hit"),
        "visibility_gap_detection_rate": rate("visibility_gap_reported"),
        "evidence_debt_explanation_rate": rate("evidence_debt_caveat", category="telemetry-gap"),
        "sigma_trace_presence_rate": rate("sigma_trace_present"),
        "mean_recommended_log_source_count": mean_count,
        "cases_with_expected_log_sources": sum(
            1 for c in cases if c.get("metrics", {}).get("log_source_hit") is not None
        ),
        "by_annotation_source": by_source,
        "interpretation": (
            "log_source_hit_rate on synthetic fixtures is visibility behavior suite pass rate, "
            "not real SOC log-source recommendation accuracy, when expectations are derived_from_prior_recommendation"
        ),
        "mean_rec_count_note": (
            "mean_recommended_log_source_count reflects increased visibility coverage, not precision; "
            "probe precision deferred until labeled probe ground truth"
        ),
    }


def sigma_visibility_delta_gate(full: dict[str, Any], no_sigma: dict[str, Any]) -> dict[str, Any]:
    """PASS if at least 2 of 3 Sigma-specific deltas are meaningful."""
    checks: list[tuple[str, float | None, float | None, float]] = [
        ("log_source_hit_rate", full.get("log_source_hit_rate"), no_sigma.get("log_source_hit_rate"), 0.10),
        ("visibility_gap_detection_rate", full.get("visibility_gap_detection_rate"), no_sigma.get("visibility_gap_detection_rate"), 0.10),
        ("sigma_trace_presence_rate", full.get("sigma_trace_presence_rate"), no_sigma.get("sigma_trace_presence_rate"), 0.50),
    ]
    deltas: dict[str, float | None] = {}
    passed = 0
    for name, fv, nv, thresh in checks:
        if fv is None or nv is None:
            deltas[name] = None
            continue
        deltas[name] = round(float(fv) - float(nv), 3)
        if deltas[name] >= thresh:
            passed += 1
    count_delta = (full.get("mean_recommended_log_source_count") or 0) - (
        no_sigma.get("mean_recommended_log_source_count") or 0
    )
    return {
        "pass": passed >= 2,
        "positive_deltas": passed,
        "deltas": deltas,
        "mean_recommended_log_source_count_delta": round(count_delta, 3),
    }
