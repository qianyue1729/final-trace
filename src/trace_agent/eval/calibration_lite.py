"""Calibration lite — behavior metrics grouped by case category."""
from __future__ import annotations

from typing import Any


def _hit(checks: dict[str, bool], key: str) -> bool | None:
    return checks.get(key) if key in checks else None


def collect_calibration(report: dict[str, Any]) -> dict[str, Any]:
    cases = report.get("cases") or []
    if not cases:
        return {"n_cases": 0}

    max_priors: list[float] = []
    entropies: list[float] = []
    overconfident = 0
    benign_prec_num = benign_prec_den = 0
    oos_prec_num = oos_prec_den = 0
    top_k_hits = top_k_total = 0
    boundary_hits = boundary_total = 0
    hard_veto_violations = 0
    by_category: dict[str, dict[str, Any]] = {}

    for c in cases:
        m = c.get("metrics") or {}
        cat = c.get("category", "unknown")
        max_p = float(m.get("max_prior", 0))
        ent = float(m.get("entropy", 0))
        max_priors.append(max_p)
        entropies.append(ent)
        if max_p > 0.55:
            overconfident += 1

        checks = c.get("checks") or {}
        qg = (c.get("quality_gates") or {}).get("gates") or {}
        if not qg.get("hard_veto_safe", True):
            hard_veto_violations += 1

        if cat == "benign":
            benign_prec_den += 1
            if checks.get("benign_anchor_ok", c.get("passed")):
                benign_prec_num += 1
        if cat in ("ambiguous", "telemetry-gap", "adversarial"):
            oos_prec_den += 1
            if checks.get("oos_anchor_ok", False) or m.get("null_oos", 0) >= 0.15:
                oos_prec_num += 1

        if checks.get("top_k_hit") is not None:
            top_k_total += 1
            if checks["top_k_hit"]:
                top_k_hits += 1
        if checks.get("boundary_ok") is not None:
            boundary_total += 1
            if checks["boundary_ok"]:
                boundary_hits += 1

        bucket = by_category.setdefault(
            cat,
            {"n": 0, "passed": 0, "mean_max_prior": 0.0, "mean_entropy": 0.0, "max_priors": []},
        )
        bucket["n"] += 1
        bucket["passed"] += int(c.get("passed", False))
        bucket["max_priors"].append(max_p)
        bucket.setdefault("entropies", []).append(ent)

    for cat, b in by_category.items():
        b["mean_max_prior"] = round(sum(b["max_priors"]) / b["n"], 4) if b["n"] else 0
        b["mean_entropy"] = round(sum(b["entropies"]) / b["n"], 4) if b["n"] else 0
        b["pass_rate"] = round(b["passed"] / b["n"], 3) if b["n"] else 0
        del b["max_priors"]
        del b["entropies"]

    n = len(cases)
    return {
        "n_cases": n,
        "mean_max_prior": round(sum(max_priors) / n, 4),
        "mean_entropy": round(sum(entropies) / n, 4),
        "overconfident_cases": overconfident,
        "benign_anchor_precision": round(benign_prec_num / benign_prec_den, 3) if benign_prec_den else None,
        "oos_anchor_precision": round(oos_prec_num / oos_prec_den, 3) if oos_prec_den else None,
        "top_k_behavior_hit_rate": round(top_k_hits / top_k_total, 3) if top_k_total else None,
        "boundary_flag_hit_rate": round(boundary_hits / boundary_total, 3) if boundary_total else None,
        "hard_veto_violations": hard_veto_violations,
        "by_category": by_category,
    }


def report_markdown(cal: dict[str, Any]) -> str:
    lines = [
        "# Prior Calibration Lite",
        "",
        f"**Cases:** {cal.get('n_cases', 0)}",
        f"- mean_max_prior: {cal.get('mean_max_prior')}",
        f"- mean_entropy: {cal.get('mean_entropy')}",
        f"- overconfident_cases: {cal.get('overconfident_cases')}",
        f"- benign_anchor_precision: {cal.get('benign_anchor_precision')}",
        f"- oos_anchor_precision: {cal.get('oos_anchor_precision')}",
        f"- top_k_behavior_hit_rate: {cal.get('top_k_behavior_hit_rate')}",
        f"- hard_veto_violations: {cal.get('hard_veto_violations')}",
        "",
        "## By category",
        "",
    ]
    for cat, b in sorted((cal.get("by_category") or {}).items()):
        lines.append(
            f"- **{cat}**: n={b['n']} pass_rate={b['pass_rate']} "
            f"mean_max_prior={b['mean_max_prior']} mean_entropy={b['mean_entropy']}"
        )
    return "\n".join(lines)
