"""Brier / ECE with family-level hit mapping and three-state status (T26/T30)."""
from __future__ import annotations

import math
from typing import Any

MIN_LABELED_CASES = 30
STABLE_LABELED_CASES = 80


def _brier(probs: list[float], labels: list[int]) -> float:
    if not probs:
        return 0.0
    return sum((p - y) ** 2 for p, y in zip(probs, labels)) / len(probs)


def _ece(probs: list[float], labels: list[int], n_bins: int = 10) -> dict[str, Any]:
    if not probs:
        return {"ece": None, "reliability_bins": []}
    bins: list[dict[str, Any]] = []
    ece = 0.0
    n = len(probs)
    for b in range(n_bins):
        lo, hi = b / n_bins, (b + 1) / n_bins
        idx = [i for i, p in enumerate(probs) if (lo <= p < hi) or (b == n_bins - 1 and p == 1.0)]
        if not idx:
            continue
        bp = sum(probs[i] for i in idx) / len(idx)
        bl = sum(labels[i] for i in idx) / len(idx)
        weight = len(idx) / n
        ece += weight * abs(bp - bl)
        bins.append({"bin": b, "mean_pred": round(bp, 4), "empirical": round(bl, 4), "count": len(idx)})
    return {"ece": round(ece, 4), "reliability_bins": bins}


def eligible_cases(fixtures: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for f in fixtures:
        ev = f.get("evaluation") or {}
        if ev.get("calibration_eligible") is False:
            continue
        if f.get("label_quality", "synthetic") == "synthetic":
            continue
        if f.get("ground_truth"):
            out.append(f)
    return out


def family_hit(case: dict[str, Any], replay_case: dict[str, Any]) -> bool:
    """Family-level calibration target: technique overlap or lifecycle template match."""
    gt = case.get("ground_truth") or {}
    expected = set(gt.get("expected_techniques") or [])
    alert_tech = case.get("alert", {}).get("technique_id", "")
    if alert_tech:
        expected.add(alert_tech)
    true_family = gt.get("true_family") or gt.get("expected_explanation_family", [None])[0]
    for expl in replay_case.get("explanations") or []:
        title = (expl.get("title") or "").lower()
        if true_family and str(true_family).lower().replace("_", " ") in title:
            return True
        for t in expected:
            if t.lower() in title:
                return True
    types = set(replay_case.get("metrics", {}).get("explanation_types") or [])
    if gt.get("true_boundary") == "in_attack" and ("lifecycle" in types or "technique_context" in types):
        return True
    return False


def _calibration_status(n: int) -> str:
    if n < MIN_LABELED_CASES:
        return "skipped"
    if n < STABLE_LABELED_CASES:
        return "experimental"
    return "stable"


def run_calibration(report: dict[str, Any], fixtures: list[dict[str, Any]]) -> dict[str, Any]:
    eligible = eligible_cases(fixtures)
    n = len(eligible)
    status = _calibration_status(n)
    if status == "skipped":
        return {
            "calibration_status": "skipped",
            "reason": "eligible labeled cases below minimum",
            "eligible_cases": n,
            "required_min_cases": MIN_LABELED_CASES,
            "brier_score": None,
            "ece": None,
        }

    by_id = {f["case_id"]: f for f in eligible}
    probs: list[float] = []
    labels: list[int] = []
    family_hits = 0
    family_total = 0

    for c in report.get("cases") or []:
        fx = by_id.get(c["case_id"])
        if not fx:
            continue
        gt = fx.get("ground_truth") or {}
        score = float(c.get("metrics", {}).get("max_prior", 0.0))
        if gt.get("benign") or gt.get("oos"):
            label = 0
        elif gt.get("true_boundary") == "in_attack" or not gt.get("benign"):
            label = 1
        else:
            label = 0
        probs.append(score)
        labels.append(label)
        family_total += 1
        if family_hit(fx, c):
            family_hits += 1

    out: dict[str, Any] = {
        "calibration_status": status,
        "eligible_cases": n,
        "required_min_cases": MIN_LABELED_CASES,
        "brier_score": round(_brier(probs, labels), 4),
        "ece": _ece(probs, labels),
        "family_level_hit_rate": round(family_hits / family_total, 3) if family_total else None,
        "warning": None
        if status == "stable"
        else "small labeled set; do not treat as production calibration",
    }
    if family_total and family_hits == family_total and all(
        f.get("label_quality") == "weak_label" for f in eligible
    ):
        out["family_hit_caution"] = (
            "family_level_hit_rate=1.0 on all-weak_label set; coarse family granularity — not generalization"
        )
    return out


def report_markdown(cal: dict[str, Any]) -> str:
    lines = [
        "# Prior Calibration (Brier / ECE)",
        "",
        f"**Status:** {cal.get('calibration_status')}",
        f"**Eligible cases:** {cal.get('eligible_cases')} / min {cal.get('required_min_cases')}",
    ]
    if cal.get("calibration_status") == "skipped":
        lines.append(f"**Reason:** {cal.get('reason')}")
    else:
        lines.append(f"**Brier:** {cal.get('brier_score')}")
        lines.append(f"**ECE:** {(cal.get('ece') or {}).get('ece')}")
        lines.append(f"**Family hit rate:** {cal.get('family_level_hit_rate')}")
        if cal.get("warning"):
            lines.append(f"**Warning:** {cal['warning']}")
    return "\n".join(lines)
