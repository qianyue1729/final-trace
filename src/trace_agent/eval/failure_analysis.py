"""Failure severity ranking S1–S4."""
from __future__ import annotations

from typing import Any


def _severity(case: dict[str, Any]) -> dict[str, Any]:
    cid = case["case_id"]
    cat = case.get("category", "")
    m = case.get("metrics") or {}
    checks = case.get("checks") or {}
    types = set(m.get("explanation_types") or [])
    reasons: list[str] = []
    severity = "S4"

    if not case.get("passed"):
        if cat == "benign" and not checks.get("benign_anchor_ok", True):
            severity, reasons = "S2", ["benign case lacks strong null anchor"]
        elif cat in ("ambiguous", "adversarial") and not checks.get("oos_anchor_ok", True):
            severity, reasons = "S3", ["oos/ambiguous case has weak oos anchor"]
        elif cat == "attack-like":
            severity, reasons = "S1", ["attack-like case failed expectations"]
        else:
            severity, reasons = "S4", ["quality or behavior check failed"]

    elif m.get("max_prior", 0) > 0.48:
        severity = "S1" if cat == "attack-like" else "S4"
        reasons = [f"near max_prior cap ({m.get('max_prior')}) — overconfident investigation prior risk"]

    elif m.get("log_source_count", 0) <= 1:
        severity, reasons = "S4", ["sparse log source visibility — observability gap"]

    elif "technique_context" not in types and "lifecycle" not in types:
        severity, reasons = "S4", ["no flow-backed or lifecycle explanation — STIX-only weak path"]

    elif cat == "benign" and "dual_use_boundary" in types:
        severity, reasons = "S2", ["dual-use boundary on benign case — false attack-chain risk"]

    roadmap = []
    if "cloud" in cid or case.get("alert", {}).get("technique_id", "").startswith("T1537"):
        roadmap.append("cloud template / exfil L2 coverage")
    if m.get("log_source_count", 0) <= 1:
        roadmap.append("sigma log source mapping / tenant available_log_sources")
    if "technique_context" not in types:
        roadmap.append("attack_flow edge or lifecycle template")

    return {
        "case_id": cid,
        "severity": severity,
        "reasons": reasons or ["monitor"],
        "roadmap_hints": roadmap,
    }


def analyze_failures(report: dict[str, Any]) -> dict[str, Any]:
    cases = report.get("cases") or []
    ranked = [_severity(c) for c in cases]
    ranked.sort(key=lambda x: x["severity"])
    near_miss = [r for r in ranked if r["severity"] != "S4" or not any(
        c.get("passed") for c in cases if c["case_id"] == r["case_id"]
    )][:20]

    gate_fail_counts: dict[str, int] = {}
    for c in cases:
        for g, ok in ((c.get("quality_gates") or {}).get("gates") or {}).items():
            if g != "all_pass" and not ok:
                gate_fail_counts[g] = gate_fail_counts.get(g, 0) + 1

    return {
        "severity_ranked": ranked[:25],
        "near_miss_cases": near_miss,
        "fragile_gates": sorted(gate_fail_counts.items(), key=lambda x: -x[1]),
        "summary": {
            "total_cases": len(cases),
            "failed_cases": sum(1 for c in cases if not c.get("passed")),
            "s1_count": sum(1 for r in ranked if r["severity"] == "S1"),
            "s2_count": sum(1 for r in ranked if r["severity"] == "S2"),
            "s3_count": sum(1 for r in ranked if r["severity"] == "S3"),
        },
    }


def report_markdown(analysis: dict[str, Any]) -> str:
    s = analysis.get("summary", {})
    lines = [
        "# Prior Failure Analysis",
        "",
        f"**Total:** {s.get('total_cases')} | **Failed:** {s.get('failed_cases')} | "
        f"S1={s.get('s1_count')} S2={s.get('s2_count')} S3={s.get('s3_count')}",
        "",
        "## Severity ranked (roadmap hints)",
        "",
    ]
    for item in analysis.get("severity_ranked") or []:
        hints = ", ".join(item.get("roadmap_hints") or []) or "—"
        lines.append(f"- **[{item['severity']}]** `{item['case_id']}` — {'; '.join(item['reasons'])} → {hints}")
    lines.extend(["", "## Reliability statement", "", "Investigation prior scores are not calibrated probabilities."])
    return "\n".join(lines)
