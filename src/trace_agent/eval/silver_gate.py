"""Silver-solid release gate — explicit blockers vs passed checks."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.eval.ablation_replay import MODES, run_ablation
from trace_agent.eval.visibility_metrics import sigma_visibility_delta_gate
from trace_agent.eval.calibration import (
    MIN_LABELED_CASES,
    STABLE_LABELED_CASES,
    eligible_cases,
    run_calibration,
)
from trace_agent.eval.prior_replay import FIXTURES_DIR, LABELED_DIR, load_fixtures, run_all
from trace_agent.prior_v2 import PriorManager

ROOT = Path(__file__).resolve().parents[3]
FLOW_TRACE = ROOT / "prior_knowledge" / "raw" / "attack_flow" / "flow_trace_index.json"
STIX_SUPPORT = ROOT / "prior_knowledge" / "raw" / "stix_technique_support.json"


def _category_counts(fixtures: list[dict]) -> dict[str, int]:
    c: dict[str, int] = {}
    for f in fixtures:
        cat = f.get("category", "unknown")
        c[cat] = c.get(cat, 0) + 1
    return c


def _ablation_sanity(ablation: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Returns (blockers, warnings). Candidate collapse is expected no_flow behavior → warning."""
    blockers: list[str] = []
    warnings: list[str] = []
    modes = ablation.get("modes") or {}
    full = modes.get("full") or {}
    nf = modes.get("no_flow") or {}
    if full and nf:
        if (nf.get("mean_explanation_count") or 0) < (full.get("mean_explanation_count") or 0) * 0.7:
            warnings.append(
                "no_flow: candidate collapse (expl_count down) — check normalized_entropy, not raw entropy"
            )
        if (nf.get("mean_max_prior") or 0) > (full.get("mean_max_prior") or 0) + 0.05:
            warnings.append("no_flow: max_prior rose — softmax on fewer H; investigate over-concentration")
        if abs((nf.get("mean_normalized_entropy") or 0) - (full.get("mean_normalized_entropy") or 0)) < 0.02:
            blockers.append("no_flow ablation shows no meaningful entropy shift")
    ns = modes.get("no_sigma") or {}
    if full and ns and ns.get("log_source_hit_rate") == full.get("log_source_hit_rate") and ns.get("mean_explanation_count") == full.get("mean_explanation_count"):
        pass  # replaced by sigma_visibility_delta_gate below
    nd = modes.get("no_dual_use") or {}
    if full and nd and nd.get("mean_explanation_count") == full.get("mean_explanation_count"):
        warnings.append("no_dual_use: explanation_count unchanged")
    return blockers, warnings


def run_silver_gate() -> dict[str, Any]:
    blockers: list[str] = []
    passed: list[str] = []

    manifest = (load_prior_bundle().prior_manifest or {}).get("sources") or {}
    if manifest.get("production_eligible") and not manifest.get("fallback_reasons"):
        passed.append("build provenance production_eligible")
    else:
        blockers.append("production_eligible=false or fallback_reasons non-empty")

    if FLOW_TRACE.is_file():
        passed.append("flow raw trace index present")
    else:
        blockers.append("flow_trace_index.json missing")

    if STIX_SUPPORT.is_file():
        passed.append("stix weak support index present")
    else:
        blockers.append("stix_technique_support.json missing")

    synth = load_fixtures(FIXTURES_DIR)
    if len(synth) >= 80:
        passed.append(f"80 synthetic replay fixtures ({len(synth)})")
    else:
        blockers.append(f"synthetic fixtures {len(synth)} < 80")

    labeled = load_fixtures(LABELED_DIR) if LABELED_DIR.is_dir() else []
    eligible = eligible_cases(labeled)
    cats = _category_counts(eligible)
    if len(eligible) >= MIN_LABELED_CASES:
        passed.append(f"labeled calibration-eligible cases ({len(eligible)})")
        if len(eligible) < STABLE_LABELED_CASES:
            blockers.append(
                f"calibration_eligible labeled cases {len(eligible)} < {STABLE_LABELED_CASES} (stable threshold)"
            )
        weak_only = all(f.get("label_quality") == "weak_label" for f in eligible)
        if weak_only:
            blockers.append("labeled set entirely weak_label — insufficient for stable calibration claims")
        semi_real_sources = {"mordor", "optc", "darpa", "atomic"}
        semi_real_hits = sum(1 for f in eligible if f.get("source") in semi_real_sources)
        if semi_real_hits < 5:
            blockers.append(
                "labeled set lacks semi-real source diversity (need more mordor/optc/atomic/darpa cases)"
            )
        if cats.get("attack-like", 0) < 10:
            blockers.append("labeled attack-like < 10")
        if cats.get("benign", 0) < 10:
            blockers.append("labeled benign < 10")
        if cats.get("ambiguous", 0) + cats.get("adversarial", 0) < 5:
            blockers.append("labeled ambiguous/oos < 5")
        if cats.get("telemetry-gap", 0) < 5:
            blockers.append("labeled telemetry-gap < 5")
    else:
        blockers.append(f"eligible labeled cases {len(eligible)} < {MIN_LABELED_CASES}")

    ledger = DecisionLedger(PriorManager())
    synth_report = run_all(FIXTURES_DIR, ledger)
    if synth_report["summary"]["failed"] == 0:
        passed.append("synthetic replay PASS")
    else:
        blockers.append(f"synthetic replay failures: {synth_report['summary']['failed']}")

    labeled_report = run_all(LABELED_DIR, ledger) if labeled else {"cases": []}
    cal = run_calibration(labeled_report, labeled)
    if cal.get("calibration_status") in ("experimental", "stable"):
        passed.append(f"calibration {cal['calibration_status']}")
    else:
        blockers.append(f"calibration {cal.get('calibration_status')}: {cal.get('reason', '')}")

    ablation = run_ablation(FIXTURES_DIR)
    if len(ablation.get("modes") or {}) >= 5:
        passed.append("ablation framework (full/no_flow/no_sigma/no_dual_use/no_lifecycle)")
    ab_blockers, ab_warnings = _ablation_sanity(ablation)
    blockers.extend(ab_blockers)
    warnings: list[str] = list(ab_warnings)

    sigma_gate = ablation.get("sigma_visibility_delta_gate") or sigma_visibility_delta_gate(
        (ablation.get("modes") or {}).get("full", {}).get("sigma_visibility") or {},
        (ablation.get("modes") or {}).get("no_sigma", {}).get("sigma_visibility") or {},
    )
    if sigma_gate.get("pass"):
        passed.append("sigma_visibility_delta_gate PASS")
    else:
        warnings.append(
            "sigma_visibility_delta_gate FAIL — Sigma present but weak measurable impact on visibility/probe metrics"
        )
    warnings.append(
        "Sigma visibility metrics use synthetic derived expected_log_sources — suite pass rate, not SOC accuracy; "
        "probe precision awaits labeled probe ground truth"
    )

    if ab_warnings:
        passed.append(f"ablation sanity warnings ({len(ab_warnings)})")
    elif not ab_blockers:
        passed.append("ablation sanity checks")

    if cal.get("calibration_status") != "stable":
        blockers.append(f"calibration not stable ({cal.get('calibration_status')})")

    if cal.get("family_level_hit_rate") == 1.0 and eligible:
        warnings.append(
            "family_level_hit_rate=1.0 on weak-label set — coarse family labels; not a generalization claim"
        )

    ece_val = (cal.get("ece") or {}).get("ece") if isinstance(cal.get("ece"), dict) else cal.get("ece")
    if cal.get("calibration_status") == "experimental" and ece_val is not None and ece_val > 0.15:
        warnings.append(f"ECE={ece_val} above informal stable threshold — calibration not production-ready")

    status = "ready" if not blockers else "blocked"
    return {
        "status": status,
        "level": "silver_solid",
        "blockers": blockers,
        "warnings": warnings,
        "passed": passed,
        "calibration": cal,
        "labeled_category_counts": cats,
        "ablation_summary": ablation.get("modes"),
        "sigma_visibility_delta_gate": sigma_gate,
    }


def report_markdown(gate: dict[str, Any]) -> str:
    lines = [
        f"# Silver-Solid Release Gate: **{gate['status'].upper()}**",
        "",
        "## Passed",
        "",
    ]
    for p in gate.get("passed") or []:
        lines.append(f"- ✅ {p}")
    lines.extend(["", "## Blockers", ""])
    for b in gate.get("blockers") or []:
        lines.append(f"- ❌ {b}")
    if gate.get("warnings"):
        lines.extend(["", "## Warnings (expected ablation behavior)", ""])
        for w in gate["warnings"]:
            lines.append(f"- ⚠️ {w}")
    return "\n".join(lines)
