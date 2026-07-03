"""Prior quality gates — Silver-tier checks on seed + build mode."""
from __future__ import annotations

from typing import Any

from trace_agent.decision.types import SeedPayload
from trace_agent.eval.metrics import collect_metrics

MAX_PRIOR = 0.55
MIN_ENTROPY = 0.45
MAX_BENIGN_NULL = 0.70
LOW_TRUST = frozenset({"file_system_timestamp", "bash_history", "web_application_log"})


def _build_mode(seed: SeedPayload) -> str:
    m = seed.prior_manifest or {}
    src = m.get("sources") or {}
    return src.get("build_mode", "unknown")


def _production_eligible(seed: SeedPayload) -> bool:
    m = seed.prior_manifest or {}
    src = m.get("sources") or {}
    if "production_eligible" in src:
        return bool(src["production_eligible"])
    return src.get("build_mode") == "opensource"


def check_semantic_firewall(seed: SeedPayload) -> bool:
    for e in seed.explanations:
        passport = (e.support or {}).get("evidence_passport") or {}
        roles = passport.get("source_roles") or {}
        if roles.get("sigma") == "causal":
            return False
        bd = passport.get("support_breakdown") or {}
        if bd.get("sigma_visibility", 0) > 0.15:
            return False
    for ce in seed.contested_edges:
        s = ce.support or {}
        build_bp = ce.boundary_prior.get("build_prior_ref") or ce.boundary_prior
        if s.get("sigma_overlap", 0) > 0 and s.get("attack_flow", 0) == 0:
            if build_bp.get("p_in_attack", 0) > 0.5:
                return False
    if seed.branch_null_anchor.benign > 0.9:
        return False
    return True


def check_hard_veto_safe(seed: SeedPayload) -> bool:
    alert_src = (seed.alert.log_source or "").lower()
    if not any(t in alert_src for t in LOW_TRUST):
        return True
    for key, meta in seed.evidence_trust_defaults.items():
        if alert_src in key.lower() and meta.get("hard_veto_allowed"):
            return False
    # Low-trust alert must still leave attack-compatible explanations
    m = collect_metrics(seed)
    return m["max_prior"] < 0.75 and seed.branch_null_anchor.benign > 0


def check_passports(seed: SeedPayload) -> bool:
    for e in seed.explanations:
        if "evidence_passport" not in (e.support or {}):
            return False
    return True


def check_telemetry_negative_evidence(seed: SeedPayload) -> bool:
    vis = seed.visibility or {}
    missing = vis.get("missing_log_sources") or []
    if not missing:
        return True
    # ponytail: missing log must not enable hard veto on those sources
    if not vis.get("interpretation"):
        return False
    return check_hard_veto_safe(seed)


def run_quality_gates(seed: SeedPayload) -> dict[str, Any]:
    m = collect_metrics(seed)
    mode = _build_mode(seed)
    prod_ok = _production_eligible(seed)
    gates = {
        "max_prior_gate": m["max_prior"] <= MAX_PRIOR,
        "entropy_gate": m["entropy"] >= MIN_ENTROPY or m["explanation_count"] <= 2,
        "null_anchor_gate": seed.branch_null_anchor.benign > 0 and seed.branch_null_anchor.oos > 0,
        "explanation_count_gate": 1 <= m["explanation_count"] <= 6,
        "benign_cap_gate": seed.branch_null_anchor.benign <= MAX_BENIGN_NULL,
        "semantic_firewall": check_semantic_firewall(seed),
        "hard_veto_safe": check_hard_veto_safe(seed),
        "telemetry_negative_evidence_gate": check_telemetry_negative_evidence(seed),
        "passport_gate": check_passports(seed),
        "fallback_production_ban": prod_ok,
    }
    gates["all_pass"] = all(gates.values())
    return {
        "gates": gates,
        "metrics": {
            **m,
            "entropy_gate_label": "PASS" if gates["entropy_gate"] else "FAIL",
            "null_anchor": {
                "benign": seed.branch_null_anchor.benign,
                "oos": seed.branch_null_anchor.oos,
            },
        },
        "build_mode": mode,
        "production_eligible": prod_ok,
        "production_eligible_reason": None
        if prod_ok
        else (seed.prior_manifest or {}).get("sources", {}).get("fallback_reasons")
        or "fallback prior cannot be used for evaluation or demo claims",
    }


def report_markdown(results: list[dict[str, Any]]) -> str:
    n_pass = sum(1 for r in results if r["gates"]["all_pass"])
    lines = [
        "# Prior Quality Gate Report",
        "",
        f"**Cases passing all gates:** {n_pass}/{len(results)}",
        "",
    ]
    for r in results:
        status = "PASS" if r["gates"]["all_pass"] else "FAIL"
        lines.append(f"## [{status}] {r['case_id']}")
        lines.append(f"- build_mode={r['build_mode']} production_eligible={r['production_eligible']}")
        lines.append(f"- metrics: {r['metrics']}")
        lines.append(f"- gates: {r['gates']}")
        lines.append("")
    return "\n".join(lines)
