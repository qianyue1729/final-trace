"""Evidence passports + seed enrichment (support roles, limitations)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from trace_agent.decision.types import AlertEvent, ContestedEdge, Explanation, SeedPayload
from trace_agent.eval.metrics import collect_metrics


def source_roles_for_support(support: dict[str, Any]) -> dict[str, str]:
    roles: dict[str, str] = {}
    if support.get("attack_flow", 0) > 0 or support.get("flow_backed"):
        roles["attack_flow"] = "temporal"
    if support.get("stix_cooccurrence", 0) > 0 or support.get("type") == "l1_predecessor":
        roles["stix"] = "cooccurrence_only"
    if support.get("sigma_overlap", 0) > 0:
        roles["sigma"] = "visibility_only"
    if support.get("lolbas_dual_use") or support.get("gtfobins_dual_use"):
        roles["lolbas"] = "boundary_only"
    return roles


def limitations_for_support(support: dict[str, Any]) -> list[str]:
    lim: list[str] = []
    flow = support.get("attack_flow", 0) or support.get("l2_attack_flow_edges", 0)
    if not flow:
        lim.append("no report-level or Flow temporal evidence on this path")
    if support.get("stix_cooccurrence", 0) or support.get("type") == "l1_predecessor":
        lim.append("STIX cooccurrence is not temporal evidence")
    if support.get("sigma_overlap", 0):
        lim.append("Sigma overlap affects visibility only, not causal weight")
    if support.get("lolbas_dual_use") or support.get("type") == "dual_use_boundary":
        lim.append("dual-use tool does not prove benign")
    return lim


_FLOW_TRACE_INDEX: dict[str, list[dict[str, Any]]] | None = None


def _load_flow_trace_index() -> dict[str, list[dict[str, Any]]]:
    global _FLOW_TRACE_INDEX
    if _FLOW_TRACE_INDEX is not None:
        return _FLOW_TRACE_INDEX
    root = Path(__file__).resolve().parents[3]
    for rel in (
        "prior_knowledge/raw/attack_flow/flow_trace_index.json",
        "prior_knowledge/raw/attack_flow/corpus/../flow_trace_index.json",
    ):
        p = root / rel
        if p.is_file():
            import json

            _FLOW_TRACE_INDEX = json.loads(p.read_text(encoding="utf-8"))
            return _FLOW_TRACE_INDEX
    _FLOW_TRACE_INDEX = {}
    return _FLOW_TRACE_INDEX


_STIX_SUPPORT: dict[str, Any] | None = None


def _load_stix_support() -> dict[str, Any]:
    global _STIX_SUPPORT
    if _STIX_SUPPORT is not None:
        return _STIX_SUPPORT
    root = Path(__file__).resolve().parents[3]
    p = root / "prior_knowledge" / "raw" / "stix_technique_support.json"
    if p.is_file():
        import json

        _STIX_SUPPORT = json.loads(p.read_text(encoding="utf-8"))
    else:
        _STIX_SUPPORT = {}
    return _STIX_SUPPORT


def build_source_trace(
    prior: Any,
    alert: AlertEvent,
    expl: Explanation,
    *,
    skip_sigma: bool = False,
) -> dict[str, Any]:
    """Trace passport fields to raw source artifacts (best-effort)."""
    tech = alert.technique_id
    node = prior.technique_node(tech) or {}
    trace: dict[str, Any] = {
        "attack_flow": [],
        "attack_flow_trace": [],
        "sigma": [],
        "lolbas": [],
        "stix": [],
        "gtfobins": [],
    }
    flow_index = _load_flow_trace_index()

    for edge in prior.technique_neighbors(tech, direction="both", top_k=5, platform=alert.platform):
        sup = edge.get("support") or {}
        if sup.get("attack_flow", 0) > 0:
            key = f"{edge['src']}->{edge['dst']}"
            trace["attack_flow"].append(
                {
                    "edge": key,
                    "flow_count": sup.get("attack_flow"),
                    "description": edge.get("description", ""),
                    "confidence": edge.get("confidence"),
                }
            )
            for ft in flow_index.get(key, [])[:3]:
                trace["attack_flow_trace"].append(ft)

    if not skip_sigma:
        for rid in (node.get("sigma_rules") or [])[:3]:
            trace["sigma"].append({"rule_id": rid, "technique": tech, "log_source": "see_sigma_index"})

    for tool in (node.get("tools") or {}).get("lolbas") or []:
        trace["lolbas"].append({"binary": tool, "technique": tech})

    for tool in (node.get("tools") or {}).get("gtfobins") or []:
        trace["gtfobins"].append({"binary": tool, "technique": tech})

    if expl.support.get("type") == "l1_predecessor":
        trace["stix"].append(
            {
                "technique": tech,
                "relationship": "tactic_predecessor",
                "note": "L1 STIX cooccurrence — not temporal",
            }
        )

    stix_sup = _load_stix_support().get(tech) or _load_stix_support().get(tech.split(".")[0])
    if stix_sup:
        trace["stix_support"] = {
            "intrusion_sets": stix_sup.get("intrusion_sets", [])[:5],
            "relationship_count": stix_sup.get("relationship_count", 0),
            "sample_relationship_ids": stix_sup.get("relationship_ids", [])[:3],
            "technique": tech,
            "role": stix_sup.get("role", "weak_cooccurrence_only"),
        }

    return trace


def passport_for_explanation(
    expl: Explanation,
    alert: AlertEvent,
    build_mode: str,
    prior: Any = None,
    *,
    skip_sigma: bool = False,
) -> dict[str, Any]:
    s = expl.support
    flow = s.get("l2_attack_flow_edges", 0) or s.get("l1_attack_flow_edges", 0)
    p = {
        "raw_sources": [k for k, v in source_roles_for_support(s).items()],
        "source_roles": source_roles_for_support(s),
        "support_breakdown": {
            "attack_flow": min(0.4, flow / 20.0),
            "stix_cooccurrence": 0.04 if s.get("type") == "l1_predecessor" else 0.0,
            "sigma_visibility": 0.06 if expl.recommended_log_sources else 0.0,
            "dual_use_boundary": -0.03 if s.get("type") == "dual_use_boundary" else 0.0,
        },
        "confidence": round(min(0.85, expl.prior_probability + 0.25), 2),
        "limitations": limitations_for_support(s),
        "build_mode": build_mode,
        "why_not_confident": _why_not_confident(expl, alert),
        "what_would_change_my_mind": _what_would_change(expl, alert),
    }
    if prior is not None:
        p["source_trace"] = build_source_trace(prior, alert, expl, skip_sigma=skip_sigma)
    return p


def passport_for_edge(edge: ContestedEdge, build_mode: str) -> dict[str, Any]:
    s = edge.support
    return {
        "raw_sources": list(source_roles_for_support(s).keys()),
        "source_roles": source_roles_for_support(s),
        "confidence": round(min(0.9, edge.boundary_prior.get("p_in_attack", 0.34) + 0.2), 2),
        "limitations": limitations_for_support(s),
        "build_mode": build_mode,
        "boundary_layer": edge.boundary_prior.get("boundary_layer", "build_time"),
    }


def _why_not_confident(expl: Explanation, alert: AlertEvent) -> list[str]:
    why: list[str] = []
    if expl.support.get("type") == "dual_use_boundary":
        why.append("dual-use tool involved")
    if len(expl.recommended_log_sources) <= 1:
        why.append("single or sparse log source mapping")
    if not expl.support.get("flow_backed") and not expl.support.get("l1_attack_flow_edges"):
        why.append("no Flow-backed temporal support")
    if alert.anomaly_score < 0.5:
        why.append("low alert anomaly score")
    return why or ["prior-only seed; no evidence update yet"]


def _what_would_change(expl: Explanation, alert: AlertEvent) -> list[str]:
    checks = ["parent process lineage", "independent EDR process event"]
    if "script" in " ".join(ls.get("log_source", "") for ls in expl.recommended_log_sources):
        checks.append("script block / powershell operational log")
    if alert.technique_id.startswith("T1105") or alert.technique_id.startswith("T1021"):
        checks.append("network connection corroboration")
    return checks


def compute_visibility(seed: SeedPayload, log_sources: list[dict[str, Any]]) -> dict[str, Any]:
    expected = sorted({s["log_source"] for s in log_sources})
    available = sorted({s["log_source"] for s in log_sources if s.get("available")})
    missing = sorted(set(expected) - set(available))
    gap = "high" if len(missing) >= 2 else ("medium" if missing else "low")
    return {
        "expected_log_sources": expected,
        "available_log_sources": available,
        "missing_log_sources": missing,
        "observability_gap": gap,
        "interpretation": "absence of missing-source evidence must not be used as negative evidence",
    }


def compute_confidence_state(seed: SeedPayload) -> dict[str, Any]:
    m = collect_metrics(seed)
    reasons: list[str] = []
    if m["max_prior"] > 0.5:
        reasons.append("approaching overconfidence cap")
    if not any(e.support.get("flow_backed") for e in seed.explanations):
        if not seed.lifecycle_template_candidates:
            reasons.append("no lifecycle match and no flow-backed path")
    if m["log_source_count"] == 0:
        reasons.append("no mapped log sources")
    if reasons:
        return {
            "confidence_state": "insufficient_prior" if len(reasons) >= 2 else "medium_uncertainty",
            "reason": reasons,
            "recommended_action": "manual triage or broaden evidence collection",
        }
    return {"confidence_state": "adequate_for_seed", "reason": [], "recommended_action": "proceed with VOI probes"}


def compute_risk_profile(loss: dict[str, float]) -> dict[str, Any]:
    return {
        "risk_profile": "conservative" if loss.get("LAMBDA_MISS", 10) >= 10 else "balanced",
        "loss_baseline": loss,
        "risk_implication": [
            "preserve attack-compatible edges when LAMBDA_MISS is high",
            "do not hard-veto using low-trust source",
            "elevate oos consideration when LAMBDA_OOS is high",
        ],
    }


def enrich_seed(
    seed: SeedPayload,
    log_sources: list[dict[str, Any]],
    build_mode: str = "unknown",
    prior: Any = None,
    ablation: dict[str, bool] | None = None,
) -> SeedPayload:
    seed.visibility = compute_visibility(seed, log_sources)
    seed.confidence_state = compute_confidence_state(seed)
    seed.risk_profile = compute_risk_profile(seed.loss_baseline)
    skip_sigma = bool((ablation or {}).get("no_sigma"))
    for e in seed.explanations:
        e.support["evidence_passport"] = passport_for_explanation(
            e, seed.alert, build_mode, prior, skip_sigma=skip_sigma
        )
    for ce in seed.contested_edges:
        ce.support["evidence_passport"] = passport_for_edge(ce, build_mode)
    return seed


def build_mode_from_seed(seed: SeedPayload) -> str:
    from trace_agent.eval.quality_gates import _build_mode

    return _build_mode(seed)
