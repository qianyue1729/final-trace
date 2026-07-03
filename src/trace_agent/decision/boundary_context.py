"""Runtime boundary adjustment on top of build-time boundary_prior."""
from __future__ import annotations

from typing import Any

from trace_agent.decision.types import AlertEvent


def _norm(bp: dict[str, float]) -> dict[str, float]:
    p_in = max(0.0, bp.get("p_in_attack", 0.34))
    p_ben = max(0.0, bp.get("p_benign", 0.33))
    p_oos = max(0.0, bp.get("p_oos", 0.33))
    total = p_in + p_ben + p_oos or 1.0
    return {
        "p_in_attack": round(min(0.55, p_in / total), 2),
        "p_benign": round(p_ben / total, 2),
        "p_oos": round(p_oos / total, 2),
        "boundary_layer": "runtime_context_seed",
        "build_prior_ref": bp.get("build_prior_ref"),
    }


def adjust_boundary_prior(
    build_prior: dict[str, float],
    alert: AlertEvent,
    edge_support: dict[str, Any] | None = None,
) -> dict[str, float]:
    """build-time prior + alert context; dual-use != benign."""
    bp = {**build_prior, "build_prior_ref": dict(build_prior)}
    attrs = alert.attributes or {}
    profile = attrs.get("tenant_profile") or {}
    support = edge_support or {}

    if profile.get("asset_role") in ("devops_server", "cicd_server"):
        bp["p_benign"] = bp.get("p_benign", 0.33) + 0.10
        bp["p_in_attack"] = bp.get("p_in_attack", 0.34) - 0.06
    elif profile.get("asset_role") in ("domain_controller", "cloud_control_plane"):
        bp["p_in_attack"] = min(0.55, bp.get("p_in_attack", 0.34) + 0.08)
        bp["p_benign"] = bp.get("p_benign", 0.33) - 0.05

    admin_tools = {t.lower() for t in profile.get("admin_tool_baseline") or []}
    if admin_tools & {"powershell", "psexec", "ssh", "wmic"}:
        bp["p_benign"] = bp.get("p_benign", 0.33) + 0.06

    if profile.get("edr_coverage") == "low":
        bp["p_oos"] = bp.get("p_oos", 0.33) + 0.04

    if attrs.get("known_admin_host") or attrs.get("admin_baseline"):
        bp["p_benign"] = bp.get("p_benign", 0.33) + 0.10
        bp["p_in_attack"] = bp.get("p_in_attack", 0.34) - 0.06

    if attrs.get("suspicious_parent") or attrs.get("external_network_after"):
        bp["p_in_attack"] = min(0.55, bp.get("p_in_attack", 0.34) + 0.10)
        bp["p_benign"] = bp.get("p_benign", 0.33) - 0.08

    if attrs.get("weak_case_link") or attrs.get("concurrent_incident"):
        bp["p_oos"] = bp.get("p_oos", 0.33) + 0.10
        bp["p_in_attack"] = bp.get("p_in_attack", 0.34) - 0.05

    if attrs.get("backup_baseline") or attrs.get("simulation"):
        bp["p_benign"] = bp.get("p_benign", 0.33) + 0.12
        bp["p_in_attack"] = bp.get("p_in_attack", 0.34) - 0.08

    # ponytail: low-trust log → uncertainty, not hard benign
    if alert.anomaly_score < 0.4 and not attrs.get("suspicious_parent"):
        bp["p_benign"] = bp.get("p_benign", 0.33) + 0.05

    if support.get("lolbas_dual_use") or support.get("gtfobins_dual_use"):
        if not (attrs.get("suspicious_parent") or attrs.get("external_network_after")):
            bp["p_benign"] = min(0.52, bp.get("p_benign", 0.33) + 0.04)

    return _norm(bp)
