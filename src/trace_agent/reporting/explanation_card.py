"""SOC-readable explanation cards from seed payload."""
from __future__ import annotations

from trace_agent.decision.types import Explanation, SeedPayload


def render_explanation_card(expl: Explanation) -> str:
    passport = (expl.support or {}).get("evidence_passport") or {}
    why = passport.get("why_not_confident") or expl.caveats
    next_checks = passport.get("what_would_change_my_mind") or []
    lines = [
        f"### {expl.id} — {expl.title}",
        "",
        f"**Prior:** {expl.prior_probability:.2f} | **Type:** {expl.support.get('type', '?')}",
        "",
        "**Why plausible:**",
    ]
    if expl.support.get("flow_backed") or expl.support.get("l2_attack_flow_edges"):
        lines.append("- ATT&CK Flow-backed technique context")
    if expl.lifecycle_template:
        lines.append(f"- Matches lifecycle template `{expl.lifecycle_template}`")
    if expl.recommended_log_sources:
        srcs = ", ".join(s["log_source"] for s in expl.recommended_log_sources[:4])
        lines.append(f"- Sigma/node maps to: {srcs}")
    lines.extend(["", "**Why this may be wrong:**"])
    lines.extend(f"- {w}" for w in why) or lines.append("- (none listed)")
    lines.extend(["", "**What to check next:**"])
    for i, c in enumerate(next_checks[:4], 1):
        lines.append(f"{i}. {c}")
    bp = expl.support.get("boundary_risk") or expl.features.get("boundary_risk")
    if bp:
        lines.append(f"\n**Boundary risk score (feature):** {bp}")
    return "\n".join(lines)


def render_seed_cards(seed: SeedPayload) -> str:
    parts = [
        f"# Seed Explanation Cards — {seed.alert.technique_id}",
        "",
        f"**Null anchor:** benign={seed.branch_null_anchor.benign} oos={seed.branch_null_anchor.oos}",
        "",
    ]
    vis = getattr(seed, "visibility", None) or {}
    if vis.get("missing_log_sources"):
        parts.append(
            "> **Telemetry gap:** "
            + ", ".join(vis["missing_log_sources"])
            + " unavailable; absence of script/process evidence is NOT used to reject explanations."
        )
        parts.append("")
    for expl in seed.explanations:
        parts.append(render_explanation_card(expl))
        parts.append("")
    return "\n".join(parts)
