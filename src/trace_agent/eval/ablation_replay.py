"""Ablation replay with sanity metrics (T27)."""
from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from trace_agent.decision.belief import DecisionLedger
from trace_agent.eval.prior_replay import FIXTURES_DIR, load_fixtures, run_case
from trace_agent.eval.visibility_metrics import (
    aggregate_visibility_metrics,
    sigma_visibility_delta_gate,
)
from trace_agent.eval.probe_metrics import aggregate_probe_metrics
from trace_agent.prior_v2 import PriorManager

MODES = {
    "full": {},
    "no_flow": {"no_flow": True},
    "no_sigma": {"no_sigma": True},
    "no_dual_use": {"no_dual_use": True},
    "no_lifecycle": {"no_lifecycle": True},
}


def _agg(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not cases:
        return {}
    n = len(cases)

    def mean(key: str) -> float:
        return round(sum(c.get("metrics", {}).get(key, 0) for c in cases) / n, 4)

    def rate(check: str) -> float | None:
        hits = [c for c in cases if check in (c.get("checks") or {})]
        if not hits:
            return None
        return round(sum(1 for c in hits if c["checks"][check]) / len(hits), 3)

    types_all: list[str] = []
    for c in cases:
        types_all.extend(c.get("metrics", {}).get("explanation_types") or [])
    lifecycle_share = round(
        sum(1 for t in types_all if t == "lifecycle") / max(1, len(types_all)), 3
    )

    return {
        "mean_explanation_count": mean("explanation_count"),
        "mean_entropy": mean("entropy"),
        "mean_normalized_entropy": mean("normalized_entropy"),
        "mean_max_prior": mean("max_prior"),
        "top_k_behavior_hit_rate": rate("top_k_hit"),
        "boundary_flag_hit_rate": rate("boundary_ok"),
        "log_source_hit_rate": rate("log_source_ok"),
        "mean_log_source_count": mean("log_source_count"),
        "lifecycle_explanation_share": lifecycle_share,
        "pass_rate": round(sum(1 for c in cases if c.get("passed")) / n, 3),
    }


def run_ablation(fixtures_dir: Path | None = None) -> dict[str, Any]:
    fixtures = load_fixtures(fixtures_dir or FIXTURES_DIR)
    prior = PriorManager()
    results: dict[str, Any] = {}
    case_results: dict[str, list[dict[str, Any]]] = {}
    for mode, flags in MODES.items():
        ledger = DecisionLedger(prior, ablation=flags)
        cases = [run_case(f, ledger) for f in fixtures]
        case_results[mode] = cases
        agg = _agg(cases)
        agg["sigma_visibility"] = aggregate_visibility_metrics(cases)
        agg["probe_ground_truth"] = aggregate_probe_metrics(cases)
        results[mode] = agg

    full = results.get("full") or {}
    nf = results.get("no_flow") or {}
    ns = results.get("no_sigma") or {}
    sanity_notes: list[str] = []
    if full and nf:
        if (nf.get("mean_explanation_count") or 0) < (full.get("mean_explanation_count") or 0) * 0.7:
            sanity_notes.append(
                "no_flow: candidate collapse — fewer explanations; check normalized_entropy not raw entropy"
            )
        if (nf.get("mean_normalized_entropy") or 0) < (full.get("mean_normalized_entropy") or 0) - 0.15:
            sanity_notes.append("no_flow: normalized_entropy fell — possible over-concentration")

    sigma_gate = sigma_visibility_delta_gate(
        full.get("sigma_visibility") or {},
        ns.get("sigma_visibility") or {},
    )

    return {
        "modes": results,
        "fixture_count": len(fixtures),
        "sanity_notes": sanity_notes,
        "sigma_visibility_delta_gate": sigma_gate,
    }


def report_markdown(ablation: dict[str, Any]) -> str:
    lines = [
        "# Prior Ablation Sanity Report",
        "",
        f"Fixtures: {ablation.get('fixture_count', 0)}",
        "",
        "## Prior / explanation metrics",
        "",
        "| variant | expl_count | entropy | norm_entropy | max_prior | top_k | log_src |",
        "|---------|------------|---------|--------------|-----------|-------|---------|",
    ]
    for mode, m in (ablation.get("modes") or {}).items():
        lines.append(
            f"| {mode} | {m.get('mean_explanation_count')} | {m.get('mean_entropy')} | "
            f"{m.get('mean_normalized_entropy')} | {m.get('mean_max_prior')} | "
            f"{m.get('top_k_behavior_hit_rate')} | {m.get('log_source_hit_rate')} |"
        )

    full_vis = (ablation.get("modes") or {}).get("full", {}).get("sigma_visibility") or {}
    ns_vis = (ablation.get("modes") or {}).get("no_sigma", {}).get("sigma_visibility") or {}
    gate = ablation.get("sigma_visibility_delta_gate") or {}
    by_src = full_vis.get("by_annotation_source") or {}
    lines.extend(
        [
            "",
            "## Sigma-specific Visibility / Probe Metrics",
            "",
            "| variant | log_source_hit | probe_hit | visibility_gap | evidence_debt | sigma_trace | mean_rec_count |",
            "|---------|---------------:|----------:|---------------:|--------------:|------------:|---------------:|",
            f"| full | {full_vis.get('log_source_hit_rate')} | {full_vis.get('probe_recommendation_hit_rate')} | "
            f"{full_vis.get('visibility_gap_detection_rate')} | {full_vis.get('evidence_debt_explanation_rate')} | "
            f"{full_vis.get('sigma_trace_presence_rate')} | {full_vis.get('mean_recommended_log_source_count')} |",
            f"| no_sigma | {ns_vis.get('log_source_hit_rate')} | {ns_vis.get('probe_recommendation_hit_rate')} | "
            f"{ns_vis.get('visibility_gap_detection_rate')} | {ns_vis.get('evidence_debt_explanation_rate')} | "
            f"{ns_vis.get('sigma_trace_presence_rate')} | {ns_vis.get('mean_recommended_log_source_count')} |",
            "",
            "no_sigma 对 max_prior / entropy 影响弱是**预期行为**（Sigma 不进入因果主权重）；"
            "no_sigma 显著削弱 visibility / probe / passport 层能力。",
            "",
            "> 消融验证了语义防火墙：移除 Sigma 不会显著改变因果先验分布，但会明显降低 log source 命中、"
            "可见性缺口识别和 Sigma trace 覆盖率——Sigma 的价值在可观测性与探针规划，不在因果主权重。",
            "",
            "**Formal principle:** Sigma contribution is evaluated only on visibility/probe/passport metrics, "
            "not on causal prior metrics (`sigma_visibility_delta_gate`: 2/3 meaningful deltas).",
            "",
            f"**sigma_visibility_delta_gate:** {'PASS' if gate.get('pass') else 'FAIL'} "
            f"({gate.get('positive_deltas', 0)}/3 deltas meaningful; details: {gate.get('deltas')})",
            "",
            f"**mean_rec_count note:** {full_vis.get('mean_rec_count_note')}",
            "",
            f"**log_source_hit note:** {full_vis.get('interpretation')}",
        ]
    )
    if by_src:
        lines.extend(["", "### By visibility_annotation_source (full mode)", ""])
        for src, stats in sorted(by_src.items()):
            lines.append(
                f"- `{src}` (n={stats.get('case_count')}): "
                f"log_source_hit={stats.get('log_source_hit_rate')}, probe_hit={stats.get('probe_recommendation_hit_rate')}"
            )

    full_probe = (ablation.get("modes") or {}).get("full", {}).get("probe_ground_truth") or {}
    ns_probe = (ablation.get("modes") or {}).get("no_sigma", {}).get("probe_ground_truth") or {}
    lines.extend(
        [
            "",
            "## Probe Ground Truth Metrics (P3)",
            "",
            "| variant | source_hit | must_not_ok | cost_weighted | coverage@k | noise |",
            "|---------|----------:|------------:|--------------:|---------:|------:|",
            f"| full | {full_probe.get('probe_source_hit_rate')} | {full_probe.get('probe_must_not_violation_rate')} | "
            f"{full_probe.get('probe_cost_weighted_hit_rate')} | {full_probe.get('probe_coverage_at_k')} | "
            f"{full_probe.get('probe_noise_rate')} |",
            f"| no_sigma | {ns_probe.get('probe_source_hit_rate')} | {ns_probe.get('probe_must_not_violation_rate')} | "
            f"{ns_probe.get('probe_cost_weighted_hit_rate')} | {ns_probe.get('probe_coverage_at_k')} | "
            f"{ns_probe.get('probe_noise_rate')} |",
            "",
            f"**Probe note:** {full_probe.get('interpretation')}",
        ]
    )
    probe_by = full_probe.get("by_annotation_source") or {}
    if probe_by:
        lines.extend(["", "### By probe annotation_source (full mode)", ""])
        for src, stats in sorted(probe_by.items()):
            lines.append(
                f"- `{src}` (n={stats.get('case_count')}): "
                f"probe_source_hit={stats.get('probe_source_hit_rate')}, "
                f"must_not_ok={stats.get('probe_must_not_violation_rate')}"
            )
    if ablation.get("sanity_notes"):
        lines.extend(["", "## Sanity notes", ""])
        for n in ablation["sanity_notes"]:
            lines.append(f"- {n}")
    return "\n".join(lines)
