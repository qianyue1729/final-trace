"""Investigation presentation semantics for Deep Agent / UI."""
from __future__ import annotations

from typing import Any


def _attack_ref_count(nodes: list[dict[str, Any]]) -> int:
    count = 0
    for node in nodes:
        ref = str(
            (node.get("attributes") or {}).get("raw_log_ref")
            or node.get("id")
            or ""
        )
        if ref.startswith("attack:"):
            count += 1
    return count


def _chain_build_assessment(
    *,
    nodes: list[dict[str, Any]],
    candidate_chain: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    node_count = len(nodes)
    attack_refs = _attack_ref_count(nodes)
    candidate_events = int(candidate_chain.get("candidate_chain_events") or 0)
    mode = str(candidate_chain.get("candidate_chain_mode") or "")

    expected_attack = 18 if candidate_events >= 18 or mode == "eval_attack_prefix" else 8
    metrics = {
        "node_count": node_count,
        "attack_ref_count": attack_refs,
        "candidate_chain_events": candidate_events,
        "candidate_chain_mode": mode,
        "expected_attack_refs": expected_attack,
    }

    if attack_refs >= expected_attack and node_count >= expected_attack:
        return "success", "建链成功", metrics
    if node_count >= 8 and attack_refs >= 1:
        return "partial", "建链部分成功", metrics
    return "failed", "建链失败", metrics


def _attribution_assessment(decision: dict[str, Any]) -> tuple[str, str]:
    action = str(decision.get("action") or "")
    boundary = decision.get("boundary_decisions") or {}
    contested = sum(1 for val in boundary.values() if val == "contested")
    total = len(boundary)

    if action == "contain_escalate" and not decision.get("require_human_review"):
        return "confirmed", "归因可自动确认"
    if action == "inconclusive":
        return "unavailable", "归因未形成"
    if total > 0 and contested == total:
        return "contested", "归因待确认"
    if action in ("escalate_incomplete", "escalate", "monitor"):
        return "pending", "归因待确认"
    return "pending", "归因待确认"


def _investigation_status(
    *,
    decision: dict[str, Any],
    chain_build_status: str,
) -> tuple[str, str, bool]:
    """Return (investigation_status, display_headline, is_demo_success)."""
    action = str(decision.get("action") or "")
    stop_reason = str(decision.get("stop_reason") or "")
    require_review = bool(decision.get("require_human_review"))

    if action == "inconclusive":
        return "failed_inconclusive", "调查未得出可展示结论", False

    if action == "contain_escalate" and not require_review:
        return "completed_automated", "调查完成 · 建议自动处置", True

    if action in ("escalate_incomplete", "escalate") or require_review:
        if chain_build_status == "success":
            return (
                "completed_needs_review",
                "调查完成 · 建议人工复核",
                True,
            )
        if chain_build_status == "partial":
            return (
                "completed_partial",
                "调查完成（链不完整）· 建议人工复核",
                False,
            )
        return "completed_needs_review", "调查完成 · 建议人工复核", require_review

    if stop_reason == "budget":
        return "failed_budget", "调查预算耗尽", False

    return "completed", "调查完成", chain_build_status == "success"


def summarize_lock_loop(
    *,
    usage: dict[str, Any],
    decision: dict[str, Any],
) -> dict[str, Any]:
    round_diag = list(usage.get("round_diagnostics") or [])
    voi_audit = list(usage.get("voi_audit") or [])
    planner_audit = list(usage.get("model_planner") or [])

    rounds: list[dict[str, Any]] = []
    for item in round_diag:
        rounds.append({
            "round": item.get("round"),
            "phase_flow": "L → Veto → O → C → K",
            "probes_selected": item.get("probes_selected"),
            "probe_results_count": item.get("probe_results_count"),
            "attach_bucket_count": item.get("attach_bucket_count"),
            "weak_bucket_count": item.get("weak_bucket_count"),
            "graph_eligible_count": item.get("graph_eligible_count"),
            "new_graph_nodes": item.get("new_graph_nodes"),
            "new_graph_edges": item.get("new_graph_edges"),
            "graph_nodes": item.get("graph_nodes"),
            "graph_edges": item.get("graph_edges"),
            "p_atk_before": item.get("p_atk_before"),
            "p_atk_after": item.get("p_atk_after"),
            "delta_p_atk": item.get("delta_p_atk"),
            "margin": item.get("margin"),
            "stop_should_stop": item.get("stop_should_stop"),
            "stop_reason_candidate": item.get("stop_reason_candidate"),
        })

    operators_by_round: dict[int, list[str]] = {}
    for item in voi_audit:
        rnd = int(item.get("round") or 0)
        op = item.get("operator")
        if rnd and op:
            operators_by_round.setdefault(rnd, []).append(str(op))

    planner_by_round = [
        {
            "round": entry.get("round"),
            "mode": entry.get("mode"),
            "abstained": entry.get("abstained"),
            "accepted": entry.get("accepted"),
            "provider_status": entry.get("provider_status"),
        }
        for entry in planner_audit[:25]
    ]

    return {
        "lock_phases": ["L(候选生成)", "Veto(检验)", "O(VOI选探针)", "C(取证入图)", "K(学习+停止)"],
        "rounds_used": usage.get("rounds"),
        "probes_used": usage.get("probes_used"),
        "elapsed_seconds": usage.get("elapsed_seconds"),
        "final_stop_reason": decision.get("stop_reason"),
        "rounds": rounds,
        "voi_operators_by_round": operators_by_round,
        "planner_audit": planner_by_round,
    }


def derive_investigation_presentation(report: dict[str, Any]) -> dict[str, Any]:
    """Map engine report to user-facing investigation semantics."""
    decision = report.get("decision") or {}
    usage = report.get("usage") or {}
    graph = report.get("graph") or {}
    nodes = list(graph.get("nodes") or [])
    trace_coverage = report.get("trace_coverage") or {}
    candidate_chain = trace_coverage.get("candidate_chain") or {}

    chain_status, chain_label, chain_metrics = _chain_build_assessment(
        nodes=nodes,
        candidate_chain=candidate_chain,
    )
    chain_metrics["edge_count"] = len(graph.get("edges") or [])

    attr_status, attr_label = _attribution_assessment(decision)
    inv_status, headline, demo_success = _investigation_status(
        decision=decision,
        chain_build_status=chain_status,
    )

    return {
        "investigation_status": inv_status,
        "display_headline": headline,
        "is_demo_success": demo_success,
        "chain_build_status": chain_status,
        "chain_build_label": chain_label,
        "attribution_status": attr_status,
        "attribution_label": attr_label,
        "chain_metrics": chain_metrics,
        "lock_loop": summarize_lock_loop(usage=usage, decision=decision),
        "presentation_notes": [
            "建链成功 = Wazuh 候选攻击链已入图，不代表自动归因成功",
            "归因待确认 = boundary contested 或 require_human_review",
            "escalate_incomplete + 建链成功 = 调查完成，不是溯源失败",
        ],
    }
