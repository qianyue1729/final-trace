"""LOCK 四本账查询工具 — 让 Agent 实时检查调查状态。

所有工具通过 session_id（从 phase_tools 的会话池获取）访问 LOCKSession。
"""
from __future__ import annotations

import json
import logging
from typing import Any, Optional

from langchain_core.tools import tool

from .phase_tools import _get_session, SessionContext
from .project import ensure_core_importable

ensure_core_importable()

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


def _get_active_session() -> Optional[SessionContext]:
    """Return the most-recently created active session (if any)."""
    from .phase_tools import _sessions, _sessions_lock
    with _sessions_lock:
        if not _sessions:
            return None
        # Pick the most recently created session
        return max(_sessions.values(), key=lambda c: c.created_at)


def _resolve_session(session_id: str = "") -> SessionContext | str:
    """Resolve a session by ID or fall back to the active session.

    Returns SessionContext on success, or a JSON error string.
    """
    if session_id:
        ctx = _get_session(session_id)
        if ctx is None:
            return _json({
                "status": "error",
                "error": (
                    f"No active session '{session_id}'. "
                    "Call init_investigation first."
                ),
            })
        return ctx
    ctx = _get_active_session()
    if ctx is None:
        return _json({
            "status": "error",
            "error": "No active session. Call init_investigation first.",
        })
    return ctx


# ══════════════════════════════════════════════════════════════
# TOOL DEFINITIONS
# ══════════════════════════════════════════════════════════════


@tool
def get_session_state(session_id: str = "") -> str:
    """获取当前调查会话的全局状态摘要。

    返回当前轮次、预算剩余、四本账的高层摘要。
    不传 session_id 时自动获取最近活跃会话。

    Args:
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    session = ctx.lock_session
    try:
        snapshot = session.to_snapshot()
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to get snapshot: {exc}"})

    return _json({
        "status": "ok",
        "session_id": ctx.session_id,
        "scenario_id": ctx.scenario_id,
        "current_phase": ctx.current_phase,
        "round": snapshot.get("round", session.round),
        "budget_remaining": snapshot.get("budget_remaining", {}),
        "graph_summary": snapshot.get("graph_stats", {}),
        "ledger_summary": snapshot.get("ledger_summary", {}),
        "obligation_summary": snapshot.get("obligation_summary", {}),
        "beta_summary": snapshot.get("beta_summary", {}),
    })


@tool
def get_decision_ledger(session_id: str = "") -> str:
    """查看决策账（第四本账）详情。

    返回竞争解释列表（含后验概率）、null 锚状态、
    边界信念（有争议边的归属概率）、margin 和 entropy。

    Args:
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    ledger = ctx.lock_session.ledger
    if ledger is None:
        return _json({"status": "error", "error": "Decision ledger not initialised."})

    try:
        # Explanations with posteriors
        probs = ledger._get_probabilities()
        explanations = []
        for expl in ledger.explanations:
            explanations.append({
                "eid": expl.id,
                "label": expl.title or expl.id,
                "posterior": round(probs.get(expl.id, 0.0), 4),
                "is_null": False,
                "null_kind": None,
                "lifecycle_stage": getattr(expl, "stage", None) or "",
            })

        # Null anchor
        null_p = probs.get("__null__", 0.0)
        if ledger.null_anchor is not None:
            explanations.append({
                "eid": "__null__",
                "label": "null_anchor",
                "posterior": round(null_p, 4),
                "is_null": True,
                "null_kind": (
                    f"benign={ledger.null_anchor.benign},oos={ledger.null_anchor.oos}"
                ),
                "lifecycle_stage": None,
            })

        # Contested edges
        contested_edges = []
        for edge_id, belief in ledger.contested.items():
            contested_edges.append({
                "edge_id": edge_id,
                "p_in_attack": round(belief.p_in_attack, 4),
                "p_benign": round(belief.p_benign, 4),
                "p_oos": round(belief.p_oos, 4),
            })

        # Log posteriors
        log_posteriors = {
            k: round(v, 4) for k, v in ledger.log_post.items()
        }

        return _json({
            "status": "ok",
            "explanations": explanations,
            "contested_edges": contested_edges,
            "leading": ledger.leading(),
            "margin": round(ledger.margin(), 4),
            "entropy": round(ledger.entropy(), 4),
            "log_posteriors": log_posteriors,
        })
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to read decision ledger: {exc}"})


@tool
def get_voi_ranking(top_k: int = 10, session_id: str = "") -> str:
    """查看当前候选探针的 VOI（信息价值）排序。

    返回按 VOI 分数从高到低排序的候选探针列表，
    包含每个探针的风险削减和成本分解。

    只在 O 拍之后有意义（需要先执行 run_o_phase）。

    Args:
        top_k: 返回前 K 个探针（默认 10）
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    session = ctx.lock_session

    # Try to use the pool from session.data (populated by L/Veto phases)
    pool = session.data.get("pool")
    if pool is None:
        return _json({
            "status": "warning",
            "error": "No candidate pool available. Run run_o_phase first to generate VOI ranking.",
            "hint": "The candidate pool is populated after L phase and VOI ranking after O phase.",
        })

    try:
        from trace_agent.probe.voi_engine import voi as compute_voi

        # Build beta dict from BetaLedger
        beta_dict: dict = {}
        if session.beta is not None:
            try:
                for k in session.beta.all_keys():
                    beta_dict[k] = {
                        "hit_rate": round(session.beta.sensitivity(k), 4),
                    }
            except Exception:
                pass

        calib: dict = {}
        graph_stats = session.graph.stats() if session.graph else None

        results = []
        for probe in pool:
            try:
                if isinstance(probe, dict):
                    pd = probe
                elif hasattr(probe, "__dict__"):
                    pd = {
                        "id": getattr(probe, "id", ""),
                        "type": getattr(probe, "source", ""),
                        "target": getattr(probe, "target", ""),
                        "target_type": getattr(probe, "target_type", ""),
                        "operator": getattr(probe, "operator", ""),
                        "tactic": getattr(probe, "tactic", ""),
                        "learning_key": (
                            probe.learning_key()
                            if hasattr(probe, "learning_key")
                            else ""
                        ),
                        "cost": getattr(probe, "cost", 0.05),
                    }
                else:
                    continue

                result = compute_voi(
                    pd,
                    session.ledger,
                    beta_dict,
                    calib,
                    session.loss,
                    session.trust,
                    graph_stats=graph_stats,
                )
                results.append({
                    "probe": pd.get("id", ""),
                    "target": pd.get("target", ""),
                    "operator": pd.get("operator", pd.get("type", "")),
                    "voi_score": round(result.voi_score, 4),
                    "risk_reduction": round(
                        result.risk_now - result.expected_risk_after, 4
                    ),
                    "cost": round(result.cost, 4),
                    "source": pd.get("type", ""),
                })
            except Exception:
                continue

        # Sort by VOI descending
        results.sort(key=lambda r: r["voi_score"], reverse=True)
        results = results[: max(1, top_k)]

        return _json({
            "status": "ok",
            "ranking": results,
            "total_candidates": len(pool),
            "top_k": top_k,
        })
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to compute VOI ranking: {exc}"})


@tool
def get_obligation_status(session_id: str = "") -> str:
    """查看义务台账的当前状态。

    返回开放、已履行、逾期的义务列表，
    包含每个义务的类型（结构/生命周期/反取证/判别）、
    锚点、deadline、当前状态。

    Args:
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    obligations = ctx.lock_session.obligations
    if obligations is None:
        return _json({"status": "error", "error": "Obligation ledger not initialised."})

    try:
        current_round = ctx.lock_session.round

        open_list = []
        discharged_list = []
        overdue_list = []

        for ob in obligations.obligations:
            ob_type = ob.type.value if hasattr(ob.type, "value") else str(ob.type)
            if ob.discharged:
                discharged_list.append({
                    "id": ob.id,
                    "type": ob_type,
                    "anchor": ob.anchor,
                    "discharged_by": getattr(ob, "discharged_by", "") or "",
                })
            else:
                is_overdue = ob.is_overdue(current_round) if hasattr(ob, "is_overdue") else False
                entry = {
                    "id": ob.id,
                    "type": ob_type,
                    "anchor": ob.anchor,
                    "deadline": ob.deadline_round,
                    "priority": "hard" if ob.hard else "voi_gated",
                    "attempts": getattr(ob, "attempts", 0),
                }
                open_list.append(entry)
                if is_overdue:
                    overdue_list.append({
                        "id": ob.id,
                        "type": ob_type,
                        "anchor": ob.anchor,
                        "deadline": ob.deadline_round,
                        "overdue_rounds": current_round - ob.deadline_round,
                    })

        return _json({
            "status": "ok",
            "open": open_list,
            "discharged": discharged_list,
            "overdue": overdue_list,
            "summary": {
                "open_count": len(open_list),
                "discharged_count": len(discharged_list),
                "overdue_count": len(overdue_list),
            },
        })
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to read obligation ledger: {exc}"})


@tool
def get_evidence_trust(session_id: str = "") -> str:
    """查看证据信任层的当前状态。

    返回按来源分组的信任评分统计、
    反取证检测结果（日志断层、EDR 静默等）、
    以及最近的信任修订记录。

    Args:
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    trust = ctx.lock_session.trust
    if trust is None:
        return _json({"status": "error", "error": "Evidence trust model not initialised."})

    try:
        # Source-level statistics
        source_stats: dict[str, dict] = {}
        for eid, et in getattr(trust, "evidence_trust_map", {}).items():
            source = getattr(et, "provenance", "unknown") or "unknown"
            if source not in source_stats:
                source_stats[source] = {
                    "count": 0,
                    "integrity_sum": 0.0,
                    "adversary_controllable_count": 0,
                }
            entry = source_stats[source]
            entry["count"] += 1
            entry["integrity_sum"] += getattr(et, "integrity", 0.0)
            if getattr(et, "adversary_controllable", False):
                entry["adversary_controllable_count"] += 1

        # Compute averages
        for src, stats in source_stats.items():
            count = stats["count"]
            stats["avg_integrity"] = round(stats["integrity_sum"] / count, 4) if count else 0.0
            del stats["integrity_sum"]  # not needed in output

        # Anti-forensics detections
        anti_forensics: list[dict] = []
        for eid, et in getattr(trust, "evidence_trust_map", {}).items():
            if getattr(et, "anti_forensics_indicator", False):
                anti_forensics.append({
                    "type": "anti_forensics",
                    "description": f"Anti-forensics indicator on evidence {eid}",
                    "affected_hosts": [getattr(et, "host_id", "")] if getattr(et, "host_id", "") else [],
                })
            if getattr(et, "absence_indicator", False):
                anti_forensics.append({
                    "type": "absence",
                    "description": f"Telemetry absence detected for {eid}",
                    "affected_hosts": [getattr(et, "host_id", "")] if getattr(et, "host_id", "") else [],
                })

        # Recent trust revisions
        recent_revisions: list[dict] = []
        for rev in getattr(trust, "revisions", []):
            recent_revisions.append({
                "evidence_id": getattr(rev, "evidence_id", ""),
                "old_trust": round(getattr(getattr(rev, "old_trust", None), "integrity", 0.0), 4),
                "new_trust": round(getattr(getattr(rev, "new_trust", None), "integrity", 0.0), 4),
                "reason": getattr(rev, "reason", ""),
            })

        # Summary from model
        summary = {}
        if hasattr(trust, "get_summary"):
            try:
                summary = trust.get_summary()
            except Exception:
                pass

        return _json({
            "status": "ok",
            "source_stats": source_stats,
            "anti_forensics": anti_forensics,
            "recent_revisions": recent_revisions[-20:],  # cap at 20
            "summary": summary,
        })
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to read evidence trust: {exc}"})


@tool
def get_attack_graph(
    max_nodes: int = 50,
    max_edges: int = 80,
    session_id: str = "",
) -> str:
    """查看当前攻击因果图。

    返回图中的节点和边，包含归属标注（属于哪个解释或 null 锚）。

    Args:
        max_nodes: 最大节点数（超出则截断）
        max_edges: 最大边数（超出则截断）
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    graph = ctx.lock_session.graph
    if graph is None:
        return _json({"status": "error", "error": "Attack graph not initialised."})

    try:
        all_nodes = list(graph._nodes.values())
        all_edges = list(graph._edges.values())
        total_nodes = len(all_nodes)
        total_edges = len(all_edges)
        truncated = total_nodes > max_nodes or total_edges > max_edges

        # Truncate nodes
        nodes_out = []
        for node in all_nodes[:max_nodes]:
            attrs = node.attributes or {}
            nodes_out.append({
                "id": node.id,
                "technique": node.technique or "",
                "tactic": node.tactic or "",
                "host": str(
                    attrs.get("host_uid") or attrs.get("asset_id")
                    or attrs.get("target") or node.host_id or ""
                ),
                "timestamp": round(float(node.timestamp or 0), 4),
                "explanation_ids": list(node.explanation_ids),
                "attributed": bool(node.explanation_ids),
            })

        # Truncate edges
        edges_out = []
        for edge in all_edges[:max_edges]:
            edges_out.append({
                "source": str(edge.src),
                "target": str(edge.dst),
                "relation": edge.relation,
            })

        # Aggregate info
        tactics_seen = sorted(set(n.tactic for n in all_nodes if n.tactic))
        hosts_seen = sorted(set(
            str(
                (n.attributes or {}).get("host_uid")
                or (n.attributes or {}).get("asset_id")
                or (n.attributes or {}).get("target")
                or n.host_id
                or ""
            )
            for n in all_nodes
        ))
        hosts_seen = [h for h in hosts_seen if h]

        return _json({
            "status": "ok",
            "nodes": nodes_out,
            "edges": edges_out,
            "total_nodes": total_nodes,
            "total_edges": total_edges,
            "truncated": truncated,
            "tactics_seen": tactics_seen,
            "hosts_seen": hosts_seen,
        })
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to read attack graph: {exc}"})


# ──────────────────────────────────────────────────────────────
# Exports
# ──────────────────────────────────────────────────────────────

QUERY_TOOLS = [
    get_session_state,
    get_decision_ledger,
    get_voi_ranking,
    get_obligation_status,
    get_evidence_trust,
    get_attack_graph,
]
