"""LOCK 调查控制工具 — 让 Agent 调整运行参数。"""
from __future__ import annotations

import json
import logging
import time
from typing import Any, Optional

from langchain_core.tools import tool

from .phase_tools import (
    _get_session,
    _remove_session,
    _build_report_from_session,
    _json,
)

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# 1. adjust_loss_parameters
# ──────────────────────────────────────────────────────────────

@tool
def adjust_loss_parameters(
    session_id: str,
    lambda_miss: Optional[float] = None,
    lambda_over: Optional[float] = None,
    lambda_oos: Optional[float] = None,
) -> str:
    """调整决策账的损失矩阵参数。

    这些参数影响 VOI 排序和停止判定的权重：
    - lambda_miss: 漏报代价（默认最高，代表漏掉真攻击的代价）
    - lambda_over: 过度归因代价（误将良性边算入攻击）
    - lambda_oos: 域外归因代价（误将其他攻击的边算入本案）

    调高 lambda_miss 会让系统更保守（倾向继续调查）。
    调高 lambda_over 会让系统更积极地剪枝（倾向排除不相关边）。

    只传入需要修改的参数，未传入的保持不变。
    """
    ctx = _get_session(session_id)
    if ctx is None:
        return _json({
            "status": "error",
            "error": f"No active session '{session_id}'. Call init_investigation first.",
        })

    session = ctx.lock_session
    loss = session.loss
    if loss is None:
        return _json({"status": "error", "error": "Session has no loss matrix initialized."})

    before = {
        "lambda_miss": round(loss.lambda_miss, 4),
        "lambda_over": round(loss.lambda_over, 4),
        "lambda_oos": round(loss.lambda_oos, 4),
    }

    changes: dict[str, dict[str, float]] = {}
    if lambda_miss is not None:
        old_val = loss.lambda_miss
        loss.lambda_miss = round(lambda_miss, 4)
        changes["lambda_miss"] = {"old": round(old_val, 4), "new": loss.lambda_miss}
    if lambda_over is not None:
        if lambda_over <= 0:
            return _json({"status": "error", "error": "lambda_over must be > 0"})
        old_val = loss.lambda_over
        loss.lambda_over = round(lambda_over, 4)
        changes["lambda_over"] = {"old": round(old_val, 4), "new": loss.lambda_over}
    if lambda_oos is not None:
        old_val = loss.lambda_oos
        loss.lambda_oos = round(lambda_oos, 4)
        changes["lambda_oos"] = {"old": round(old_val, 4), "new": loss.lambda_oos}

    after = {
        "lambda_miss": round(loss.lambda_miss, 4),
        "lambda_over": round(loss.lambda_over, 4),
        "lambda_oos": round(loss.lambda_oos, 4),
    }

    return _json({
        "status": "ok",
        "session_id": session_id,
        "changes": changes,
        "before": before,
        "after": after,
    })


# ──────────────────────────────────────────────────────────────
# 2. set_investigation_budget
# ──────────────────────────────────────────────────────────────

@tool
def set_investigation_budget(
    session_id: str,
    remaining_rounds: Optional[int] = None,
    remaining_probes: Optional[int] = None,
    fanout_per_round: Optional[int] = None,
) -> str:
    """调整当前调查的剩余预算。

    用于在调查过程中动态调整：
    - remaining_rounds: 剩余轮次数（会加上已用轮次来设定 total_rounds）
    - remaining_probes: 剩余探针数（会加上已用探针数来设定 total_probes）
    - fanout_per_round: 每轮扇出槽数（影响 O 拍选多少个探针）

    只传入需要修改的参数。
    """
    ctx = _get_session(session_id)
    if ctx is None:
        return _json({
            "status": "error",
            "error": f"No active session '{session_id}'. Call init_investigation first.",
        })

    budget = ctx.lock_session.budget
    if budget is None:
        return _json({"status": "error", "error": "Session has no budget initialized."})

    before = {
        "total_rounds": budget.total_rounds,
        "rounds_used": budget.rounds_used,
        "remaining_rounds": max(0, budget.total_rounds - budget.rounds_used),
        "total_probes": budget.total_probes,
        "probes_used": budget.probes_used,
        "remaining_probes": budget.remaining_probes,
        "fanout_per_round": budget.fanout_per_round,
    }

    changes: dict[str, dict[str, Any]] = {}
    if remaining_rounds is not None:
        old_total = budget.total_rounds
        budget.total_rounds = budget.rounds_used + remaining_rounds
        changes["remaining_rounds"] = {
            "old_remaining": max(0, old_total - budget.rounds_used),
            "new_remaining": remaining_rounds,
            "new_total": budget.total_rounds,
        }
    if remaining_probes is not None:
        old_total = budget.total_probes
        budget.total_probes = budget.probes_used + remaining_probes
        changes["remaining_probes"] = {
            "old_remaining": old_total - budget.probes_used,
            "new_remaining": remaining_probes,
            "new_total": budget.total_probes,
        }
    if fanout_per_round is not None:
        if fanout_per_round < 1:
            return _json({"status": "error", "error": "fanout_per_round must be >= 1"})
        old_val = budget.fanout_per_round
        budget.fanout_per_round = fanout_per_round
        # Also update session-level fanout_budget
        ctx.lock_session.fanout_budget = fanout_per_round
        changes["fanout_per_round"] = {"old": old_val, "new": fanout_per_round}

    after = {
        "total_rounds": budget.total_rounds,
        "rounds_used": budget.rounds_used,
        "remaining_rounds": max(0, budget.total_rounds - budget.rounds_used),
        "total_probes": budget.total_probes,
        "probes_used": budget.probes_used,
        "remaining_probes": budget.remaining_probes,
        "fanout_per_round": budget.fanout_per_round,
    }

    return _json({
        "status": "ok",
        "session_id": session_id,
        "changes": changes,
        "before": before,
        "after": after,
    })


# ──────────────────────────────────────────────────────────────
# 3. force_stop
# ──────────────────────────────────────────────────────────────

@tool
def force_stop(
    session_id: str,
    reason: str = "user_requested",
) -> str:
    """强制停止当前调查并生成报告。

    无论 LOCK 循环是否满足停止条件，立即终止并基于当前状态生成调查报告。

    Args:
        session_id: 调查会话 ID
        reason: 停止原因说明（默认 "user_requested"）
    """
    ctx = _get_session(session_id)
    if ctx is None:
        return _json({
            "status": "error",
            "error": f"No active session '{session_id}'. Call init_investigation first.",
        })

    t0 = time.time()
    try:
        # Build report from current session state
        elapsed = t0 - ctx.created_at
        report = _build_report_from_session(ctx, elapsed=elapsed)

        # Override stop_reason
        if "decision" in report:
            report["decision"]["stop_reason"] = f"forced:{reason}"
        report["forced_stop"] = True
        report["forced_stop_reason"] = reason

        # Compact the report
        from .tools import _compact_report
        compact = _compact_report(report)

    except Exception as exc:
        compact = {
            "status": "error",
            "error": f"Failed to build report on force_stop: {exc}",
            "forced_stop": True,
            "forced_stop_reason": reason,
        }
    finally:
        # Always clean up the session
        _remove_session(session_id)
        try:
            ctx.orch.close()
        except Exception:
            pass

    return _json(compact)


# ──────────────────────────────────────────────────────────────
# Exports
# ──────────────────────────────────────────────────────────────

CONTROL_TOOLS = [
    adjust_loss_parameters,
    set_investigation_budget,
    force_stop,
]
