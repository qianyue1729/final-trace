"""LOCK 拍级进度事件协议。

为 deep-agent 前端提供细粒度的 LOCK 循环可视化数据。
每个拍开始和结束时各发送一个事件。
"""
from __future__ import annotations

import logging
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# 枚举
# ──────────────────────────────────────────────────────────────

class Phase(str, Enum):
    L = "L"
    VETO = "Veto"
    O = "O"
    C = "C"
    K = "K"


class EventKind(str, Enum):
    PHASE_START = "phase_start"
    PHASE_END = "phase_end"
    STOP_DECISION = "stop_decision"
    ROUND_SUMMARY = "round_summary"


# ──────────────────────────────────────────────────────────────
# 辅助
# ──────────────────────────────────────────────────────────────

def _r4(v: Any) -> float:
    """Round float to 4 decimal places; pass through non-floats."""
    if isinstance(v, float):
        return round(v, 4)
    return v


def _r4_list(lst: list[dict]) -> list[dict]:
    """Round all float values inside a list of dicts to 4 decimals."""
    out = []
    for d in lst:
        out.append({k: _r4(v) for k, v in d.items()})
    return out


# ──────────────────────────────────────────────────────────────
# 基类
# ──────────────────────────────────────────────────────────────

@dataclass
class PhaseProgressEvent:
    """所有进度事件的基类。"""
    kind: str           # EventKind value
    phase: str          # Phase value
    round: int = 0
    tool_name: str = ""      # "run_trace_scenario" / "run_production_trace" / phase tool name
    tool_call_id: str = ""
    timestamp: float = 0.0   # time.time()
    event_kind: str = ""     # EventKind value for frontend discrimination

    def to_stream_dict(self) -> dict:
        """转为 stream_writer 可发送的 dict。"""
        d = asdict(self)
        d["kind"] = "lock_phase"  # 前端识别键
        return d


# ──────────────────────────────────────────────────────────────
# 各拍事件
# ──────────────────────────────────────────────────────────────

@dataclass
class LPhaseEvent(PhaseProgressEvent):
    """L 拍事件：候选生成。"""
    phase: str = "L"
    candidates_count: int = 0
    pool_summary: dict = field(default_factory=dict)  # {generator_type: count}
    prior_sources: list[str] = field(default_factory=list)


@dataclass
class VetoEvent(PhaseProgressEvent):
    """② 检验拍事件。"""
    phase: str = "Veto"
    vetoed_count: int = 0
    veto_reasons: dict = field(default_factory=dict)  # {reason: count}
    mandated_count: int = 0
    obligation_types: dict = field(default_factory=dict)  # {type: count}
    surviving_count: int = 0
    trust_revisions: int = 0


@dataclass
class OPhaseEvent(PhaseProgressEvent):
    """O 拍事件：VOI 排序（模型选择 Wazuh 操作符）。"""
    phase: str = "O"
    voi_ranking: list[dict] = field(default_factory=list)  # [{probe, operator, target, voi_score, risk_reduction, cost, source}]
    slots_total: int = 0
    slots_filled: int = 0
    obligation_slots: int = 0
    llm_gate_triggered: bool = False
    max_voi: float = 0.0

    def to_stream_dict(self) -> dict:
        d = super().to_stream_dict()
        d["voi_ranking"] = _r4_list(d.get("voi_ranking", []))
        d["max_voi"] = _r4(d.get("max_voi", 0.0))
        return d


@dataclass
class CPhaseEvent(PhaseProgressEvent):
    """C 拍事件：扇出取证（包含 Wazuh 查询和 LLM 研判结果）。"""
    phase: str = "C"
    events_fetched: int = 0
    attached: int = 0
    parked: int = 0
    discarded: int = 0
    spawned: int = 0
    weak_attached: int = 0
    trust_scores: dict = field(default_factory=dict)  # {source: avg_integrity}
    delta_p_atk: Optional[float] = None  # P(attack) 变化
    # 模型推理可见性字段
    wazuh_queries: list[dict] = field(default_factory=list)  # [{operator, target, events_returned, elapsed_ms}]
    llm_judgements: list[dict] = field(default_factory=list)  # [{event_ref, verdict, confidence, reasoning}]
    mcp_compiler_audit: Optional[dict] = None

    def to_stream_dict(self) -> dict:
        d = super().to_stream_dict()
        if d.get("delta_p_atk") is not None:
            d["delta_p_atk"] = _r4(d["delta_p_atk"])
        ts = d.get("trust_scores", {})
        d["trust_scores"] = {k: _r4(v) for k, v in ts.items()}
        d["wazuh_queries"] = d.get("wazuh_queries", [])
        d["llm_judgements"] = _r4_list(d.get("llm_judgements", []))
        d["mcp_compiler_audit"] = d.get("mcp_compiler_audit")
        return d


@dataclass
class KPhaseEvent(PhaseProgressEvent):
    """K 拍事件：学习 + 决策账更新。"""
    phase: str = "K"
    # 决策账快照
    explanations: list[dict] = field(default_factory=list)  # [{eid, label, posterior, is_null, null_kind}]
    contested_edges: list[dict] = field(default_factory=list)  # [{edge_id, p_in, p_benign, p_oos}]
    leading_explanation: str = ""
    margin: float = 0.0
    entropy: float = 0.0
    # Beta 更新
    beta_updates: list[dict] = field(default_factory=list)  # [{probe_key, hit, new_alpha, new_beta}]
    # 义务
    obligations_open: int = 0
    obligations_discharged: int = 0
    obligations_overdue: int = 0
    # 图增量
    new_nodes: int = 0
    new_edges: int = 0
    graph_node_count: int = 0
    graph_edge_count: int = 0
    # 图快照（bounded snapshot，每轮 K phase_end 下发）
    graph_nodes: list[dict] = field(default_factory=list)   # [{id, technique, tactic, host, timestamp, attributed}]
    graph_edges: list[dict] = field(default_factory=list)   # [{source, target, relation}]
    graph_truncated: bool = False

    def to_stream_dict(self) -> dict:
        d = super().to_stream_dict()
        d["explanations"] = _r4_list(d.get("explanations", []))
        d["contested_edges"] = _r4_list(d.get("contested_edges", []))
        d["beta_updates"] = _r4_list(d.get("beta_updates", []))
        d["margin"] = _r4(d.get("margin", 0.0))
        d["entropy"] = _r4(d.get("entropy", 0.0))
        return d


@dataclass
class StopDecisionEvent(PhaseProgressEvent):
    """停止决策事件。"""
    kind: str = "phase_end"
    event_kind: str = "stop_decision"
    phase: str = "K"
    decision: str = ""          # "continue" / "stop"
    stop_reason: str = ""       # "budget" / "voi_floor" / "robust" / "obligations_clear"
    max_voi: float = 0.0
    eps_voi: float = 0.0
    decision_robust: bool = False
    hard_obligations_open: int = 0
    budget_remaining: dict = field(default_factory=dict)  # {rounds, probes}
    reasoning: str = ""         # 人类可读的停止/继续推理

    def to_stream_dict(self) -> dict:
        d = super().to_stream_dict()
        d["max_voi"] = _r4(d.get("max_voi", 0.0))
        d["eps_voi"] = _r4(d.get("eps_voi", 0.0))
        return d


@dataclass
class RoundSummaryEvent(PhaseProgressEvent):
    """每轮结束时的汇总事件。"""
    kind: str = "phase_end"
    event_kind: str = "round_summary"
    phase: str = "K"
    round_elapsed_seconds: float = 0.0
    total_rounds: int = 0
    graph_snapshot: dict = field(default_factory=dict)  # session.to_snapshot() 的精简版
    ledger_snapshot: dict = field(default_factory=dict)
    budget_snapshot: dict = field(default_factory=dict)

    def to_stream_dict(self) -> dict:
        d = super().to_stream_dict()
        d["round_elapsed_seconds"] = _r4(d.get("round_elapsed_seconds", 0.0))
        return d


# ──────────────────────────────────────────────────────────────
# 构建函数
# ──────────────────────────────────────────────────────────────

def build_phase_event(
    phase: Phase,
    event_kind: EventKind,
    result: Any,          # PhaseResult
    session: Any,         # LOCKSession
    **extra: Any,
) -> PhaseProgressEvent:
    """从 PhaseResult + LOCKSession 构建对应的 PhaseProgressEvent。

    phase_start 事件: 主要包含当前 session 快照
    phase_end 事件: 包含 PhaseResult.data 中的拍级详情

    Args:
        phase: 当前拍 (L / Veto / O / C / K)
        event_kind: phase_start 或 phase_end
        result: PhaseResult（phase_start 时可为 None）
        session: LOCKSession
        **extra: 额外字段覆盖（如 tool_name, tool_call_id）
    """
    rnd = session.round if session else 0
    data = result.data if result and hasattr(result, "data") else {}
    ts = time.time()

    tool_name = extra.get("tool_name", "")
    tool_call_id = extra.get("tool_call_id", "")

    if phase == Phase.L:
        evt = LPhaseEvent(
            kind=event_kind.value,
            event_kind=event_kind.value,
            phase=phase.value,
            round=rnd,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            timestamp=ts,
        )
        if event_kind == EventKind.PHASE_END:
            pool = data.get("pool", [])
            pool_summary: dict[str, int] = {}
            for c in pool:
                gen = getattr(c, "generator", None) or (c.get("generator", "?") if isinstance(c, dict) else "?")
                pool_summary[gen] = pool_summary.get(gen, 0) + 1
            evt.candidates_count = len(pool)
            evt.pool_summary = pool_summary
            evt.prior_sources = list(data.get("prior_sources", []))

    elif phase == Phase.VETO:
        evt = VetoEvent(
            kind=event_kind.value,
            event_kind=event_kind.value,
            phase=phase.value,
            round=rnd,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            timestamp=ts,
        )
        if event_kind == EventKind.PHASE_END:
            evt.vetoed_count = data.get("vetoed_count", 0)
            evt.veto_reasons = dict(data.get("veto_reasons", {}))
            evt.mandated_count = data.get("mandated_count", 0)
            evt.obligation_types = dict(data.get("obligation_types", {}))
            evt.surviving_count = data.get("surviving_count", 0)
            evt.trust_revisions = data.get("trust_revisions", 0)

    elif phase == Phase.O:
        evt = OPhaseEvent(
            kind=event_kind.value,
            event_kind=event_kind.value,
            phase=phase.value,
            round=rnd,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            timestamp=ts,
        )
        if event_kind == EventKind.PHASE_END:
            ranking = list(data.get("voi_ranking", []))
            # Ensure each entry has operator and target fields
            enriched_ranking = []
            for r in ranking[:5]:
                entry = dict(r)
                if "operator" not in entry:
                    entry["operator"] = entry.get("source", "")
                if "target" not in entry:
                    entry["target"] = entry.get("target", "")
                enriched_ranking.append(entry)
            evt.voi_ranking = enriched_ranking
            evt.slots_total = data.get("slots_total", 0)
            evt.slots_filled = data.get("slots_filled", 0)
            evt.obligation_slots = data.get("obligation_slots", 0)
            evt.llm_gate_triggered = data.get("llm_gate_triggered", False)
            evt.max_voi = _r4(data.get("max_voi", 0.0))

    elif phase == Phase.C:
        evt = CPhaseEvent(
            kind=event_kind.value,
            event_kind=event_kind.value,
            phase=phase.value,
            round=rnd,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            timestamp=ts,
        )
        if event_kind == EventKind.PHASE_END:
            evt.events_fetched = data.get("events_fetched", 0)
            evt.attached = data.get("attached", 0)
            evt.parked = data.get("parked", 0)
            evt.discarded = data.get("discarded", 0)
            evt.spawned = data.get("spawned", 0)
            evt.weak_attached = data.get("weak_attached", 0)
            evt.trust_scores = dict(data.get("trust_scores", {}))
            raw_delta = data.get("delta_p_atk")
            evt.delta_p_atk = _r4(raw_delta) if raw_delta is not None else None
            # Wazuh 查询结果和 LLM 研判（模型推理可见性）
            evt.wazuh_queries = list(data.get("wazuh_queries", []))[:10]
            evt.llm_judgements = list(data.get("llm_judgements", []))[:10]
            evt.mcp_compiler_audit = data.get("mcp_compiler_audit")

    elif phase == Phase.K:
        evt = KPhaseEvent(
            kind=event_kind.value,
            event_kind=event_kind.value,
            phase=phase.value,
            round=rnd,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            timestamp=ts,
        )
        if event_kind == EventKind.PHASE_END:
            # explanations: 非 null 解释 + 一个 null 锚
            raw_expls = list(data.get("explanations", []))
            non_null = [e for e in raw_expls if not e.get("is_null", False)]
            null_anchors = [e for e in raw_expls if e.get("is_null", False)]
            expl_list = non_null + null_anchors[:1]
            evt.explanations = _r4_list(expl_list)

            # contested_edges
            raw_edges = list(data.get("contested_edges", []))
            evt.contested_edges = _r4_list(raw_edges)

            evt.leading_explanation = data.get("leading_explanation", "")
            evt.margin = _r4(data.get("margin", 0.0))
            evt.entropy = _r4(data.get("entropy", 0.0))
            evt.beta_updates = _r4_list(list(data.get("beta_updates", [])))
            evt.obligations_open = data.get("obligations_open", 0)
            evt.obligations_discharged = data.get("obligations_discharged", 0)
            evt.obligations_overdue = data.get("obligations_overdue", 0)
            evt.new_nodes = data.get("new_nodes", 0)
            evt.new_edges = data.get("new_edges", 0)
            evt.graph_node_count = data.get("graph_node_count", 0)
            evt.graph_edge_count = data.get("graph_edge_count", 0)
            evt.graph_nodes = list(data.get("graph_nodes", []))
            evt.graph_edges = list(data.get("graph_edges", []))
            evt.graph_truncated = bool(data.get("graph_truncated", False))
    else:
        # Fallback — should not happen
        evt = PhaseProgressEvent(
            kind=event_kind.value,
            event_kind=event_kind.value,
            phase=phase.value,
            round=rnd,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            timestamp=ts,
        )

    return evt


def build_stop_event(k_result: Any, session: Any) -> StopDecisionEvent:
    """从 K 拍结果构建停止决策事件。

    Args:
        k_result: K 拍的 PhaseResult
        session: LOCKSession
    """
    data = k_result.data if k_result and hasattr(k_result, "data") else {}
    rnd = session.round if session else 0
    budget = session.budget if session else None

    budget_remaining: dict[str, int] = {}
    if budget is not None:
        budget_remaining = {
            "rounds": max(0, budget.total_rounds - budget.rounds_used),
            "probes": budget.remaining_probes,
        }

    return StopDecisionEvent(
        kind=EventKind.STOP_DECISION.value,
        phase=Phase.K.value,
        round=rnd,
        timestamp=time.time(),
        decision=data.get("decision", "continue"),
        stop_reason=data.get("stop_reason", ""),
        max_voi=_r4(data.get("max_voi", 0.0)),
        eps_voi=_r4(data.get("eps_voi", 0.0)),
        decision_robust=data.get("decision_robust", False),
        hard_obligations_open=data.get("hard_obligations_open", 0),
        budget_remaining=budget_remaining,
        reasoning=data.get("reasoning", ""),
    )


def build_round_summary(session: Any, round_elapsed: float) -> RoundSummaryEvent:
    """构建轮次汇总事件。

    Args:
        session: LOCKSession
        round_elapsed: 本轮耗时（秒）
    """
    rnd = session.round if session else 0
    snapshot = session.to_snapshot() if session and hasattr(session, "to_snapshot") else {}

    graph_snapshot = {
        "node_count": snapshot.get("graph_stats", {}).get("node_count", 0),
        "edge_count": snapshot.get("graph_stats", {}).get("edge_count", 0),
        "tactics": snapshot.get("graph_stats", {}).get("tactics", []),
    }

    ledger_snapshot = snapshot.get("ledger_summary", {})
    budget_snapshot = snapshot.get("budget_remaining", {})

    budget = session.budget if session else None
    total_rounds = budget.total_rounds if budget else 0

    return RoundSummaryEvent(
        kind=EventKind.ROUND_SUMMARY.value,
        phase=Phase.K.value,
        round=rnd,
        timestamp=time.time(),
        round_elapsed_seconds=_r4(round_elapsed),
        total_rounds=total_rounds,
        graph_snapshot=graph_snapshot,
        ledger_snapshot=ledger_snapshot,
        budget_snapshot=budget_snapshot,
    )


# ──────────────────────────────────────────────────────────────
# 导出
# ──────────────────────────────────────────────────────────────

__all__ = [
    "Phase",
    "EventKind",
    "PhaseProgressEvent",
    "LPhaseEvent",
    "VetoEvent",
    "OPhaseEvent",
    "CPhaseEvent",
    "KPhaseEvent",
    "StopDecisionEvent",
    "RoundSummaryEvent",
    "build_phase_event",
    "build_stop_event",
    "build_round_summary",
]
