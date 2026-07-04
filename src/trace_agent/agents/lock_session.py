"""LOCKSession — LOCK 循环拍级执行器之间的共享状态容器。

将 DecisionOrchestrator 单体 __init__ / _bootstrap 中散落的四本账、预算、
轮次计数等状态提取到统一的 dataclass，供 L/Veto/O/C/K 五个拍级执行器
通过同一个 session 对象传递和修改状态。

本文件不修改任何现有模块，仅做聚合与快照。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# BudgetState 的本地镜像（避免从 orchestrator 循环导入）
# ──────────────────────────────────────────────────────────────
@dataclass
class BudgetState:
    """探查预算追踪（与 orchestrator.BudgetState 保持一致）。"""
    total_rounds: int = 50
    total_probes: int = 400
    rounds_used: int = 0
    probes_used: int = 0
    fanout_per_round: int = 8
    min_rounds_before_robust: int = 4
    min_rounds_after_root: int = 8

    def exhausted(self) -> bool:
        return self.rounds_used >= self.total_rounds or self.probes_used >= self.total_probes

    @property
    def remaining_probes(self) -> int:
        return max(0, self.total_probes - self.probes_used)

    def to_dict(self) -> dict:
        return {"remaining": self.remaining_probes, "total": self.total_probes}


# ──────────────────────────────────────────────────────────────
# LOCKSession
# ──────────────────────────────────────────────────────────────
@dataclass
class LOCKSession:
    """LOCK 循环的共享状态容器，在 5 个拍级执行器之间传递。"""

    # ── 四本账 ──
    graph: Any = None                              # SessionGraph
    beta: Any = None                               # BetaLedger
    obligations: Any = None                        # ObligationLedger
    ledger: Any = None                             # RuntimeDecisionLedger (第四本账)
    trust: Any = None                              # EvidenceTrustModel

    # ── 循环控制 ──
    round: int = 0                                 # 当前轮次
    prev_stats: dict = field(default_factory=dict) # 上一轮图统计
    last_llm_round: int = 0                        # 上次 LLM 闸门触发的轮次
    budget: Optional[BudgetState] = None           # 预算状态

    # ── 告警与种子 ──
    alert: Any = None                              # AlertEvent
    seed: Any = None                               # SeedPayload

    # ── 运行时配置 ──
    fanout_budget: int = 5                         # 每轮扇出槽数
    loss: Any = None                               # LossMatrix
    automation_policy: dict = field(default_factory=dict)
    mcp_runtime: Any = None

    # ── 编排器引用（供 C 拍等需要 executor 的拍使用）──
    executor: Any = None                           # SoarMcpProbeExecutor
    prior_manager: Any = None                      # PriorManager
    decision_calibrator: Any = None                # GenCalibration (VOI cost + record)
    artifact_calibrator: Any = None                 # ArtifactCalibrator (confidence calibrate)
    ingest: Any = None                             # IngestPipeline（如启用）
    ingest_factory: Any = None                     # ingest 工厂函数

    # ── 进度回调 ──
    progress_cb: Any = None                        # 进度回调函数

    # ── 内部辅助（_bootstrap 产出）──
    cascade: Any = None                            # RevisionCascade
    _exploration_debt: Any = None                  # ExplorationDebt
    _scenario_hosts: list = field(default_factory=list)

    # ── 拍间传递（执行器使用）──
    data: dict = field(default_factory=dict)       # 拍间暂存（pool/chosen/ingest_result）
    _last_pool_candidates: list = field(default_factory=list)  # O 拍写入供 K 拍停止判定
    _max_pool_voi: float = 0.0                     # 池内最高 VOI（K 拍修正用）
    _trust_revision_since: int = 0                 # 信任修订游标
    _host_last_probed: dict = field(default_factory=dict)      # 主机轮换状态
    _dead_pairs: set = field(default_factory=set)              # 无效(target,operator)对
    _planner_recent_query_keys: set = field(default_factory=set)  # 规划器去重键

    # ----------------------------------------------------------
    # 类方法：从告警 + 配置初始化
    # ----------------------------------------------------------
    @classmethod
    def from_seed(
        cls,
        alert: Any,                                # AlertEvent
        prior_manager: Any = None,                 # PriorManager
        budget: Optional[BudgetState] = None,
        executor: Any = None,
        config_dict: Optional[dict] = None,
    ) -> "LOCKSession":
        """从告警 + 配置初始化所有四本账。

        等价于 ``DecisionOrchestrator.__init__`` + ``_bootstrap()`` 的
        核心初始化路径，但不启动主循环。

        Args:
            alert: 触发告警 (AlertEvent)
            prior_manager: PriorManager 实例（可选；无则走 minimal seed）
            budget: 预算状态（可选；默认 50 rounds / 400 probes）
            executor: C 拍取证执行器
            config_dict: 额外配置，可含 loss / automation_policy /
                         data_dir / fanout_budget / ingest_factory /
                         decision_calibrator / progress_cb 等
        """
        from trace_agent.decision.runtime_ledger import RuntimeDecisionLedger
        from trace_agent.decision.runtime_types import LossMatrix
        from trace_agent.loop.session_graph import SessionGraph
        from trace_agent.loop.beta_ledger import BetaLedger
        from trace_agent.loop.gen_calibration import GenCalibration
        from trace_agent.loop.revision_cascade import RevisionCascade
        from trace_agent.loop.ingest import IngestPipeline
        from trace_agent.obligation_integration.obligation_ledger import ObligationLedger
        from trace_agent.loop.exploration_debt import (
            ExplorationDebt,
            ENTRY_TACTIC_REQUIRED_FAMILIES,
        )
        from trace_agent.loop.generators import normalize_tactic

        cfg = config_dict or {}
        session = cls()

        # ── alert / executor / prior_manager ──
        session.alert = alert
        session.executor = executor
        session.prior_manager = prior_manager

        # ── budget ──
        session.budget = budget or BudgetState()

        # ── loss matrix ──
        loss = cfg.get("loss")
        if loss is None:
            loss = LossMatrix()
        session.loss = loss

        # ── automation policy ──
        session.automation_policy = {
            "min_slice_support": 80,
            "min_precision": 0.90,
            "min_recall": 0.80,
            "contain_threshold": 0.70,
            "dismiss_threshold": 0.30,
            **(cfg.get("automation_policy") or {}),
        }

        # ── fanout ──
        session.fanout_budget = int(cfg.get("fanout_budget", 5))

        # ── optional refs ──
        session.artifact_calibrator = cfg.get("decision_calibrator")  # ArtifactCalibrator for confidence
        session.ingest_factory = cfg.get("ingest_factory")
        session.mcp_runtime = cfg.get("mcp_runtime")
        session.progress_cb = cfg.get("progress_cb")

        # ── data_dir ──
        data_dir = cfg.get("data_dir")

        # ============================================================
        # Seed
        # ============================================================
        seed = cfg.get("seed")
        if seed is None:
            if prior_manager is not None:
                from trace_agent.decision.belief import DecisionLedger
                dl = DecisionLedger(prior_manager)
                seed = dl.seed(alert)
            else:
                seed = _create_minimal_seed(alert)
        session.seed = seed

        # ============================================================
        # 四本账
        # ============================================================
        # 1) 图账本
        session.graph = SessionGraph()

        # 2) 决策账（第四本账）
        session.ledger = RuntimeDecisionLedger.from_seed(seed, loss)

        # 3) Beta 台账
        session.beta = BetaLedger()

        # 3b) 标定 — GenCalibration provides cost() + to_dict() for VOI
        gen_calib = GenCalibration()
        session.decision_calibrator = gen_calib

        # 4) 义务台账
        session.obligations = _create_obligation_ledger(data_dir, loss)

        # 5) 证据信任层
        session.trust = _create_trust_model(data_dir)

        # ============================================================
        # Supporting infrastructure
        # ============================================================
        session.cascade = RevisionCascade(
            session.graph, session.trust, session.obligations, session.ledger,
        )

        ingest_factory = session.ingest_factory
        if callable(ingest_factory):
            session.ingest = ingest_factory(session.trust, session.graph, session.ledger)
        else:
            session.ingest = IngestPipeline(session.trust, session.graph, session.ledger)

        # ============================================================
        # Bootstrap graph with alert event
        # ============================================================
        session.graph.add_events([{
            "technique": alert.technique_id,
            "tactic": alert.tactic or "unknown",
            "timestamp": float(alert.timestamp or 0),
            "source": alert.log_source or "alert",
            "trust_tier": "high",
            "explanation_ids": [e.id for e in seed.explanations],
            "_fact_confirmed": True,
            "_attribution_status": "CONTESTED",
            "malicious_status": "unknown",
            "attributes": {
                **(alert.attributes or {}),
                "asset_id": alert.asset_id or "",
                "target": alert.asset_id or "",
            },
        }])

        # Wazuh bootstrap attack chain (best-effort)
        try:
            from trace_engine.attack_chain_materializer import (
                materialize_attack_chain_from_executor,
            )
            if executor is not None:
                chain_events = materialize_attack_chain_from_executor(
                    executor,
                    explanation_ids=[e.id for e in seed.explanations],
                    alert_context={
                        "technique": alert.technique_id,
                        "asset": alert.asset_id,
                        "tactic": alert.tactic,
                        "timestamp": alert.timestamp,
                        "attributes": dict(alert.attributes or {}),
                    },
                )
                if chain_events:
                    session.graph.add_events(chain_events)
        except Exception:
            pass

        # ExplorationDebt
        entry_tactic = normalize_tactic(alert.tactic or "") or "execution"
        required = ENTRY_TACTIC_REQUIRED_FAMILIES.get(
            entry_tactic,
            ENTRY_TACTIC_REQUIRED_FAMILIES.get("_default", set()),
        )
        session._exploration_debt = ExplorationDebt(required_families=set(required))

        # Scenario known hosts
        session._scenario_hosts = []
        if executor is not None:
            known_hosts_fn = getattr(executor, "known_hosts", None)
            if callable(known_hosts_fn):
                try:
                    session._scenario_hosts = list(known_hosts_fn())
                except Exception:
                    pass

        # prev_stats 初始化
        session.prev_stats = session.graph.stats()

        return session

    # ----------------------------------------------------------
    # 快照 & 统计
    # ----------------------------------------------------------
    def to_snapshot(self) -> dict:
        """返回可 JSON 序列化的状态快照（供流事件使用）。

        容错设计：任何账本为 None 时返回空摘要。
        """
        # ── graph_stats ──
        try:
            gs = self.graph.stats() if self.graph else {}
        except Exception:
            gs = {}
        graph_stats = {
            "node_count": gs.get("node_count", 0),
            "edge_count": gs.get("edge_count", 0),
            "tactics": gs.get("tactics_seen", []),
        }

        # ── ledger_summary ──
        if self.ledger is not None:
            try:
                explanation_count = len(self.ledger.explanations)
                leading_id = self.ledger.leading()
                margin_val = self.ledger.margin()
                entropy_val = self.ledger.entropy()
            except Exception:
                explanation_count, leading_id, margin_val, entropy_val = 0, "", 0.0, 0.0
            ledger_summary = {
                "explanation_count": explanation_count,
                "leading": leading_id,
                "margin": round(margin_val, 4),
                "entropy": round(entropy_val, 4),
            }
        else:
            ledger_summary = {
                "explanation_count": 0,
                "leading": "",
                "margin": 0.0,
                "entropy": 0.0,
            }

        # ── obligation_summary ──
        if self.obligations is not None:
            try:
                all_obs = self.obligations.obligations
                open_obs = [o for o in all_obs if not o.discharged]
                overdue_count = sum(
                    1 for o in open_obs if o.is_overdue(self.round)
                )
                obligation_summary = {
                    "total": len(all_obs),
                    "open": len(open_obs),
                    "closed": len(all_obs) - len(open_obs),
                    "overdue": overdue_count,
                }
            except Exception:
                obligation_summary = {"total": 0, "open": 0, "closed": 0, "overdue": 0}
        else:
            obligation_summary = {"total": 0, "open": 0, "closed": 0, "overdue": 0}

        # ── beta_summary ──
        if self.beta is not None:
            try:
                keys = self.beta.all_keys()
                if keys:
                    top = sorted(
                        keys,
                        key=lambda k: self.beta.sensitivity(k),
                        reverse=True,
                    )[:5]
                    top_operators = [
                        {
                            "key": k,
                            "hit_rate": round(self.beta.sensitivity(k), 3),
                        }
                        for k in top
                    ]
                else:
                    top_operators = []
                beta_summary = {
                    "tracked_keys": len(keys),
                    "top_operators": top_operators,
                }
            except Exception:
                beta_summary = {"tracked_keys": 0, "top_operators": []}
        else:
            beta_summary = {"tracked_keys": 0, "top_operators": []}

        # ── budget_remaining ──
        if self.budget is not None:
            budget_remaining = {
                "rounds_remaining": max(
                    0, self.budget.total_rounds - self.budget.rounds_used
                ),
                "probes_remaining": self.budget.remaining_probes,
            }
        else:
            budget_remaining = {"rounds_remaining": 0, "probes_remaining": 0}

        return {
            "round": self.round,
            "graph_stats": graph_stats,
            "ledger_summary": ledger_summary,
            "obligation_summary": obligation_summary,
            "beta_summary": beta_summary,
            "budget_remaining": budget_remaining,
        }

    def stats(self) -> dict:
        """返回当前图统计信息（等价于 ``self.graph.stats()``）。"""
        if self.graph is not None:
            try:
                return self.graph.stats()
            except Exception:
                pass
        return {
            "node_count": 0,
            "edge_count": 0,
            "frontier_count": 0,
            "max_depth": 0,
            "tactics_seen": [],
            "techniques_seen": [],
        }


# ──────────────────────────────────────────────────────────────
# 模块级辅助函数（避免在 LOCKSession 方法中重复导入）
# ──────────────────────────────────────────────────────────────

def _create_obligation_ledger(data_dir: Any, loss: Any) -> Any:
    """加载 lifecycle 模板；失败时回退空模板。"""
    from trace_agent.obligation_integration.obligation_ledger import ObligationLedger

    candidates = []
    if data_dir:
        candidates.append(Path(data_dir) / "lifecycle_templates.json")
    pkg = Path(__file__).resolve().parents[1] / "data" / "lifecycle_templates.json"
    candidates.append(pkg)
    for path in candidates:
        if path.is_file():
            try:
                return ObligationLedger.from_json(path, loss=loss)
            except Exception:
                pass
    return ObligationLedger(loss=loss)


def _create_trust_model(data_dir: Any = None) -> Any:
    """创建或回退信任模型。"""
    try:
        from trace_agent import create_evidence_trust_model
        return create_evidence_trust_model(data_dir=data_dir)
    except Exception:
        pass
    try:
        from trace_agent import create_evidence_trust_model
        return create_evidence_trust_model()
    except Exception:
        pass

    # Minimal duck-typed fallback
    return _MinimalTrust()


def _create_minimal_seed(alert: Any) -> Any:
    """无 PriorManager 时创建最小 SeedPayload。"""
    from trace_agent.decision.types import (
        Explanation,
        NullAnchor,
        SeedPayload,
    )

    tid = alert.technique_id
    tactic = alert.tactic or "execution"

    explanations = [
        Explanation(
            id="H1",
            title=f"{tid} attack-fit explanation",
            current_technique=tid,
            stage=tactic,
            lifecycle_template=None,
            predecessor_tactics=[],
            technique_context=[],
            raw_score=0.5,
            prior_probability=0.5,
            features={},
            support={"type": "fallback"},
            recommended_log_sources=[],
            caveats=["no prior manager — minimal seed"],
        ),
    ]
    null_anchor = NullAnchor(benign=0.25, oos=0.15, reasons=["minimal seed"])

    return SeedPayload(
        alert=alert,
        explanations=explanations,
        branch_null_anchor=null_anchor,
        contested_edges=[],
        lifecycle_template_candidates=[],
        score_v3_initial_scores={e.id: e.prior_probability for e in explanations},
        loss_baseline={"lambda_miss": 10.0, "lambda_over": 2.0, "lambda_oos": 4.0},
        evidence_trust_defaults={},
        prior_manifest=None,
    )


class _MinimalTrust:
    """Minimal duck-typed trust model fallback."""

    def __init__(self) -> None:
        self.evidence_trust_map: dict = {}
        self.revisions: list = []

    def weight_likelihood(self, base: float, evidence_id: str) -> float:
        return base * 0.5

    def get_trust(self, evidence_id: str) -> None:
        return None

    def assess(self, event: Any) -> None:
        return None

    def set_context(self, ctx: Any) -> None:
        pass

    def ingest(self, events: list) -> tuple:
        return [], []

    def get_summary(self) -> dict:
        return {"total_evidence": 0, "forge_resistant_count": 0}

    def get_revisions(self) -> list:
        return []

    def get_pending_revisions(self, since_round: int) -> list:
        return []
