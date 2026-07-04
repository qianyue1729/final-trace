"""trace_agent 全模块消融实验框架

在 soar_mcp_env 的 3 个攻击场景上，对 trace_agent 溯源系统做 13 个变体（含 full 基线）的消融实验，
量化每个模块（含 LLM）对溯源性能的边际贡献。

Usage:
    from trace_agent.eval.ablation_experiment import (
        AblationConfig, AblationResult, AblationOrchestrator,
        FULL_VARIANTS, generate_ablation_report,
    )
"""
from __future__ import annotations

import json
import logging
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

from trace_agent.agents.orchestrator import (
    DecisionOrchestrator,
    InvestigationResult,
    BudgetState,
    _MinimalTrust,
)
from trace_agent.decision.types import AlertEvent
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.loop.exploration_debt import (
    ExplorationDebt,
    ENTRY_TACTIC_REQUIRED_FAMILIES,
)
from trace_agent.loop.generators import normalize_tactic
from trace_agent.loop.probe import Probe

logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════
# 常量
# ═══════════════════════════════════════════════════════════════════

SOAR_ENV_DIR = Path(__file__).resolve().parent.parent.parent.parent / "soar_mcp_env"
SCENARIOS_DIR = SOAR_ENV_DIR / "scenarios"
RESULTS_DIR = SOAR_ENV_DIR / "results"
REPORTS_DIR = Path(__file__).resolve().parent.parent.parent.parent / "reports"

SCENARIO_IDS = ["pipeline_18", "apt_5host", "multipath_12host"]


# ═══════════════════════════════════════════════════════════════════
# 数据类
# ═══════════════════════════════════════════════════════════════════


@dataclass
class AblationConfig:
    """消融实验配置 — 每个 flag 代表一个可关闭的模块维度。"""

    name: str
    description: str

    # Layer 1: AI 组件
    no_llm_triage: bool = False          # 关闭 C 拍 LLM triage
    no_model_planner: bool = False       # 关闭 L 拍模型探针规划
    no_prior: bool = False               # 关闭先验知识系统

    # Layer 2: 核心算法
    no_evidence_trust: bool = False      # 降级为 _MinimalTrust
    no_obligations: bool = False         # 跳过义务账本
    no_voi: bool = False                 # VOI 替换为 priority_hint
    no_exploration_debt: bool = False    # 探索债务恒清零

    # Layer 3: 生成器
    prior_generator_only: bool = False   # 仅保留 prior_generator

    # Layer 4: 级联机制
    no_revision_cascade: bool = False    # 跳过证据修订级联
    no_adaptive_strategy: bool = False   # 禁用自适应策略

    def active_flags(self) -> list[str]:
        """返回所有已激活的消融 flag 名称。"""
        flags = []
        for f in (
            "no_llm_triage", "no_model_planner", "no_prior",
            "no_evidence_trust", "no_obligations", "no_voi",
            "no_exploration_debt", "prior_generator_only",
            "no_revision_cascade", "no_adaptive_strategy",
        ):
            if getattr(self, f):
                flags.append(f)
        return flags


@dataclass
class AblationResult:
    """消融实验结果指标。"""

    # 核心性能指标
    recall: float = 0.0
    precision: float = 0.0
    f1: float = 0.0
    gt_coverage_pct: float = 0.0
    decision_correct: bool = False

    # 资源消耗
    rounds_used: int = 0
    probes_used: int = 0
    llm_calls: int = 0
    llm_tokens: int = 0
    elapsed_seconds: float = 0.0

    # 图拓扑
    graph_nodes: int = 0
    graph_edges: int = 0
    hosts_covered: int = 0
    tactics_covered: int = 0

    # 元数据
    scenario_id: str = ""
    variant_name: str = ""
    timestamp: str = ""

    # 错误信息
    error: str = ""
    decision: str = ""
    stop_reason: str = ""


# ═══════════════════════════════════════════════════════════════════
# 探索债务覆盖 — 恒清零变体
# ═══════════════════════════════════════════════════════════════════


class _AlwaysClearedDebt(ExplorationDebt):
    """探索债务恒清零 — is_cleared() 恒返回 True。"""

    def is_cleared(self, rounds_used: int) -> bool:
        return True

    def uncovered_families(self) -> set[str]:
        return set()


# ═══════════════════════════════════════════════════════════════════
# AblationOrchestrator — 通过方法覆写实现消融控制
# ═══════════════════════════════════════════════════════════════════


class AblationOrchestrator(DecisionOrchestrator):
    """消融实验专用编排器。

    通过覆写 DecisionOrchestrator 的关键方法实现各维度的消融控制。
    每个消融 flag 对应一个具体的行为变更。
    """

    def __init__(
        self,
        ablation_config: AblationConfig,
        alert: AlertEvent,
        executor: Any,
        prior_manager: Any = None,
        budget: Optional[BudgetState] = None,
        ingest_factory: Any = None,
        **kwargs: Any,
    ) -> None:
        self._ablation = ablation_config
        self._ablation_logs: list[str] = []

        # ── Layer 1: AI 组件消融 ──

        # no_llm_triage: 不使用 ingest_factory，C 拍回退到纯规则 IngestPipeline
        if ablation_config.no_llm_triage:
            ingest_factory = None
            self._log_ablation("no_llm_triage",
                               "LLM triage disabled, using rule-based IngestPipeline")

        # no_model_planner: 关闭模型探针规划
        if ablation_config.no_model_planner:
            kwargs["planner_mode"] = "off"
            from trace_agent.loop.model_probe_planner import NullProbePlanner
            kwargs["probe_planner"] = NullProbePlanner()
            self._log_ablation("no_model_planner",
                               "Model probe planner disabled, planner_mode=off")

        # no_prior: 关闭先验知识系统
        if ablation_config.no_prior:
            prior_manager = None
            self._log_ablation("no_prior",
                               "Prior knowledge system disabled, using _create_minimal_seed()")

        super().__init__(
            alert=alert,
            executor=executor,
            prior_manager=prior_manager,
            budget=budget,
            ingest_factory=ingest_factory,
            **kwargs,
        )

    def _log_ablation(self, flag: str, message: str) -> None:
        """记录消融日志。"""
        entry = f"[ABLATION:{flag}] {message}"
        self._ablation_logs.append(entry)
        logger.info(entry)
        print(f"  {entry}")

    # ── Bootstrap 覆写 ──

    def _bootstrap(self) -> None:
        """Phase 0 覆写：注入消融控制的组件。"""
        super()._bootstrap()

        # no_evidence_trust: 注入 _MinimalTrust
        if self._ablation.no_evidence_trust:
            self.trust = _MinimalTrust()
            # 重建 cascade 和 ingest 以使用新的 trust
            from trace_agent.loop.revision_cascade import RevisionCascade
            self.cascade = RevisionCascade(
                self.graph, self.trust, self.obligations, self.ledger,
            )
            if callable(self._ingest_factory):
                self.ingest = self._ingest_factory(
                    self.trust, self.graph, self.ledger,
                )
            else:
                from trace_agent.loop.ingest import IngestPipeline
                self.ingest = IngestPipeline(self.trust, self.graph, self.ledger)
            self._log_ablation("no_evidence_trust",
                               "Evidence trust degraded to _MinimalTrust")

        # no_exploration_debt: 替换为恒清零实现
        if self._ablation.no_exploration_debt:
            entry_tactic = normalize_tactic(self.alert.tactic or "") or "execution"
            required = ENTRY_TACTIC_REQUIRED_FAMILIES.get(
                entry_tactic,
                ENTRY_TACTIC_REQUIRED_FAMILIES["_default"],
            )
            self._exploration_debt = _AlwaysClearedDebt(
                required_families=set(required),
            )
            self._log_ablation("no_exploration_debt",
                               "Exploration debt set to always-cleared")

    # ── Veto 覆写：级联 + 义务 ──

    def _veto_phase(self, pool: CandidatePool) -> CandidatePool:
        """② 检验拍覆写：可选跳过级联和义务。"""
        graph_dict = self._graph_to_dict()

        # 0. 证据修订级联
        if not self._ablation.no_revision_cascade:
            if self.trust and hasattr(self.trust, "get_pending_revisions"):
                try:
                    revisions = self.trust.get_pending_revisions(
                        self._trust_revision_since,
                    )
                    if revisions and self.cascade:
                        self.cascade.apply(revisions)
                    if self.obligations and hasattr(
                        self.obligations, "cascade_on_revision",
                    ):
                        self.obligations.cascade_on_revision(revisions)
                    if revisions:
                        self._trust_revision_since = max(
                            getattr(r, "round", self.budget.rounds_used)
                            for r in revisions
                        ) + 1
                except Exception:
                    pass
        # else: skip cascade entirely

        # 1. Obligation scanning
        if not self._ablation.no_obligations:
            try:
                self.obligations.scan(
                    graph_dict,
                    self.ledger,
                    self.trust,
                    self.graph.stats(),
                    current_round=self.budget.rounds_used,
                )
            except (TypeError, AttributeError):
                pass

            # 2. Discharge met obligations
            try:
                self.obligations.discharge(graph_dict, self.ledger)
            except (TypeError, AttributeError):
                pass

        # 3. Beta sensitivity VETO
        veto_ids: list[str] = []
        for probe in pool.peek():
            key = probe.learning_key()
            if (
                self.beta.total_observations(key) >= 2
                and self.beta.sensitivity(key) < 0.2
            ):
                veto_ids.append(probe.id)

        # 4. Non-host filter
        if self._known_hosts_lower:
            for probe in pool.peek():
                target_lower = (getattr(probe, "target", "") or "").lower().strip()
                if target_lower and target_lower not in self._known_hosts_lower:
                    veto_ids.append(probe.id)

        if veto_ids:
            pool.remove(veto_ids)

        return pool

    # ── O 拍覆写：VOI / 义务 ──

    def _o_phase(self, pool: CandidatePool) -> list[Probe]:
        """O 拍覆写：可选替换 VOI 为 priority_hint、跳过义务物化。"""
        slots = self.budget.fanout_per_round

        # 义务物化 → 并入统一池
        graph_dict = self._graph_to_dict()
        mandated_probes: list[Probe] = []
        if not self._ablation.no_obligations:
            try:
                mandated_raw = self.obligations.materialize_open(
                    graph_dict,
                    current_round=self.budget.rounds_used,
                ) or []
                mandated_probes = [
                    p
                    for p in self._obligation_dicts_to_probes(mandated_raw)
                    if self._probe_is_executable(p)
                ]
            except Exception:
                pass

        candidates = mandated_probes + pool.drain()

        # 去重
        deduped: dict[str, Probe] = {}
        for probe in candidates:
            key = probe.dedup_key()
            existing = deduped.get(key)
            if existing is None or (
                probe.source == "obligation"
                or probe.priority_hint > existing.priority_hint
            ):
                deduped[key] = probe
        candidates = list(deduped.values())

        self._last_pool_candidates = list(candidates)
        if not candidates:
            self._max_pool_voi = 0.0
            return []

        # VOI 排序 vs priority_hint 排序
        scored: list[tuple[float, Probe]] = []
        if self._ablation.no_voi:
            # 直接用 priority_hint 排序，跳过 VOI 计算
            scored = [(probe.priority_hint, probe) for probe in candidates]
            self._max_pool_voi = max(
                (s for s, _ in scored), default=0.0,
            )
        else:
            graph_stats = self._compute_graph_stats()
            beta_dict = self._beta_to_dict()
            calib_dict = self._calib_to_dict()

            for probe in candidates:
                try:
                    probe_dict = self._probe_to_dict(probe)
                    from trace_agent.probe.voi_engine import voi

                    voi_result = voi(
                        probe_dict, self.ledger, beta_dict, calib_dict,
                        self.loss, self.trust, graph_stats=graph_stats,
                    )
                    base = voi_result.voi_score
                    self._voi_audit.append({
                        "probe_id": probe.id,
                        "operator": probe.operator,
                        "target": probe.target,
                        "voi": voi_result.voi_score,
                        "risk_now": voi_result.risk_now,
                        "expected_risk_after": voi_result.expected_risk_after,
                        "risk_reduction": (
                            voi_result.risk_now - voi_result.expected_risk_after
                        ),
                        "cost": voi_result.cost,
                        **voi_result.audit,
                    })
                    if probe.source == "obligation" and probe.metadata.get("hard"):
                        base += 0.08 * self.loss.lambda_miss
                    elif probe.source == "obligation":
                        base += 0.03 * self.loss.lambda_over
                    scored.append((base, probe))
                except Exception:
                    scored.append((probe.priority_hint, probe))

            self._max_pool_voi = max((s for s, _ in scored), default=0.0)

        selected: list[Probe] = []
        remaining = list(scored)

        while remaining and len(selected) < slots:
            best_idx = 0
            best_adj = -float("inf")
            for i, (base_voi, probe) in enumerate(remaining):
                adj = self._adjusted_voi(probe, base_voi, selected)
                if adj > best_adj:
                    best_adj = adj
                    best_idx = i
            _, chosen_probe = remaining.pop(best_idx)
            selected.append(chosen_probe)

        return selected

    # ── L 拍覆写：生成器消融 ──

    def _l_phase(self, prev_stats: dict) -> CandidatePool:
        """L 拍覆写：prior_generator_only 时仅调用 prior_generator。"""
        if self._ablation.prior_generator_only:
            pool = CandidatePool()
            try:
                from trace_agent.loop.generators import prior_generator

                prior_probes = prior_generator(
                    self.graph, self.ledger, self.prior_manager,
                )
                pool.add(prior_probes)
            except Exception:
                pass
            # 仍然走 model planner（如果未关闭）
            for probe in self._model_planner_phase(pool):
                pool.add([probe])
            return pool

        # 默认：走完整 L 拍
        return super()._l_phase(prev_stats)

    # ── K 拍中的自适应策略覆写 ──

    def _adaptive_strategy(self, prev_node_count: int) -> None:
        """自适应策略覆写：no_adaptive_strategy 时变为 no-op。"""
        if self._ablation.no_adaptive_strategy:
            return
        super()._adaptive_strategy(prev_node_count)


# ═══════════════════════════════════════════════════════════════════
# 预定义 13 组实验配置
# ═══════════════════════════════════════════════════════════════════

FULL_VARIANTS: list[AblationConfig] = [
    # ── 基线：完整系统 ──
    AblationConfig(
        name="full",
        description="完整系统（所有模块启用）— 基线对照",
    ),
    # ── Layer 1: AI 组件 ──
    AblationConfig(
        name="no_llm_triage",
        description="关闭 C 拍 LLM triage，回退到纯规则 IngestPipeline",
        no_llm_triage=True,
    ),
    AblationConfig(
        name="no_model_planner",
        description="关闭 L 拍模型探针规划，仅使用规则生成器",
        no_model_planner=True,
    ),
    AblationConfig(
        name="no_prior",
        description="关闭先验知识系统，使用 minimal seed",
        no_prior=True,
    ),
    # ── Layer 2: 核心算法 ──
    AblationConfig(
        name="no_evidence_trust",
        description="证据信任降级为 _MinimalTrust",
        no_evidence_trust=True,
    ),
    AblationConfig(
        name="no_obligations",
        description="跳过义务账本（扫描 + 物化 + discharge）",
        no_obligations=True,
    ),
    AblationConfig(
        name="no_voi",
        description="VOI 排序替换为 priority_hint 排序",
        no_voi=True,
    ),
    AblationConfig(
        name="no_exploration_debt",
        description="探索债务恒清零，不影响停止判定",
        no_exploration_debt=True,
    ),
    # ── Layer 3: 生成器 ──
    AblationConfig(
        name="prior_generator_only",
        description="L 拍仅保留 prior_generator，禁用其余 5 类生成器",
        prior_generator_only=True,
    ),
    # ── Layer 4: 级联机制 ──
    AblationConfig(
        name="no_revision_cascade",
        description="跳过证据修订级联（VETO 拍中的 cascade.apply）",
        no_revision_cascade=True,
    ),
    AblationConfig(
        name="no_adaptive_strategy",
        description="禁用自适应策略（停滞检测 + fanout 扩展 + 探索权重）",
        no_adaptive_strategy=True,
    ),
    # ── 组合消融 ──
    AblationConfig(
        name="no_all_ai",
        description="关闭所有 AI 组件（LLM + planner + prior）",
        no_llm_triage=True,
        no_model_planner=True,
        no_prior=True,
    ),
    AblationConfig(
        name="no_all_algorithm",
        description="关闭所有核心算法（trust + obligations + VOI + debt）",
        no_evidence_trust=True,
        no_obligations=True,
        no_voi=True,
        no_exploration_debt=True,
    ),
]


# ═══════════════════════════════════════════════════════════════════
# 实验运行器
# ═══════════════════════════════════════════════════════════════════


def run_ablation_variant(
    scenario_id: str,
    config: AblationConfig,
    *,
    max_rounds: int = 30,
    use_llm: bool = True,
    verbose: bool = True,
) -> AblationResult:
    """运行单个消融变体在单个场景上的完整 LOCK 循环。

    Args:
        scenario_id: 场景 ID（pipeline_18 / apt_5host / multipath_12host）
        config: 消融配置
        max_rounds: 最大轮数
        use_llm: 是否尝试使用 LLM（受 no_llm_triage 覆盖）
        verbose: 是否打印详细日志

    Returns:
        AblationResult 实验结果
    """
    from trace_agent.loop.scenario_executor import ScenarioExecutor
    from trace_agent.eval.soar_integration_runner import (
        load_scenario,
        find_entry_event,
        build_alert_event,
        TECHNIQUE_TACTIC_MAP,
    )

    t0 = time.time()
    ts_str = time.strftime("%Y%m%d_%H%M%S")
    llm_client = None

    if verbose:
        print(f"\n{'=' * 60}")
        print(f"  消融: {config.name} | 场景: {scenario_id}")
        print(f"  {config.description}")
        if config.active_flags():
            print(f"  激活 flags: {', '.join(config.active_flags())}")
        print(f"{'=' * 60}")

    try:
        # ── Step 1: 加载场景 ──
        scenario_data, registry_spec = load_scenario(scenario_id)
        run_config = registry_spec.get("run", {})

        # ── Step 2: 构建 AlertEvent ──
        entry_event = find_entry_event(scenario_data, registry_spec)
        alert = build_alert_event(entry_event)

        # ── Step 3: 创建 ScenarioExecutor ──
        executor = ScenarioExecutor(scenario_data, seed=42)

        # ── Step 3.5: 时间游标对齐 ──
        alert_ts = float(alert.timestamp or 0)
        if alert_ts > 0 and hasattr(executor, "_time_cursor"):
            executor._time_cursor = alert_ts

        # ── Step 4: LLM client ──
        if use_llm and not config.no_llm_triage:
            try:
                from trace_agent.llm import create_llm_client
                llm_client = create_llm_client()
            except Exception:
                llm_client = None

        # ── Step 5: ingest_factory ──
        ingest_factory = None
        if llm_client is not None:
            from trace_agent.loop.llm_ingest import LLMIngestPipeline

            ingest_factory = lambda trust, graph, ledger, _llm=llm_client: LLMIngestPipeline(
                trust, graph, ledger,
                llm_client=_llm, mode="assist",
            )

        # ── Step 6: Budget ──
        budget = BudgetState(
            total_rounds=max_rounds,
            total_probes=max_rounds * 8,
            fanout_per_round=run_config.get("beam_width", 5),
        )

        # ── Step 7: 创建 AblationOrchestrator ──
        orch = AblationOrchestrator(
            ablation_config=config,
            alert=alert,
            executor=executor,
            prior_manager=None,
            budget=budget,
            ingest_factory=ingest_factory,
        )

        # ── Step 8: 运行 LOCK 循环 ──
        if verbose:
            print(f"  运行 LOCK 循环 (max_rounds={max_rounds})...")

        result: InvestigationResult = orch.run(max_rounds=max_rounds)
        elapsed = time.time() - t0

        # ── Step 9: 收集指标 ──
        ablation_result = _collect_metrics(
            result=result,
            orch=orch,
            scenario_data=scenario_data,
            scenario_id=scenario_id,
            variant_name=config.name,
            elapsed=elapsed,
            ts_str=ts_str,
            llm_client=llm_client,
        )

        if verbose:
            print(f"  Recall={ablation_result.recall:.3f} "
                  f"Precision={ablation_result.precision:.3f} "
                  f"F1={ablation_result.f1:.3f} "
                  f"GT={ablation_result.gt_coverage_pct:.1f}% "
                  f"Decision={'Y' if ablation_result.decision_correct else 'N'} "
                  f"({elapsed:.1f}s)")

        return ablation_result

    except Exception as exc:
        elapsed = time.time() - t0
        error_msg = f"{type(exc).__name__}: {exc}"
        if verbose:
            print(f"  [ERROR] {config.name}/{scenario_id}: {error_msg}")
            traceback.print_exc()
        return AblationResult(
            scenario_id=scenario_id,
            variant_name=config.name,
            timestamp=ts_str,
            elapsed_seconds=elapsed,
            error=error_msg,
        )


def _collect_metrics(
    *,
    result: InvestigationResult,
    orch: AblationOrchestrator,
    scenario_data: dict,
    scenario_id: str,
    variant_name: str,
    elapsed: float,
    ts_str: str,
    llm_client: Any = None,
) -> AblationResult:
    """从 LOCK 结果和 orchestrator 状态收集消融指标。"""

    # GT coverage
    gt = scenario_data.get("ground_truth", {})
    attack_refs = set(gt.get("attack_edge_refs", []))
    total_attack_edges = len(attack_refs)

    graph_node_ids: set[str] = set()
    if orch.graph is not None:
        graph_node_ids = set(orch.graph._nodes.keys())

    found_attack_edges = len(graph_node_ids & attack_refs)
    attack_in_graph = sum(
        1 for nid in graph_node_ids if nid.startswith("attack:")
    )
    total_graph_events = len(graph_node_ids)

    precision = (
        attack_in_graph / total_graph_events if total_graph_events > 0 else 0.0
    )
    recall = (
        found_attack_edges / total_attack_edges if total_attack_edges > 0 else 0.0
    )
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )
    gt_coverage_pct = (
        100.0 * found_attack_edges / total_attack_edges
        if total_attack_edges > 0
        else 0.0
    )

    # 决策正确性
    decision = result.decision or "unknown"
    decision_correct = decision == "contain_escalate"

    # 图拓扑
    graph_stats = orch.graph.stats() if orch.graph else {}
    hosts: set[str] = set()
    if orch.graph:
        for node in orch.graph._nodes.values():
            attrs = node.attributes or {}
            for key in ("host_uid", "asset_id", "host", "target"):
                val = attrs.get(key)
                if val:
                    hosts.add(str(val).lower())

    tactics = set(graph_stats.get("tactics_seen", []) or [])

    # LLM stats
    llm_calls = 0
    llm_tokens = 0
    if llm_client is not None:
        stats = getattr(llm_client, "stats", {})
        llm_calls = stats.get("total_calls", 0)
        llm_tokens = stats.get("total_tokens", 0)

    return AblationResult(
        recall=round(recall, 4),
        precision=round(precision, 4),
        f1=round(f1, 4),
        gt_coverage_pct=round(gt_coverage_pct, 2),
        decision_correct=decision_correct,
        rounds_used=result.rounds_used,
        probes_used=result.total_events_processed,
        llm_calls=llm_calls,
        llm_tokens=llm_tokens,
        elapsed_seconds=round(elapsed, 2),
        graph_nodes=graph_stats.get("node_count", 0),
        graph_edges=graph_stats.get("edge_count", 0),
        hosts_covered=len(hosts),
        tactics_covered=len(tactics),
        scenario_id=scenario_id,
        variant_name=variant_name,
        timestamp=ts_str,
        decision=decision,
        stop_reason=result.stop_reason or "",
    )


# ═══════════════════════════════════════════════════════════════════
# 报告生成
# ═══════════════════════════════════════════════════════════════════


def generate_ablation_report(results: list[AblationResult]) -> str:
    """生成 Markdown 汇总报告。

    Args:
        results: 所有消融变体 x 场景的实验结果

    Returns:
        Markdown 格式的报告字符串
    """
    lines: list[str] = []
    lines.append("# trace_agent 全模块消融实验报告")
    lines.append("")
    lines.append(f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"总变体数: {len(set(r.variant_name for r in results))}")
    lines.append(f"总场景数: {len(set(r.scenario_id for r in results))}")
    lines.append(f"总实验数: {len(results)}")
    lines.append("")

    # ── 汇总表 ──
    lines.append("## 汇总矩阵")
    lines.append("")
    lines.append("| Variant | Scenario | Recall | Precision | F1 | GT% | Decision | Correct | Rounds | Time(s) |")
    lines.append("|---------|----------|--------|-----------|----|-----|----------|---------|--------|---------|")

    for r in sorted(results, key=lambda x: (x.variant_name, x.scenario_id)):
        correct = "Y" if r.decision_correct else "N"
        lines.append(
            f"| {r.variant_name} | {r.scenario_id} "
            f"| {r.recall:.3f} | {r.precision:.3f} | {r.f1:.3f} "
            f"| {r.gt_coverage_pct:.1f}% | {r.decision} | {correct} "
            f"| {r.rounds_used} | {r.elapsed_seconds:.1f} |"
        )
    lines.append("")

    # ── Delta 分析 ──
    lines.append("## Delta 分析（相对 full 基线）")
    lines.append("")

    delta_table = compute_delta_analysis(results)
    lines.append(delta_table)
    lines.append("")

    # ── 错误汇总 ──
    errors = [r for r in results if r.error]
    if errors:
        lines.append("## 错误汇总")
        lines.append("")
        for r in errors:
            lines.append(f"- **{r.variant_name}/{r.scenario_id}**: {r.error}")
        lines.append("")

    # ── 资源统计 ──
    lines.append("## 资源消耗汇总")
    lines.append("")
    lines.append("| Variant | Avg LLM Calls | Avg LLM Tokens | Avg Time(s) | Avg Rounds |")
    lines.append("|---------|--------------|----------------|-------------|------------|")

    variant_groups: dict[str, list[AblationResult]] = {}
    for r in results:
        variant_groups.setdefault(r.variant_name, []).append(r)

    for variant, group in sorted(variant_groups.items()):
        valid = [g for g in group if not g.error]
        if not valid:
            continue
        n = len(valid)
        avg_llm = sum(g.llm_calls for g in valid) / n
        avg_tokens = sum(g.llm_tokens for g in valid) / n
        avg_time = sum(g.elapsed_seconds for g in valid) / n
        avg_rounds = sum(g.rounds_used for g in valid) / n
        lines.append(
            f"| {variant} | {avg_llm:.0f} | {avg_tokens:.0f} "
            f"| {avg_time:.1f} | {avg_rounds:.1f} |"
        )
    lines.append("")

    return "\n".join(lines)


def compute_delta_analysis(results: list[AblationResult]) -> str:
    """计算每个变体相对 full 基线的 delta 差值。

    Returns:
        Markdown 格式的 delta 分析表
    """
    # 分离基线和其他变体
    baseline_results: dict[str, AblationResult] = {}
    variant_results: dict[str, dict[str, AblationResult]] = {}

    for r in results:
        if r.variant_name == "full":
            baseline_results[r.scenario_id] = r
        else:
            variant_results.setdefault(r.variant_name, {})[r.scenario_id] = r

    if not baseline_results:
        return "(无 full 基线数据，无法计算 delta)"

    lines: list[str] = []
    lines.append("| Variant | Δ Recall | Δ Precision | Δ F1 | Δ GT% | Δ Decision | Δ Rounds | Δ Time(s) |")
    lines.append("|---------|----------|-------------|------|-------|------------|----------|-----------|")

    for variant, scenario_map in sorted(variant_results.items()):
        deltas_recall = []
        deltas_prec = []
        deltas_f1 = []
        deltas_gt = []
        deltas_dec = []
        deltas_rounds = []
        deltas_time = []

        for sid, vr in scenario_map.items():
            bl = baseline_results.get(sid)
            if not bl or vr.error or bl.error:
                continue
            deltas_recall.append(vr.recall - bl.recall)
            deltas_prec.append(vr.precision - bl.precision)
            deltas_f1.append(vr.f1 - bl.f1)
            deltas_gt.append(vr.gt_coverage_pct - bl.gt_coverage_pct)
            deltas_dec.append(
                int(vr.decision_correct) - int(bl.decision_correct),
            )
            deltas_rounds.append(vr.rounds_used - bl.rounds_used)
            deltas_time.append(vr.elapsed_seconds - bl.elapsed_seconds)

        if not deltas_recall:
            continue

        n = len(deltas_recall)
        lines.append(
            f"| {variant} "
            f"| {sum(deltas_recall) / n:+.3f} "
            f"| {sum(deltas_prec) / n:+.3f} "
            f"| {sum(deltas_f1) / n:+.3f} "
            f"| {sum(deltas_gt) / n:+.1f}% "
            f"| {sum(deltas_dec) / n:+.1f} "
            f"| {sum(deltas_rounds) / n:+.1f} "
            f"| {sum(deltas_time) / n:+.1f} |"
        )

    return "\n".join(lines)


def save_ablation_results(
    results: list[AblationResult],
    output_dir: Optional[Path] = None,
) -> Path:
    """保存实验结果到 JSON 文件。

    Args:
        results: 实验结果列表
        output_dir: 输出目录（默认 soar_mcp_env/results/）

    Returns:
        输出文件路径
    """
    if output_dir is None:
        output_dir = RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = time.strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"ablation_full_{ts}.json"

    data = {
        "timestamp": ts,
        "total_variants": len(set(r.variant_name for r in results)),
        "total_scenarios": len(set(r.scenario_id for r in results)),
        "total_experiments": len(results),
        "results": [asdict(r) for r in results],
    }

    output_path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return output_path


def save_ablation_report(
    results: list[AblationResult],
    output_dir: Optional[Path] = None,
) -> Path:
    """保存 Markdown 报告到文件。

    Args:
        results: 实验结果列表
        output_dir: 输出目录（默认 reports/）

    Returns:
        输出文件路径
    """
    if output_dir is None:
        output_dir = REPORTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    report = generate_ablation_report(results)
    output_path = output_dir / "ablation_experiment_summary.md"
    output_path.write_text(report, encoding="utf-8")
    return output_path
