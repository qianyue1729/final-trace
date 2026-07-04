"""[DEPRECATED] 单体 LOCK 编排器 — 已被 ModularOrchestrator 替代。
保留用于向后兼容，新代码请使用 modular_orchestrator.py。

DecisionOrchestrator — RFC-004-02 §10 LOCK 主循环（单环）

只有一个 while。决策账只是 self.ledgers 里多出来的一本；没有"外环"。
L→②检验→O→C→K 每拍照常跳。
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from trace_agent.decision.types import AlertEvent, Explanation, NullAnchor, ContestedEdge, SeedPayload
from trace_agent.decision.calibrator import ArtifactCalibrator, RUNTIME_FEATURES
from trace_agent.decision.runtime_ledger import RuntimeDecisionLedger
from trace_agent.decision.runtime_types import (
    ConfidenceStatus,
    DecisionConfidence,
    LossMatrix,
    StopDecision,
)
from trace_agent.obligation_integration.obligation_ledger import ObligationLedger
from trace_agent.probe.voi_engine import voi, bayes_risk, should_stop, compute_max_voi
from trace_agent.loop.session_graph import SessionGraph
from trace_agent.loop.beta_ledger import BetaLedger
from trace_agent.loop.gen_calibration import GenCalibration
from trace_agent.loop.probe import Probe
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.loop.generators import (
    prior_generator,
    rule_gap_generator,
    cross_host_probe_generator,
    chain_follow_generator,
    structural_debt_generator,
    lifecycle_template_generator,
    LATE_STAGE_TACTICS,
    normalize_tactic,
)
from trace_agent.loop.executor import ProbeExecutor
from trace_agent.loop.ingest import IngestPipeline
from trace_agent.loop.model_probe_planner import (
    NullProbePlanner,
    PlannerContext,
    PlannerTimeWindow,
    ProbeIntentValidator,
    ProbePlanner,
)
from trace_agent.loop.revision_cascade import RevisionCascade
from trace_agent.loop.exploration_debt import (
    ExplorationDebt,
    OPERATOR_FAMILY,
    ENTRY_TACTIC_REQUIRED_FAMILIES,
)
from trace_agent.utils.config import EPS_VOI, K_MAX, OBLIGATION_BUDGET_FRACTION


@dataclass
class InvestigationResult:
    """LOCK 主循环的最终输出，分离调查分数与标定概率。"""
    decision: str                    # "contain_escalate" / "monitor" / "dismiss_benign"
    confidence: Optional[float]      # 兼容字段；仅 stable 标定时有值
    decision_confidence: DecisionConfidence
    stop_reason: str                 # "budget" / "voi_floor" / "robust" / "max_rounds" / "no_probes"
    leading_explanation: str         # MAP explanation label
    leading_explanation_id: str      # MAP explanation ID
    alternatives: list[dict] = field(default_factory=list)       # 次优解释
    boundary_decisions: dict = field(default_factory=dict)       # edge_id → "include"/"prune"
    rounds_used: int = 0
    total_events_processed: int = 0
    counterfactuals: list[str] = field(default_factory=list)     # 反事实
    final_entropy: float = 0.0
    final_risk: float = 0.0
    voi_audit: list[dict[str, Any]] = field(default_factory=list)
    incomplete: bool = False
    unresolved_obligations: list[dict[str, Any]] = field(default_factory=list)
    planner_audit: list[dict[str, Any]] = field(default_factory=list)
    round_diagnostics: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class BudgetState:
    """探查预算追踪。"""
    total_rounds: int = 50
    total_probes: int = 400
    rounds_used: int = 0
    probes_used: int = 0
    fanout_per_round: int = 8       # 每轮扇出槽数
    min_rounds_before_robust: int = 4   # robust 停止前至少跑 N 轮
    min_rounds_after_root: int = 8      # 图内见 initial-access 后继续扩图 N 轮

    def exhausted(self) -> bool:
        return self.rounds_used >= self.total_rounds or self.probes_used >= self.total_probes

    @property
    def remaining_probes(self) -> int:
        return max(0, self.total_probes - self.probes_used)

    def to_dict(self) -> dict:
        """Convert to dict for should_stop() compatibility."""
        return {"remaining": self.remaining_probes, "total": self.total_probes}


class DecisionOrchestrator:
    """RFC-004-02 §10 — LOCK 主循环编排器。

    单环 L→②检验→O→C→K，四本账（图/Beta/义务/决策账）。
    """

    def __init__(self,
                 alert: AlertEvent,
                 executor: ProbeExecutor,
                 prior_manager=None,
                 data_dir: Optional[Path] = None,
                 loss: Optional[LossMatrix] = None,
                 budget: Optional[BudgetState] = None,
                 seed: Optional[SeedPayload] = None,
                 decision_calibrator: Optional[ArtifactCalibrator] = None,
                 automation_policy: Optional[dict[str, Any]] = None,
                 probe_planner: Optional[ProbePlanner] = None,
                 planner_mode: str = "shadow",
                 planner_max_intents: int = 4,
                 planner_cost_budget: float = 1.0,
                 planner_max_graph_nodes: int = 40,
                 ingest_factory=None,
                 demo_profile_enabled: bool = False,
                 demo_plateau_rounds: int = 5,
                 demo_min_graph_nodes: int = 8,
                 demo_min_graph_edges: int = 6,
                 progress_cb=None):
        """
        Args:
            alert: 触发调查的告警事件
            executor: C 拍取证执行器（MockExecutor for testing）
            prior_manager: PriorManager for L1-L4 lookup (optional, graceful without)
            data_dir: 数据目录
            loss: 损失矩阵（默认从 loss_baseline.json 加载）
            budget: 探查预算（默认 50 rounds / 200 probes）
            seed: 可选预生成的 SeedPayload（跳过 DecisionLedger.seed）
        """
        self.alert = alert
        self.executor = executor
        self.prior_manager = prior_manager
        self.data_dir = data_dir
        self.budget = budget or BudgetState()
        self._provided_seed = seed
        self.decision_calibrator = decision_calibrator
        self.automation_policy = {
            "min_slice_support": 80,
            "min_precision": 0.90,
            "min_recall": 0.80,
            "contain_threshold": 0.70,
            "dismiss_threshold": 0.30,
            **(automation_policy or {}),
        }
        self.probe_planner = probe_planner or NullProbePlanner()
        self.planner_mode = (
            planner_mode if planner_mode in ("off", "shadow", "assist")
            else "shadow"
        )
        self.planner_max_intents = max(0, planner_max_intents)
        self.planner_cost_budget = max(0.0, planner_cost_budget)
        self.planner_max_graph_nodes = max(1, planner_max_graph_nodes)
        self._planner_validator = ProbeIntentValidator()
        self._planner_audit: list[dict[str, Any]] = []
        self._planner_recent_query_keys: set[str] = set()
        self._ingest_factory = ingest_factory
        self._demo_profile_enabled = bool(demo_profile_enabled)
        self._demo_plateau_rounds = max(1, demo_plateau_rounds)
        self._demo_min_graph_nodes = max(1, demo_min_graph_nodes)
        self._demo_min_graph_edges = max(0, demo_min_graph_edges)
        self._posterior_history: list[float] = []
        self._round_diagnostics: list[dict[str, Any]] = []
        self._progress_cb = progress_cb

        # Loss matrix
        if loss is None:
            loss = LossMatrix()  # defaults: miss=10, over=2, oos=4
        self.loss = loss

        # Adaptive strategy state
        self._stagnation_rounds = 0
        self._explore_weight = 1.0
        self._force_new_host_probe = False

        # Will be initialized in _bootstrap()
        self.graph: Optional[SessionGraph] = None
        self.ledger: Optional[RuntimeDecisionLedger] = None
        self.beta: Optional[BetaLedger] = None
        self.calib: Optional[GenCalibration] = None
        self.obligations: Optional[ObligationLedger] = None
        self.trust: Any = None
        self.cascade: Optional[RevisionCascade] = None
        self.ingest: Optional[IngestPipeline] = None
        self._last_pool_candidates: list[Probe] = []
        self._max_pool_voi: float = 0.0
        self._trust_revision_since: int = 0
        self._calibration_diag_cursor: int = 0
        self._voi_audit: list[dict[str, Any]] = []

    def run(self, max_rounds: Optional[int] = None) -> InvestigationResult:
        """执行完整 LOCK 主循环。

        RFC-004-02 §10 伪代码实现：
        1. triage + bootstrap (seed 四本账)
        2. while True:
             L → ② → O → C → K → stop?
        3. return InvestigationResult
        """
        if max_rounds is not None:
            self.budget.total_rounds = max_rounds

        # ═══ Phase 0: Bootstrap ═══
        self._bootstrap()
        self._emit_progress({
            "stage": "lock_loop",
            "phase": "bootstrap",
            "round": 0,
            "status": "completed",
            "graph_nodes": self.graph.stats().get("node_count", 0),
        })

        prev_stats = self.graph.stats()

        # ═══ Main Loop ═══
        while not self.budget.exhausted():
            self.budget.rounds_used += 1
            round_no = self.budget.rounds_used

            # ── L 拍：选哪条 ──
            self._emit_progress({
                "stage": "lock_loop", "phase": "L", "round": round_no,
                "status": "running",
            })
            pool = self._l_phase(prev_stats)
            planner_result = (
                dict(self._planner_audit[-1])
                if self._planner_audit
                and self._planner_audit[-1].get("round") == round_no
                else None
            )
            self._emit_progress({
                "stage": "lock_loop", "phase": "L", "round": round_no,
                "status": "completed", "candidate_count": len(pool.peek()),
                "model_planner": planner_result,
            })

            # ── ② 检验拍 ──
            pool = self._veto_phase(pool)
            self._emit_progress({
                "stage": "lock_loop", "phase": "Veto", "round": round_no,
                "status": "completed", "candidate_count": len(pool.peek()),
            })

            # ── O 拍：怎么查 ──
            chosen = self._o_phase(pool)
            self._emit_progress({
                "stage": "lock_loop", "phase": "O", "round": round_no,
                "status": "completed",
                "probes_selected": [probe.operator for probe in chosen],
            })

            if not chosen:
                # No viable probes remain
                self._emit_progress({
                    "stage": "lock_loop", "phase": "K", "round": round_no,
                    "status": "stopped", "stop_reason": "no_probes",
                })
                break

            # ── C 拍：验真 ──
            ingest_result = self._c_phase(chosen)
            routed = getattr(ingest_result, "routed", {}) or {}
            judgement_stats = getattr(self.ingest, "llm_stats", {"mode": "off"})
            judgement_audit = list(judgement_stats.get("audit") or [])
            self._emit_progress({
                "stage": "lock_loop", "phase": "C", "round": round_no,
                "status": "completed",
                "events": len(getattr(ingest_result, "all_events", []) or []),
                "attached": len(routed.get("ATTACH", [])),
                "model_judgement": {
                    "mode": judgement_stats.get("mode", "off"),
                    "l3_llm_calls": judgement_stats.get("l3_llm_calls", 0),
                    "provider_errors": judgement_stats.get("provider_errors", 0),
                    "shadow_summary": judgement_stats.get("shadow_summary") or {},
                    "latest_audit": judgement_audit[-1] if judgement_audit else None,
                },
            })

            # ── K 拍：收尾 ──
            stop_decision = self._k_phase(chosen, ingest_result)
            diagnostic = (
                dict(self._round_diagnostics[-1])
                if self._round_diagnostics else {}
            )
            self._emit_progress({
                "stage": "lock_loop", "phase": "K", "round": round_no,
                "status": "stopped" if stop_decision.should_stop else "completed",
                **diagnostic,
                "stop_should_stop": stop_decision.should_stop,
                "stop_reason_candidate": stop_decision.reason,
            })

            prev_stats = self.graph.stats()

            # ── 停止判定 ──
            if stop_decision.should_stop:
                return self._build_result(stop_decision.reason)

        # Budget exhausted or no probes
        return self._build_result("budget" if self.budget.exhausted() else "no_probes")

    def _emit_progress(self, event: dict[str, Any]) -> None:
        """Report bounded LOCK progress without allowing observers to break a run."""
        if not callable(self._progress_cb):
            return
        try:
            self._progress_cb(dict(event))
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════
    # Phase implementations
    # ═══════════════════════════════════════════════════════════════════

    def _bootstrap(self):
        """Phase 0: seed 四本账 + 初始化所有组件。"""
        # 1. Build or use provided SeedPayload
        seed = self._get_seed()

        # 2. Initialize four ledgers
        self.graph = SessionGraph()
        self.ledger = RuntimeDecisionLedger.from_seed(seed, self.loss)
        self.beta = BetaLedger()
        self.calib = GenCalibration()

        # 3. Obligations (+ lifecycle templates for §8)
        self.obligations = self._create_obligation_ledger()

        # 4. Evidence Trust
        self.trust = self._create_trust_model()

        # 5. Supporting infrastructure
        self.cascade = RevisionCascade(self.graph, self.trust, self.obligations, self.ledger)
        self.ingest = (
            self._ingest_factory(self.trust, self.graph, self.ledger)
            if callable(self._ingest_factory)
            else IngestPipeline(self.trust, self.graph, self.ledger)
        )

        # 6. Bootstrap graph with alert event
        self.graph.add_events([{
            "technique": self.alert.technique_id,
            "tactic": self.alert.tactic or "unknown",
            "timestamp": float(self.alert.timestamp or 0),
            "source": self.alert.log_source or "alert",
            "trust_tier": "high",
            "explanation_ids": [e.id for e in seed.explanations],
            "_fact_confirmed": True,
            "_attribution_status": "CONTESTED",
            "malicious_status": "unknown",
            "attributes": {
                **(self.alert.attributes or {}),
                "asset_id": self.alert.asset_id or "",
                "target": self.alert.asset_id or "",
            },
        }])

        # 6b. Wazuh bootstrap attack chain → ordered graph edges (production)
        try:
            from trace_engine.attack_chain_materializer import (
                materialize_attack_chain_from_executor,
            )

            chain_events = materialize_attack_chain_from_executor(
                self.executor,
                explanation_ids=[e.id for e in seed.explanations],
                alert_context={
                    "technique": self.alert.technique_id,
                    "asset": self.alert.asset_id,
                    "tactic": self.alert.tactic,
                    "timestamp": self.alert.timestamp,
                    "attributes": dict(self.alert.attributes or {}),
                },
            )
            if chain_events:
                self.graph.add_events(chain_events)
        except Exception:
            pass

        # 7. Initialize Exploration Debt (Task 3/5)
        entry_tactic = normalize_tactic(self.alert.tactic or "") or "execution"
        required = ENTRY_TACTIC_REQUIRED_FAMILIES.get(
            entry_tactic,
            ENTRY_TACTIC_REQUIRED_FAMILIES["_default"]
        )
        self._exploration_debt = ExplorationDebt(required_families=set(required))

        # 8. Cache scenario known hosts for host-coverage stop gate + veto filtering
        self._scenario_hosts = []
        known_hosts_fn = getattr(self.executor, "known_hosts", None)
        if callable(known_hosts_fn):
            try:
                self._scenario_hosts = list(known_hosts_fn())
            except Exception:
                pass
        self._known_hosts_lower = {h.lower() for h in self._scenario_hosts} if self._scenario_hosts else set()
        # Track (target_lower, operator) pairs that returned 0 raw events — skip in future rounds
        self._dead_pairs: set = set()
        # Host rotation: last round each host was probed (staleness bonus in _adjusted_voi)
        self._host_last_probed: dict[str, int] = {}

    def _get_seed(self) -> SeedPayload:
        """Get or generate SeedPayload."""
        if self._provided_seed is not None:
            return self._provided_seed

        # Try using DecisionLedger if prior_manager is available
        if self.prior_manager is not None:
            from trace_agent.decision.belief import DecisionLedger
            dl = DecisionLedger(self.prior_manager)
            return dl.seed(self.alert)

        # Fallback: create a minimal seed without PriorManager
        return self._create_minimal_seed()

    def _create_minimal_seed(self) -> SeedPayload:
        """Create minimal SeedPayload when no PriorManager is available."""
        tid = self.alert.technique_id
        tactic = self.alert.tactic or "execution"

        explanations = [
            Explanation(
                id="H1",
                title=f"{tid} attack-fit explanation",
                current_technique=tid,
                stage=tactic,
                lifecycle_template=None,
                predecessor_tactics=[],
                technique_context=[],
                raw_score=0.6,
                prior_probability=0.4,
                features={},
                support={"type": "fallback"},
                recommended_log_sources=[],
                caveats=["minimal seed - no prior manager"],
            ),
            Explanation(
                id="H2",
                title=f"{tid} alternative explanation",
                current_technique=tid,
                stage=tactic,
                lifecycle_template=None,
                predecessor_tactics=[],
                technique_context=[],
                raw_score=0.3,
                prior_probability=0.25,
                features={},
                support={"type": "fallback"},
                recommended_log_sources=[],
                caveats=["minimal seed - no prior manager"],
            ),
        ]
        null_anchor = NullAnchor(benign=0.25, oos=0.10, reasons=["minimal seed"])

        return SeedPayload(
            alert=self.alert,
            explanations=explanations,
            branch_null_anchor=null_anchor,
            contested_edges=[],
            lifecycle_template_candidates=[],
            score_v3_initial_scores={"H1": 0.4, "H2": 0.25},
            loss_baseline={
                "lambda_miss": self.loss.lambda_miss,
                "lambda_over": self.loss.lambda_over,
                "lambda_oos": self.loss.lambda_oos,
            },
            evidence_trust_defaults={},
            prior_manifest={},
        )

    def _create_obligation_ledger(self) -> ObligationLedger:
        """加载 lifecycle 模板；失败时回退空模板。"""
        candidates = []
        if self.data_dir:
            candidates.append(Path(self.data_dir) / "lifecycle_templates.json")
        pkg = Path(__file__).resolve().parents[1] / "data" / "lifecycle_templates.json"
        candidates.append(pkg)
        for path in candidates:
            if path.is_file():
                try:
                    return ObligationLedger.from_json(path, loss=self.loss)
                except Exception:
                    pass
        return ObligationLedger(loss=self.loss)

    def _create_trust_model(self):
        """Create or fallback trust model."""
        try:
            from trace_agent import create_evidence_trust_model
            return create_evidence_trust_model(data_dir=self.data_dir)
        except Exception:
            try:
                from trace_agent import create_evidence_trust_model
                return create_evidence_trust_model()
            except Exception:
                # Minimal duck-typed trust model
                return _MinimalTrust()

    def _l_phase(self, prev_stats: dict) -> CandidatePool:
        """L 拍：生成候选探针。"""
        pool = CandidatePool()

        # Prior-based generation
        try:
            prior_probes = prior_generator(self.graph, self.ledger, self.prior_manager)
            pool.add(prior_probes)
        except Exception:
            pass

        # Structural gap generation
        try:
            gap_probes = rule_gap_generator(self.graph, prev_stats)
            pool.add(gap_probes)
        except Exception:
            pass

        # Cross-host backward trace (ScenarioExecutor.known_hosts)
        try:
            known_hosts_fn = getattr(self.executor, "known_hosts", None)
            if callable(known_hosts_fn):
                cross_probes = cross_host_probe_generator(
                    self.graph,
                    known_hosts_fn(),
                    alert_asset=self.alert.asset_id or "",
                )
                pool.add(cross_probes)
        except Exception:
            pass

        # Chain follow: fill kill-chain gaps on hosts already in graph
        try:
            pool.add(chain_follow_generator(self.graph))
        except Exception:
            pass

        # Structural debt: bridge orphan/leaf nodes and disconnected components
        try:
            pool.add(structural_debt_generator(self.graph, self.ledger))
        except Exception:
            pass

        # Lifecycle template: predict missing kill-chain phases from templates
        try:
            pool.add(lifecycle_template_generator(self.graph))
        except Exception:
            pass

        for probe in self._model_planner_phase(pool):
            pool.add([probe])

        return pool

    def _model_planner_phase(self, rule_pool: CandidatePool) -> list[Probe]:
        if self.planner_mode == "off" or self.planner_max_intents <= 0:
            return []
        context = self._planner_context()
        result = self.probe_planner.plan(context)
        rule_keys = {probe.dedup_key() for probe in rule_pool.peek()}
        validated = []
        assist_probes: list[Probe] = []
        for intent in result.intents[:self.planner_max_intents]:
            probe_cost = self.calib.cost({
                "operator": intent.operator,
                "target_type": "host",
            }) if self.calib else 0.10
            check = self._planner_validator.validate(
                intent,
                context,
                projected_cost=probe_cost,
            )
            projected_voi = None
            overlap = False
            if check.accepted and check.target_host:
                probe = Probe(
                    id=Probe.generate_id(
                        check.target_host,
                        intent.operator,
                        intent.tactic,
                    ),
                    target=check.target_host,
                    target_type="host",
                    operator=intent.operator,
                    tactic=intent.tactic,
                    source="model_planner",
                    metadata={
                        "time_window": {
                            "from_ms": intent.time_window.from_ms,
                            "to_ms": intent.time_window.to_ms,
                        },
                        "distinguishes": list(intent.distinguishes),
                        "evidence_refs": list(intent.evidence_refs),
                        "reason_codes": list(intent.reason_codes),
                    },
                )
                overlap = probe.dedup_key() in rule_keys
                try:
                    projected_voi = voi(
                        self._probe_to_dict(probe),
                        self.ledger,
                        self._beta_to_dict(),
                        self._calib_to_dict(),
                        self.loss,
                        self.trust,
                        graph_stats=self._compute_graph_stats(),
                    ).voi_score
                except Exception:
                    projected_voi = None
                if self.planner_mode == "assist":
                    assist_probes.append(probe)
            validated.append({
                "target_entity_id": intent.target_entity_id,
                "operator": intent.operator,
                "tactic": intent.tactic,
                "accepted": check.accepted,
                "rejection_reason_codes": list(check.reason_codes),
                "target_host": check.target_host,
                "datasource": check.datasource,
                "projected_cost": check.projected_cost,
                "projected_voi": projected_voi,
                "overlaps_rule_candidate": overlap,
            })
        self._planner_audit.append({
            "round": self.budget.rounds_used,
            "mode": self.planner_mode,
            "provider_status": result.provider_status,
            "model_version": result.model_version,
            "latency_ms": result.latency_ms,
            "token_cost": result.token_cost,
            "abstained": result.abstained,
            "proposed": len(result.intents),
            "accepted": sum(item["accepted"] for item in validated),
            "missed_opportunity_candidates": sum(
                item["accepted"] and not item["overlaps_rule_candidate"]
                for item in validated
            ),
            "validations": validated,
            "executed_model_probes": (
                len(assist_probes) if self.planner_mode == "assist" else 0
            ),
        })
        return assist_probes

    def _planner_context(self) -> PlannerContext:
        nodes = list(self.graph._nodes.values())[-self.planner_max_graph_nodes:]
        node_ids = {str(node.id) for node in nodes}
        graph = {
            "nodes": [
                {
                    "id": str(node.id),
                    "technique": node.technique,
                    "tactic": node.tactic,
                    "host_id": node.host_id,
                    "attribution_status": node.attribution_status,
                }
                for node in nodes
            ],
            "edges": [
                {
                    "id": str(edge.id),
                    "src": str(edge.src),
                    "dst": str(edge.dst),
                    "relation": edge.relation,
                }
                for edge in self.graph._edges.values()
                if str(edge.src) in node_ids or str(edge.dst) in node_ids
            ],
        }
        entities: dict[str, dict[str, Any]] = {}
        for host in self._scenario_hosts:
            entities[f"host:{host}"] = {"host_id": host, "type": "host"}
        for node in nodes:
            if node.host_id:
                entities[str(node.id)] = {
                    "host_id": node.host_id,
                    "type": "event",
                }
                entities.setdefault(
                    f"host:{node.host_id}",
                    {"host_id": node.host_id, "type": "host"},
                )
        mcp_config = getattr(self.executor, "mcp_config", None)
        operators = dict(
            getattr(mcp_config, "operator_datasource_map", {}) or {}
        )
        if not operators:
            from trace_agent.loop.scenario_executor import OPERATOR_ACTION_MAP
            operators = {name: "local" for name in OPERATOR_ACTION_MAP}
        capabilities = getattr(
            getattr(self.executor, "transport", None),
            "capabilities",
            None,
        )
        dimensions = set(
            getattr(capabilities, "supported_query_dimensions", {"host"})
        )
        window_fn = getattr(self.executor, "_window_ms", None)
        if callable(window_fn):
            from_ms, to_ms = window_fn()
        else:
            cursor = int(getattr(self.executor, "_time_cursor", 0) * 1000)
            from_ms, to_ms = 0, max(0, cursor)
        explanations = [
            {
                "id": explanation.id,
                "title": explanation.title,
                "stage": explanation.stage,
                "investigation_weight": self.ledger.posterior(explanation.id),
            }
            for explanation in self.ledger.explanations
        ]
        obligations = (
            self.obligations.unresolved(self.budget.rounds_used)
            if self.obligations else []
        )
        evidence_refs = node_ids | {
            item["id"] for item in obligations
        }
        status = getattr(
            self.decision_calibrator,
            "status",
            ConfidenceStatus.UNAVAILABLE,
        )
        from trace_agent.loop.investigation_guidance import guidance_for

        investigation_guidance: list[dict[str, Any]] = []
        seen_guidance: set[str] = set()
        for node in reversed(nodes):
            for item in guidance_for(node.tactic, node.technique):
                if item["id"] not in seen_guidance:
                    investigation_guidance.append(item)
                    seen_guidance.add(item["id"])
            if len(investigation_guidance) >= 4:
                break
        return PlannerContext(
            graph=graph,
            explanations=explanations,
            confidence_status=(
                status.value if isinstance(status, ConfidenceStatus)
                else str(status)
            ),
            obligations=obligations,
            entities=entities,
            operators=operators,
            supported_query_dimensions=dimensions,
            allowed_window=PlannerTimeWindow(from_ms, to_ms),
            budget_remaining=max(
                0, self.budget.total_probes - self.budget.probes_used
            ),
            cost_remaining=self.planner_cost_budget,
            evidence_refs=evidence_refs,
            recent_query_keys=set(self._planner_recent_query_keys),
            recent_probe_outcomes=list(self._voi_audit[-20:]),
            investigation_guidance=investigation_guidance,
        )

    def _veto_phase(self, pool: CandidatePool) -> CandidatePool:
        """② 检验拍：证据修订级联 + VETO 过滤 + MANDATE 义务扫描。"""
        graph_dict = self._graph_to_dict()

        # 0. 证据修订级联（RFC §5/§8）
        if self.trust and hasattr(self.trust, "get_pending_revisions"):
            try:
                revisions = self.trust.get_pending_revisions(self._trust_revision_since)
                if revisions and self.cascade:
                    self.cascade.apply(revisions)
                if self.obligations and hasattr(self.obligations, "cascade_on_revision"):
                    self.obligations.cascade_on_revision(revisions)
                if revisions:
                    self._trust_revision_since = max(
                        getattr(r, "round", self.budget.rounds_used) for r in revisions
                    ) + 1
            except Exception:
                pass

        # 1. Obligation scanning
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

        # 3. Beta sensitivity VETO: prune probe types with repeated misses
        veto_ids: list[str] = []
        for probe in pool.peek():
            key = probe.learning_key()
            if self.beta.total_observations(key) >= 2 and self.beta.sensitivity(key) < 0.2:
                veto_ids.append(probe.id)

        # 4. Non-host filter: remove probes whose target doesn't match any known host
        if self._known_hosts_lower:
            for probe in pool.peek():
                target_lower = (getattr(probe, 'target', '') or '').lower().strip()
                if target_lower and target_lower not in self._known_hosts_lower:
                    veto_ids.append(probe.id)

        # NOTE: dead_pairs tracking removed — with commit_event_refs fix,
        # probes return NEW events each round as time window expands.
        # Marking them dead would prevent discovering events in future time windows.

        if veto_ids:
            pool.remove(veto_ids)

        return pool

    def _o_phase(self, pool: CandidatePool) -> list[Probe]:
        """O 拍：义务探针并入池 + VOI 排序（硬义务加权，不抢占可执行槽）。"""
        slots = self.budget.fanout_per_round

        # 义务物化 → 并入统一池（RFC §8：与 VOI 同框架排序）
        graph_dict = self._graph_to_dict()
        mandated_probes: list[Probe] = []
        try:
            mandated_raw = self.obligations.materialize_open(
                graph_dict,
                current_round=self.budget.rounds_used,
            ) or []
            mandated_probes = [
                p for p in self._obligation_dicts_to_probes(mandated_raw)
                if self._probe_is_executable(p)
            ]
        except Exception:
            pass

        candidates = mandated_probes + pool.drain()
        # 去重：同 target+operator+tactic 保留义务源或更高 priority_hint
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

        graph_stats = self._compute_graph_stats()
        beta_dict = self._beta_to_dict()
        calib_dict = self._calib_to_dict()

        scored: list[tuple[float, Probe]] = []
        for probe in candidates:
            try:
                probe_dict = self._probe_to_dict(probe)
                voi_result = voi(probe_dict, self.ledger, beta_dict, calib_dict,
                                 self.loss, self.trust, graph_stats=graph_stats)
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

    def _adjusted_voi(self, probe: Probe, base_voi: float, selected: list[Probe]) -> float:
        """调整后 VOI：覆盖债奖励 + 重复惩罚 + 轻量主机多样性。"""
        family = OPERATOR_FAMILY.get(probe.operator)

        # Coverage bonus: uncovered family 奖励
        coverage_bonus = 0.0
        if hasattr(self, '_exploration_debt') and family:
            uncovered = self._exploration_debt.uncovered_families()
            if family in uncovered:
                coverage_bonus = 0.25

        # Duplicate penalty: 同 operator / 同 family 已选则惩罚
        duplicate_penalty = 0.0
        selected_ops = {p.operator for p in selected}
        selected_families = {OPERATOR_FAMILY.get(p.operator) for p in selected}

        if probe.operator in selected_ops:
            duplicate_penalty += 0.35
        elif family and family in selected_families:
            duplicate_penalty += 0.20

        probe_host = getattr(probe, 'target', '') or ''
        probe_host_lower = probe_host.lower()

        # 追根/沿链探针优先
        source_bonus = 0.0
        if probe.source == "cross_host":
            source_bonus += 0.15
        if probe.source == "chain_follow":
            source_bonus += 0.10

        # 尚未发现 initial-access 时，优先告警主机上的认证/邮件类探针（反向溯源）
        if not self._has_initial_access_in_graph():
            alert_asset = (self.alert.asset_id or "").lower()
            probe_tactic = normalize_tactic(probe.tactic or "")
            if alert_asset and probe_host_lower == alert_asset:
                if probe_tactic == "initial-access":
                    source_bonus += 0.25
                if probe.operator in ("auth_log", "email_trace", "web_proxy"):
                    source_bonus += 0.18

        # 未入图主机轻量探索奖励（不压过告警主机的优先级）
        graph_hosts = set()
        if self.graph:
            for node in self.graph._nodes.values():
                attrs = node.attributes or {}
                for key in ("host_uid", "asset_id", "host", "target"):
                    val = attrs.get(key)
                    if val:
                        graph_hosts.add(str(val).lower())
        if probe_host and probe_host_lower not in graph_hosts:
            source_bonus += 0.10

        # 主机探索轮换（仅中后期轮次启用）：长期未探查的已知主机获得
        # staleness bonus，防止后期轮次探针持续集中在同一主机(如告警主机)。
        # 早期轮次(R1-R3)不干扰——事件密集主机需要多算子集中覆盖。
        rotation_bonus = 0.0
        if self.budget.rounds_used >= 4:
            if probe_host_lower and probe_host_lower in self._known_hosts_lower:
                last_round = self._host_last_probed.get(probe_host_lower)
                if last_round is None:
                    rotation_bonus += 0.15   # 从未探查过的已知主机
                else:
                    staleness = self.budget.rounds_used - last_round
                    rotation_bonus += min(0.30, 0.06 * staleness)

            # 同轮主机多样性：本轮已选 3+ 个同主机探针后开始轻度惩罚
            same_host_selected = sum(
                1 for p in selected
                if (getattr(p, 'target', '') or '').lower() == probe_host_lower
            )
            if same_host_selected >= 3:
                rotation_bonus -= 0.08 * (same_host_selected - 2)

        return base_voi + coverage_bonus - duplicate_penalty + source_bonus + rotation_bonus

    def _c_phase(self, chosen: list[Probe]) -> Any:
        """C 拍：扇出取证 + 证据信任入账 + 入图判假级联。"""
        # 1. Execute fanout
        raw_events = self.executor.execute_fanout(chosen)

        # 1a. Evidence trust ingest (RFC §5 — ②/C 前置信任)
        self._ingest_evidence_trust(raw_events)

        # 1b. Track dead probe pairs (returned 0 raw events) for future veto
        if self._dead_pairs is not None:
            probe_event_counts: dict[str, int] = {}
            for ev in raw_events:
                pid = ev.get("probe_id", "")
                if pid:
                    probe_event_counts[pid] = probe_event_counts.get(pid, 0) + 1
            for probe in chosen:
                if probe_event_counts.get(probe.id, 0) == 0:
                    key = ((probe.target or '').lower().strip(), probe.operator)
                    self._dead_pairs.add(key)

        # 2. Reset LLM round budget if LLMIngestPipeline
        if hasattr(self.ingest, 'reset_round_budget'):
            self.ingest.reset_round_budget()

        # 3. Ingest pipeline (L0-L4 + 5-bucket routing)
        alert_context = {
            "host": self.alert.asset_id or "",
            "tactic": normalize_tactic(getattr(self.alert, "tactic", "") or ""),
            "timestamp": float(getattr(self.alert, "timestamp", 0) or 0),
        }
        result = self.ingest.triage(raw_events, chosen, alert_context=alert_context)

        # 3b. Commit triaged refs：仅 graph_eligible / DISCARD，保留未提升 WEAK/PARK 可重取
        from trace_agent.loop.ingest import ROUTE_DISCARD as _ROUTE_DISCARD
        if hasattr(self.executor, 'commit_event_refs'):
            to_commit: list[str] = []
            for ev in result.all_events:
                eid = str(ev.get('id', ''))
                if not eid:
                    continue
                bucket = ev.get("_route_bucket", "")
                if bucket == _ROUTE_DISCARD or ev.get("_graph_eligible") or ev.get("_fact_confirmed"):
                    to_commit.append(eid)
            if to_commit:
                self.executor.commit_event_refs(to_commit)

        # Record host rotation state for staleness bonus
        for probe in chosen:
            host_lower = (probe.target or '').lower().strip()
            if host_lower:
                self._host_last_probed[host_lower] = self.budget.rounds_used

        self.budget.probes_used += len(chosen)
        return result

    def _k_phase(self, chosen: list[Probe], ingest_result) -> StopDecision:
        """K 拍：学习 + 决策账更新 + 停止判定 + 自适应策略。"""
        from trace_agent.loop.ingest import ROUTE_DISCARD

        prev_node_count = self.graph.stats().get("node_count", 0)
        prev_edge_count = self.graph.stats().get("edge_count", 0)
        probs_before = self.ledger._get_probabilities()
        p_atk_before = round(1.0 - probs_before.get("__null__", 0.0), 6)
        graph_events = [
            e for e in getattr(ingest_result, "graph_eligible", [])
            if _has_required_fields(e)
        ]
        attribution_confirmed = list(ingest_result.confirmed)

        # 1. Graph update — fact-confirmed events (attribution may be CONTESTED)
        if graph_events:
            self.graph.add_events(graph_events)
            if hasattr(self.executor, "commit_event_refs"):
                self.executor.commit_event_refs([
                    str(e.get("id")) for e in graph_events if e.get("id")
                ])

        # Hard-discard permanently commits executor refs
        discarded = ingest_result.routed.get(ROUTE_DISCARD, [])
        if discarded and hasattr(self.executor, "commit_event_refs"):
            self.executor.commit_event_refs([
                str(e.get("id")) for e in discarded if e.get("id")
            ])

        # 2. Decision ledger Bayesian update (all graph-eligible facts)
        if graph_events:
            try:
                self.ledger.update(graph_events, self.trust)
            except Exception as exc:
                import logging
                logging.getLogger(__name__).warning("ledger.update failed: %s", exc)

        # 2b. K 拍证据修订级联
        if self.trust and self.cascade:
            try:
                pending = []
                if hasattr(self.trust, "get_pending_revisions"):
                    pending = self.trust.get_pending_revisions(self._trust_revision_since)
                elif hasattr(self.trust, "get_revisions"):
                    pending = self.trust.get_revisions()[self._trust_revision_since:]
                if pending:
                    self.cascade.apply(pending)
                    self._trust_revision_since = max(
                        getattr(r, "round", self.budget.rounds_used) for r in pending
                    ) + 1
            except Exception:
                pass

        # 3. Abductive maintenance (attribution-confirmed only)
        try:
            self.ledger.spawn_merge_cull(attribution_confirmed, self.trust, budget=K_MAX)
        except Exception:
            pass

        # 4. Beta ledger update
        for probe in chosen:
            key = probe.learning_key()
            hit = any(
                e.get("probe_id") == probe.id or e.get("tactic") == probe.tactic
                for e in graph_events
            )
            self.beta.update(key, success=int(hit), fail=int(not hit))

        # 5. Generator calibration
        for probe in chosen:
            hit = any(
                e.get("probe_id") == probe.id or e.get("tactic") == probe.tactic
                for e in graph_events
            )
            self.calib.record(probe.source, hit)

        fetch_stats = getattr(self.executor, "fetch_stats", {})
        diagnostics = fetch_stats.get("query_diagnostics", [])
        new_diagnostics = diagnostics[self._calibration_diag_cursor:]
        self._calibration_diag_cursor = len(diagnostics)
        for probe in chosen:
            matched = [
                item for item in new_diagnostics
                if probe.id in (item.get("probe_ids") or [])
            ]
            self.calib.record_probe_cost(
                probe,
                query_count=sum(int(item.get("pages", 0)) for item in matched),
                records_scanned=sum(
                    int(item.get("records", 0)) for item in matched
                ),
                failed=any(item.get("error") for item in matched),
            )

        # 5.5 Exploration Debt update (Task 5)
        for probe in chosen:
            probe_hit = any(
                e.get("probe_id") == probe.id or e.get("tactic") == probe.tactic
                for e in graph_events
            )
            # no_data: 该探针完全无任何事件返回
            probe_no_data = not any(
                e.get("probe_id") == probe.id for e in (getattr(ingest_result, "all_events", []) or graph_events)
            )
            self._exploration_debt.record_attempt(probe.operator, hit=probe_hit, no_data=probe_no_data)
            if probe.source == "model_planner" and probe_no_data:
                window = probe.metadata.get("time_window") or {}
                self._planner_recent_query_keys.add("|".join((
                    probe.target,
                    probe.operator,
                    probe.tactic,
                    str(window.get("from_ms", 0)),
                    str(window.get("to_ms", 0)),
                )))
            obligation_id = probe.metadata.get("obligation_id")
            if obligation_id:
                self.obligations.record_attempt(
                    obligation_id,
                    self.budget.rounds_used,
                    failed=probe_no_data,
                )

        # 6. Obligation discharge
        graph_dict = self._graph_to_dict()
        try:
            self.obligations.discharge(graph_dict, self.ledger)
        except (TypeError, AttributeError):
            pass

        # 7. Adaptive stagnation detection
        self._adaptive_strategy(prev_node_count)

        # 8. Stopping decision — 使用真实 maxVOI（候选池 + 义务探针）
        budget_dict = self.budget.to_dict()
        stop_candidates = list(self._last_pool_candidates)
        try:
            stop_candidates.extend(
                self._obligation_dicts_to_probes(
                    self.obligations.materialize_open(
                        self._graph_to_dict(),
                        current_round=self.budget.rounds_used,
                    ) or []
                )
            )
        except Exception:
            pass
        stop = should_stop(
            self.ledger,
            self._beta_to_dict(),
            budget_dict,
            self.obligations,
            self.loss,
            candidate_probes=stop_candidates or None,
            trust=self.trust,
            calib=self._calib_to_dict(),
            graph_stats=self._compute_graph_stats(),
            probe_to_dict=self._probe_to_dict,
        )
        if stop.max_voi <= 0 and self._max_pool_voi > 0:
            stop = StopDecision(
                should_stop=stop.should_stop,
                reason=stop.reason,
                max_voi=self._max_pool_voi,
                risk_now=stop.risk_now,
            )

        probs_after = self.ledger._get_probabilities()
        p_atk_after = round(1.0 - probs_after.get("__null__", 0.0), 6)
        self._posterior_history.append(p_atk_after)

        routed = getattr(ingest_result, "routed", {}) or {}
        graph_stats = self.graph.stats()
        self._round_diagnostics.append({
            "round": self.budget.rounds_used,
            "probes_selected": [p.operator for p in chosen],
            "probe_results_count": len(getattr(ingest_result, "all_events", []) or []),
            "attach_bucket_count": len(routed.get("ATTACH", [])),
            "weak_bucket_count": len(routed.get("WEAK", [])),
            "park_bucket_count": len(routed.get("PARK", [])),
            "discard_bucket_count": len(routed.get("DISCARD", [])),
            "graph_eligible_count": len(getattr(ingest_result, "graph_eligible", []) or []),
            "confirmed_count": len(getattr(ingest_result, "confirmed", []) or []),
            "new_graph_nodes": graph_stats.get("node_count", 0) - prev_node_count,
            "new_graph_edges": graph_stats.get("edge_count", 0) - prev_edge_count,
            "graph_nodes": graph_stats.get("node_count", 0),
            "graph_edges": graph_stats.get("edge_count", 0),
            "p_atk_before": p_atk_before,
            "p_atk_after": p_atk_after,
            "delta_p_atk": round(p_atk_after - p_atk_before, 6),
            "p_null": round(probs_after.get("__null__", 0.0), 6),
            "margin": round(self.ledger.margin(), 6),
            "entropy": round(self.ledger.entropy(), 6),
            "stop_should_stop": stop.should_stop,
            "stop_reason_candidate": stop.reason,
        })

        plateau_stop = self._check_demo_plateau_stop()
        if plateau_stop is not None:
            stop = plateau_stop

        # ── Stop debug trace ──
        self._print_stop_debug(stop)

        # Suppress premature stops (both robust and voi_floor) when investigation incomplete
        if stop.should_stop and stop.reason in ("robust", "voi_floor") and self._suppress_robust_stop():
            # 二层出口：决策已足够鲁棒且高置信时，允许 partial-chain 提前停
            if self._decision_robust_partial_chain():
                stop = StopDecision(
                    should_stop=True,
                    reason="robust_partial_chain",
                    max_voi=stop.max_voi,
                    risk_now=stop.risk_now,
                )
            else:
                stop = StopDecision(
                    should_stop=False,
                    reason="continue",
                    max_voi=stop.max_voi,
                    risk_now=stop.risk_now,
                )
        return stop

    def _apply_demo_partial_conclusion(
        self,
        *,
        decision: str,
        incomplete: bool,
        stop_reason: str,
        unresolved_obligations: list[dict[str, Any]],
        leading_id: str,
        investigation_score: float,
    ) -> tuple[str, bool]:
        """Demo profile: surface partial human-review conclusion for Level 2 demos."""
        stats = self.graph.stats()
        nodes = int(stats.get("node_count", 0) or 0)
        edges = int(stats.get("edge_count", 0) or 0)
        if nodes < self._demo_min_graph_nodes or edges < self._demo_min_graph_edges:
            return decision, incomplete
        if stop_reason not in (
            "budget",
            "voi_floor",
            "no_probes",
            "evidence_plateau_partial_chain",
        ):
            return decision, incomplete

        needs_human_review = (
            bool(unresolved_obligations)
            or leading_id == "__null__"
            or abs(investigation_score) < 0.5
        )
        if needs_human_review and decision in ("monitor", "escalate_incomplete"):
            return "escalate_incomplete", True
        return decision, incomplete

    def _check_demo_plateau_stop(self) -> Optional[StopDecision]:
        """Demo profile: early stop when posterior plateaus with partial evidence."""
        if not self._demo_profile_enabled:
            return None
        n = self._demo_plateau_rounds
        if len(self._posterior_history) < n:
            return None
        recent = self._posterior_history[-n:]
        if len(set(recent)) > 1:
            return None

        stats = self.graph.stats()
        nodes = int(stats.get("node_count", 0) or 0)
        edges = int(stats.get("edge_count", 0) or 0)
        if nodes < self._demo_min_graph_nodes or edges < self._demo_min_graph_edges:
            return None

        unresolved = (
            self.obligations.unresolved(self.budget.rounds_used)
            if self.obligations else []
        )
        leading_id = self.ledger.leading()
        margin = self.ledger.margin()
        needs_partial_stop = (
            any(item.get("hard") for item in unresolved)
            or any(item.get("overdue") for item in unresolved)
            or leading_id == "__null__"
            or margin < 0.15
        )
        if not needs_partial_stop:
            return None

        risk_now = bayes_risk(self.ledger, self.loss)
        return StopDecision(
            should_stop=True,
            reason="evidence_plateau_partial_chain",
            max_voi=0.0,
            risk_now=risk_now,
        )

    def _adaptive_strategy(self, prev_node_count: int):
        """连续2轮无新节点时切换策略：增大fanout、探索权重、强制新主机探针。"""
        current_count = self.graph.stats().get("node_count", 0)
        if current_count <= prev_node_count:
            self._stagnation_rounds += 1
        else:
            self._stagnation_rounds = 0

        if self._stagnation_rounds >= 2:
            # 临时增加fanout
            self.budget.fanout_per_round = min(12, self.budget.fanout_per_round + 2)
            # 增大exploration权重
            self._explore_weight = min(3.0, self._explore_weight * 1.5)
            # 标记强制生成新主机探针
            self._force_new_host_probe = True
            self._stagnation_rounds = 0  # 重置

    def _has_initial_access_in_graph(self) -> bool:
        tactics = {
            normalize_tactic(t)
            for t in (self.graph.stats().get("tactics_seen") or [])
        }
        return "initial-access" in tactics

    def _print_stop_debug(self, stop: StopDecision) -> None:
        """每轮打印 stop debug 表，用于诊断停止行为。"""
        try:
            probs = self.ledger._get_probabilities()
            p_null = probs.get("__null__", 0.0)
            p_attack = 1.0 - p_null
            margin = self.ledger.margin()
            entropy = self.ledger.entropy()
            debt_cleared = (
                self._exploration_debt.is_cleared(self.budget.rounds_used)
                if hasattr(self, '_exploration_debt') else True
            )
            tactics_seen = self.graph.stats().get("tactics_seen", []) if self.graph else []
            print(
                f"  [STOP] R{self.budget.rounds_used} | "
                f"P_atk={p_attack:.3f} P_null={p_null:.3f} | "
                f"margin={margin:.3f} entropy={entropy:.3f} | "
                f"voi={stop.max_voi:.4f} | "
                f"debt_clear={debt_cleared} | "
                f"tactics={len(tactics_seen)} | "
                f"stop={stop.should_stop}({stop.reason})"
            )
        except Exception:
            pass

    def _decision_robust_partial_chain(self) -> bool:
        """决策已鲁棒 + 高置信时允许 partial-chain 提前停止。

        条件：
        1. P_attack >= 0.7 (contain_escalate 阈值)
        2. 至少跑完 min_rounds_before_robust
        3. 非首轮（已有证据积累）
        4. 没有高价值义务未清
        5. 主机覆盖率 >= 80% (场景已知主机)
        6. 已过 min_rounds_after_root（发现 initial-access 后继续扩图）
        7. 最近轮次无新节点（无探索动量）
        """
        probs = self.ledger._get_probabilities()
        p_null = probs.get("__null__", 0.0)
        p_attack = 1.0 - p_null

        # 条件 1: 决策已过 contain_escalate 阈值
        if p_attack < 0.7 and p_null < 0.7:
            return False  # 还在 monitor 区间，不允许提前停

        # 条件 2: 至少跑完 min_rounds
        if self.budget.rounds_used < self.budget.min_rounds_before_robust:
            return False

        # 条件 3: 没有高价值硬义务
        if self.obligations and hasattr(self.obligations, "open_hard"):
            if self.obligations.open_hard():
                return False

        # 条件 4: 主机覆盖率门控 — 已知主机80%以上入图才允许提前停
        if hasattr(self, '_scenario_hosts') and self._scenario_hosts:
            known_count = len(self._scenario_hosts)
            graph_hosts = set()
            if self.graph:
                for node in self.graph._nodes.values():
                    attrs = node.attributes or {}
                    for key in ("host_uid", "asset_id", "host", "target"):
                        val = attrs.get(key)
                        if val:
                            graph_hosts.add(str(val).lower())
            covered = sum(1 for h in self._scenario_hosts if h.lower() in graph_hosts)
            coverage_ratio = covered / known_count if known_count > 0 else 1.0
            if coverage_ratio < 0.80:
                return False  # 主机覆盖率不足，不允许提前停

        # 条件 5: 发现 initial-access 后必须继续扩图 min_rounds_after_root 轮
        if self._has_initial_access_in_graph():
            if self.budget.rounds_used < self.budget.min_rounds_after_root:
                return False

        # 条件 6: 最近轮次仍有新节点入图 → 还有探索动量，不允许停
        if self._stagnation_rounds == 0:
            return False

        return True

    def _suppress_robust_stop(self) -> bool:
        """延后 robust 停止：未完成溯因 / 最小轮次 / 根因后扩图 / 攻击链不完整 / 覆盖债未清。"""
        # 覆盖债未清 → 不允许停
        if hasattr(self, '_exploration_debt'):
            if not self._exploration_debt.is_cleared(self.budget.rounds_used):
                return True
        if self.budget.rounds_used < self.budget.min_rounds_before_robust:
            return True
        if self._backward_trace_incomplete():
            return True
        if self._has_initial_access_in_graph() and self.budget.rounds_used < self.budget.min_rounds_after_root:
            return True
        # 攻击链太短，还需要继续探索
        if len(self.graph.stats().get("tactics_seen", [])) < 4:
            return True
        # 多主机场景覆盖不够（已知主机数 vs 图中主机数）
        known_hosts = len(self._scenario_hosts) if hasattr(self, '_scenario_hosts') else 0
        if known_hosts > 1:
            graph_hosts = set()
            for node in self.graph._nodes.values():
                attrs = node.attributes or {}
                for key in ("host_uid", "asset_id", "host", "target"):
                    val = attrs.get(key)
                    if val:
                        graph_hosts.add(str(val).lower())
            covered = sum(1 for h in self._scenario_hosts if h.lower() in graph_hosts)
            coverage_ratio = covered / known_hosts if known_hosts > 0 else 1.0
            if coverage_ratio < 0.80:
                return True
        # 攻击链不连通
        if not self._chain_completeness_check():
            return True
        # 动量检查：最近轮次仍有新节点入图 → 不允许停
        if self._stagnation_rounds == 0:
            return True
        return False

    def _chain_completeness_check(self) -> bool:
        """检查已发现攻击链是否连通，返回True表示连通(完整)"""
        stats = self.graph.stats()
        tactics_seen = stats.get("tactics_seen", [])
        if len(tactics_seen) < 2:
            return False  # 太少，不算完整
        # 检查kill-chain中是否有断裂（相邻tactics之间gap > 1）
        TACTIC_ORDER = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact"
        ]
        seen_indices = sorted([TACTIC_ORDER.index(t) for t in tactics_seen if t in TACTIC_ORDER])
        if len(seen_indices) < 2:
            return False
        # 如果最大gap > 2，认为不连通
        max_gap = max(seen_indices[i+1] - seen_indices[i] for i in range(len(seen_indices)-1))
        return max_gap <= 2

    def _backward_trace_incomplete(self) -> bool:
        """Late-stage alert without initial-access in graph → keep investigating."""
        tactics = {
            normalize_tactic(t)
            for t in (self.graph.stats().get("tactics_seen") or [])
        }
        if "initial-access" in tactics:
            return False
        alert_tactic = normalize_tactic(self.alert.tactic or "")
        return alert_tactic in LATE_STAGE_TACTICS

    def _build_result(self, stop_reason: str) -> InvestigationResult:
        """Construct final InvestigationResult from current state."""
        # Leading explanation
        leading_id = self.ledger.leading()
        leading_label = leading_id
        for expl in self.ledger.explanations:
            if expl.id == leading_id:
                leading_label = getattr(expl, 'title', expl.id)
                break

        # Decision based on posterior
        probs = self.ledger._get_probabilities()
        p_null = probs.get("__null__", 0.0)
        p_attack = 1.0 - p_null

        if p_attack > 0.7:
            decision = "contain_escalate"
        elif p_null > 0.7:
            decision = "dismiss_benign"
        else:
            decision = "monitor"

        unresolved_obligations = (
            self.obligations.unresolved(self.budget.rounds_used)
            if self.obligations else []
        )
        incomplete = (
            stop_reason in ("budget", "no_probes", "evidence_plateau_partial_chain", "voi_floor")
            and any(item["hard"] for item in unresolved_obligations)
        )
        if incomplete:
            decision = "escalate_incomplete"

        if self._demo_profile_enabled:
            decision, incomplete = self._apply_demo_partial_conclusion(
                decision=decision,
                incomplete=incomplete,
                stop_reason=stop_reason,
                unresolved_obligations=unresolved_obligations,
                leading_id=leading_id,
                investigation_score=p_attack - p_null,
            )

        investigation_score = p_attack - p_null

        # Alternatives
        alternatives = []
        for eid, log_p in sorted(self.ledger.log_post.items(), key=lambda x: x[1], reverse=True):
            if eid != leading_id:
                p = probs.get(eid, 0.0)
                alternatives.append({"id": eid, "investigation_weight": p})

        # Boundary calibration is independent and currently unavailable.
        boundary_decisions = {}
        try:
            contested = self.ledger.get_contested()
            for edge_id in contested:
                boundary_decisions[edge_id] = "contested"
        except (TypeError, AttributeError):
            pass

        # Counterfactuals
        counterfactuals = []
        if alternatives:
            top_alt = alternatives[0]
            counterfactuals.append(
                f"If {top_alt['id']} became the leading explanation, "
                f"the decision might change to "
                f"{'monitor' if decision == 'contain_escalate' else 'contain_escalate'}"
            )

        # Final risk
        try:
            final_risk = bayes_risk(self.ledger, self.loss)
        except Exception:
            final_risk = 0.0

        confidence = self._decision_confidence(
            investigation_score=investigation_score,
            decision=decision,
            entropy=self.ledger.entropy(),
            risk=final_risk,
        )

        return InvestigationResult(
            decision=decision,
            confidence=(
                confidence.calibrated_probability
                if confidence.confidence_status == ConfidenceStatus.STABLE
                else None
            ),
            decision_confidence=confidence,
            stop_reason=stop_reason,
            leading_explanation=leading_label,
            leading_explanation_id=leading_id,
            alternatives=alternatives,
            boundary_decisions=boundary_decisions,
            rounds_used=self.budget.rounds_used,
            total_events_processed=self.budget.probes_used,
            counterfactuals=counterfactuals,
            final_entropy=self.ledger.entropy(),
            final_risk=final_risk,
            voi_audit=list(self._voi_audit[-200:]),
            incomplete=incomplete,
            unresolved_obligations=unresolved_obligations,
            planner_audit=list(self._planner_audit),
            round_diagnostics=list(self._round_diagnostics),
        )

    def _decision_confidence(
        self,
        *,
        investigation_score: float,
        decision: str,
        entropy: float,
        risk: float,
    ) -> DecisionConfidence:
        features = dict(zip(RUNTIME_FEATURES, (
            investigation_score,
            self.ledger.margin(),
            entropy,
            risk,
        )))
        if self.decision_calibrator is None:
            estimate = ArtifactCalibrator().calibrate(features)
        else:
            estimate = self.decision_calibrator.calibrate(features)

        reasons = list(estimate.reason_codes)
        policy = self.automation_policy
        if estimate.status != ConfidenceStatus.STABLE:
            reasons.append("calibration_not_stable")
        if estimate.sample_count < int(policy["min_slice_support"]):
            reasons.append("slice_support_below_minimum")
        precision = estimate.metrics.get("precision")
        recall = estimate.metrics.get("recall")
        if precision is None or float(precision) < float(policy["min_precision"]):
            reasons.append("precision_target_not_met")
        if recall is None or float(recall) < float(policy["min_recall"]):
            reasons.append("recall_target_not_met")
        if self.obligations and hasattr(self.obligations, "open_hard"):
            if self.obligations.open_hard():
                reasons.append("unresolved_hard_obligation")
        fetch_stats = getattr(self.executor, "fetch_stats", {})
        if fetch_stats.get("coverage_truncated"):
            reasons.append("telemetry_coverage_truncated")

        interval = estimate.interval
        robust = False
        if interval is not None:
            low, high = interval
            if decision == "contain_escalate":
                robust = low >= float(policy["contain_threshold"])
            elif decision == "dismiss_benign":
                robust = high <= float(policy["dismiss_threshold"])
        if not robust:
            reasons.append("decision_not_robust_across_interval")
        if decision == "monitor":
            reasons.append("advisory_action_only")

        reason_codes = tuple(dict.fromkeys(reasons))
        automation_eligible = not reason_codes
        return DecisionConfidence(
            investigation_score=investigation_score,
            calibrated_probability=estimate.probability,
            confidence_status=estimate.status,
            calibrator_version=estimate.version,
            sample_count=estimate.sample_count,
            slice_key=estimate.slice_key,
            interval=estimate.interval,
            automation_eligible=automation_eligible,
            reason_codes=reason_codes,
            calibration_metadata=estimate.metrics,
        )

    # ═══════════════════════════════════════════════════════════════════
    # Conversion helpers
    # ═══════════════════════════════════════════════════════════════════

    def _ingest_evidence_trust(self, raw_events: list[dict]) -> None:
        """C 拍前批量入账证据信任 — 驱动 L2/似然/MANDATE/反取证义务。"""
        if not raw_events or not hasattr(self.trust, "set_context"):
            return
        try:
            from trace_agent.core.types import TrustContext

            compromised = self._host_likely_compromised()
            ctx = TrustContext(
                host=self.alert.asset_id or "",
                is_host_compromised=compromised,
                available_sources=list({
                    ev.get("source", "") for ev in raw_events if ev.get("source")
                }),
                environment_profile="production",
                current_round=self.budget.rounds_used,
            )
            self.trust.set_context(ctx)
            trust_events = []
            for ev in raw_events:
                attrs = ev.get("attributes") or {}
                trust_events.append({
                    "id": ev.get("id", ""),
                    "source": ev.get("source", ""),
                    "host": (
                        ev.get("source_host")
                        or ev.get("host")
                        or attrs.get("host_uid")
                        or attrs.get("asset_id")
                        or self.alert.asset_id
                        or ""
                    ),
                    "timestamp": ev.get("timestamp", 0),
                    "event_type": ev.get("tactic") or ev.get("technique", ""),
                    "indicators": attrs.get("anti_forensics_indicators") or [],
                })
            if hasattr(self.trust, "ingest"):
                self.trust.ingest(trust_events)
        except Exception:
            pass

    def _host_likely_compromised(self) -> bool:
        """图内已有攻击链阶段时，告警主机视为可能失陷（触发动态降权）。"""
        if not self.graph:
            return False
        tactics = self.graph.stats().get("tactics_seen") or []
        return len(tactics) >= 2

    def _probe_is_executable(self, probe: Probe) -> bool:
        """义务/合成探针仅在其 target 可解析为已知或图中主机时入池。"""
        mcp_config = getattr(self.executor, "mcp_config", None)
        operator_registry = (
            getattr(mcp_config, "operator_datasource_map", {})
            if mcp_config is not None else {}
        )
        if operator_registry and probe.operator not in operator_registry:
            return False
        target_lower = (probe.target or "").lower().strip()
        if not target_lower or target_lower in ("unknown", "ledger"):
            return False
        if self._known_hosts_lower and target_lower in self._known_hosts_lower:
            return True
        if self.graph:
            for node in self.graph._nodes.values():
                attrs = node.attributes or {}
                for key in ("host_uid", "asset_id", "host", "target"):
                    val = attrs.get(key)
                    if val and str(val).lower() == target_lower:
                        return True
        # 无 known_hosts 约束时允许（单测/MockExecutor）
        return not self._known_hosts_lower

    @staticmethod
    def _obligation_dicts_to_probes(raw: list[dict]) -> list[Probe]:
        """义务物化 dict → Probe（进统一候选池 / O 拍预占）。"""
        probes: list[Probe] = []
        for ob in raw:
            target = str(ob.get("target") or "")
            operator = str(ob.get("operator") or "")
            tactic = str(ob.get("tactic") or "discovery")
            if not target or not operator:
                continue
            probe = Probe(
                id=ob.get("id", Probe.generate_id(target, operator, tactic)),
                target=target,
                target_type="host",
                operator=operator,
                tactic=tactic,
                source="obligation",
                metadata={
                    "obligation_id": ob.get("obligation_id"),
                    "hard": ob.get("hard", False),
                    "reason_code": ob.get("reason_code"),
                    "acceptance_criterion": ob.get(
                        "acceptance_criterion", {}
                    ),
                },
                priority_hint=float(ob.get("priority", 1.0)),
            )
            probes.append(probe)
        return probes

    def _graph_to_dict(self) -> dict:
        """Convert SessionGraph to dict for ObligationLedger compatibility."""
        nodes = []
        tactics_seen: set[str] = set()
        hosts_seen: set[str] = set()
        for node in self.graph._nodes.values():
            attrs = node.attributes or {}
            tactic = node.tactic or ""
            if tactic:
                tactics_seen.add(tactic)
            for key in ("host_uid", "asset_id", "host", "target"):
                val = attrs.get(key)
                if val:
                    hosts_seen.add(str(val))
            nodes.append({
                "id": node.id,
                "technique": node.technique,
                "tactic": node.tactic,
                "timestamp": node.timestamp,
                "source": node.source,
                "trust_tier": node.trust_tier,
                "fact_confirmed": node.fact_confirmed,
                "attribution_status": node.attribution_status,
                "malicious_status": node.malicious_status,
                "malicious": node.malicious_status == "confirmed",
                "host_id": node.host_id,
                "entity_id": node.entity_id,
                "provenance": dict(node.provenance),
                "requires_parent": bool(attrs.get("requires_parent", False)),
                "type": "host" if attrs.get("host_uid") or attrs.get("host") else "event",
                "bridge_candidate": len(hosts_seen) > 1 and attrs.get("bridge_candidate", False),
                "provenance_confirmed": attrs.get(
                    "provenance_confirmed", False
                ),
                "visibility_restored": attrs.get("visibility_restored", False),
                "source_unavailable_decision": attrs.get(
                    "source_unavailable_decision", False
                ),
                "attributes": node.attributes,
            })
        edges = []
        for edge in self.graph._edges.values():
            edges.append({
                "id": edge.id,
                "src": edge.src,
                "dst": edge.dst,
                "relation": edge.relation,
                "tactic": "",
            })
        return {
            "nodes": nodes,
            "edges": edges,
            "known_hosts": list(self._scenario_hosts),
        }

    def _probe_to_dict(self, probe: Probe) -> dict:
        """Convert Probe to dict for voi() compatibility."""
        return {
            "id": probe.id,
            "type": probe.source,
            "target": probe.target,
            "target_type": probe.target_type,
            "operator": probe.operator,
            "tactic": probe.tactic,
            "learning_key": probe.learning_key(),
            "source": probe.source,
            "metadata": dict(probe.metadata),
            "cost": self.calib.cost(probe) if self.calib else 0.10,
        }

    def _beta_to_dict(self) -> dict:
        """Convert BetaLedger to dict for voi()/should_stop() compatibility."""
        result = {}
        for key in self.beta.all_keys():
            alpha, beta_val = self.beta.get_params(key)
            result[key] = {"alpha": alpha, "beta": beta_val}
        observations = [
            (key, values)
            for key, values in result.items()
            if not key.startswith("__")
        ]
        global_success = sum(max(0.0, v["alpha"] - 1.0) for _, v in observations)
        global_fail = sum(max(0.0, v["beta"] - 1.0) for _, v in observations)
        result["__global__"] = {
            "alpha": 1.0 + global_success,
            "beta": 1.0 + global_fail,
        }
        result["__tenant__:global"] = dict(result["__global__"])
        by_target: dict[str, list[dict]] = {}
        for key, values in observations:
            parts = key.split("|")
            if len(parts) >= 2:
                by_target.setdefault(parts[1], []).append(values)
        for target_type, values in by_target.items():
            result[f"__target_type__:{target_type}"] = {
                "alpha": 1.0 + sum(
                    max(0.0, item["alpha"] - 1.0) for item in values
                ),
                "beta": 1.0 + sum(
                    max(0.0, item["beta"] - 1.0) for item in values
                ),
            }
        return result

    def _calib_to_dict(self) -> dict:
        """Expose versioned cost calibration for VOI audit and persistence."""
        return self.calib.to_dict() if self.calib else {}

    def _compute_graph_stats(self) -> dict:
        """Build graph_stats dict for dual-mode VOI (exploration mode)."""
        stats = self.graph.stats()
        hosts: set[str] = set()
        tactics_per_host: dict[str, set[str]] = {}
        for node in self.graph._nodes.values():
            attrs = node.attributes or {}
            host = ""
            for key in ("host_uid", "asset_id", "host", "target"):
                val = attrs.get(key)
                if val:
                    host = str(val).lower()
                    break
            if host:
                hosts.add(host)
                tactic = normalize_tactic(node.tactic or "")
                tactics_per_host.setdefault(host, set()).add(tactic)
        return {
            "hosts": hosts,
            "tactics_seen": set(normalize_tactic(t) for t in (stats.get("tactics_seen") or [])),
            "tactics_per_host": tactics_per_host,
            "node_count": stats.get("node_count", 0),
        }

    def close(self) -> None:
        close = getattr(self.ingest, "close", None)
        if callable(close):
            close()


# ═══════════════════════════════════════════════════════════════════
# Minimal fallback trust model
# ═══════════════════════════════════════════════════════════════════

class _MinimalTrust:
    """Duck-typed minimal trust model for when full model unavailable."""
    evidence_trust_map: dict = {}

    def weight_likelihood(self, base: float, evidence_id: str) -> float:
        return base * 0.7  # moderate trust default

    def get_trust(self, evidence_id: str):
        return None

    def assess(self, event: dict):
        """Minimal trust assessment."""
        return _MinimalTrustResult()

    def ingest(self, events):
        pass


class _MinimalTrustResult:
    """Duck-typed trust assessment result."""
    integrity: float = 0.6
    adversary_controllable: bool = False
    trust_tier: str = "medium"


# ═══════════════════════════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════════════════════════

def _has_required_fields(event: dict) -> bool:
    """Check if event has the required fields for SessionGraph.add_events()."""
    return all(k in event for k in ("technique", "tactic", "timestamp", "source"))


# ═══════════════════════════════════════════════════════════════════
# Convenience function
# ═══════════════════════════════════════════════════════════════════

def run_investigation(alert: AlertEvent,
                      executor: ProbeExecutor,
                      prior_manager=None,
                      max_rounds: int = 50,
                      **kwargs) -> InvestigationResult:
    """一行启动完整 LOCK 调查。

    Usage:
        from trace_agent.agents.orchestrator import run_investigation
        from trace_agent.loop.mock_executor import MockExecutor
        from trace_agent.decision.types import AlertEvent

        alert = AlertEvent(technique_id="T1059.001", tactic="execution")
        result = run_investigation(alert, MockExecutor(MockExecutor.create_attack_scenario()))
        print(result.decision, result.decision_confidence.to_dict())
    """
    orch = DecisionOrchestrator(alert=alert, executor=executor,
                                prior_manager=prior_manager, **kwargs)
    return orch.run(max_rounds=max_rounds)


# ═══════════════════════════════════════════════════════════════════
# Backward-compatible TraceOrchestrator (legacy)
# ═══════════════════════════════════════════════════════════════════

class TraceOrchestrator:
    """Legacy orchestrator — kept for backward compatibility."""

    def __init__(self, ledger=None):
        self.ledger = ledger

    def initialize_case(self, alert: AlertEvent):
        from trace_agent.loop.state import LockState
        seed = self.ledger.seed(alert)
        # Build obligation items from seed (backward compat)
        items = []
        if seed.branch_null_anchor.benign > 0:
            items.append({"type": "boundary_check", "target": "benign_null_anchor",
                          "priority": "medium", "reason": "benign null anchor present", "policy": "voi_gated"})
        if seed.branch_null_anchor.oos > 0:
            items.append({"type": "boundary_check", "target": "oos_null_anchor",
                          "priority": "medium", "reason": "out-of-scope null anchor present", "policy": "voi_gated"})
        for edge in seed.contested_edges:
            items.append({"type": "contested_edge_boundary", "target": f"{edge.src}->{edge.dst}",
                          "priority": "medium", "reason": edge.reason,
                          "boundary_prior": edge.boundary_prior, "policy": "voi_gated"})
        return LockState(
            alert=alert,
            phase="L_INITIALIZED",
            decision_ledger_seed=seed,
            graph_ledger={"status": "initialized", "nodes": [], "edges": [],
                          "seed_technique": seed.alert.technique_id,
                          "candidate_edges": [{"src": e.src, "dst": e.dst,
                              "boundary_prior": e.boundary_prior, "support": e.support}
                              for e in seed.contested_edges]},
            beta_ledger={"status": "initialized", "probe_priors": {}},
            obligation_ledger={"status": "initialized", "items": items},
            recommended_probes=[{"type": "log_source_probe", "explanation_id": expl.id,
                "log_source": src.get("log_source"), "available": src.get("available"),
                "trust": src.get("trust"), "tier": src.get("tier"),
                "reason": "seed recommended log source"}
                for expl in seed.explanations for src in expl.recommended_log_sources],
            case_metadata={
                "explanation_count": len(seed.explanations),
                "contested_edge_count": len(seed.contested_edges),
                "has_null_anchor": True,
                "source": "DecisionLedger.seed",
            },
        )
