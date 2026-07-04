"""modular_orchestrator — 用拍级执行器组合驱动的 LOCK 编排器。

支持两种运行模式：
1. run() — 跑完整循环直到停止（等价原 DecisionOrchestrator.run()）
2. run_phase(phase_name) — 执行单个拍并返回 PhaseResult（供 deep-agent 工具层调用）

替代原单体 DecisionOrchestrator 循环，通过 LOCKSession + 五个 PhaseExecutor
（L / Veto / O / C / K）组合实现完整的 LOCK 调查流程。
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from trace_agent.agents.lock_session import LOCKSession, BudgetState
from trace_agent.agents.orchestrator import InvestigationResult
from trace_agent.decision.calibrator import ArtifactCalibrator, RUNTIME_FEATURES
from trace_agent.decision.runtime_types import ConfidenceStatus, DecisionConfidence
from trace_agent.loop.model_probe_planner import NullProbePlanner, ProbeIntentValidator
from trace_agent.probe.voi_engine import bayes_risk

from trace_agent.phases.base import PhaseResult
from trace_agent.phases.l_phase import LPhaseExecutor
from trace_agent.phases.veto_phase import VetoPhaseExecutor
from trace_agent.phases.o_phase import OPhaseExecutor
from trace_agent.phases.c_phase import CPhaseExecutor
from trace_agent.phases.k_phase import KPhaseExecutor

logger = logging.getLogger(__name__)

# 拍名称 → 前置条件（拍名集合）
_PHASE_PREREQUISITES: dict[str, set[str]] = {
    "L": set(),
    "Veto": {"L"},
    "O": {"L", "Veto"},
    "C": {"L", "Veto", "O"},
    "K": {"L", "Veto", "O", "C"},
}


class ModularOrchestrator:
    """用拍级执行器组合驱动的 LOCK 编排器。

    支持两种运行模式：
    1. run() — 跑完整循环直到停止（等价原 DecisionOrchestrator.run()）
    2. run_phase(phase_name) — 执行单个拍并返回 PhaseResult（供 deep-agent 工具层调用）
    """

    def __init__(
        self,
        session: LOCKSession,
        *,
        probe_planner=None,
        planner_mode: str = "shadow",
        planner_max_intents: int = 4,
        planner_cost_budget: float = 1.0,
        planner_max_graph_nodes: int = 40,
        demo_profile_enabled: bool = False,
        demo_plateau_rounds: int = 5,
        demo_min_graph_nodes: int = 8,
        demo_min_graph_edges: int = 6,
    ):
        self.session = session

        # ── 共享审计列表（跨轮次累积）──
        self._voi_audit: list[dict[str, Any]] = []
        self._planner_audit: list[dict[str, Any]] = []
        self._posterior_history: list[float] = []
        self._round_diagnostics: list[dict[str, Any]] = []

        # ── 五个拍级执行器 ──
        planner_validator = ProbeIntentValidator()
        planner_recent_query_keys = getattr(
            session, "_planner_recent_query_keys", None
        ) or set()

        self.l_phase = LPhaseExecutor(
            probe_planner=probe_planner or NullProbePlanner(),
            planner_mode=planner_mode,
            planner_max_intents=planner_max_intents,
            planner_cost_budget=planner_cost_budget,
            planner_max_graph_nodes=planner_max_graph_nodes,
            planner_validator=planner_validator,
            planner_audit=self._planner_audit,
            planner_recent_query_keys=planner_recent_query_keys,
        )
        self.veto_phase = VetoPhaseExecutor()
        self.o_phase = OPhaseExecutor(voi_audit=self._voi_audit)
        self.c_phase = CPhaseExecutor()
        self.k_phase = KPhaseExecutor(
            posterior_history=self._posterior_history,
            round_diagnostics=self._round_diagnostics,
            demo_profile_enabled=demo_profile_enabled,
            demo_plateau_rounds=demo_plateau_rounds,
            demo_min_graph_nodes=demo_min_graph_nodes,
            demo_min_graph_edges=demo_min_graph_edges,
        )

        # ── Demo profile 标志（供 _build_result 使用）──
        self._demo_profile_enabled = demo_profile_enabled

        # ── 已执行的拍跟踪（供 run_phase 前置条件检查）──
        self._executed_phases: set[str] = set()

    # ------------------------------------------------------------------
    # 公开 API
    # ------------------------------------------------------------------

    def run(self, max_rounds: Optional[int] = None) -> InvestigationResult:
        """完整 LOCK 循环，等价原 DecisionOrchestrator.run()。

        Args:
            max_rounds: 可选最大轮次覆盖

        Returns:
            InvestigationResult 与原编排器返回结构完全兼容
        """
        if max_rounds is not None and self.session.budget:
            self.session.budget.total_rounds = max_rounds

        self._emit_progress({
            "stage": "lock_loop",
            "phase": "bootstrap",
            "round": 0,
            "status": "completed",
            "graph_nodes": self.session.graph.stats().get("node_count", 0)
            if self.session.graph else 0,
        })

        # ═══ Main Loop ═══
        while not self._budget_exhausted():
            should_stop, k_result = self.run_one_round()

            if should_stop:
                stop_reason = "no_probes"
                if k_result and k_result.data.get("stop_decision"):
                    stop_reason = k_result.data["stop_decision"].reason or "robust"
                elif self._budget_exhausted():
                    stop_reason = "budget"
                return self._build_result(stop_reason)

        # Budget exhausted
        return self._build_result(
            "budget" if self._budget_exhausted() else "no_probes"
        )

    def run_phase(self, phase_name: str) -> PhaseResult:
        """执行单个拍: 'L' / 'Veto' / 'O' / 'C' / 'K'。

        每个拍可独立调用，但会检查前置条件。

        Args:
            phase_name: 拍名称

        Returns:
            PhaseResult

        Raises:
            ValueError: 无效的拍名称
            RuntimeError: 前置条件未满足
        """
        phase_name = phase_name.strip()
        if phase_name not in _PHASE_PREREQUISITES:
            raise ValueError(
                f"Unknown phase '{phase_name}'. "
                f"Valid: {list(_PHASE_PREREQUISITES.keys())}"
            )

        # 前置条件检查
        missing = _PHASE_PREREQUISITES[phase_name] - self._executed_phases
        if missing:
            raise RuntimeError(
                f"Phase '{phase_name}' requires {sorted(missing)} "
                f"to be executed first. Missing: {sorted(missing)}"
            )

        # 预算检查
        if self._budget_exhausted():
            return PhaseResult(
                phase=phase_name,
                success=False,
                data={"reason": "budget_exhausted"},
                progress_event={"phase": phase_name, "status": "skipped", "reason": "budget"},
            )

        result = self._execute_phase(phase_name)
        self._executed_phases.add(phase_name)
        return result

    def run_one_round(self) -> tuple[bool, PhaseResult]:
        """执行一轮完整 L→Veto→O→C→K，返回 (should_stop, k_result)。

        Returns:
            (should_stop, k_result): should_stop 为 True 时应停止循环
        """
        session = self.session
        budget = session.budget

        # 轮次递增
        budget.rounds_used += 1
        session.round = budget.rounds_used
        round_no = budget.rounds_used

        # ── L 拍 ──
        self._emit_progress({
            "stage": "lock_loop", "phase": "L", "round": round_no,
            "status": "running",
        })
        l_result = self._execute_phase("L")
        self._emit_progress({
            "stage": "lock_loop", "phase": "L", "round": round_no,
            "status": "completed",
            "candidate_count": l_result.data.get("candidates_count", 0),
            "model_planner": (
                dict(self._planner_audit[-1])
                if self._planner_audit
                and self._planner_audit[-1].get("round") == round_no
                else None
            ),
        })

        # L→Veto 传递 pool
        pool = l_result.data.get("pool")
        if pool is not None:
            session.data["pool"] = pool

        # ── Veto 拍 ──
        veto_result = self._execute_phase("Veto")
        self._emit_progress({
            "stage": "lock_loop", "phase": "Veto", "round": round_no,
            "status": "completed",
            "candidate_count": len(veto_result.data.get("surviving_pool", [])),
        })

        # Veto→O 传递 pool
        veto_pool = veto_result.data.get("pool")
        if veto_pool is not None:
            session.data["pool"] = veto_pool

        # ── O 拍 ──
        o_result = self._execute_phase("O")
        chosen = o_result.data.get("chosen", [])
        self._emit_progress({
            "stage": "lock_loop", "phase": "O", "round": round_no,
            "status": "completed",
            "probes_selected": [p.operator for p in chosen] if chosen else [],
        })

        if not chosen:
            # No viable probes — 提前结束本轮
            self._emit_progress({
                "stage": "lock_loop", "phase": "K", "round": round_no,
                "status": "stopped", "stop_reason": "no_probes",
            })
            empty_k = PhaseResult(
                phase="K", success=True, should_stop=True,
                data={"stop_decision": None, "reason": "no_probes"},
                progress_event={"phase": "K", "status": "stopped", "stop_reason": "no_probes"},
            )
            return True, empty_k

        # O→C 传递 chosen
        session.data["chosen"] = chosen

        # ── C 拍 ──
        c_result = self._execute_phase("C")
        ingest_result = c_result.data.get("ingest_result")
        routed = getattr(ingest_result, "routed", {}) or {}
        judgement_stats = getattr(
            session.ingest, "llm_stats", {"mode": "off"}
        )
        judgement_audit = list(judgement_stats.get("audit") or [])
        self._emit_progress({
            "stage": "lock_loop", "phase": "C", "round": round_no,
            "status": "completed",
            "events": c_result.data.get("events_fetched", 0),
            "attached": len(routed.get("ATTACH", [])),
            "wazuh_queries": c_result.data.get("wazuh_queries", []),
            "mcp_compiler_audit": c_result.data.get(
                "mcp_compiler_audit"
            ),
            "model_judgement": {
                "mode": judgement_stats.get("mode", "off"),
                "provider_status": judgement_stats.get(
                    "provider_status", "disabled"
                ),
                "l3_llm_calls": judgement_stats.get("l3_llm_calls", 0),
                "provider_errors": judgement_stats.get("provider_errors", 0),
                "shadow_summary": judgement_stats.get("shadow_summary") or {},
                "latest_audit": judgement_audit[-1] if judgement_audit else None,
            },
        })

        # C→K 传递 ingest_result
        session.data["ingest_result"] = ingest_result

        # ── K 拍 ──
        k_result = self._execute_phase("K")
        diagnostic = (
            dict(self._round_diagnostics[-1])
            if self._round_diagnostics else {}
        )
        self._emit_progress({
            "stage": "lock_loop", "phase": "K", "round": round_no,
            "status": "stopped" if k_result.should_stop else "completed",
            **diagnostic,
            "stop_should_stop": k_result.should_stop,
            "stop_reason_candidate": (
                k_result.data.get("stop_decision", {}).reason
                if hasattr(k_result.data.get("stop_decision", {}), "reason")
                else ""
            ),
        })

        # 更新 prev_stats 供下轮使用
        session.prev_stats = session.graph.stats() if session.graph else {}

        # 更新已执行拍集合（一轮完成后全部就绪）
        self._executed_phases = {"L", "Veto", "O", "C", "K"}

        return k_result.should_stop, k_result

    def should_stop(self) -> bool:
        """基于 K 拍的最新结果判断是否应停止。"""
        if self._round_diagnostics:
            last = self._round_diagnostics[-1]
            return bool(last.get("stop_should_stop", False))
        return False

    def close(self) -> None:
        """清理资源（关闭 ingest pipeline 等）。"""
        ingest = getattr(self.session, "ingest", None)
        if ingest is not None:
            close_fn = getattr(ingest, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception:
                    pass
        planner = getattr(self.l_phase, "probe_planner", None)
        close_fn = getattr(planner, "close", None)
        if callable(close_fn):
            try:
                close_fn()
            except Exception:
                pass
        mcp_runtime = getattr(self.session, "mcp_runtime", None)
        close_fn = getattr(mcp_runtime, "close", None)
        if callable(close_fn):
            try:
                close_fn()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # 内部：执行单个拍
    # ------------------------------------------------------------------

    def _execute_phase(self, phase_name: str) -> PhaseResult:
        """路由到对应的 PhaseExecutor.execute()。"""
        executor_map = {
            "L": self.l_phase,
            "Veto": self.veto_phase,
            "O": self.o_phase,
            "C": self.c_phase,
            "K": self.k_phase,
        }
        phase_executor = executor_map[phase_name]
        try:
            return phase_executor.execute(self.session)
        except Exception as exc:
            logger.error("[ModularOrchestrator] phase '%s' failed: %s", phase_name, exc)
            return PhaseResult(
                phase=phase_name,
                success=False,
                data={"error": str(exc)},
                progress_event={"phase": phase_name, "status": "error", "error": str(exc)},
            )

    # ------------------------------------------------------------------
    # 内部：进度 & 预算
    # ------------------------------------------------------------------

    def _emit_progress(self, event: dict[str, Any]) -> None:
        """发送进度回调，容错。"""
        cb = getattr(self.session, "progress_cb", None)
        if not callable(cb):
            return
        try:
            cb(dict(event))
        except Exception:
            pass

    def _budget_exhausted(self) -> bool:
        """检查预算是否耗尽。"""
        budget = self.session.budget
        if budget is None:
            return True
        return budget.exhausted()

    # ------------------------------------------------------------------
    # 内部：构建 InvestigationResult
    # ------------------------------------------------------------------

    def _build_result(self, stop_reason: str) -> InvestigationResult:
        """从 session 组装最终 InvestigationResult。

        忠实复制原 DecisionOrchestrator._build_result() 逻辑。
        """
        session = self.session
        ledger = session.ledger
        budget = session.budget
        obligations = session.obligations
        loss = session.loss

        # Leading explanation
        leading_id = ledger.leading()
        leading_label = leading_id
        for expl in ledger.explanations:
            if expl.id == leading_id:
                leading_label = getattr(expl, "title", expl.id)
                break

        # Decision based on posterior
        probs = ledger._get_probabilities()
        p_null = probs.get("__null__", 0.0)
        p_attack = 1.0 - p_null

        if p_attack > 0.7:
            decision = "contain_escalate"
        elif p_null > 0.7:
            decision = "dismiss_benign"
        else:
            decision = "monitor"

        unresolved_obligations = (
            obligations.unresolved(budget.rounds_used)
            if obligations else []
        )
        incomplete = (
            stop_reason in (
                "budget", "no_probes", "evidence_plateau_partial_chain", "voi_floor"
            )
            and any(
                item.get("hard") if isinstance(item, dict) else getattr(item, "hard", False)
                for item in unresolved_obligations
            )
        )
        if incomplete:
            decision = "escalate_incomplete"

        # Demo partial conclusion
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
        for eid, log_p in sorted(
            ledger.log_post.items(), key=lambda x: x[1], reverse=True
        ):
            if eid != leading_id:
                p = probs.get(eid, 0.0)
                alternatives.append({"id": eid, "investigation_weight": p})

        # Boundary decisions
        boundary_decisions: dict = {}
        try:
            contested = ledger.get_contested()
            for edge_id in contested:
                boundary_decisions[edge_id] = "contested"
        except (TypeError, AttributeError):
            pass

        # Counterfactuals
        counterfactuals: list[str] = []
        if alternatives:
            top_alt = alternatives[0]
            counterfactuals.append(
                f"If {top_alt['id']} became the leading explanation, "
                f"the decision might change to "
                f"{'monitor' if decision == 'contain_escalate' else 'contain_escalate'}"
            )

        # Final risk
        try:
            final_risk = bayes_risk(ledger, loss)
        except Exception:
            final_risk = 0.0

        # Decision confidence
        confidence = self._decision_confidence(
            investigation_score=investigation_score,
            decision=decision,
            entropy=ledger.entropy(),
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
            rounds_used=budget.rounds_used,
            total_events_processed=budget.probes_used,
            counterfactuals=counterfactuals,
            final_entropy=ledger.entropy(),
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
        """计算决策置信度，忠实复制原编排器逻辑。"""
        session = self.session
        features = dict(zip(RUNTIME_FEATURES, (
            investigation_score,
            session.ledger.margin(),
            entropy,
            risk,
        )))
        calibrator = getattr(session, "artifact_calibrator", None)
        if calibrator is None:
            estimate = ArtifactCalibrator().calibrate(features)
        else:
            estimate = calibrator.calibrate(features)

        reasons = list(estimate.reason_codes)
        policy = session.automation_policy
        if estimate.status != ConfidenceStatus.STABLE:
            reasons.append("calibration_not_stable")
        if estimate.sample_count < int(policy.get("min_slice_support", 80)):
            reasons.append("slice_support_below_minimum")
        precision = estimate.metrics.get("precision")
        recall = estimate.metrics.get("recall")
        if precision is None or float(precision) < float(policy.get("min_precision", 0.90)):
            reasons.append("precision_target_not_met")
        if recall is None or float(recall) < float(policy.get("min_recall", 0.80)):
            reasons.append("recall_target_not_met")
        if session.obligations and hasattr(session.obligations, "open_hard"):
            if session.obligations.open_hard():
                reasons.append("unresolved_hard_obligation")
        fetch_stats = getattr(session.executor, "fetch_stats", {})
        if fetch_stats.get("coverage_truncated"):
            reasons.append("telemetry_coverage_truncated")

        interval = estimate.interval
        robust = False
        if interval is not None:
            low, high = interval
            if decision == "contain_escalate":
                robust = low >= float(policy.get("contain_threshold", 0.70))
            elif decision == "dismiss_benign":
                robust = high <= float(policy.get("dismiss_threshold", 0.30))
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

    def _apply_demo_partial_conclusion(
        self,
        *,
        decision: str,
        incomplete: bool,
        stop_reason: str,
        unresolved_obligations: list,
        leading_id: str,
        investigation_score: float,
    ) -> tuple[str, bool]:
        """Demo profile: 允许部分结论提升。

        忠实复制原 DecisionOrchestrator._apply_demo_partial_conclusion()。
        """
        if stop_reason not in (
            "evidence_plateau_partial_chain",
            "budget",
            "no_probes",
            "voi_floor",
        ):
            return decision, incomplete

        has_partial_evidence = investigation_score > 0.15
        has_unresolved = bool(unresolved_obligations)

        if has_partial_evidence and has_unresolved:
            if decision == "monitor":
                decision = "escalate_incomplete"
                incomplete = True

        return decision, incomplete
