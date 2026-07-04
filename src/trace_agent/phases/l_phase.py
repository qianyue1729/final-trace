"""l_phase — L 拍：候选生成。

从 DecisionOrchestrator._l_phase() 忠实提取，通过 LOCKSession 读写状态。
"""
from __future__ import annotations

import logging
from typing import Any

from trace_agent.agents.lock_session import LOCKSession
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.loop.generators import (
    prior_generator,
    rule_gap_generator,
    cross_host_probe_generator,
    chain_follow_generator,
    structural_debt_generator,
    lifecycle_template_generator,
    clue_pivot_probe_generator,
)
from trace_agent.loop.probe import Probe

from .base import PhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class LPhaseExecutor(PhaseExecutor):
    """L 拍：候选生成。

    调用 6 个生成器 + 可选模型规划器，产出候选 Probe 列表投入统一池。
    """

    def __init__(
        self,
        probe_planner=None,
        planner_mode: str = "shadow",
        planner_max_intents: int = 4,
        planner_cost_budget: float = 1.0,
        planner_max_graph_nodes: int = 40,
        planner_validator=None,
        planner_audit: list | None = None,
        planner_recent_query_keys: set | None = None,
    ):
        self.probe_planner = probe_planner
        self.planner_mode = planner_mode
        self.planner_max_intents = max(0, planner_max_intents)
        self.planner_cost_budget = max(0.0, planner_cost_budget)
        self.planner_max_graph_nodes = max(1, planner_max_graph_nodes)
        self.planner_validator = planner_validator
        self.planner_audit = planner_audit if planner_audit is not None else []
        self.planner_recent_query_keys = (
            planner_recent_query_keys if planner_recent_query_keys is not None else set()
        )

    def execute(self, session: LOCKSession) -> PhaseResult:
        """执行 L 拍：生成候选探针池。"""
        pool = CandidatePool()
        prev_stats = session.prev_stats or {}
        generators = [
            ("prior", self._gen_prior, session, pool),
            ("rule_gap", self._gen_rule_gap, session, pool),
            ("cross_host", self._gen_cross_host, session, pool),
            ("chain_follow", self._gen_chain_follow, session, pool),
            ("structural_debt", self._gen_structural_debt, session, pool),
            ("lifecycle", self._gen_lifecycle, session, pool),
            ("clue_pivot", self._gen_clue_pivot, session, pool),
        ]
        summary: dict[str, int] = {}
        for name, gen_fn, *args in generators:
            added = gen_fn(session, pool)
            summary[name] = added

        # Model planner (optional)
        planner_probes = self._model_planner_phase(session, pool)
        for probe in planner_probes:
            pool.add([probe])
        summary["model_planner"] = len(planner_probes)
        planner_audit = (
            dict(self.planner_audit[-1])
            if self.planner_audit
            and self.planner_audit[-1].get("round")
            == session.budget.rounds_used
            else None
        )

        candidates = pool.peek()
        return PhaseResult(
            phase="L",
            success=True,
            data={
                "candidates_count": len(candidates),
                "pool_summary": summary,
                "pool": pool,
                "model_planner": planner_audit,
            },
            progress_event={
                "phase": "L",
                "status": "completed",
                "candidate_count": len(candidates),
                "model_planner": planner_audit,
            },
        )

    # ------------------------------------------------------------------
    # Generator wrappers
    # ------------------------------------------------------------------

    def _gen_prior(self, session: LOCKSession, pool: CandidatePool) -> int:
        try:
            probes = prior_generator(session.graph, session.ledger, session.prior_manager)
            return pool.add(probes)
        except Exception:
            return 0

    def _gen_rule_gap(self, session: LOCKSession, pool: CandidatePool) -> int:
        try:
            probes = rule_gap_generator(session.graph, session.prev_stats or {})
            return pool.add(probes)
        except Exception:
            return 0

    def _gen_cross_host(self, session: LOCKSession, pool: CandidatePool) -> int:
        try:
            known_hosts_fn = getattr(session.executor, "known_hosts", None)
            if callable(known_hosts_fn):
                probes = cross_host_probe_generator(
                    session.graph,
                    known_hosts_fn(),
                    alert_asset=session.alert.asset_id or "",
                )
                return pool.add(probes)
        except Exception:
            pass
        return 0

    def _gen_chain_follow(self, session: LOCKSession, pool: CandidatePool) -> int:
        try:
            probes = chain_follow_generator(session.graph)
            return pool.add(probes)
        except Exception:
            return 0

    def _gen_structural_debt(self, session: LOCKSession, pool: CandidatePool) -> int:
        try:
            probes = structural_debt_generator(session.graph, session.ledger)
            return pool.add(probes)
        except Exception:
            return 0

    def _gen_lifecycle(self, session: LOCKSession, pool: CandidatePool) -> int:
        try:
            probes = lifecycle_template_generator(session.graph)
            return pool.add(probes)
        except Exception:
            return 0

    def _gen_clue_pivot(self, session: LOCKSession, pool: CandidatePool) -> int:
        try:
            mcp_config = getattr(session.executor, "mcp_config", None)
            rules = getattr(mcp_config, "clue_pivot_rules", None) if mcp_config else None
            if not rules:
                return 0
            cached = list(getattr(session.executor, "_events", []) or [])
            probes = clue_pivot_probe_generator(session.graph, rules, cached)
            return pool.add(probes)
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Model planner
    # ------------------------------------------------------------------

    def _model_planner_phase(self, session: LOCKSession, rule_pool: CandidatePool) -> list[Probe]:
        """Optional model planner phase — faithful port from orchestrator."""
        if self.planner_mode == "off" or self.planner_max_intents <= 0:
            return []
        if self.probe_planner is None:
            return []
        try:
            context = self._planner_context(session)
            result = self.probe_planner.plan(context)
            rule_keys = {probe.dedup_key() for probe in rule_pool.peek()}
            validated = []
            assist_probes: list[Probe] = []
            for intent in result.intents[:self.planner_max_intents]:
                probe_cost = (
                    session.decision_calibrator.cost({"operator": intent.operator, "target_type": "host"})
                    if session.decision_calibrator else 0.10
                )
                check = self.planner_validator.validate(
                    intent, context, projected_cost=probe_cost,
                ) if self.planner_validator else _NullCheck()
                projected_voi = None
                overlap = False
                if check.accepted and check.target_host:
                    probe = Probe(
                        id=Probe.generate_id(check.target_host, intent.operator, intent.tactic),
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
                        from trace_agent.probe.voi_engine import voi
                        from ._helpers import (
                            probe_to_dict, beta_to_dict, calib_to_dict, compute_graph_stats,
                        )
                        projected_voi = voi(
                            probe_to_dict(probe, session.decision_calibrator),
                            session.ledger,
                            beta_to_dict(session.beta),
                            calib_to_dict(session.decision_calibrator),
                            session.loss,
                            session.trust,
                            graph_stats=compute_graph_stats(session.graph),
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
            self.planner_audit.append({
                "round": session.budget.rounds_used,
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
        except Exception as exc:
            logger.warning("[LPhase] model planner failed: %s", exc)
            return []

    def _planner_context(self, session: LOCKSession):
        """Build PlannerContext — faithful port from orchestrator."""
        from trace_agent.loop.model_probe_planner import PlannerContext, PlannerTimeWindow
        from trace_agent.decision.runtime_types import ConfidenceStatus
        from ._helpers import graph_to_dict

        nodes = list(session.graph._nodes.values())[-self.planner_max_graph_nodes:]
        node_ids = {str(node.id) for node in nodes}
        graph = {
            "nodes": [
                {"id": str(node.id), "technique": node.technique,
                 "tactic": node.tactic, "host_id": node.host_id,
                 "attribution_status": node.attribution_status}
                for node in nodes
            ],
            "edges": [
                {"id": str(edge.id), "src": str(edge.src), "dst": str(edge.dst),
                 "relation": edge.relation}
                for edge in session.graph._edges.values()
                if str(edge.src) in node_ids or str(edge.dst) in node_ids
            ],
        }
        entities: dict[str, dict[str, Any]] = {}
        for host in (session._scenario_hosts or []):
            entities[f"host:{host}"] = {"host_id": host, "type": "host"}
        for node in nodes:
            if node.host_id:
                entities[str(node.id)] = {"host_id": node.host_id, "type": "event"}
                entities.setdefault(f"host:{node.host_id}", {"host_id": node.host_id, "type": "host"})
        mcp_config = getattr(session.executor, "mcp_config", None)
        operators = dict(getattr(mcp_config, "operator_datasource_map", {}) or {})
        if not operators:
            try:
                from trace_agent.loop.scenario_executor import OPERATOR_ACTION_MAP
                operators = {name: "local" for name in OPERATOR_ACTION_MAP}
            except Exception:
                pass
        capabilities = getattr(getattr(session.executor, "transport", None), "capabilities", None)
        dimensions = set(getattr(capabilities, "supported_query_dimensions", {"host"}))
        window_fn = getattr(session.executor, "_window_ms", None)
        if callable(window_fn):
            from_ms, to_ms = window_fn()
        else:
            cursor = int(getattr(session.executor, "_time_cursor", 0) * 1000)
            from_ms, to_ms = 0, max(0, cursor)
        explanations = [
            {"id": e.id, "title": e.title, "stage": e.stage,
             "investigation_weight": session.ledger.posterior(e.id)}
            for e in session.ledger.explanations
        ]
        obligations = (
            session.obligations.unresolved(session.budget.rounds_used)
            if session.obligations else []
        )
        evidence_refs = node_ids | {item["id"] for item in obligations}
        status = getattr(session.decision_calibrator, "status", ConfidenceStatus.UNAVAILABLE)
        try:
            from trace_agent.loop.investigation_guidance import guidance_for
        except Exception:
            guidance_for = None
        investigation_guidance: list[dict[str, Any]] = []
        if guidance_for:
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
                status.value if isinstance(status, ConfidenceStatus) else str(status)
            ),
            obligations=obligations,
            entities=entities,
            operators=operators,
            supported_query_dimensions=dimensions,
            allowed_window=PlannerTimeWindow(from_ms, to_ms),
            budget_remaining=max(0, session.budget.total_probes - session.budget.probes_used),
            cost_remaining=self.planner_cost_budget,
            evidence_refs=evidence_refs,
            recent_query_keys=set(self.planner_recent_query_keys),
            recent_probe_outcomes=list((session._exploration_debt and []) or []),
            investigation_guidance=investigation_guidance,
        )


class _NullCheck:
    """Fallback validator result when no validator is configured."""
    accepted: bool = True
    reason_codes: tuple = ()
    target_host: str = ""
    datasource: str = ""
    projected_cost: float = 0.10
