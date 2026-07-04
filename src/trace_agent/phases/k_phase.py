"""k_phase — K 拍：收尾（学习 + 决策账更新 + 停止判定 + 自适应策略）。

从 DecisionOrchestrator._k_phase() 及其辅助方法忠实提取，
通过 LOCKSession 读写状态。
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from trace_agent.agents.lock_session import LOCKSession
from trace_agent.decision.runtime_types import StopDecision
from trace_agent.loop.generators import LATE_STAGE_TACTICS, normalize_tactic
from trace_agent.probe.voi_engine import bayes_risk, should_stop
from trace_agent.utils.config import K_MAX

from ._helpers import (
    beta_to_dict,
    calib_to_dict,
    compute_graph_stats,
    get_graph_hosts,
    graph_to_dict,
    has_initial_access_in_graph,
    has_required_fields,
    obligation_dicts_to_probes,
    probe_to_dict,
)
from .base import PhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


def _decision_explanations(session: LOCKSession) -> list[dict[str, Any]]:
    ledger = session.ledger
    probs = ledger._get_probabilities() if ledger is not None else {}
    rows: list[dict[str, Any]] = []
    for expl in getattr(ledger, "explanations", []) or []:
        eid = str(getattr(expl, "id", "") or "")
        if not eid:
            continue
        rows.append({
            "eid": eid,
            "label": str(getattr(expl, "title", "") or eid),
            "posterior": float(probs.get(eid, 0.0) or 0.0),
            "is_null": False,
            "null_kind": None,
        })
    null_anchor = getattr(ledger, "null_anchor", None)
    if null_anchor is not None:
        rows.append({
            "eid": "__null__",
            "label": "null_anchor",
            "posterior": float(probs.get("__null__", 0.0) or 0.0),
            "is_null": True,
            "null_kind": (
                f"benign={getattr(null_anchor, 'benign', 0.0)},"
                f"oos={getattr(null_anchor, 'oos', 0.0)}"
            ),
        })
    return rows


def _contested_edges(session: LOCKSession) -> list[dict[str, Any]]:
    ledger = session.ledger
    rows: list[dict[str, Any]] = []
    for edge_id, belief in (getattr(ledger, "contested", {}) or {}).items():
        rows.append({
            "edge_id": str(edge_id),
            "p_in": float(getattr(belief, "p_in_attack", 0.0) or 0.0),
            "p_benign": float(getattr(belief, "p_benign", 0.0) or 0.0),
            "p_oos": float(getattr(belief, "p_oos", 0.0) or 0.0),
        })
    return rows


def _beta_update_rows(
    session: LOCKSession,
    chosen: list,
    graph_events: list[dict],
) -> list[dict[str, Any]]:
    beta = session.beta
    if beta is None:
        return []
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for probe in chosen:
        key = probe.learning_key()
        if key in seen:
            continue
        seen.add(key)
        hit = any(
            event.get("probe_id") == probe.id or event.get("tactic") == probe.tactic
            for event in graph_events
        )
        alpha, beta_value = beta.get_params(key)
        rows.append({
            "probe_key": key,
            "hit": bool(hit),
            "new_alpha": float(alpha),
            "new_beta": float(beta_value),
        })
    return rows


def _obligation_counts(session: LOCKSession) -> dict[str, int]:
    ledger = session.obligations
    obligations = list(getattr(ledger, "obligations", []) or [])
    current_round = int(
        session.round
        or getattr(getattr(session, "budget", None), "rounds_used", 0)
        or 0
    )
    open_count = 0
    discharged_count = 0
    overdue_count = 0
    for obligation in obligations:
        if getattr(obligation, "discharged", False):
            discharged_count += 1
            continue
        open_count += 1
        is_overdue = getattr(obligation, "is_overdue", None)
        if callable(is_overdue) and is_overdue(current_round):
            overdue_count += 1
    return {
        "open": open_count,
        "discharged": discharged_count,
        "overdue": overdue_count,
    }


class KPhaseExecutor(PhaseExecutor):
    """K 拍：学习 + 决策账更新 + 停止判定 + 自适应策略。"""

    def __init__(
        self,
        posterior_history: list | None = None,
        round_diagnostics: list | None = None,
        stagnation_rounds: int = 0,
        explore_weight: float = 1.0,
        force_new_host_probe: bool = False,
        calibration_diag_cursor: int = 0,
        demo_profile_enabled: bool = False,
        demo_plateau_rounds: int = 5,
        demo_min_graph_nodes: int = 8,
        demo_min_graph_edges: int = 6,
    ):
        self.posterior_history = posterior_history if posterior_history is not None else []
        self.round_diagnostics = round_diagnostics if round_diagnostics is not None else []
        self.stagnation_rounds = stagnation_rounds
        self.explore_weight = explore_weight
        self.force_new_host_probe = force_new_host_probe
        self.calibration_diag_cursor = calibration_diag_cursor
        self.demo_profile_enabled = demo_profile_enabled
        self.demo_plateau_rounds = max(1, demo_plateau_rounds)
        self.demo_min_graph_nodes = max(1, demo_min_graph_nodes)
        self.demo_min_graph_edges = max(0, demo_min_graph_edges)

    def execute(self, session: LOCKSession) -> PhaseResult:
        """执行 K 拍。

        session.data["chosen"] — O 拍选出的探针列表
        session.data["ingest_result"] — C 拍入图结果
        """
        chosen = session.data.get("chosen", [])
        ingest_result = session.data.get("ingest_result")

        from trace_agent.loop.ingest import ROUTE_DISCARD

        prev_node_count = session.graph.stats().get("node_count", 0)
        prev_edge_count = session.graph.stats().get("edge_count", 0)
        probs_before = session.ledger._get_probabilities()
        p_atk_before = round(1.0 - probs_before.get("__null__", 0.0), 6)

        graph_events = [
            e for e in getattr(ingest_result, "graph_eligible", [])
            if has_required_fields(e)
        ]
        attribution_confirmed = list(ingest_result.confirmed) if ingest_result else []

        # 1. Graph update — fact-confirmed events
        if graph_events:
            session.graph.add_events(graph_events)
            if hasattr(session.executor, "commit_event_refs"):
                session.executor.commit_event_refs([
                    str(e.get("id")) for e in graph_events if e.get("id")
                ])

        # Hard-discard permanently commits executor refs
        discarded = (ingest_result.routed.get(ROUTE_DISCARD, []) if ingest_result else [])
        if discarded and hasattr(session.executor, "commit_event_refs"):
            session.executor.commit_event_refs([
                str(e.get("id")) for e in discarded if e.get("id")
            ])

        # 2. Decision ledger Bayesian update
        if graph_events:
            try:
                session.ledger.update(graph_events, session.trust)
            except Exception as exc:
                logger.warning("[KPhase] ledger.update failed: %s", exc)

        # 2b. K 拍证据修订级联
        self._k_revision_cascade(session)

        # 3. Abductive maintenance
        try:
            session.ledger.spawn_merge_cull(attribution_confirmed, session.trust, budget=K_MAX)
        except Exception:
            pass

        # 4. Beta ledger update
        for probe in chosen:
            key = probe.learning_key()
            hit = any(
                e.get("probe_id") == probe.id or e.get("tactic") == probe.tactic
                for e in graph_events
            )
            session.beta.update(key, success=int(hit), fail=int(not hit))

        # 5. Generator calibration
        calib = session.decision_calibrator
        if calib:
            for probe in chosen:
                hit = any(
                    e.get("probe_id") == probe.id or e.get("tactic") == probe.tactic
                    for e in graph_events
                )
                calib.record(probe.source, hit)

            fetch_stats = getattr(session.executor, "fetch_stats", {})
            diagnostics = fetch_stats.get("query_diagnostics", [])
            new_diagnostics = diagnostics[self.calibration_diag_cursor:]
            self.calibration_diag_cursor = len(diagnostics)
            for probe in chosen:
                matched = [
                    item for item in new_diagnostics
                    if probe.id in (item.get("probe_ids") or [])
                ]
                calib.record_probe_cost(
                    probe,
                    query_count=sum(int(item.get("pages", 0)) for item in matched),
                    records_scanned=sum(int(item.get("records", 0)) for item in matched),
                    failed=any(item.get("error") for item in matched),
                )

        # 5.5 Exploration Debt update
        planner_recent_query_keys = getattr(session, "_planner_recent_query_keys", None)
        for probe in chosen:
            probe_hit = any(
                e.get("probe_id") == probe.id or e.get("tactic") == probe.tactic
                for e in graph_events
            )
            probe_no_data = not any(
                e.get("probe_id") == probe.id
                for e in (getattr(ingest_result, "all_events", []) or graph_events)
            )
            if session._exploration_debt:
                session._exploration_debt.record_attempt(
                    probe.operator, hit=probe_hit, no_data=probe_no_data,
                )
            if probe.source == "model_planner" and probe_no_data and planner_recent_query_keys is not None:
                window = probe.metadata.get("time_window") or {}
                planner_recent_query_keys.add("|".join((
                    probe.target, probe.operator, probe.tactic,
                    str(window.get("from_ms", 0)), str(window.get("to_ms", 0)),
                )))
            obligation_id = probe.metadata.get("obligation_id")
            if obligation_id and session.obligations:
                session.obligations.record_attempt(
                    obligation_id, session.budget.rounds_used, failed=probe_no_data,
                )

        # 6. Obligation discharge
        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])
        try:
            session.obligations.discharge(graph_dict, session.ledger)
        except (TypeError, AttributeError):
            pass

        # 7. Adaptive stagnation detection
        self._adaptive_strategy(session, prev_node_count)

        # 8. Stopping decision
        stop = self._compute_stop_decision(session)

        # Posterior history
        probs_after = session.ledger._get_probabilities()
        p_atk_after = round(1.0 - probs_after.get("__null__", 0.0), 6)
        self.posterior_history.append(p_atk_after)

        # Round diagnostics
        routed = getattr(ingest_result, "routed", {}) or {}
        graph_stats = session.graph.stats()
        self.round_diagnostics.append({
            "round": session.budget.rounds_used,
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
            "margin": round(session.ledger.margin(), 6),
            "entropy": round(session.ledger.entropy(), 6),
            "stop_should_stop": stop.should_stop,
            "stop_reason_candidate": stop.reason,
        })

        # Demo plateau check
        plateau_stop = self._check_demo_plateau_stop(session)
        if plateau_stop is not None:
            stop = plateau_stop

        # Suppress premature stops
        if stop.should_stop and stop.reason in ("robust", "voi_floor"):
            if self._suppress_robust_stop(session):
                if self._decision_robust_partial_chain(session):
                    stop = StopDecision(
                        should_stop=True, reason="robust_partial_chain",
                        max_voi=stop.max_voi, risk_now=stop.risk_now,
                    )
                else:
                    stop = StopDecision(
                        should_stop=False, reason="continue",
                        max_voi=stop.max_voi, risk_now=stop.risk_now,
                    )

        # Debug print
        self._print_stop_debug(session, stop)

        round_diagnostic = self.round_diagnostics[-1] if self.round_diagnostics else {}
        obligation_counts = _obligation_counts(session)

        # Bounded graph snapshot for frontend streaming (≤60 nodes / ≤100 edges)
        graph_nodes_payload: list[dict] = []
        graph_edges_payload: list[dict] = []
        graph_truncated = False
        if session.graph is not None:
            all_nodes = sorted(
                session.graph._nodes.values(),
                key=lambda n: float(n.timestamp or 0),
            )
            all_edges = list(session.graph._edges.values())
            graph_truncated = len(all_nodes) > 60 or len(all_edges) > 100
            for node in all_nodes[:60]:
                attrs = node.attributes or {}
                graph_nodes_payload.append({
                    "id": str(node.id),
                    "technique": node.technique or "",
                    "tactic": node.tactic or "",
                    "host": str(
                        attrs.get("host_uid") or attrs.get("asset_id")
                        or attrs.get("target") or node.host_id or ""
                    ),
                    "timestamp": round(float(node.timestamp or 0), 4),
                    "attributed": bool(node.explanation_ids),
                })
            for edge in all_edges[:100]:
                graph_edges_payload.append({
                    "source": str(edge.src),
                    "target": str(edge.dst),
                    "relation": edge.relation,
                })

        return PhaseResult(
            phase="K",
            success=True,
            should_stop=stop.should_stop,
            data={
                "stop_decision": stop,
                "ledger_snapshot": {
                    "leading": session.ledger.leading(),
                    "margin": session.ledger.margin(),
                    "entropy": session.ledger.entropy(),
                },
                "round_diagnostic": round_diagnostic,
                "explanations": _decision_explanations(session),
                "contested_edges": _contested_edges(session),
                "leading_explanation": session.ledger.leading(),
                "margin": session.ledger.margin(),
                "entropy": session.ledger.entropy(),
                "beta_updates": _beta_update_rows(session, chosen, graph_events),
                "obligations_open": obligation_counts["open"],
                "obligations_discharged": obligation_counts["discharged"],
                "obligations_overdue": obligation_counts["overdue"],
                "new_nodes": int(round_diagnostic.get("new_graph_nodes", 0) or 0),
                "new_edges": int(round_diagnostic.get("new_graph_edges", 0) or 0),
                "graph_node_count": int(round_diagnostic.get("graph_nodes", 0) or 0),
                "graph_edge_count": int(round_diagnostic.get("graph_edges", 0) or 0),
                "graph_nodes": graph_nodes_payload,
                "graph_edges": graph_edges_payload,
                "graph_truncated": graph_truncated,
            },
            progress_event={
                "phase": "K",
                "status": "stopped" if stop.should_stop else "completed",
                "stop_should_stop": stop.should_stop,
                "stop_reason_candidate": stop.reason,
            },
        )

    # ------------------------------------------------------------------
    # Stop decision helpers
    # ------------------------------------------------------------------

    def _compute_stop_decision(self, session: LOCKSession) -> StopDecision:
        """Compute should_stop using the full candidate pool + obligations."""
        budget_dict = session.budget.to_dict()
        stop_candidates = list(getattr(session, "_last_pool_candidates", []))
        try:
            stop_candidates.extend(
                obligation_dicts_to_probes(
                    session.obligations.materialize_open(
                        graph_to_dict(session.graph, session._scenario_hosts or []),
                        current_round=session.budget.rounds_used,
                    ) or []
                )
            )
        except Exception:
            pass
        stop = should_stop(
            session.ledger,
            beta_to_dict(session.beta),
            budget_dict,
            session.obligations,
            session.loss,
            candidate_probes=stop_candidates or None,
            trust=session.trust,
            calib=calib_to_dict(session.decision_calibrator),
            graph_stats=compute_graph_stats(session.graph),
            probe_to_dict=lambda p: probe_to_dict(p, session.decision_calibrator),
        )
        max_pool_voi = getattr(session, "_max_pool_voi", 0.0)
        if stop.max_voi <= 0 and max_pool_voi > 0:
            stop = StopDecision(
                should_stop=stop.should_stop,
                reason=stop.reason,
                max_voi=max_pool_voi,
                risk_now=stop.risk_now,
            )
        return stop

    def _k_revision_cascade(self, session: LOCKSession) -> None:
        """K 拍证据修订级联。"""
        if not session.trust or not session.cascade:
            return
        try:
            pending = []
            trust_revision_since = getattr(session, "_trust_revision_since", 0)
            if hasattr(session.trust, "get_pending_revisions"):
                pending = session.trust.get_pending_revisions(trust_revision_since)
            elif hasattr(session.trust, "get_revisions"):
                pending = session.trust.get_revisions()[trust_revision_since:]
            if pending:
                session.cascade.apply(pending)
                session._trust_revision_since = max(
                    getattr(r, "round", session.budget.rounds_used) for r in pending
                ) + 1
        except Exception:
            pass

    def _adaptive_strategy(self, session: LOCKSession, prev_node_count: int) -> None:
        """连续2轮无新节点时切换策略。"""
        current_count = session.graph.stats().get("node_count", 0)
        if current_count <= prev_node_count:
            self.stagnation_rounds += 1
        else:
            self.stagnation_rounds = 0

        if self.stagnation_rounds >= 2:
            session.budget.fanout_per_round = min(12, session.budget.fanout_per_round + 2)
            self.explore_weight = min(3.0, self.explore_weight * 1.5)
            self.force_new_host_probe = True
            self.stagnation_rounds = 0

    def _check_demo_plateau_stop(self, session: LOCKSession) -> Optional[StopDecision]:
        """Demo profile: early stop when posterior plateaus with partial evidence."""
        if not self.demo_profile_enabled:
            return None
        n = self.demo_plateau_rounds
        if len(self.posterior_history) < n:
            return None
        recent = self.posterior_history[-n:]
        if len(set(recent)) > 1:
            return None
        stats = session.graph.stats()
        nodes = int(stats.get("node_count", 0) or 0)
        edges = int(stats.get("edge_count", 0) or 0)
        if nodes < self.demo_min_graph_nodes or edges < self.demo_min_graph_edges:
            return None
        unresolved = (
            session.obligations.unresolved(session.budget.rounds_used)
            if session.obligations else []
        )
        leading_id = session.ledger.leading()
        margin = session.ledger.margin()
        needs_partial_stop = (
            any(item.get("hard") for item in unresolved)
            or any(item.get("overdue") for item in unresolved)
            or leading_id == "__null__"
            or margin < 0.15
        )
        if not needs_partial_stop:
            return None
        risk_now = bayes_risk(session.ledger, session.loss)
        return StopDecision(
            should_stop=True, reason="evidence_plateau_partial_chain",
            max_voi=0.0, risk_now=risk_now,
        )

    def _suppress_robust_stop(self, session: LOCKSession) -> bool:
        """延后 robust 停止：未完成溯因 / 最小轮次 / 根因后扩图 / 攻击链不完整。"""
        if session._exploration_debt:
            if not session._exploration_debt.is_cleared(session.budget.rounds_used):
                return True
        if session.budget.rounds_used < session.budget.min_rounds_before_robust:
            return True
        if self._backward_trace_incomplete(session):
            return True
        if has_initial_access_in_graph(session.graph) and session.budget.rounds_used < session.budget.min_rounds_after_root:
            return True
        if len(session.graph.stats().get("tactics_seen", [])) < 4:
            return True
        known_hosts = len(session._scenario_hosts) if session._scenario_hosts else 0
        if known_hosts > 1:
            graph_hosts = get_graph_hosts(session.graph)
            covered = sum(1 for h in session._scenario_hosts if h.lower() in graph_hosts)
            coverage_ratio = covered / known_hosts if known_hosts > 0 else 1.0
            if coverage_ratio < 0.80:
                return True
        if not self._chain_completeness_check(session):
            return True
        if self.stagnation_rounds == 0:
            return True
        return False

    def _decision_robust_partial_chain(self, session: LOCKSession) -> bool:
        """决策已鲁棒 + 高置信时允许 partial-chain 提前停止。"""
        probs = session.ledger._get_probabilities()
        p_null = probs.get("__null__", 0.0)
        p_attack = 1.0 - p_null

        if p_attack < 0.7 and p_null < 0.7:
            return False
        if session.budget.rounds_used < session.budget.min_rounds_before_robust:
            return False
        if session.obligations and hasattr(session.obligations, "open_hard"):
            if session.obligations.open_hard():
                return False
        if session._scenario_hosts:
            known_count = len(session._scenario_hosts)
            graph_hosts = get_graph_hosts(session.graph)
            covered = sum(1 for h in session._scenario_hosts if h.lower() in graph_hosts)
            coverage_ratio = covered / known_count if known_count > 0 else 1.0
            if coverage_ratio < 0.80:
                return False
        if has_initial_access_in_graph(session.graph):
            if session.budget.rounds_used < session.budget.min_rounds_after_root:
                return False
        if self.stagnation_rounds == 0:
            return False
        return True

    @staticmethod
    def _chain_completeness_check(session: LOCKSession) -> bool:
        """检查已发现攻击链是否连通。"""
        stats = session.graph.stats()
        tactics_seen = stats.get("tactics_seen", [])
        if len(tactics_seen) < 2:
            return False
        TACTIC_ORDER = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]
        seen_indices = sorted([TACTIC_ORDER.index(t) for t in tactics_seen if t in TACTIC_ORDER])
        if len(seen_indices) < 2:
            return False
        max_gap = max(seen_indices[i + 1] - seen_indices[i] for i in range(len(seen_indices) - 1))
        return max_gap <= 2

    @staticmethod
    def _backward_trace_incomplete(session: LOCKSession) -> bool:
        """Late-stage alert without initial-access in graph → keep investigating."""
        tactics = {
            normalize_tactic(t)
            for t in (session.graph.stats().get("tactics_seen") or [])
        }
        if "initial-access" in tactics:
            return False
        alert_tactic = normalize_tactic(session.alert.tactic or "")
        return alert_tactic in LATE_STAGE_TACTICS

    def _print_stop_debug(self, session: LOCKSession, stop: StopDecision) -> None:
        """Print stop debug trace each round."""
        try:
            probs = session.ledger._get_probabilities()
            p_null = probs.get("__null__", 0.0)
            p_attack = 1.0 - p_null
            margin = session.ledger.margin()
            entropy = session.ledger.entropy()
            debt_cleared = (
                session._exploration_debt.is_cleared(session.budget.rounds_used)
                if session._exploration_debt else True
            )
            tactics_seen = session.graph.stats().get("tactics_seen", []) if session.graph else []
            print(
                f"  [STOP] R{session.budget.rounds_used} | "
                f"P_atk={p_attack:.3f} P_null={p_null:.3f} | "
                f"margin={margin:.3f} entropy={entropy:.3f} | "
                f"voi={stop.max_voi:.4f} | "
                f"debt_clear={debt_cleared} | "
                f"tactics={len(tactics_seen)} | "
                f"stop={stop.should_stop}({stop.reason})"
            )
        except Exception:
            pass
