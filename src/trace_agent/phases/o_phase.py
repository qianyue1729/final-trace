"""o_phase — O 拍：VOI 排序 + 义务预占。

从 DecisionOrchestrator._o_phase() 与 _adjusted_voi() 忠实提取，
通过 LOCKSession 读写状态。
"""
from __future__ import annotations

import logging
from typing import Any

from trace_agent.agents.lock_session import LOCKSession
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.loop.exploration_debt import OPERATOR_FAMILY
from trace_agent.loop.generators import normalize_tactic
from trace_agent.loop.probe import Probe
from trace_agent.probe.voi_engine import voi

from ._helpers import (
    beta_to_dict,
    calib_to_dict,
    compute_graph_stats,
    get_graph_hosts,
    graph_to_dict,
    has_initial_access_in_graph,
    obligation_dicts_to_probes,
    probe_is_executable,
    probe_to_dict,
)
from .base import PhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class OPhaseExecutor(PhaseExecutor):
    """O 拍：义务物化并入池 + VOI 排序 + 贪心选择。"""

    def __init__(self, voi_audit: list | None = None):
        self.voi_audit = voi_audit if voi_audit is not None else []

    def execute(self, session: LOCKSession) -> PhaseResult:
        """执行 O 拍：VOI 排序选出 top-K 探针。"""
        slots = session.budget.fanout_per_round

        # 义务物化 → 并入统一池
        pool = session.data.get("pool", CandidatePool())
        known_hosts_lower = (
            {h.lower() for h in session._scenario_hosts}
            if session._scenario_hosts else set()
        )
        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])

        mandated_probes: list[Probe] = []
        try:
            mandated_raw = session.obligations.materialize_open(
                graph_dict, current_round=session.budget.rounds_used,
            ) or []
            mandated_probes = [
                p for p in obligation_dicts_to_probes(mandated_raw)
                if probe_is_executable(p, session.executor, known_hosts_lower, session.graph)
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

        session._last_pool_candidates = list(candidates)
        if not candidates:
            session._max_pool_voi = 0.0
            return PhaseResult(
                phase="O", success=True,
                data={"chosen": [], "slots_filled": 0, "llm_gate_triggered": False},
                progress_event={"phase": "O", "status": "completed", "probes_selected": []},
            )

        # VOI scoring
        graph_stats = compute_graph_stats(session.graph)
        beta_dict = beta_to_dict(session.beta)
        calib_dict = calib_to_dict(session.decision_calibrator)

        scored: list[tuple[float, Probe]] = []
        for probe in candidates:
            try:
                probe_dict = probe_to_dict(probe, session.decision_calibrator)
                voi_result = voi(
                    probe_dict, session.ledger, beta_dict, calib_dict,
                    session.loss, session.trust, graph_stats=graph_stats,
                )
                base = voi_result.voi_score
                self.voi_audit.append({
                    "probe_id": probe.id,
                    "operator": probe.operator,
                    "target": probe.target,
                    "voi": voi_result.voi_score,
                    "risk_now": voi_result.risk_now,
                    "expected_risk_after": voi_result.expected_risk_after,
                    "risk_reduction": voi_result.risk_now - voi_result.expected_risk_after,
                    "cost": voi_result.cost,
                    **voi_result.audit,
                })
                if probe.source == "obligation" and probe.metadata.get("hard"):
                    base += 0.08 * session.loss.lambda_miss
                elif probe.source == "obligation":
                    base += 0.03 * session.loss.lambda_over
                scored.append((base, probe))
            except Exception:
                scored.append((probe.priority_hint, probe))

        session._max_pool_voi = max((s for s, _ in scored), default=0.0)

        # Greedy selection with adjusted VOI
        selected: list[Probe] = []
        remaining = list(scored)

        while remaining and len(selected) < slots:
            best_idx = 0
            best_adj = -float("inf")
            for i, (base_voi, probe) in enumerate(remaining):
                adj = self._adjusted_voi(session, probe, base_voi, selected, known_hosts_lower)
                if adj > best_adj:
                    best_adj = adj
                    best_idx = i
            _, chosen_probe = remaining.pop(best_idx)
            selected.append(chosen_probe)

        # Build full VOI ranking for frontend visibility
        voi_ranking_data = []
        for probe in selected:
            # Find VOI audit entry for this probe
            audit_entry = next(
                (a for a in self.voi_audit if a.get("probe_id") == probe.id),
                None,
            )
            voi_ranking_data.append({
                "probe": probe.id,
                "operator": probe.operator,
                "target": probe.target or "",
                "voi_score": round(audit_entry["voi"], 4) if audit_entry else 0.0,
                "risk_reduction": round(audit_entry["risk_reduction"], 4) if audit_entry else 0.0,
                "cost": round(audit_entry["cost"], 4) if audit_entry else 0.0,
                "source": probe.source or "",
            })

        return PhaseResult(
            phase="O",
            success=True,
            data={
                "chosen": selected,
                "slots_total": slots,
                "slots_filled": len(selected),
                "obligation_slots": len(mandated_probes),
                "llm_gate_triggered": False,
                "max_voi": round(session._max_pool_voi, 4),
                "voi_ranking": voi_ranking_data,
            },
            progress_event={
                "phase": "O",
                "status": "completed",
                "probes_selected": [p.operator for p in selected],
            },
        )

    def _adjusted_voi(
        self,
        session: LOCKSession,
        probe: Probe,
        base_voi: float,
        selected: list[Probe],
        known_hosts_lower: set,
    ) -> float:
        """调整后 VOI：覆盖债奖励 + 重复惩罚 + 轻量主机多样性。

        Faithful port from DecisionOrchestrator._adjusted_voi().
        """
        family = OPERATOR_FAMILY.get(probe.operator)

        # Coverage bonus
        coverage_bonus = 0.0
        if hasattr(session, "_exploration_debt") and session._exploration_debt and family:
            uncovered = session._exploration_debt.uncovered_families()
            if family in uncovered:
                coverage_bonus = 0.25

        # Duplicate penalty
        duplicate_penalty = 0.0
        selected_ops = {p.operator for p in selected}
        selected_families = {OPERATOR_FAMILY.get(p.operator) for p in selected}
        if probe.operator in selected_ops:
            duplicate_penalty += 0.35
        elif family and family in selected_families:
            duplicate_penalty += 0.20

        probe_host = getattr(probe, "target", "") or ""
        probe_host_lower = probe_host.lower()

        # Source bonus: cross_host / chain_follow probes preferred
        source_bonus = 0.0
        if probe.source == "cross_host":
            source_bonus += 0.15
        if probe.source == "chain_follow":
            source_bonus += 0.10

        # Prioritize alert-host auth/email/web probes when no initial-access yet
        if not has_initial_access_in_graph(session.graph):
            alert_asset = (session.alert.asset_id or "").lower()
            probe_tactic = normalize_tactic(probe.tactic or "")
            if alert_asset and probe_host_lower == alert_asset:
                if probe_tactic == "initial-access":
                    source_bonus += 0.25
                if probe.operator in ("auth_log", "email_trace", "web_proxy"):
                    source_bonus += 0.18

        # Unseen host exploration bonus
        graph_hosts = get_graph_hosts(session.graph)
        if probe_host and probe_host_lower not in graph_hosts:
            source_bonus += 0.10

        # Host rotation bonus (mid/late rounds only)
        rotation_bonus = 0.0
        host_last_probed = getattr(session, "_host_last_probed", {}) or {}
        if session.budget.rounds_used >= 4:
            if probe_host_lower and probe_host_lower in known_hosts_lower:
                last_round = host_last_probed.get(probe_host_lower)
                if last_round is None:
                    rotation_bonus += 0.15
                else:
                    staleness = session.budget.rounds_used - last_round
                    rotation_bonus += min(0.30, 0.06 * staleness)

            # Same-host penalty if already 3+ probes on same host this round
            same_host_selected = sum(
                1 for p in selected
                if (getattr(p, "target", "") or "").lower() == probe_host_lower
            )
            if same_host_selected >= 3:
                rotation_bonus -= 0.08 * (same_host_selected - 2)

        return base_voi + coverage_bonus - duplicate_penalty + source_bonus + rotation_bonus
