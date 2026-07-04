"""veto_phase — ② 检验拍：证据修订级联 + VETO 过滤 + MANDATE 义务扫描。

从 DecisionOrchestrator._veto_phase() 忠实提取，通过 LOCKSession 读写状态。
"""
from __future__ import annotations

import logging
from collections import Counter

from trace_agent.agents.lock_session import LOCKSession
from trace_agent.loop.candidate_pool import CandidatePool

from ._helpers import graph_to_dict
from .base import PhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class VetoPhaseExecutor(PhaseExecutor):
    """② 检验拍：证据修订级联 + 义务扫描 + VETO 剪枝。"""

    def execute(self, session: LOCKSession) -> PhaseResult:
        """执行检验拍。

        Args:
            session: LOCKSession（需包含 pool 在 session 中或由外部传入）

        注意：本执行器通过 session.data["pool"] 获取候选池，
        或接受 pool 参数。编排器应在调用前将 L 拍结果写入 session。
        """
        pool: CandidatePool = session.data.get("pool")
        if pool is None:
            pool = CandidatePool()

        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])
        known_hosts_lower = (
            {h.lower() for h in session._scenario_hosts}
            if session._scenario_hosts else set()
        )

        vetoed_count = 0
        veto_reasons: list[str] = []

        # 0. 证据修订级联（RFC §5/§8）
        trust_revisions = self._apply_revision_cascade(session)

        # 1. Obligation scanning
        new_obligations = []
        try:
            new_obligations = session.obligations.scan(
                graph_dict,
                session.ledger,
                session.trust,
                session.graph.stats(),
                current_round=session.budget.rounds_used,
            ) or []
        except (TypeError, AttributeError):
            pass

        # 2. Discharge met obligations
        try:
            session.obligations.discharge(graph_dict, session.ledger)
        except (TypeError, AttributeError):
            pass

        # 3. Beta sensitivity VETO: prune probe types with repeated misses
        veto_ids: list[str] = []
        for probe in pool.peek():
            key = probe.learning_key()
            if (session.beta.total_observations(key) >= 2
                    and session.beta.sensitivity(key) < 0.2):
                veto_ids.append(probe.id)
                veto_reasons.append(f"beta_veto:{key}")

        # 4. Non-host filter: remove probes whose target doesn't match any known host
        if known_hosts_lower:
            for probe in pool.peek():
                target_lower = (getattr(probe, "target", "") or "").lower().strip()
                if target_lower and target_lower not in known_hosts_lower:
                    veto_ids.append(probe.id)
                    veto_reasons.append(f"unknown_host:{target_lower}")

        if veto_ids:
            pool.remove(veto_ids)
            vetoed_count = len(set(veto_ids))

        surviving = pool.peek()
        reason_counts = Counter(
            reason.split(":", 1)[0] for reason in veto_reasons
        )
        obligation_types = Counter(
            (
                obligation.type.value
                if hasattr(obligation.type, "value")
                else str(obligation.type)
            )
            for obligation in new_obligations
        )

        return PhaseResult(
            phase="Veto",
            success=True,
            data={
                "vetoed_count": vetoed_count,
                "veto_reasons": dict(reason_counts),
                "surviving_count": len(surviving),
                "mandated_count": len(new_obligations),
                "obligation_types": dict(obligation_types),
                "trust_revisions": trust_revisions,
                "surviving_pool": surviving,
                "pool": pool,
            },
            progress_event={
                "phase": "Veto",
                "status": "completed",
                "candidate_count": len(surviving),
            },
        )

    def _apply_revision_cascade(self, session: LOCKSession) -> int:
        """Apply pending trust revisions through the cascade."""
        if not session.trust or not hasattr(session.trust, "get_pending_revisions"):
            return 0
        try:
            trust_revision_since = getattr(session, "_trust_revision_since", 0)
            revisions = session.trust.get_pending_revisions(trust_revision_since)
            if revisions and session.cascade:
                session.cascade.apply(revisions)
            if revisions and session.obligations and hasattr(
                session.obligations, "cascade_on_revision"
            ):
                session.obligations.cascade_on_revision(revisions)
            if revisions:
                session._trust_revision_since = max(
                    getattr(r, "round", session.budget.rounds_used) for r in revisions
                ) + 1
            return len(revisions)
        except Exception as exc:
            logger.warning("[VetoPhase] revision cascade failed: %s", exc)
            return 0
