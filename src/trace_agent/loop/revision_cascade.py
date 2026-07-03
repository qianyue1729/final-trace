"""RevisionCascade — RFC-004-02 §5/§8 证据信任修订级联

当证据信任评估发生变化（如主机被确认失陷→该主机日志降权），
级联影响：VETO 判定 / 义务状态 / 图边有效性。

RFC-004-02 §5: "证据修订 → 级联失效 VETO/义务"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from ..utils.config import TAU_HARD


@dataclass
class CascadeResult:
    """证据修订级联的结果。"""

    restored_edges: list[str] = field(default_factory=list)  # 被误删的边恢复
    invalidated_obligations: list[str] = field(default_factory=list)  # 失效的义务
    new_obligations: list[dict] = field(default_factory=list)  # 新生成的义务
    graph_changes: list[dict] = field(default_factory=list)  # 图变更记录
    veto_reassessments: list[dict] = field(default_factory=list)  # VETO 重评结果


class RevisionCascade:
    """证据信任修订 → 级联失效 VETO/义务/图边。

    触发场景：
    1. 主机被确认失陷 → 该主机上的日志源 integrity 下降
    2. 新证据佐证旧证据 → integrity 上升
    3. 发现反取证迹象 → 相关时间窗口内证据 integrity 下降

    级联效果：
    - integrity 下降到 forge-resistant 以下：之前基于该证据的硬 VETO 失效 → 恢复被删路径
    - integrity 上升到 forge-resistant 以上：之前的软否定可升级为硬 VETO
    - 义务与证据关联：修订后可能新增/失效义务
    """

    def __init__(self, graph: Any, trust: Any, obligations: Any, ledger: Any) -> None:
        """
        Args:
            graph: SessionGraph
            trust: EvidenceTrustModel (or duck-typed with .get_trust(id) method)
            obligations: ObligationLedger (with .cascade_on_revision())
            ledger: RuntimeDecisionLedger (for explanation reassessment)
        """
        self._graph = graph
        self._trust = trust
        self._obligations = obligations
        self._ledger = ledger
        self._veto_history: list[dict] = []  # track past veto decisions for reassessment

    def apply(self, revisions: list) -> CascadeResult:
        """Apply trust revisions and cascade effects.

        For each revision:
        1. Check if any past hard VETO was based on this evidence
           - If integrity dropped below forge-resistant: VETO → invalid, restore edge
        2. Check if any edges in graph were added based on this evidence
           - If integrity dropped significantly: mark edge as weakened
        3. Forward to obligations.cascade_on_revision() for obligation-level cascade
        4. If anti-forensics indicators discovered: generate new obligations

        Args:
            revisions: list of TrustRevision objects (or dicts with evidence_id,
                       old_trust, new_trust, reason)

        Returns:
            CascadeResult with all changes made
        """
        result = CascadeResult()

        if not revisions:
            return result

        for revision in revisions:
            # 1. Reassess past VETOs
            veto_changes = self._reassess_vetos(revision)
            result.veto_reassessments.extend(veto_changes)

            # Restore edges invalidated by now-invalid VETOs
            for vc in veto_changes:
                if vc.get("action") == "invalidate":
                    edge_id = vc.get("edge_id", "")
                    if edge_id:
                        result.restored_edges.append(edge_id)

            # 2. Assess graph impact
            graph_changes = self._assess_graph_impact(revision)
            result.graph_changes.extend(graph_changes)

            # 3. Generate new obligations from trust changes
            new_obs = self._generate_new_obligations(revision)
            result.new_obligations.extend(new_obs)

        # 4. Forward all revisions to obligations for obligation-level cascade
        if self._obligations is not None and hasattr(self._obligations, "cascade_on_revision"):
            cascade_changes = self._obligations.cascade_on_revision(revisions)
            if cascade_changes:
                result.invalidated_obligations.extend(cascade_changes)

        return result

    def record_veto(
        self,
        evidence_id: str,
        veto_type: str,
        edge_id: str,
        integrity_at_time: float,
    ) -> None:
        """Record a VETO decision for future reassessment.

        Called by the main loop when a hard VETO is applied.
        """
        self._veto_history.append(
            {
                "evidence_id": evidence_id,
                "veto_type": veto_type,
                "edge_id": edge_id,
                "integrity_at_time": integrity_at_time,
                "invalidated": False,
            }
        )

    def _reassess_vetos(self, revision: Any) -> list[dict]:
        """Check if any past VETOs based on this evidence are now invalid.

        If the evidence's integrity dropped below TAU_HARD (no longer forge-resistant),
        any hard VETO that relied on it becomes invalid → the removed edge should be restored.
        """
        changes: list[dict] = []
        evidence_id = self._get_evidence_id(revision)
        new_trust = self._get_new_trust(revision)

        if new_trust is None:
            return changes

        # Determine if evidence is still forge-resistant
        still_forge_resistant = self._is_forge_resistant(new_trust)

        for record in self._veto_history:
            if record["evidence_id"] != evidence_id:
                continue
            if record["invalidated"]:
                continue

            # If evidence was forge-resistant at VETO time but no longer is → invalidate
            if not still_forge_resistant:
                record["invalidated"] = True
                changes.append(
                    {
                        "evidence_id": evidence_id,
                        "veto_type": record["veto_type"],
                        "edge_id": record["edge_id"],
                        "action": "invalidate",
                        "reason": "evidence_no_longer_forge_resistant",
                    }
                )

        return changes

    def _assess_graph_impact(self, revision: Any) -> list[dict]:
        """Check if graph edges need updating based on integrity changes.

        Significant integrity drops (>0.3) weaken edges associated with the evidence.
        """
        changes: list[dict] = []
        evidence_id = self._get_evidence_id(revision)
        old_trust = self._get_old_trust(revision)
        new_trust = self._get_new_trust(revision)

        if old_trust is None or new_trust is None:
            return changes

        old_integrity = self._get_integrity(old_trust)
        new_integrity = self._get_integrity(new_trust)
        drop = old_integrity - new_integrity

        # Significant drop threshold: 0.3
        if drop >= 0.3:
            changes.append(
                {
                    "evidence_id": evidence_id,
                    "action": "weaken",
                    "old_integrity": old_integrity,
                    "new_integrity": new_integrity,
                    "drop": drop,
                }
            )

        return changes

    def _generate_new_obligations(self, revision: Any) -> list[dict]:
        """Generate obligations from trust changes (e.g., anti-forensics detected).

        When a revision reason indicates anti-forensics or the new trust vector
        has anti_forensics_indicator=True, generate a new obligation.
        """
        obligations: list[dict] = []
        evidence_id = self._get_evidence_id(revision)
        reason = self._get_reason(revision)
        new_trust = self._get_new_trust(revision)

        is_anti_forensics = False
        if new_trust is not None and hasattr(new_trust, "anti_forensics_indicator"):
            is_anti_forensics = new_trust.anti_forensics_indicator
        if reason and "anti_forensics" in reason:
            is_anti_forensics = True

        if is_anti_forensics:
            obligations.append(
                {
                    "type": "anti_forensics",
                    "anchor": f"anti_forensics_cascade:{evidence_id}",
                    "hard": True,
                    "reason": f"anti-forensics detected via revision: {reason}",
                    "evidence_id": evidence_id,
                }
            )

        return obligations

    # ------------------------------------------------------------------
    # Private helpers — duck-typing adapters
    # ------------------------------------------------------------------

    @staticmethod
    def _get_evidence_id(revision: Any) -> str:
        if hasattr(revision, "evidence_id"):
            return revision.evidence_id
        if isinstance(revision, dict):
            return revision.get("evidence_id", "")
        return str(revision)

    @staticmethod
    def _get_new_trust(revision: Any) -> Any:
        if hasattr(revision, "new_trust"):
            return revision.new_trust
        if isinstance(revision, dict):
            return revision.get("new_trust")
        return None

    @staticmethod
    def _get_old_trust(revision: Any) -> Any:
        if hasattr(revision, "old_trust"):
            return revision.old_trust
        if isinstance(revision, dict):
            return revision.get("old_trust")
        return None

    @staticmethod
    def _get_reason(revision: Any) -> str:
        if hasattr(revision, "reason"):
            return revision.reason
        if isinstance(revision, dict):
            return revision.get("reason", "")
        return ""

    @staticmethod
    def _get_integrity(trust: Any) -> float:
        if hasattr(trust, "effective_integrity"):
            return trust.effective_integrity()
        if hasattr(trust, "integrity"):
            return trust.integrity
        if isinstance(trust, dict):
            return trust.get("integrity", 0.0)
        return 0.0

    @staticmethod
    def _is_forge_resistant(trust: Any) -> bool:
        if hasattr(trust, "is_forge_resistant"):
            return trust.is_forge_resistant(TAU_HARD)
        if hasattr(trust, "integrity"):
            integrity = trust.effective_integrity() if hasattr(trust, "effective_integrity") else trust.integrity
            controllable = getattr(trust, "adversary_controllable", False)
            return integrity >= TAU_HARD and not controllable
        return False
