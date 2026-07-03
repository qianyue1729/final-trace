"""硬 VETO 前置卫士 — RFC-004-02 §5 硬约束 #1"""
from __future__ import annotations
from ..core.types import EvidenceTrust
from ..utils.config import TAU_HARD


class VetoGates:
    """
    与 VETO 层对接的信任闸门。

    RFC-004-02 §5 硬约束 #1：
    InvariantVeto 仍为定义性 0/1；但 TemporalOrderVeto / DisconfirmedVeto
    的"硬"判定额外要求 is_forge_resistant()。
    被对手可控证据"证伪"的，最多降为强负向采集先验，绝不永久删。
    """

    @staticmethod
    def can_hard_veto(evidence: EvidenceTrust, tau_hard: float = TAU_HARD) -> bool:
        """
        判定证据是否 forge-resistant，从而有资格触发硬 VETO。
        仅 forge-resistant 证据可持删除权。
        """
        return evidence.is_forge_resistant(tau_hard)

    @staticmethod
    def downgrade_to_soft_prior(evidence: EvidenceTrust, reason: str) -> EvidenceTrust:
        """
        将本应硬删的 VETO 降级为强负向采集先验。

        当证据 not forge-resistant 但试图触发硬 VETO 时调用。
        返回降级后的信任向量，供后续似然计算感知"软否定"。
        """
        original_integrity = evidence.base_integrity if evidence.base_integrity > 0 else evidence.integrity
        return EvidenceTrust(
            integrity=original_integrity * 0.15,  # 强负向
            provenance=evidence.provenance,
            adversary_controllable=True,
            corroboration=evidence.corroboration,
            absence_indicator=False,
            anti_forensics_indicator=False,
            base_integrity=original_integrity,
            downweight_applied=True,
            downweight_factor=0.15,
            source_chain=evidence.source_chain,
            discovery_round=evidence.discovery_round,
            last_revised_round=evidence.last_revised_round,
        )

    @staticmethod
    def evaluate_veto_eligibility(evidence: EvidenceTrust,
                                  veto_type: str,
                                  tau_hard: float = TAU_HARD) -> dict:
        """
        评估 VETO 资格并返回详细结果。

        Args:
            evidence: 要评估的证据
            veto_type: "invariant" / "temporal_order" / "disconfirmed"

        Returns:
            {eligible: bool, reason: str, action: "hard_veto"/"soft_prior"/"pass"}
        """
        # InvariantVeto 始终为定义性 0/1（不需要 forge-resistant）
        if veto_type == "invariant":
            return {
                "eligible": True,
                "reason": "Invariant violations are definitional",
                "action": "hard_veto",
            }

        # TemporalOrder / Disconfirmed 需要 forge-resistant
        if evidence.is_forge_resistant(tau_hard):
            return {
                "eligible": True,
                "reason": f"Evidence is forge-resistant (integrity={evidence.effective_integrity():.2f})",
                "action": "hard_veto",
            }
        else:
            return {
                "eligible": False,
                "reason": (
                    f"Evidence not forge-resistant "
                    f"(integrity={evidence.effective_integrity():.2f}, "
                    f"controllable={evidence.adversary_controllable})"
                ),
                "action": "soft_prior",
            }
