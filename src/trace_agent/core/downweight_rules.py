"""动态降权规则引擎 — RFC-004-02 §5.3"""
from __future__ import annotations
from typing import Dict
from .types import EvidenceTrust, TrustContext
from ..utils.config import (
    DOWNWEIGHT_FACTORS, EXEMPT_SOURCES,
    COROB_BONUS_THRESHOLD, COROB_BONUS_VALUE
)


class DownweightEngine:
    """
    主机失陷情景下的动态降权规则。

    规则（README.md §5.3）：
    - host compromised: host-local writable logs → ×0.4, shell history → ×0.2,
      file artifacts → ×0.3, remote immutable → 不降权
    - 单源: corroboration_bonus = 0
    - ≥2 独立源: corroboration_bonus = +0.15
    """

    def apply(self, trust: EvidenceTrust, event: Dict,
              context: TrustContext) -> EvidenceTrust:
        """
        对单条证据应用动态降权规则。

        仅在 context.is_host_compromised=True 时触发降权。
        豁免源（EDR/Sysmon/auditd/CloudTrail）不降权。
        """
        if not context.is_host_compromised:
            return trust

        # 豁免源不降权
        if trust.provenance in EXEMPT_SOURCES:
            return trust

        # 查表降权
        factor = DOWNWEIGHT_FACTORS.get(trust.provenance, 1.0)

        if factor < 1.0:
            return EvidenceTrust(
                integrity=trust.integrity * factor,
                provenance=trust.provenance,
                adversary_controllable=True,  # 失陷主机日志视为可控
                corroboration=trust.corroboration,
                absence_indicator=trust.absence_indicator,
                anti_forensics_indicator=trust.anti_forensics_indicator,
                base_integrity=trust.base_integrity if trust.base_integrity > 0 else trust.integrity,
                downweight_applied=True,
                downweight_factor=factor,
                source_chain=trust.source_chain,
                discovery_round=trust.discovery_round,
                last_revised_round=context.current_round,
            )

        return trust

    def apply_recompute(self, trust: EvidenceTrust, host: str,
                        context: TrustContext) -> EvidenceTrust:
        """
        主机状态更新后重新计算降权。
        从 base_integrity 重新开始计算。
        """
        if not context.is_host_compromised:
            return trust

        if trust.provenance in EXEMPT_SOURCES:
            return trust

        # 使用原始 integrity 重算
        original_integrity = trust.base_integrity if trust.base_integrity > 0 else trust.integrity
        factor = DOWNWEIGHT_FACTORS.get(trust.provenance, 1.0)

        if factor < 1.0:
            return EvidenceTrust(
                integrity=original_integrity * factor,
                provenance=trust.provenance,
                adversary_controllable=True,
                corroboration=trust.corroboration,
                absence_indicator=trust.absence_indicator,
                anti_forensics_indicator=trust.anti_forensics_indicator,
                base_integrity=original_integrity,
                downweight_applied=True,
                downweight_factor=factor,
                source_chain=trust.source_chain,
                discovery_round=trust.discovery_round,
                last_revised_round=context.current_round,
            )

        return trust

    @staticmethod
    def compute_corroboration_bonus(corroboration: int) -> float:
        """
        计算佐证加成。≥2 独立来源时加成，否则为 0。
        """
        if corroboration >= COROB_BONUS_THRESHOLD:
            return COROB_BONUS_VALUE
        return 0.0
