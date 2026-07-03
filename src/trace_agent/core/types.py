from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


class TrustTier(str, Enum):
    """信任分级（递减排序）"""
    FORGE_RESISTANT = "forge-resistant"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EvidenceTrust:
    """单条证据的信任向量 — RFC-004-02 §5"""
    integrity: float                    # [0, 1] 抗伪造程度
    provenance: str                     # 来源标识 "sysmon"/"auditd"/...
    adversary_controllable: bool        # 处于对手控制面内?
    corroboration: int                  # 独立来源佐证数
    absence_indicator: bool = False     # 记录应有却缺失
    anti_forensics_indicator: bool = False  # 检测到反取证迹象
    base_integrity: float = 0.0         # 降权前原始 integrity
    downweight_applied: bool = False
    downweight_factor: float = 1.0      # ∈(0, 1]
    source_chain: List[str] = field(default_factory=list)
    discovery_round: int = 0
    last_revised_round: int = 0

    def effective_integrity(self) -> float:
        """计算有效完整性（已应用降权）"""
        return self.integrity * self.downweight_factor

    def is_forge_resistant(self, tau_hard: float = 0.8) -> bool:
        """判定是否抗伪造 — 硬 VETO 权判定"""
        return (self.effective_integrity() >= tau_hard
                and not self.adversary_controllable)


@dataclass
class LogSourceSpec:
    """日志源注册表条目"""
    source_id: str
    integrity: float
    tier: TrustTier
    adversary_controllable_base: bool | str  # False / True / "contextual"
    hard_veto_allowed: bool
    platforms: List[str]
    observes: List[str]
    sigma_technique_coverage: int = 0


@dataclass
class TrustContext:
    """证据信任评估的上下文"""
    host: str
    is_host_compromised: bool
    available_sources: List[str]
    environment_profile: str
    current_round: int = 0


@dataclass
class TrustRevision:
    """证据修订记录（供级联使用）"""
    evidence_id: str
    round: int
    old_trust: EvidenceTrust
    new_trust: EvidenceTrust
    reason: str  # "host_compromised" / "contradicted_by_forge_resistant"
    cascading_vetos: List[str] = field(default_factory=list)
