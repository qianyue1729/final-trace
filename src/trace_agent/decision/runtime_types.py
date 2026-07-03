"""LOCK 循环运行时类型 — RFC-004-02 §4/§6/§7/§8"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class ConfidenceStatus(str, Enum):
    UNAVAILABLE = "unavailable"
    EXPERIMENTAL = "experimental"
    STABLE = "stable"
    STALE = "stale"


@dataclass(frozen=True)
class DecisionConfidence:
    """Separates a relative investigation score from calibrated probability."""

    investigation_score: float
    calibrated_probability: Optional[float] = None
    confidence_status: ConfidenceStatus = ConfidenceStatus.UNAVAILABLE
    calibrator_version: Optional[str] = None
    sample_count: int = 0
    slice_key: str = "global"
    interval: Optional[tuple[float, float]] = None
    automation_eligible: bool = False
    reason_codes: tuple[str, ...] = ()
    calibration_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        probability = self.calibrated_probability
        if self.confidence_status in (
            ConfidenceStatus.UNAVAILABLE,
            ConfidenceStatus.STALE,
        ) and probability is not None:
            raise ValueError(
                "unavailable or stale confidence cannot carry a probability"
            )
        if probability is not None and not 0.0 <= probability <= 1.0:
            raise ValueError("calibrated_probability must be in [0, 1]")
        if self.confidence_status == ConfidenceStatus.STABLE and probability is None:
            raise ValueError("stable confidence requires a calibrated probability")
        if self.interval is not None:
            low, high = self.interval
            if not 0.0 <= low <= high <= 1.0:
                raise ValueError("confidence interval must be ordered within [0, 1]")

    def to_dict(self) -> dict[str, Any]:
        return {
            "investigation_score": self.investigation_score,
            "calibrated_probability": self.calibrated_probability,
            "confidence_status": self.confidence_status.value,
            "calibrator_version": self.calibrator_version,
            "sample_count": self.sample_count,
            "slice_key": self.slice_key,
            "interval": list(self.interval) if self.interval is not None else None,
            "automation_eligible": self.automation_eligible,
            "reason_codes": list(self.reason_codes),
            "calibration_metadata": dict(self.calibration_metadata),
        }


@dataclass
class LossMatrix:
    """非对称损失矩阵 — RFC-004-02 §6/§11.1
    
    LAMBDA_OVER > 0 是治过度归因的真正下限。
    """
    lambda_miss: float = 10.0      # 漏掉真攻击代价
    lambda_over: float = 2.0       # 误归因良性边代价（必须 > 0）
    lambda_oos: float = 4.0        # 误归入域外真恶意代价

    @classmethod
    def from_json(cls, path: Path) -> "LossMatrix":
        """从 loss_baseline.json 加载默认配置"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return cls(
            lambda_miss=data.get("lambda_miss", 10.0),
            lambda_over=data.get("lambda_over", 2.0),
            lambda_oos=data.get("lambda_oos", 4.0),
        )

    @classmethod
    def from_profile(cls, path: Path, profile: str) -> "LossMatrix":
        """从 loss_baseline.json 的 profiles 段加载特定配置"""
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        p = data.get("profiles", {}).get(profile)
        if not p:
            return cls.from_json(path)
        return cls(
            lambda_miss=p.get("lambda_miss", 10.0),
            lambda_over=p.get("lambda_over", 2.0),
            lambda_oos=p.get("lambda_oos", 4.0),
        )


@dataclass
class BoundaryBelief:
    """RFC-004-02 §4 边界归属信念（三元归一）"""
    edge_id: str
    p_in_attack: float
    p_benign: float
    p_oos: float

    def entropy(self) -> float:
        """边界信念的熵"""
        import math
        total = 0.0
        for p in [self.p_in_attack, self.p_benign, self.p_oos]:
            if p > 0:
                total -= p * math.log(p)
        return total

    def converged(self, threshold: float = 0.85) -> bool:
        """是否已收敛（某一项 > threshold）"""
        return max(self.p_in_attack, self.p_benign, self.p_oos) >= threshold


@dataclass
class PosteriorState:
    """运行时后验状态快照"""
    log_post: dict[str, float] = field(default_factory=dict)  # explanation_id → 归一化对数后验
    contested: dict[str, BoundaryBelief] = field(default_factory=dict)
    round: int = 0


@dataclass
class VOIResult:
    """VOI 计算结果"""
    probe_id: str
    voi_score: float
    risk_now: float
    expected_risk_after: float
    cost: float
    audit: dict[str, Any] = field(default_factory=dict)


@dataclass
class StopDecision:
    """停止决策结果"""
    should_stop: bool
    reason: str   # "budget" / "voi_floor" / "robust" / "continue"
    max_voi: float = 0.0
    risk_now: float = 0.0


class ObligationType(str, Enum):
    """义务类型 — RFC-004-02 §8"""
    STRUCTURAL = "structural"           # 继承 RFC-003：恶意孤儿/桥接主机/悬空凭据
    LIFECYCLE = "lifecycle"             # 杀伤链模板阶段缺失
    ANTI_FORENSICS = "anti_forensics"  # 反取证债务
    DISCRIMINATIVE = "discriminative"   # 判别债务（margin 过小）


@dataclass
class ObligationIntent:
    affected_entity_ids: list[str]
    host_ids: list[str]
    question: str
    allowed_operators: list[str]
    acceptance_criterion: dict[str, Any]
    reason_code: str


@dataclass
class Obligation:
    """RFC-004-02 §8 统一义务"""
    id: str
    type: ObligationType
    anchor: str                  # 触发条件/锚定描述
    sla_rounds: int              # SLA 时限（轮数）
    hard: bool                   # True = 硬阻断（结构/反取证）; False = VOI 门控
    created_round: int
    deadline_round: int
    discharged: bool = False
    discharged_by: str = ""
    voi_estimate: float = 0.0
    tags: list[str] = field(default_factory=list)
    explanation_id: Optional[str] = None  # 关联解释 ID（生命周期/判别债务）
    intent: Optional[ObligationIntent] = None
    attempts: int = 0
    failures: int = 0
    blocked_reason: str = ""
    last_attempt_round: Optional[int] = None

    def is_overdue(self, current_round: int) -> bool:
        return not self.discharged and current_round > self.deadline_round

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_reason) and not self.discharged

    def record_attempt(self, current_round: int, *, failed: bool = False) -> None:
        self.attempts += 1
        self.failures += int(failed)
        self.last_attempt_round = current_round

    def discharge(self, by: str) -> None:
        self.discharged = True
        self.discharged_by = by
