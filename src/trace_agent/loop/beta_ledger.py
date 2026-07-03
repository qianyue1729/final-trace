"""BetaLedger — RFC-004-02 §9 探针灵敏度台账（第二本账运行时组件）

Per-(operator, target_type, tactic) Beta posterior tracking.
K 拍记录 hit/miss，O 拍读灵敏度/Thompson 采样。

职责分工（§6.1 一致性契约）：
- Beta 台账只供 P(no_data) / 探针灵敏度的收缩先验
- "这类查法历史上返不返回可归因信号" = 标定成本与灵敏度
- 不另给一套竞争的结局分布（那是解释似然的职责）
"""
from __future__ import annotations

import math
import random
from typing import Optional


class BetaLedger:
    """Per-probe-type Beta posterior for sensitivity estimation.

    Key format: "{operator}|{target_type}|{tactic}"
    Each key tracks (alpha, beta) pair:
      - alpha = 1 + cumulative successes (hits)
      - beta = 1 + cumulative failures (misses)
      - sensitivity = E[Beta] = alpha / (alpha + beta)
    """

    def __init__(self, alpha0: float = 1.0, beta0: float = 1.0):
        """
        Args:
            alpha0: Prior alpha (default 1.0 = uniform)
            beta0: Prior beta (default 1.0 = uniform)
        """
        self._alpha0 = alpha0
        self._beta0 = beta0
        self._params: dict[str, tuple[float, float]] = {}

    def update(self, key: str, success: int = 0, fail: int = 0) -> None:
        """K 拍记录 hit/miss.

        Args:
            key: Learning key (use learning_key() to generate)
            success: Number of hits this round
            fail: Number of misses this round
        """
        alpha, beta = self._params.get(key, (self._alpha0, self._beta0))
        self._params[key] = (alpha + success, beta + fail)

    def sensitivity(self, key: str) -> float:
        """P(returns signal | signal exists) = E[Beta] = α/(α+β).

        For cold-start (unseen key), returns prior mean = alpha0/(alpha0+beta0).
        """
        alpha, beta = self._params.get(key, (self._alpha0, self._beta0))
        return alpha / (alpha + beta)

    def p_no_data(self, key: str) -> float:
        """1 - sensitivity: probability probe returns empty.

        Used by predict_outcomes() in VOI calculation.
        """
        return 1.0 - self.sensitivity(key)

    def thompson_sample(self, key: str) -> float:
        """Thompson sampling for exploration/exploitation balance (O 拍).

        Draws from Beta(alpha, beta) distribution.
        Returns sampled probability in [0, 1].
        """
        alpha, beta = self._params.get(key, (self._alpha0, self._beta0))
        return random.betavariate(alpha, beta)

    def get_params(self, key: str) -> tuple[float, float]:
        """Return current (alpha, beta) for a key. Returns prior if unseen."""
        return self._params.get(key, (self._alpha0, self._beta0))

    def variance(self, key: str) -> float:
        """Var[Beta] = αβ / ((α+β)²(α+β+1)). Useful for confidence intervals."""
        alpha, beta = self._params.get(key, (self._alpha0, self._beta0))
        total = alpha + beta
        return (alpha * beta) / (total * total * (total + 1))

    def total_observations(self, key: str) -> int:
        """Total observations = alpha + beta - alpha0 - beta0"""
        alpha, beta = self._params.get(key, (self._alpha0, self._beta0))
        return int((alpha - self._alpha0) + (beta - self._beta0))

    def all_keys(self) -> list[str]:
        """Return all tracked keys."""
        return list(self._params.keys())

    @staticmethod
    def learning_key(operator: str, target_type: str, tactic: str) -> str:
        """Generate standardized learning key.

        Format: "{operator}|{target_type}|{tactic}"
        All components lowercased and stripped.
        """
        return f"{operator.strip().lower()}|{target_type.strip().lower()}|{tactic.strip().lower()}"

    def to_dict(self) -> dict:
        """Serialize state for persistence."""
        return {
            "alpha0": self._alpha0,
            "beta0": self._beta0,
            "params": {k: list(v) for k, v in self._params.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BetaLedger":
        """Restore from serialized state."""
        ledger = cls(alpha0=data["alpha0"], beta0=data["beta0"])
        ledger._params = {k: tuple(v) for k, v in data["params"].items()}
        return ledger
