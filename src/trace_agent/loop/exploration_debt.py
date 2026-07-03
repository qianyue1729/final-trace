"""ExplorationDebt — 追踪关键 operator family 覆盖状态。

替代固定 MIN_EXPLORE_ROUNDS，以覆盖情况决定是否允许停止。
"""
from __future__ import annotations

from dataclasses import dataclass, field


# Operator → 逻辑 family 映射
OPERATOR_FAMILY: dict[str, str] = {
    "process_tree": "process",
    "script_execution": "process",
    "network_flow": "network",
    "lateral_movement_check": "network",
    "dns_query": "network",
    "file_hash_lookup": "file_or_persistence",
    "persistence_scan": "file_or_persistence",
    "registry_query": "file_or_persistence",
    "credential_access_check": "credential",
    "auth_log": "credential",
}

# 根据入口 tactic 确定必须覆盖的 family 集合
ENTRY_TACTIC_REQUIRED_FAMILIES: dict[str, set[str]] = {
    "initial-access": {"process", "network", "credential"},
    "execution": {"process", "network", "file_or_persistence"},
    "persistence": {"process", "network", "file_or_persistence"},
    "privilege-escalation": {"process", "network", "file_or_persistence"},
    "defense-evasion": {"process", "network", "file_or_persistence"},
    "credential-access": {"credential", "process", "network"},
    "discovery": {"process", "network", "credential"},
    "lateral-movement": {"network", "process", "credential"},
    "collection": {"file_or_persistence", "process", "network"},
    "command-and-control": {"network", "process", "file_or_persistence"},
    "exfiltration": {"network", "process", "file_or_persistence"},
    "impact": {"process", "file_or_persistence", "network"},
    # fallback
    "_default": {"process", "network", "file_or_persistence"},
}


@dataclass
class ExplorationDebt:
    """追踪关键 operator family 覆盖状态。

    规则：
    - 所有 required_families 都被 attempted（或 trusted_negative）后，覆盖债清除。
    - 绝对最低轮数 (min_rounds) 之前不允许清除。
    - 未清除时 orchestrator 禁止 voi_floor/robust 停止。
    """

    required_families: set[str]
    attempted_families: set[str] = field(default_factory=set)
    productive_families: set[str] = field(default_factory=set)
    trusted_negative_families: set[str] = field(default_factory=set)
    min_rounds: int = 3  # 绝对最低轮数

    def is_cleared(self, rounds_used: int) -> bool:
        """覆盖债是否已清。

        需同时满足：
        1. 超过最低轮数
        2. 所有 required_families 都已尝试
        3. 至少有一个 family 产生了进图事件（避免全部 trusted_negative 就放行）
        """
        if rounds_used < self.min_rounds:
            return False
        all_covered = self.required_families.issubset(
            self.attempted_families | self.trusted_negative_families
        )
        has_productive = len(self.productive_families) > 0
        return all_covered and has_productive

    def uncovered_families(self) -> set[str]:
        """仍未覆盖的 family 集合。"""
        return self.required_families - self.attempted_families - self.trusted_negative_families

    def record_attempt(self, operator: str, hit: bool, no_data: bool = False) -> None:
        """记录一次探针执行结果。

        Args:
            operator: 探针 operator 名
            hit: 是否命中（产生 graph_eligible 事件）
            no_data: 是否完全无数据返回（trusted negative）
        """
        family = OPERATOR_FAMILY.get(operator)
        if not family:
            return
        self.attempted_families.add(family)
        if hit:
            self.productive_families.add(family)
        elif no_data:
            self.trusted_negative_families.add(family)
