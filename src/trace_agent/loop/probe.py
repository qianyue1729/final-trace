"""Probe — RFC-004-02 统一候选探针数据类"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import hashlib


@dataclass
class Probe:
    """统一候选探针 — L 拍生成，② 拍过滤，O 拍排序，C 拍执行。

    RFC-004-02: Probe(target + operator) 进统一池。
    """

    id: str                        # unique probe identifier
    target: str                    # target entity ("host-A", "user-admin", "192.168.1.1")
    target_type: str               # "host" / "user" / "file" / "network" / "process"
    operator: str                  # query operator ("process_tree" / "auth_log" / "dns_query" / ...)
    tactic: str                    # MITRE tactic this probe is investigating
    source: str                    # who generated it: "prior" / "rule_gap" / "obligation" / "llm_scout"
    explanation_ids: list[str] = field(default_factory=list)  # which explanations this relates to
    metadata: dict[str, Any] = field(default_factory=dict)
    priority_hint: float = 0.0    # optional pre-VOI priority hint

    def learning_key(self) -> str:
        """BetaLedger key: '{operator}|{target_type}|{tactic}'"""
        return f"{self.operator.lower().strip()}|{self.target_type.lower().strip()}|{self.tactic.lower().strip()}"

    def dedup_key(self) -> str:
        """Deduplication key: same target + same operator = same probe."""
        return f"{self.target}::{self.operator}::{self.tactic}"

    @staticmethod
    def generate_id(target: str, operator: str, tactic: str) -> str:
        """Generate deterministic probe ID from components."""
        raw = f"{target}|{operator}|{tactic}"
        return f"P-{hashlib.md5(raw.encode()).hexdigest()[:8]}"
