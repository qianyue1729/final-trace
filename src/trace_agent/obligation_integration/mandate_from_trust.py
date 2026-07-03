"""从证据信任扫描生成 MANDATE 义务 — RFC-004-02 §8 反取证债务"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List

from trace_agent.decision.runtime_types import ObligationIntent


@dataclass
class MandateObligation:
    """
    由证据信任层生成的强制义务。

    RFC-004-02 §8：反取证债务属于硬阻断类型，
    未清时无条件续跑（obligations.open_hard()）。
    """
    id: str
    type: str          # "anti_forensics" / "absence"
    anchor: str        # 触发条件/锚定描述
    sla_hours: int     # SLA 时限（小时）
    hard: bool = True  # 证据信任层生成的义务默认为硬义务
    discharged: bool = False
    discharged_by: str = ""  # 哪个探针/事件关闭了此义务
    tags: List[str] = field(default_factory=list)
    intent: ObligationIntent | None = None

    def discharge(self, by: str) -> None:
        """关闭此义务"""
        self.discharged = True
        self.discharged_by = by


def mandate_from_absence(aspect: str, round_num: int,
                         confidence: float = 0.6,
                         host_id: str = "") -> MandateObligation:
    """
    缺失痕迹 → MANDATE（反取证债务 / 结构债务）。

    RFC-004-02 §5 硬约束 #2：
    "应有却没有"的痕迹生成 MANDATE 义务。
    """
    return MandateObligation(
        id=f"mandate_absence_{aspect}_{round_num}",
        type="absence",
        anchor=f"Expected but missing evidence: {aspect}",
        sla_hours=1,
        hard=True,
        tags=["absence", "anti_forensics_debt"],
        intent=ObligationIntent(
            affected_entity_ids=[aspect],
            host_ids=[host_id] if host_id else [],
            question=f"Restore visibility for expected evidence: {aspect}",
            allowed_operators=["process_tree", "auth_log", "network_flow"],
            acceptance_criterion={
                "type": "visibility_restored_or_unavailable",
                "aspect": aspect,
            },
            reason_code="telemetry_absence",
        ),
    )


def mandate_from_anti_forensics(issue_type: str, round_num: int,
                                severity: str = "high",
                                host_id: str = "") -> MandateObligation:
    """
    反取证迹象 → MANDATE（反取证债务）。

    RFC-004-02 §8：反取证债务属于硬阻断，
    "证据被抹"本身是高价值线索，必须主动追。
    """
    sla = 1 if severity == "critical" else 2
    return MandateObligation(
        id=f"mandate_anti_forensics_{issue_type}_{round_num}",
        type="anti_forensics",
        anchor=f"Anti-forensics indicator detected: {issue_type}",
        sla_hours=sla,
        hard=True,
        tags=["anti_forensics", "anti_forensics_debt", severity],
        intent=ObligationIntent(
            affected_entity_ids=[issue_type],
            host_ids=[host_id] if host_id else [],
            question=f"Resolve anti-forensics indicator: {issue_type}",
            allowed_operators=["process_tree", "auth_log", "network_flow"],
            acceptance_criterion={
                "type": "visibility_restored_or_unavailable",
                "issue_type": issue_type,
            },
            reason_code="anti_forensics_indicator",
        ),
    )


def mandates_from_scan_results(absence_issues: List[dict],
                               af_issues: List[dict],
                               round_num: int) -> List[MandateObligation]:
    """
    批量从扫描结果生成义务列表。
    便捷函数，整合 absence + anti-forensics 扫描结果。
    """
    mandates = []

    for issue in absence_issues:
        mandates.append(mandate_from_absence(
            aspect=issue.get('aspect', 'unknown'),
            round_num=round_num,
            confidence=issue.get('confidence', 0.6),
            host_id=issue.get('host_id', ''),
        ))

    for issue in af_issues:
        mandates.append(mandate_from_anti_forensics(
            issue_type=issue.get('type', 'unknown'),
            round_num=round_num,
            severity=issue.get('severity', 'high'),
            host_id=issue.get('host_id', ''),
        ))

    return mandates
