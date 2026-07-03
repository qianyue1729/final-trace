"""ObligationLedger — RFC-004-02 §8 四类义务统一管理引擎"""
from __future__ import annotations
import json
import math
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..decision.runtime_types import (
    LossMatrix,
    Obligation,
    ObligationIntent,
    ObligationType,
)
from ..utils.config import (
    EPS_VOI, OBLIGATION_BUDGET_FRACTION, DISCRIMINATIVE_MARGIN_THRESHOLD
)


class ObligationLedger:
    """
    RFC-004-02 §8 — 义务台账。

    管理四类义务：
    1. 结构债务（structural）— 恶意孤儿/桥接主机/悬空凭据 [硬阻断]
    2. 生命周期债务（lifecycle）— 模板中 required 阶段缺失 [VOI 门控]
    3. 反取证债务（anti_forensics）— 日志断层/证据被抹 [硬阻断]
    4. 判别债务（discriminative）— margin 过小+预测分歧大 [VOI 门控]

    义务分级：
    - 硬阻断（结构+反取证）：未清时 open_hard()=True → 无条件续跑
    - VOI 门控（生命周期+判别）：物化为探针后 VOI 进入 max_voi，仅 VOI≥EPS 阻断停止
    """

    def __init__(self, lifecycle_templates: Optional[List[dict]] = None,
                 loss: Optional[LossMatrix] = None):
        self.templates = lifecycle_templates or []
        self.loss = loss or LossMatrix()
        self.obligations: List[Obligation] = []
        self._id_counter = 0

    @classmethod
    def from_json(cls, templates_path: Path, loss: Optional[LossMatrix] = None) -> "ObligationLedger":
        """从 lifecycle_templates.json 加载"""
        with open(templates_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        templates = data.get("templates", [])
        return cls(lifecycle_templates=templates, loss=loss)

    def _next_id(self, prefix: str) -> str:
        self._id_counter += 1
        return f"{prefix}_{self._id_counter}"

    # =========================================================================
    # ② 检验拍：扫描 + 生成
    # =========================================================================

    def scan(
        self,
        graph: dict,
        ledger,
        trust,
        prev_stats: dict,
        current_round: int = 0,
    ) -> List[Obligation]:
        """
        扫描四类义务触发条件，返回新增义务列表。

        Args:
            graph: 攻击图（含 nodes/edges）
            ledger: RuntimeDecisionLedger（duck typing: leading/margin/posterior/explanations）
            trust: EvidenceTrustModel（duck typing: evidence_trust_map）
            prev_stats: 上一轮统计信息

        Returns:
            新增义务列表（已去重后追加到 self.obligations）
        """
        new_obligations: List[Obligation] = []
        new_obligations.extend(self.scan_structural(graph, current_round))
        new_obligations.extend(
            self.scan_lifecycle(ledger, graph, current_round)
        )
        new_obligations.extend(
            self.scan_anti_forensics(trust, current_round)
        )
        new_obligations.extend(
            self.scan_discriminative(ledger, graph, current_round)
        )

        # 去重：同 anchor 不重复生成
        existing_anchors = {o.anchor for o in self.obligations if not o.discharged}
        actually_added: List[Obligation] = []
        for ob in new_obligations:
            if ob.anchor not in existing_anchors:
                self.obligations.append(ob)
                existing_anchors.add(ob.anchor)
                actually_added.append(ob)

        return actually_added

    def scan_structural(
        self,
        graph: dict,
        current_round: int = 0,
    ) -> List[Obligation]:
        """
        结构债务：恶意孤儿 / 桥接主机 / 悬空凭据。

        硬阻断：未清时 open_hard()=True → 无条件续跑。
        """
        new_obs: List[Obligation] = []
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])

        edge_sources = {e.get("src") for e in edges}
        edge_targets = {e.get("dst") for e in edges}

        for node in nodes:
            node_id = node.get("id", "")
            host_id = str(node.get("host_id") or "")

            # Orphan fact: this fact explicitly requires a parent but has none.
            if (
                node.get("fact_confirmed", False)
                and node.get("requires_parent", False)
                and node_id not in edge_targets
            ):
                ob = Obligation(
                    id=self._next_id("structural_orphan"),
                    type=ObligationType.STRUCTURAL,
                    anchor=f"orphan_fact:{node_id}",
                    sla_rounds=5,
                    hard=True,
                    created_round=current_round,
                    deadline_round=current_round + 5,
                    tags=["structural", "orphan"],
                    intent=ObligationIntent(
                        affected_entity_ids=[node_id],
                        host_ids=[host_id] if host_id else [],
                        question="Find a supported causal parent for the orphan fact.",
                        allowed_operators=["process_tree", "auth_log", "network_flow"],
                        acceptance_criterion={
                            "type": "supported_parent_edge",
                            "node_id": node_id,
                        },
                        reason_code="orphan_fact_missing_parent",
                    ),
                )
                new_obs.append(ob)

            # 桥接主机：同时出现在多条不相关攻击路径中但未确认角色
            if node.get("type") == "host" and node.get("bridge_candidate", False):
                ob = Obligation(
                    id=self._next_id("structural_bridge"),
                    type=ObligationType.STRUCTURAL,
                    anchor=f"bridge_host:{node_id}",
                    sla_rounds=4,
                    hard=True,
                    created_round=current_round,
                    deadline_round=current_round + 4,
                    tags=["structural", "bridge"],
                    intent=ObligationIntent(
                        affected_entity_ids=[node_id],
                        host_ids=[host_id] if host_id else [],
                        question="Resolve cross-host bridge provenance.",
                        allowed_operators=["network_flow", "auth_log"],
                        acceptance_criterion={
                            "type": "bridge_provenance_resolved",
                            "node_id": node_id,
                        },
                        reason_code="bridge_provenance_ambiguous",
                    ),
                )
                new_obs.append(ob)

        # 悬空凭据：凭据被使用但来源未确认
        for node in nodes:
            if node.get("type") == "credential" and not node.get("provenance_confirmed"):
                ob = Obligation(
                    id=self._next_id("structural_credential"),
                    type=ObligationType.STRUCTURAL,
                    anchor=f"dangling_credential:{node.get('id', '')}",
                    sla_rounds=4,
                    hard=True,
                    created_round=current_round,
                    deadline_round=current_round + 4,
                    tags=["structural", "credential"],
                    intent=ObligationIntent(
                        affected_entity_ids=[str(node.get("id", ""))],
                        host_ids=[str(node.get("host_id"))]
                        if node.get("host_id") else [],
                        question="Identify the credential's source and provenance.",
                        allowed_operators=["auth_log", "credential_access_check"],
                        acceptance_criterion={
                            "type": "credential_provenance_confirmed",
                            "node_id": str(node.get("id", "")),
                        },
                        reason_code="credential_source_missing",
                    ),
                )
                new_obs.append(ob)

        return new_obs

    def scan_lifecycle(
        self,
        ledger,
        graph: dict,
        current_round: int = 0,
    ) -> List[Obligation]:
        """
        生命周期债务：领先解释的杀伤链模板中未被解释的 required 阶段。

        debt_policy 决定义务等级：
        - "hard" → 生命周期类统一归为 VOI 门控（§8 设计）
        - "voi_gated" → hard=False
        - "hard_if_xxx" → 条件型也走 VOI 门控
        """
        new_obs: List[Obligation] = []
        if not ledger or not self.templates:
            return new_obs

        # 获取领先解释
        leading_id = ledger.leading() if hasattr(ledger, 'leading') else ""
        if not leading_id or leading_id == "__null__":
            return new_obs

        # 找到对应的解释对象
        leading_expl = None
        if hasattr(ledger, 'explanations'):
            for expl in ledger.explanations:
                if expl.id == leading_id:
                    leading_expl = expl
                    break

        if not leading_expl:
            return new_obs

        # 提取 lifecycle_template id
        template_id = None
        if hasattr(leading_expl, 'lifecycle_template'):
            template_id = leading_expl.lifecycle_template
        if not template_id and hasattr(leading_expl, 'support'):
            template_id = (leading_expl.support or {}).get("template_id")

        if not template_id:
            return new_obs

        # 找对应模板
        template = None
        for t in self.templates:
            if t.get("template_id") == template_id:
                template = t
                break

        if not template:
            return new_obs

        # 收集图中已确认的 tactics
        confirmed_tactics: set = set()
        for node in graph.get("nodes", []):
            tactic = node.get("tactic", "")
            if tactic and node.get("fact_confirmed", False):
                confirmed_tactics.add(tactic)
        for edge in graph.get("edges", []):
            tactic = edge.get("tactic", "")
            if tactic:
                confirmed_tactics.add(tactic)

        # 检查每个 required 阶段是否被覆盖
        for stage_spec in template.get("stages", []):
            if stage_spec.get("required") is not True:
                continue  # conditional / false 不生成义务

            stage_name = stage_spec.get("stage", "")
            expected_tactics = stage_spec.get("expected_tactics", [])
            debt_policy = stage_spec.get("debt_policy", "voi_gated")

            # 检查是否已有覆盖
            covered = any(t in confirmed_tactics for t in expected_tactics)
            if covered:
                continue

            # 生命周期义务统一走 VOI 门控（RFC-004-02 §8 设计）
            is_hard = False

            ob = Obligation(
                id=self._next_id("lifecycle"),
                type=ObligationType.LIFECYCLE,
                anchor=f"lifecycle_gap:{template_id}:{stage_name}",
                sla_rounds=8,
                hard=is_hard,
                created_round=current_round,
                deadline_round=current_round + 8,
                tags=["lifecycle", stage_name, template_id],
                explanation_id=leading_id,
                intent=ObligationIntent(
                    affected_entity_ids=[],
                    host_ids=sorted({
                        str(node.get("host_id"))
                        for node in graph.get("nodes", [])
                        if node.get("host_id")
                    }),
                    question=f"Find evidence for lifecycle stage {stage_name}.",
                    allowed_operators=[
                        "process_tree",
                        "auth_log",
                        "network_flow",
                        "file_hash_lookup",
                    ],
                    acceptance_criterion={
                        "type": "tactic_observed",
                        "expected_tactics": list(expected_tactics),
                        "template_id": template_id,
                        "stage": stage_name,
                    },
                    reason_code="required_lifecycle_stage_missing",
                ),
            )
            new_obs.append(ob)

        return new_obs

    def scan_anti_forensics(
        self,
        trust,
        current_round: int = 0,
    ) -> List[Obligation]:
        """
        反取证债务：从 EvidenceTrustModel 的反取证/缺失标记消费。

        硬阻断：未清时 open_hard()=True → 无条件续跑。
        """
        new_obs: List[Obligation] = []
        if not trust:
            return new_obs

        # 从 trust model 获取反取证/缺失标记的证据
        if hasattr(trust, 'evidence_trust_map'):
            for eid, et in trust.evidence_trust_map.items():
                is_anti_forensics = getattr(et, 'anti_forensics_indicator', False)
                is_absence = getattr(et, 'absence_indicator', False)

                if is_anti_forensics or is_absence:
                    ob_type_tag = "anti_forensics" if is_anti_forensics else "absence"
                    ob = Obligation(
                        id=self._next_id("anti_forensics"),
                        type=ObligationType.ANTI_FORENSICS,
                        anchor=f"anti_forensics:{eid}",
                        sla_rounds=3,
                        hard=True,
                        created_round=current_round,
                        deadline_round=current_round + 3,
                        tags=["anti_forensics", ob_type_tag],
                        intent=ObligationIntent(
                            affected_entity_ids=[str(eid)],
                            host_ids=[
                                str(getattr(et, "host_id", ""))
                            ] if getattr(et, "host_id", "") else [],
                            question="Restore visibility or record an explicit unavailable-source decision.",
                            allowed_operators=[
                                "process_tree",
                                "auth_log",
                                "network_flow",
                            ],
                            acceptance_criterion={
                                "type": "visibility_restored_or_unavailable",
                                "evidence_id": str(eid),
                            },
                            reason_code=(
                                "anti_forensics_indicator"
                                if is_anti_forensics
                                else "telemetry_absence"
                            ),
                        ),
                    )
                    new_obs.append(ob)

        return new_obs

    def scan_discriminative(
        self,
        ledger,
        graph: Optional[dict] = None,
        current_round: int = 0,
    ) -> List[Obligation]:
        """
        判别债务：领先与次优解释 margin 过小。

        VOI 门控：物化为探针后仅在 VOI ≥ EPS_VOI 时阻断停止。
        """
        new_obs: List[Obligation] = []
        if not ledger or not hasattr(ledger, 'margin'):
            return new_obs

        margin = ledger.margin()
        if margin < DISCRIMINATIVE_MARGIN_THRESHOLD:
            leading_id = ledger.leading()
            ob = Obligation(
                id=self._next_id("discriminative"),
                type=ObligationType.DISCRIMINATIVE,
                anchor=f"discriminative_margin:{leading_id}:{margin:.3f}",
                sla_rounds=6,
                hard=False,
                created_round=current_round,
                deadline_round=current_round + 6,
                tags=["discriminative", "margin_low"],
                explanation_id=leading_id,
                intent=ObligationIntent(
                    affected_entity_ids=[],
                    host_ids=sorted({
                        str(node.get("host_id"))
                        for node in (graph or {}).get("nodes", [])
                        if node.get("host_id")
                    }),
                    question="Collect evidence that discriminates the leading explanation.",
                    allowed_operators=[
                        "process_tree",
                        "auth_log",
                        "network_flow",
                    ],
                    acceptance_criterion={
                        "type": "minimum_margin",
                        "threshold": DISCRIMINATIVE_MARGIN_THRESHOLD,
                    },
                    reason_code="explanation_margin_low",
                ),
            )
            new_obs.append(ob)

        return new_obs

    # =========================================================================
    # K 拍：履行 / 关闭
    # =========================================================================

    def discharge(self, graph: dict, ledger) -> List[str]:
        """
        关闭已满足/不再适用的义务。

        Returns:
            已关闭义务 ID 列表
        """
        discharged_ids: List[str] = []

        # 收集图中已确认的 tactics
        confirmed_tactics: set = set()
        for node in graph.get("nodes", []):
            tactic = node.get("tactic", "")
            if tactic and node.get("fact_confirmed", False):
                confirmed_tactics.add(tactic)

        # 收集图中已有出边的节点
        edge_sources = {e.get("src") for e in graph.get("edges", [])}

        for ob in self.obligations:
            if ob.discharged:
                continue

            if ob.type == ObligationType.LIFECYCLE:
                self._try_discharge_lifecycle(ob, confirmed_tactics, ledger, discharged_ids)

            elif ob.type == ObligationType.DISCRIMINATIVE:
                self._try_discharge_discriminative(ob, ledger, discharged_ids)

            elif ob.type == ObligationType.STRUCTURAL:
                self._try_discharge_structural(ob, graph, edge_sources, discharged_ids)

            elif ob.type == ObligationType.ANTI_FORENSICS:
                self._try_discharge_anti_forensics(ob, graph, discharged_ids)

        return discharged_ids

    def _try_discharge_lifecycle(self, ob: Obligation, confirmed_tactics: set,
                                 ledger, discharged_ids: List[str]) -> None:
        """尝试关闭生命周期义务"""
        criterion = ob.intent.acceptance_criterion if ob.intent else {}
        expected = criterion.get("expected_tactics") or []
        if any(tactic in confirmed_tactics for tactic in expected):
            ob.discharge(f"criterion_met:{criterion.get('stage', 'lifecycle')}")
            discharged_ids.append(ob.id)
            return

        # 关联解释已被淘汰 → 义务随之关闭
        if ob.explanation_id and hasattr(ledger, 'posterior'):
            if ledger.posterior(ob.explanation_id) < 0.01:
                ob.discharge(f"explanation_culled:{ob.explanation_id}")
                discharged_ids.append(ob.id)

    def _try_discharge_discriminative(self, ob: Obligation, ledger,
                                      discharged_ids: List[str]) -> None:
        """尝试关闭判别义务：margin 已恢复"""
        if hasattr(ledger, 'margin') and ledger.margin() >= DISCRIMINATIVE_MARGIN_THRESHOLD:
            ob.discharge("margin_restored")
            discharged_ids.append(ob.id)

    def _try_discharge_structural(self, ob: Obligation, graph: dict,
                                  edge_sources: set, discharged_ids: List[str]) -> None:
        """尝试关闭结构义务"""
        criterion = ob.intent.acceptance_criterion if ob.intent else {}
        criterion_type = criterion.get("type")
        node_id = str(criterion.get("node_id") or "")
        if criterion_type == "supported_parent_edge":
            edge_targets = {edge.get("dst") for edge in graph.get("edges", [])}
            if node_id in edge_targets:
                ob.discharge(f"orphan_resolved:{node_id}")
                discharged_ids.append(ob.id)
        elif criterion_type == "credential_provenance_confirmed":
            for node in graph.get("nodes", []):
                if node.get("id") == node_id and node.get("provenance_confirmed"):
                    ob.discharge(f"credential_resolved:{node_id}")
                    discharged_ids.append(ob.id)
                    return
        elif criterion_type == "bridge_provenance_resolved":
            for node in graph.get("nodes", []):
                if node.get("id") == node_id and not node.get("bridge_candidate", False):
                    ob.discharge(f"bridge_resolved:{node_id}")
                    discharged_ids.append(ob.id)
                    return

    def _try_discharge_anti_forensics(self, ob: Obligation, graph: dict,
                                      discharged_ids: List[str]) -> None:
        """尝试关闭反取证义务：对应证据已被补全或确认"""
        criterion = ob.intent.acceptance_criterion if ob.intent else {}
        evidence_id = str(criterion.get("evidence_id") or "")
        for node in graph.get("nodes", []):
            if node.get("id") == evidence_id and (
                node.get("visibility_restored", False)
                or node.get("source_unavailable_decision", False)
            ):
                ob.discharge(f"evidence_recovered:{evidence_id}")
                discharged_ids.append(ob.id)
                return

    # =========================================================================
    # 停止判据接口
    # =========================================================================

    def open_hard(self) -> bool:
        """是否有未清硬阻断义务 → 无条件续跑"""
        return any(
            ob.hard and not ob.discharged
            for ob in self.obligations
        )

    def open_voi_gated(self) -> List[Obligation]:
        """未清 VOI 门控义务列表"""
        return [
            ob for ob in self.obligations
            if not ob.hard and not ob.discharged
        ]

    def open_count(self) -> int:
        """所有未清义务数"""
        return sum(1 for ob in self.obligations if not ob.discharged)

    def record_attempt(
        self,
        obligation_id: str,
        current_round: int,
        *,
        failed: bool = False,
    ) -> None:
        for obligation in self.obligations:
            if obligation.id == obligation_id and not obligation.discharged:
                obligation.record_attempt(current_round, failed=failed)
                return

    def unresolved(self, current_round: int) -> list[dict[str, Any]]:
        return [
            {
                "id": obligation.id,
                "type": obligation.type.value,
                "hard": obligation.hard,
                "reason_code": (
                    obligation.intent.reason_code
                    if obligation.intent else "missing_typed_intent"
                ),
                "question": obligation.intent.question if obligation.intent else "",
                "host_ids": list(obligation.intent.host_ids)
                if obligation.intent else [],
                "deadline_round": obligation.deadline_round,
                "overdue": obligation.is_overdue(current_round),
                "attempts": obligation.attempts,
                "failures": obligation.failures,
                "blocked_reason": obligation.blocked_reason,
            }
            for obligation in self.obligations
            if not obligation.discharged
        ]

    def budget_remaining(self, total_budget: int) -> int:
        """
        义务占用预算：最多 ⌈B × OBLIGATION_BUDGET_FRACTION⌉ 轮用于义务探针。

        Args:
            total_budget: 总探查轮预算 B

        Returns:
            义务探针剩余可用轮数
        """
        max_obligation_rounds = math.ceil(total_budget * OBLIGATION_BUDGET_FRACTION)
        used = sum(1 for ob in self.obligations if ob.discharged)
        return max(0, max_obligation_rounds - used)

    # =========================================================================
    # 级联
    # =========================================================================

    def cascade_on_revision(self, revisions: list) -> List[str]:
        """
        证据修订级联：当信任修订发生时，重新评估受影响义务。

        可能导致：
        - 硬义务变软（如果证据不再 forge-resistant）
        - 软义务升级为硬（如果新证据升级为反取证指标）

        Returns:
            变更描述列表
        """
        changes: List[str] = []

        for revision in revisions:
            evidence_id = revision.evidence_id if hasattr(revision, 'evidence_id') else str(revision)

            for ob in self.obligations:
                if ob.discharged:
                    continue
                if evidence_id in ob.anchor:
                    if hasattr(revision, 'new_trust'):
                        new_trust = revision.new_trust
                        if hasattr(new_trust, 'adversary_controllable') and new_trust.adversary_controllable:
                            changes.append(f"cascade_noted:{ob.id}:evidence_downgraded")
                        elif hasattr(new_trust, 'anti_forensics_indicator') and new_trust.anti_forensics_indicator:
                            if not ob.hard:
                                ob.hard = True
                                changes.append(f"cascade_upgrade:{ob.id}:promoted_to_hard")

        return changes

    # =========================================================================
    # 物化为探针
    # =========================================================================

    def materialize_open(
        self,
        graph: dict,
        veto_filter: Optional[Callable] = None,
        current_round: int = 0,
    ) -> List[dict]:
        """
        将开放义务物化为可排序的探针候选。

        Args:
            graph: 当前攻击图
            veto_filter: 可选的否决过滤器（排除已知低价值/违反约束的探针）

        Returns:
            探针候选列表，按优先级降序
        """
        probes: List[dict] = []
        graph_hosts = {
            str(node.get("host_id"))
            for node in graph.get("nodes", [])
            if node.get("host_id")
        }
        graph_hosts.update(str(host) for host in graph.get("known_hosts", []))

        for ob in self.obligations:
            if ob.discharged:
                continue
            intent = ob.intent
            if intent is None:
                ob.blocked_reason = "missing_typed_intent"
                continue
            host = next(
                (host for host in intent.host_ids if host in graph_hosts),
                None,
            )
            if host is None:
                ob.blocked_reason = "affected_host_unresolved"
                continue
            operator = next(
                (value for value in intent.allowed_operators if value),
                None,
            )
            if operator is None:
                ob.blocked_reason = "no_allowed_operator"
                continue
            ob.blocked_reason = ""
            criterion = intent.acceptance_criterion
            expected_tactics = criterion.get("expected_tactics") or []
            tactic = (
                expected_tactics[0]
                if expected_tactics
                else "discovery"
            )

            probe: Dict[str, Any] = {
                "id": f"probe_from_{ob.id}",
                "obligation_id": ob.id,
                "type": ob.type.value,
                "target": host,
                "target_type": "host",
                "operator": operator,
                "tactic": tactic,
                "question": intent.question,
                "acceptance_criterion": dict(criterion),
                "reason_code": intent.reason_code,
                "hard": ob.hard,
                "priority": self._compute_priority(ob, current_round),
                "tags": ob.tags,
            }

            if veto_filter:
                filtered = veto_filter([probe], graph, None)
                if isinstance(filtered, tuple):
                    probe_list, _ = filtered
                    if probe_list:
                        probes.append(probe_list[0])
                elif isinstance(filtered, list):
                    if filtered:
                        probes.append(filtered[0])
                else:
                    probes.append(probe)
            else:
                probes.append(probe)

        # 按优先级降序排列
        probes.sort(key=lambda p: p.get("priority", 0), reverse=True)
        return probes

    # =========================================================================
    # 调度
    # =========================================================================

    def prioritize(self, current_round: int = 0) -> List[Obligation]:
        """
        价值×紧迫排序：VOI(obligation) / time_to_deadline。

        硬义务始终排在最前（紧急度倍增）。
        """
        open_obs = [ob for ob in self.obligations if not ob.discharged]

        def priority_key(ob: Obligation) -> float:
            time_to_deadline = max(1, ob.deadline_round - current_round)
            voi_est = ob.voi_estimate if ob.voi_estimate > 0 else (1.0 if ob.hard else 0.5)
            return voi_est / time_to_deadline

        return sorted(open_obs, key=priority_key, reverse=True)

    # =========================================================================
    # 内部工具
    # =========================================================================

    def _compute_priority(
        self,
        ob: Obligation,
        current_round: int = 0,
    ) -> float:
        """
        计算单个义务的优先级分数。

        公式: voi_est × urgency × hard_multiplier
        - urgency = 1 / time_to_deadline
        - hard_multiplier = 2.0（硬） / 1.0（软）
        """
        time_to_deadline = max(1, ob.deadline_round - current_round)
        voi_est = ob.voi_estimate if ob.voi_estimate > 0 else (1.0 if ob.hard else 0.5)
        urgency = 1.0 / time_to_deadline
        return voi_est * urgency * (2.0 if ob.hard else 1.0)

    # =========================================================================
    # 序列化 / 调试
    # =========================================================================

    def summary(self) -> Dict[str, Any]:
        """返回义务台账摘要（用于日志/报告）"""
        open_obs = [ob for ob in self.obligations if not ob.discharged]
        return {
            "total": len(self.obligations),
            "open": len(open_obs),
            "open_hard": sum(1 for ob in open_obs if ob.hard),
            "open_voi_gated": sum(1 for ob in open_obs if not ob.hard),
            "blocked": sum(1 for ob in open_obs if ob.blocked),
            "by_type": {
                t.value: sum(1 for ob in open_obs if ob.type == t)
                for t in ObligationType
            },
        }
