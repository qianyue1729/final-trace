"""EvidenceTrustModel - RFC-004-02 §5 证据信任模型运行时引擎"""
from __future__ import annotations
from typing import Dict, List, Optional, Tuple

from .types import EvidenceTrust, TrustContext, TrustRevision
from .trust_registry import LogSourceRegistry
from .downweight_rules import DownweightEngine
from .anti_forensics import AntiForensicsScanner
from ..utils.config import TAU_HARD, TAU_SOFT, UNKNOWN_SOURCE_INTEGRITY, COROB_BONUS_VALUE, COROB_BONUS_THRESHOLD


class EvidenceTrustModel:
    """
    RFC-004-02 §5 证据信任模型。

    职责：
    1. 对入图事实进行信任标注（integrity, provenance, adversary_controllable）
    2. 应用动态降权（主机失陷情景）
    3. 扫描缺失/反取证迹象，返回 MANDATE 义务 ID
    4. 维护证据修订和级联
    5. 为 VETO 层和决策账提供 is_forge_resistant / weight_likelihood 接口
    """

    def __init__(self, registry: LogSourceRegistry,
                 downweight_engine: DownweightEngine,
                 anti_forensics: AntiForensicsScanner,
                 tau_hard: float = TAU_HARD,
                 tau_soft: float = TAU_SOFT):
        self.registry = registry
        self.downweight = downweight_engine
        self.anti_forensics = anti_forensics
        self.tau_hard = tau_hard
        self.tau_soft = tau_soft

        # 状态
        self.evidence_trust_map: Dict[str, EvidenceTrust] = {}
        self.revisions: List[TrustRevision] = []
        self.current_round: int = 0
        self.trust_context: Optional[TrustContext] = None

    def set_context(self, context: TrustContext) -> None:
        """设置评估上下文（每轮初始化）"""
        self.trust_context = context
        self.current_round = context.current_round

    def ingest(self, events: List[Dict]) -> Tuple[List[EvidenceTrust], List[str]]:
        """
        批量摄入事件，标注信任向量 + 扫描缺失/反取证。

        Args:
            events: 事件列表，每个事件为 dict，需含:
                - id: str — 事件唯一标识
                - source: str — 日志源标识（对应注册表 key）
                - host: str — 事件所在主机
                - timestamp: int/float — 时间戳（秒）
                - event_type: str — 观测类型
                可选:
                - event_id: int — Windows Event ID
                - indicators: list — 反取证指标

        Returns:
            (trust_list, mandate_ids):
            - trust_list: 每条事件对应的 EvidenceTrust
            - mandate_ids: 由缺失/反取证生成的 MANDATE 义务 ID 列表
        """
        if not self.trust_context:
            raise RuntimeError("Must call set_context() before ingest()")

        trust_list = []

        for event in events:
            evidence_id = event.get('id', '')
            source_id = event.get('source', '')

            # 从注册表查询源配置
            source_spec = self.registry.get_source(source_id)

            if not source_spec:
                trust = self._create_unknown_source_trust(event)
            else:
                trust = EvidenceTrust(
                    integrity=source_spec.integrity,
                    provenance=source_id,
                    adversary_controllable=(
                        source_spec.adversary_controllable_base is True
                    ),
                    corroboration=1,
                    absence_indicator=False,
                    anti_forensics_indicator=False,
                    base_integrity=source_spec.integrity,
                    discovery_round=self.current_round,
                )

                # "contextual" 型源需细化判定
                if source_spec.adversary_controllable_base == "contextual":
                    trust.adversary_controllable = self._is_contextually_controllable(event)

            # 应用动态降权
            if self.trust_context.is_host_compromised:
                trust = self.downweight.apply(trust, event, self.trust_context)

            # 存储
            self.evidence_trust_map[evidence_id] = trust
            trust_list.append(trust)

        # 扫描缺失 + 反取证 → 生成 mandate IDs
        mandate_ids = self._scan_and_create_mandates(events)

        return trust_list, mandate_ids

    def revise_on_host_compromise(self, host: str) -> List[TrustRevision]:
        """
        主机被判失陷时的修订级联。
        对该主机所有已标注证据重新降权。
        """
        revisions = []

        for evidence_id, old_trust in list(self.evidence_trust_map.items()):
            # 跳过信号证据
            if old_trust.absence_indicator or old_trust.anti_forensics_indicator:
                continue

            # 已经降过权的跳过
            if old_trust.downweight_applied:
                continue

            # 重算
            new_trust = self.downweight.apply_recompute(
                old_trust, host, self.trust_context
            )

            if new_trust.integrity != old_trust.integrity or \
               new_trust.adversary_controllable != old_trust.adversary_controllable:
                revision = TrustRevision(
                    evidence_id=evidence_id,
                    round=self.current_round,
                    old_trust=old_trust,
                    new_trust=new_trust,
                    reason="host_compromised",
                )
                revisions.append(revision)
                self.evidence_trust_map[evidence_id] = new_trust

        self.revisions.extend(revisions)
        return revisions

    def revise_on_contradiction(self, evidence_id: str,
                                contradicting_evidence_id: str) -> Optional[TrustRevision]:
        """
        低信任证据被 forge-resistant 证据否定时的修订。
        RFC-004-02 §5: 被对手可控证据"证伪"的，最多降为强负向先验。
        """
        low_trust = self.evidence_trust_map.get(evidence_id)
        high_trust = self.evidence_trust_map.get(contradicting_evidence_id)

        if not low_trust or not high_trust:
            return None

        # 矛盾方必须是 forge-resistant
        if not high_trust.is_forge_resistant(self.tau_hard):
            return None

        # 被矛盾方已是 forge-resistant 则无需降级
        if low_trust.is_forge_resistant(self.tau_hard):
            return None

        # 降为强负向（×0.2）
        original_integrity = low_trust.base_integrity if low_trust.base_integrity > 0 else low_trust.integrity
        new_trust = EvidenceTrust(
            integrity=original_integrity * 0.2,
            provenance=low_trust.provenance,
            adversary_controllable=True,
            corroboration=low_trust.corroboration,
            absence_indicator=False,
            anti_forensics_indicator=False,
            base_integrity=original_integrity,
            downweight_applied=True,
            downweight_factor=0.2,
            source_chain=low_trust.source_chain,
            discovery_round=low_trust.discovery_round,
            last_revised_round=self.current_round,
        )

        revision = TrustRevision(
            evidence_id=evidence_id,
            round=self.current_round,
            old_trust=low_trust,
            new_trust=new_trust,
            reason="contradicted_by_forge_resistant",
        )

        self.evidence_trust_map[evidence_id] = new_trust
        self.revisions.append(revision)
        return revision

    def assess(self, event: Dict) -> EvidenceTrust:
        """单条事件信任评估 — 供 C 拍 L2 与 batch ingest 共用。

        若该 event.id 已在 evidence_trust_map 中则直接返回（ingest 优先）。
        无 set_context 时使用保守默认上下文。
        """
        evidence_id = event.get("id", "")
        existing = self.evidence_trust_map.get(evidence_id)
        if existing is not None:
            return existing

        if not self.trust_context:
            self.trust_context = TrustContext(
                host=event.get("host", event.get("source_host", "")),
                is_host_compromised=False,
                available_sources=[],
                environment_profile="default",
                current_round=self.current_round,
            )

        source_id = event.get("source", "")
        source_spec = self.registry.get_source(source_id)

        if not source_spec:
            trust = self._create_unknown_source_trust(event)
        else:
            trust = EvidenceTrust(
                integrity=source_spec.integrity,
                provenance=source_id,
                adversary_controllable=(
                    source_spec.adversary_controllable_base is True
                ),
                corroboration=1,
                absence_indicator=False,
                anti_forensics_indicator=False,
                base_integrity=source_spec.integrity,
                discovery_round=self.current_round,
            )
            if source_spec.adversary_controllable_base == "contextual":
                trust.adversary_controllable = self._is_contextually_controllable(event)

        if self.trust_context.is_host_compromised:
            trust = self.downweight.apply(trust, event, self.trust_context)

        if evidence_id:
            self.evidence_trust_map[evidence_id] = trust
        return trust

    def get_trust(self, evidence_id: str) -> Optional[EvidenceTrust]:
        """查询单条证据的信任向量"""
        return self.evidence_trust_map.get(evidence_id)

    def weight_likelihood(self, likelihood_base: float,
                          evidence_id: str) -> float:
        """
        对似然进行信任加权 — RFC-004-02 §6.1 w_trust(e)。

        低 integrity / 对手可控证据的似然被压低，
        使诱饵难以主导后验。
        """
        trust = self.get_trust(evidence_id)
        if not trust:
            return likelihood_base

        # w_trust = effective_integrity × controllable_penalty × corroboration_bonus
        weight = trust.effective_integrity()

        if trust.adversary_controllable:
            weight *= 0.5

        # 佐证加成
        if trust.corroboration >= COROB_BONUS_THRESHOLD:
            weight = min(1.0, weight + COROB_BONUS_VALUE)

        return likelihood_base * max(0.01, weight)  # 下界 0.01 防止归零

    def get_revisions(self) -> List[TrustRevision]:
        """获取所有修订记录（供 K 拍级联消费）"""
        return self.revisions

    def get_pending_revisions(self, since_round: int) -> List[TrustRevision]:
        """获取指定轮次后的修订"""
        return [r for r in self.revisions if r.round >= since_round]

    def get_summary(self) -> Dict:
        """返回当前状态摘要"""
        return {
            "total_evidence": len(self.evidence_trust_map),
            "forge_resistant_count": sum(
                1 for t in self.evidence_trust_map.values()
                if t.is_forge_resistant(self.tau_hard)
            ),
            "adversary_controllable_count": sum(
                1 for t in self.evidence_trust_map.values()
                if t.adversary_controllable
            ),
            "downweighted_count": sum(
                1 for t in self.evidence_trust_map.values()
                if t.downweight_applied
            ),
            "revisions_count": len(self.revisions),
            "absence_mandates": sum(
                1 for t in self.evidence_trust_map.values()
                if t.absence_indicator
            ),
            "anti_forensics_flags": sum(
                1 for t in self.evidence_trust_map.values()
                if t.anti_forensics_indicator
            ),
        }

    # --- 私有方法 ---

    def _create_unknown_source_trust(self, event: Dict) -> EvidenceTrust:
        """未知来源的保守默认值"""
        return EvidenceTrust(
            integrity=UNKNOWN_SOURCE_INTEGRITY,
            provenance=event.get('source', 'unknown'),
            adversary_controllable=True,
            corroboration=1,
            absence_indicator=False,
            anti_forensics_indicator=False,
            base_integrity=UNKNOWN_SOURCE_INTEGRITY,
            discovery_round=self.current_round,
        )

    def _is_contextually_controllable(self, event: Dict) -> bool:
        """对 "contextual" 源的细化判定"""
        # 如果整个主机已失陷，contextual 源视为可控
        if self.trust_context and self.trust_context.is_host_compromised:
            return True
        return False

    def _scan_and_create_mandates(self, events: List[Dict]) -> List[str]:
        """扫描缺失 + 反取证，创建虚拟 mandate 条目"""
        mandate_ids = []

        # 缺失扫描
        absence_issues = self.anti_forensics.scan_absence(
            self.trust_context, events
        )
        for issue in absence_issues:
            mid = f"mandate_absence_{issue['aspect']}_{self.current_round}"
            self.evidence_trust_map[mid] = EvidenceTrust(
                integrity=0.0,
                provenance="absence_signal",
                adversary_controllable=False,
                corroboration=0,
                absence_indicator=True,
                anti_forensics_indicator=False,
                discovery_round=self.current_round,
            )
            mandate_ids.append(mid)

        # 反取证扫描
        af_issues = self.anti_forensics.scan_anti_forensics(
            self.trust_context, events
        )
        for issue in af_issues:
            mid = f"mandate_anti_forensics_{issue['type']}_{self.current_round}"
            self.evidence_trust_map[mid] = EvidenceTrust(
                integrity=0.0,
                provenance="anti_forensics_signal",
                adversary_controllable=False,
                corroboration=0,
                absence_indicator=False,
                anti_forensics_indicator=True,
                discovery_round=self.current_round,
            )
            mandate_ids.append(mid)

        return mandate_ids
