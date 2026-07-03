"""RuntimeDecisionLedger — RFC-004-02 §4 第四本账运行时引擎"""
from __future__ import annotations
import copy
import math
from typing import Dict, List, Optional, Tuple

from .types import Explanation, NullAnchor, ContestedEdge, SeedPayload
from .runtime_types import LossMatrix, BoundaryBelief, PosteriorState
from ..utils.config import (K_MAX, TAU_SPAWN, TAU_MERGE, EPS_CULL, CULL_PATIENCE)


class RuntimeDecisionLedger:
    """
    RFC-004-02 §4 — 决策账运行时引擎。

    维护少数(≤K_MAX)竞争解释的后验 + null 锚 + contested 边界信念。
    K 拍调用 update() 做贝叶斯更新，O 拍通过 hypothetical_update() 做 VOI 前瞻。
    """

    def __init__(self, explanations: List[Explanation],
                 null_anchor: NullAnchor,
                 contested_edges: List[ContestedEdge],
                 loss: LossMatrix,
                 log_post: Optional[Dict[str, float]] = None):
        self.explanations = explanations
        self.null_anchor = null_anchor
        self.loss = loss
        self.round = 0
        self._cull_tracker: Dict[str, int] = {}  # explanation_id → 低后验持续轮数

        # 初始化后验（对数空间）
        if log_post is None:
            # 从 prior_probability 初始化
            self.log_post: Dict[str, float] = {}
            for e in explanations:
                p = max(e.prior_probability, 1e-6)
                self.log_post[e.id] = math.log(p)
            # null 锚也占后验份额
            null_p = max(self.null_anchor.benign + self.null_anchor.oos, 1e-6)
            self.log_post["__null__"] = math.log(null_p)
            self._normalize_log_post()
        else:
            self.log_post = log_post

        # 初始化边界信念
        self.contested: Dict[str, BoundaryBelief] = {}
        for edge in contested_edges:
            bp = edge.boundary_prior
            self.contested[f"{edge.src}->{edge.dst}"] = BoundaryBelief(
                edge_id=f"{edge.src}->{edge.dst}",
                p_in_attack=bp.get("p_in_attack", 0.34),
                p_benign=bp.get("p_benign", 0.33),
                p_oos=bp.get("p_oos", 0.33),
            )

    @classmethod
    def from_seed(cls, seed: SeedPayload, loss: Optional[LossMatrix] = None) -> "RuntimeDecisionLedger":
        """从 SeedPayload 初始化运行时决策账"""
        if loss is None:
            lb = seed.loss_baseline or {}
            loss = LossMatrix(
                lambda_miss=lb.get("lambda_miss", lb.get("LAMBDA_MISS", 10.0)),
                lambda_over=lb.get("lambda_over", lb.get("LAMBDA_OVER", 2.0)),
                lambda_oos=lb.get("lambda_oos", lb.get("LAMBDA_OOS", 4.0)),
            )
        ledger = cls(
            explanations=seed.explanations,
            null_anchor=seed.branch_null_anchor,
            contested_edges=seed.contested_edges,
            loss=loss,
        )
        # Read-only seed metadata used when C-phase builds model context.
        ledger.prior_manifest = seed.prior_manifest or {}
        ledger.visibility = seed.visibility or {}
        ledger.evidence_trust_defaults = seed.evidence_trust_defaults or {}
        return ledger

    # ─── K 拍核心：贝叶斯更新 ───

    def update(self, evidence: List[dict], trust) -> None:
        """
        贝叶斯更新 — route-aware + lifecycle-aware。

        对每条 evidence，计算各解释下的似然，更新对数后验。
        同时更新 contested 边界信念。

        Route-awareness:
        - ATTACH / graph_eligible → 由路由与事实确认状态决定信号强度
        - WEAK + graph_eligible → 弱攻击正证据（衰减权重）
        - DISCARD → 不更新
        - PARK → 微弱反证

        Args:
            evidence: 事件列表（每个需含 id, source, tactic/technique 等，
                      可选 _route_bucket, _graph_eligible 等）
            trust: EvidenceTrustModel 实例（提供 weight_likelihood 接口）
        """
        self.round += 1

        for event in evidence:
            # Route-aware signal classification
            signal = self._classify_signal(event)

            # 对每个解释计算 log-likelihood
            ll_map: Dict[str, float] = {}
            for expl in self.explanations:
                ll_map[expl.id] = self._log_likelihood_v2(event, expl, trust, signal)

            # null 锚的似然
            ll_map["__null__"] = self._null_log_likelihood_v2(event, trust, signal)

            # 贝叶斯更新：log_post[H] += log_likelihood(e|H)
            for key in self.log_post:
                if key in ll_map:
                    self.log_post[key] += ll_map[key]

            self._normalize_log_post()

            # 更新 contested 边界信念
            self._update_contested(event, ll_map, trust)

    def _classify_signal(self, event: dict) -> str:
        """从事件路由/属性分类证据信号。

        Returns:
            "attack_strong" / "attack_weak" / "parked" / "discarded" / "neutral"
        """
        route = event.get("_route_bucket", "")
        graph_eligible = event.get("_graph_eligible", False)

        # ATTACH 且归因确认 → 强攻击证据
        if route == "ATTACH" and event.get("_attribution_confirmed"):
            return "attack_strong"

        # ATTACH → 强攻击证据
        if route == "ATTACH":
            return "attack_strong"

        # WEAK + graph_eligible (promoted) → 弱攻击证据
        if route == "WEAK" and graph_eligible:
            return "attack_weak"

        # graph_eligible（被提升但非显式 ATTACH）→ 弱攻击证据
        if graph_eligible:
            return "attack_weak"

        # PARK → 中性/轻微反证
        if route == "PARK":
            return "parked"

        # DISCARD → 不更新
        if route == "DISCARD":
            return "discarded"

        return "neutral"

    def _log_likelihood(self, event: dict, explanation: Explanation, trust) -> float:
        """
        P(e|H) ∝ fit_struct · fit_stage · w_trust
        对数空间，各项有界 [-3, 0]，防止连乘过自信。

        RFC-004-02 §6.1：似然 = 廉价图查询 × 信任加权，只用比值。
        """
        # fit_struct: 事件 technique 能否挂接到解释子图
        fit_struct = self._compute_fit_struct(event, explanation)

        # fit_stage: 事件 tactic 是否匹配解释预期阶段
        fit_stage = self._compute_fit_stage(event, explanation)

        # w_trust: 信任权重（调用 EvidenceTrustModel）
        evidence_id = event.get("id", "")
        w_trust = trust.weight_likelihood(1.0, evidence_id) if trust else 0.5

        # 各项取对数，有界 [-3, 0]
        log_struct = max(-3.0, min(0.0, math.log(max(fit_struct, 0.05))))
        log_stage = max(-3.0, min(0.0, math.log(max(fit_stage, 0.05))))
        log_trust = max(-3.0, min(0.0, math.log(max(w_trust, 0.05))))

        return log_struct + log_stage + log_trust

    def _log_likelihood_v2(self, event: dict, explanation: Explanation,
                           trust, signal: str) -> float:
        """
        Route-aware P(e|H) — 在结构/阶段匹配基础上叠加路由信号。

        强攻击证据对 attack hypothesis 给正似然；
        弱攻击证据给衰减正似然；
        中性/反证不给正似然。
        """
        if signal == "discarded":
            return 0.0  # 丢弃事件不影响后验

        # 基础似然（结构+阶段+信任）
        fit_struct = self._compute_fit_struct(event, explanation)
        fit_stage = self._compute_fit_stage_v2(event, explanation)
        evidence_id = event.get("id", "")
        w_trust = trust.weight_likelihood(1.0, evidence_id) if trust else 0.5

        log_struct = max(-3.0, min(0.0, math.log(max(fit_struct, 0.05))))
        log_stage = max(-3.0, min(0.0, math.log(max(fit_stage, 0.05))))
        log_trust = max(-3.0, min(0.0, math.log(max(w_trust, 0.05))))

        base_ll = log_struct + log_stage + log_trust

        # Route-aware boost：攻击证据额外加分
        if signal == "attack_strong":
            # 强攻击证据：确保 attack hypothesis 获得正似然
            base_ll = max(base_ll, -0.5)  # floor: 至少不惩罚
            base_ll += 0.8  # 强正证据 boost
        elif signal == "attack_weak":
            # 弱攻击证据：温和正似然
            base_ll = max(base_ll, -1.0)
            base_ll += 0.4
        elif signal == "parked":
            # 停泊事件：对 attack 略微负面
            base_ll = min(base_ll, -0.3)

        # 限幅：单事件影响 [-2, +1.5]
        return max(-2.0, min(1.5, base_ll))

    def _compute_fit_struct(self, event: dict, explanation: Explanation) -> float:
        """结构匹配：事件 technique 与解释的技术上下文 overlap"""
        event_technique = event.get("technique_id", "") or event.get("technique", "")

        # 与解释的 current_technique 直接匹配
        if event_technique and event_technique == explanation.current_technique:
            return 0.9

        # 在解释的 technique_context 中
        if explanation.technique_context:
            for ctx in explanation.technique_context:
                if event_technique in (ctx.get("src", ""), ctx.get("dst", "")):
                    return 0.7

        # 在解释的 predecessor_tactics 相关技术中
        if explanation.predecessor_tactics:
            for pred in explanation.predecessor_tactics:
                related = pred.get("related_techniques", [])
                if event_technique in related:
                    return 0.5

        # lifecycle template 阶段匹配
        if explanation.lifecycle_template and explanation.support:
            template_id = explanation.support.get("template_id", "")
            if template_id and event_technique:
                return 0.3  # 弱关联

        return 0.3  # 无明显关联（中性，不惩罚）

    def _compute_fit_stage(self, event: dict, explanation: Explanation) -> float:
        """阶段匹配：事件 tactic 是否匹配解释预期阶段"""
        event_tactic = event.get("tactic", "")

        if not event_tactic:
            return 0.4  # 无 tactic 信息，中性

        # 与解释当前 stage 匹配
        if explanation.stage and event_tactic == explanation.stage:
            return 0.9

        # 在解释的 predecessor_tactics 中
        if explanation.predecessor_tactics:
            pred_tactics = [p.get("prev_tactic", "") for p in explanation.predecessor_tactics]
            if event_tactic in pred_tactics:
                return 0.7

        # lifecycle template 的某个阶段包含此 tactic
        if explanation.support and explanation.support.get("type") == "lifecycle":
            # lifecycle explanation，任何攻击战术都有中等匹配
            return 0.4

        return 0.2  # 不匹配

    def _compute_fit_stage_v2(self, event: dict, explanation: Explanation) -> float:
        """阶段匹配 v2：支持反向溯源 — 前驱阶段是正证据。

        Kill-chain 反向逻辑：
        - 入口告警是 execution/exfiltration
        - 发现 initial-access / credential-access 等前驱事件
        - 这些是溯源正证据，不应被惩罚
        """
        event_tactic = event.get("tactic", "")

        if not event_tactic:
            return 0.5  # 无 tactic 信息，中性（比 v1 宽松）

        # 与解释当前 stage 直接匹配
        if explanation.stage and event_tactic == explanation.stage:
            return 0.9

        # 在解释的 predecessor_tactics 中（显式声明的前驱）
        if explanation.predecessor_tactics:
            pred_tactics = [p.get("prev_tactic", "") for p in explanation.predecessor_tactics]
            if event_tactic in pred_tactics:
                return 0.75

        # 隐式前驱检查：kill-chain 顺序中的前驱阶段
        if explanation.stage and self._is_kill_chain_predecessor(event_tactic, explanation.stage):
            return 0.65  # 反向溯源正证据

        # 后继阶段（前向扩展）
        if explanation.stage and self._is_kill_chain_predecessor(explanation.stage, event_tactic):
            return 0.55  # 弱正证据

        # lifecycle template
        if explanation.support and explanation.support.get("type") == "lifecycle":
            return 0.5

        return 0.35  # 不匹配但不严重惩罚

    @staticmethod
    def _is_kill_chain_predecessor(candidate_tactic: str, reference_tactic: str) -> bool:
        """candidate_tactic 是否是 reference_tactic 的 kill-chain 前驱。"""
        _TACTIC_ORDER = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]
        try:
            ci = _TACTIC_ORDER.index(candidate_tactic)
            ri = _TACTIC_ORDER.index(reference_tactic)
            return ci < ri
        except ValueError:
            return False

    def _null_log_likelihood(self, event: dict, trust) -> float:
        """null 锚似然：事件是良性/不相关的概率"""
        evidence_id = event.get("id", "")
        w_trust = trust.weight_likelihood(1.0, evidence_id) if trust else 0.5

        # null 锚对低信任证据更宽容（对手可控证据更可能是噪声）
        # 但 base_null 不应太高，避免在少量事件后就压倒攻击假说
        base_null = 0.2  # 基线：事件是良性的先验（保守值）

        # 信任权重反转：低信任 → null 高；高信任 → null 低
        null_boost = max(0.1, 1.0 - w_trust) * 0.5  # dampened boost
        fit_null = base_null * (1.0 + null_boost)
        fit_null = min(0.5, fit_null)

        return max(-3.0, min(0.0, math.log(max(fit_null, 0.05))))

    def _null_log_likelihood_v2(self, event: dict, trust, signal: str) -> float:
        """Route-aware null 锚似然。

        核心规则：
        - attack_strong 证据 → null 大幅下降
        - attack_weak 证据 → null 小幅下降
        - parked 证据 → null 小幅上升
        - discarded → 不影响
        """
        if signal == "discarded":
            return 0.0  # 不影响

        evidence_id = event.get("id", "")
        w_trust = trust.weight_likelihood(1.0, evidence_id) if trust else 0.5

        if signal == "attack_strong":
            # 强攻击证据 → null 应该下降
            # 高信任 attack → null 极低
            fit_null = 0.08 * (1.0 + max(0.0, 1.0 - w_trust) * 0.3)
            return max(-3.0, math.log(max(fit_null, 0.02)))

        if signal == "attack_weak":
            # 弱攻击证据 → null 小幅下降
            fit_null = 0.15 * (1.0 + max(0.0, 1.0 - w_trust) * 0.4)
            return max(-3.0, math.log(max(fit_null, 0.05)))

        if signal == "parked":
            # 停泊证据 → null 小幅上升
            fit_null = 0.35
            return max(-3.0, min(0.0, math.log(fit_null)))

        # neutral
        base_null = 0.2
        null_boost = max(0.1, 1.0 - w_trust) * 0.5
        fit_null = base_null * (1.0 + null_boost)
        fit_null = min(0.5, fit_null)
        return max(-3.0, min(0.0, math.log(max(fit_null, 0.05))))

    def _update_contested(self, event: dict, ll_map: Dict[str, float], trust) -> None:
        """更新 contested 边界信念；无匹配边时按 L3 边界信号注册新边。"""
        event_technique = event.get("technique_id", "") or event.get("technique", "")
        if not event_technique:
            return

        is_boundary = event.get("_l3_is_boundary", False)
        route = event.get("_route_bucket", "")
        needs_contested = (
            is_boundary
            or route in ("WEAK", "PARK", "SPAWN")
            or event.get("_attribution_status") == "CONTESTED"
        )

        matched = False
        for edge_id, belief in list(self.contested.items()):
            src, dst = edge_id.split("->") if "->" in edge_id else ("", "")
            host_tactic_match = (
                "::" in edge_id
                and event_technique in edge_id
                and (event.get("tactic", "") in edge_id or not event.get("tactic"))
            )
            if event_technique not in (src, dst) and not host_tactic_match:
                continue
            matched = True

            max_attack_ll = max(
                (ll_map.get(e.id, -3.0) for e in self.explanations),
                default=-3.0,
            )
            null_ll = ll_map.get("__null__", -3.0)

            attack_factor = math.exp(max_attack_ll)
            null_factor = math.exp(null_ll)

            new_in = belief.p_in_attack * attack_factor
            new_benign = belief.p_benign * null_factor
            new_oos = belief.p_oos * null_factor * 0.8

            total = new_in + new_benign + new_oos
            if total > 0:
                belief.p_in_attack = new_in / total
                belief.p_benign = new_benign / total
                belief.p_oos = new_oos / total

        if not matched and needs_contested:
            edge_id = self.edge_id_from_event(event)
            prior = {"p_in_attack": 0.34, "p_benign": 0.40, "p_oos": 0.26}
            if route == "SPAWN":
                prior = {"p_in_attack": 0.22, "p_benign": 0.28, "p_oos": 0.50}
            elif is_boundary:
                prior = {"p_in_attack": 0.28, "p_benign": 0.48, "p_oos": 0.24}
            self.register_contested_edge(edge_id, prior)

    # ─── 查询接口 ───

    def entropy(self) -> float:
        """决策相关不确定性（信息熵）"""
        probs = self._get_probabilities()
        h = 0.0
        for p in probs.values():
            if p > 0:
                h -= p * math.log(p)
        return h

    def leading(self) -> str:
        """MAP 解释 ID"""
        if not self.log_post:
            return ""
        return max(self.log_post, key=self.log_post.get)

    def margin(self) -> float:
        """最优 vs 次优后验间隔"""
        probs = self._get_probabilities()
        if len(probs) < 2:
            return 1.0
        sorted_p = sorted(probs.values(), reverse=True)
        return sorted_p[0] - sorted_p[1]

    def posterior(self, explanation_id: str) -> float:
        """查询单个解释的后验概率"""
        probs = self._get_probabilities()
        return probs.get(explanation_id, 0.0)

    def get_contested(self) -> Dict[str, BoundaryBelief]:
        """返回所有边界信念"""
        return self.contested

    def register_contested_edge(
        self,
        edge_id: str,
        boundary_prior: Optional[dict] = None,
    ) -> None:
        """运行时注册有争议边 — L3/C 拍边界证据写入 contested。"""
        if not edge_id or edge_id in self.contested:
            return
        bp = boundary_prior or {}
        p_in = bp.get("p_in_attack", 0.34)
        p_ben = bp.get("p_benign", 0.33)
        p_oos = bp.get("p_oos", 0.33)
        total = p_in + p_ben + p_oos or 1.0
        self.contested[edge_id] = BoundaryBelief(
            edge_id=edge_id,
            p_in_attack=p_in / total,
            p_benign=p_ben / total,
            p_oos=p_oos / total,
        )

    @staticmethod
    def edge_id_from_event(event: dict, graph=None) -> str:
        """从事件构造 contested 边 ID（图边或 host::tactic::technique）。"""
        technique = event.get("technique_id") or event.get("technique") or ""
        parent_ids = event.get("_l1_parent_candidates") or []
        if parent_ids and technique and graph is not None:
            parent = graph.get_node(parent_ids[0])
            if parent and parent.technique:
                return f"{parent.technique}->{technique}"
        attrs = event.get("attributes") or {}
        host = (
            event.get("target")
            or attrs.get("host_uid")
            or attrs.get("asset_id")
            or attrs.get("host")
            or ""
        )
        tactic = event.get("tactic") or "unknown"
        if host and technique:
            return f"{host}::{tactic}::{technique}"
        if technique:
            return f"event::{event.get('id', technique)}"
        return f"event::{event.get('id', 'unknown')}"

    def get_state(self) -> PosteriorState:
        """获取当前后验状态快照"""
        return PosteriorState(
            log_post=dict(self.log_post),
            contested=dict(self.contested),
            round=self.round,
        )

    # ─── VOI 前瞻 ───

    def probe_outcome_likelihoods(
        self,
        probe: dict,
        outcome: str,
    ) -> dict[str, float]:
        """Map a typed probe outcome to explanation-specific likelihoods."""
        if outcome == "no_data":
            return {key: 1.0 for key in self.log_post}
        if outcome == "benign":
            return {
                key: 0.80 if key == "__null__" else 0.20
                for key in self.log_post
            }
        if outcome == "oos":
            return {
                key: 0.70 if key == "__null__" else 0.15
                for key in self.log_post
            }

        target_id = outcome.split(":", 1)[1] if ":" in outcome else None
        tactic = str(probe.get("tactic") or "").lower()
        likelihoods = {"__null__": 0.10}
        for explanation in self.explanations:
            expected = {
                str(value).lower()
                for value in getattr(explanation, "expected_tactics", [])
            }
            stage = getattr(explanation, "stage", None)
            if stage:
                expected.add(str(stage).lower())
            for predecessor in getattr(
                explanation, "predecessor_tactics", []
            ):
                if isinstance(predecessor, dict):
                    value = predecessor.get("tactic") or predecessor.get("name")
                    if value:
                        expected.add(str(value).lower())
            likelihood = 0.55 if tactic and tactic in expected else 0.25
            if target_id == explanation.id:
                likelihood = max(likelihood, 0.85)
            likelihoods[explanation.id] = likelihood
        return likelihoods

    def hypothetical_update(
        self,
        probe: dict | str,
        outcome: str,
        trust=None,
        *,
        modeled_likelihoods: Optional[dict[str, float]] = None,
        target_edge_id: Optional[str] = None,
    ) -> "RuntimeDecisionLedger":
        """
        假设更新：返回浅拷贝后验，不修改本体。
        用于 VOI 一步前瞻计算。

        Args:
            probe: Typed probe context or legacy probe ID
            outcome: 假设结果 "attributable"/"benign"/"oos"/"no_data"
            trust: EvidenceTrustModel
        """
        # 创建副本
        new_ledger = RuntimeDecisionLedger(
            explanations=self.explanations,
            null_anchor=self.null_anchor,
            contested_edges=[],  # 不复制原始 edges
            loss=self.loss,
            log_post=dict(self.log_post),
        )
        new_ledger.contested = {k: copy.copy(v) for k, v in self.contested.items()}
        new_ledger.round = self.round
        new_ledger._cull_tracker = dict(self._cull_tracker)

        probe_dict = probe if isinstance(probe, dict) else {"id": probe}
        likelihoods = modeled_likelihoods or self.probe_outcome_likelihoods(
            probe_dict, outcome
        )
        for explanation_id in new_ledger.log_post:
            likelihood = max(
                1e-6,
                min(1.0, float(likelihoods.get(explanation_id, 1e-6))),
            )
            new_ledger.log_post[explanation_id] += math.log(likelihood)

        # Only a probe explicitly bound to one contested edge may move it.
        if target_edge_id and target_edge_id in new_ledger.contested:
            belief = new_ledger.contested[target_edge_id]
            if outcome == "benign":
                factors = (0.35, 1.0, 0.55)
            elif outcome == "oos":
                factors = (0.40, 0.55, 1.0)
            elif outcome.startswith("attributable"):
                factors = (1.0, 0.45, 0.45)
            else:
                factors = (1.0, 1.0, 1.0)
            belief.p_in_attack *= factors[0]
            belief.p_benign *= factors[1]
            belief.p_oos *= factors[2]
            total = belief.p_in_attack + belief.p_benign + belief.p_oos
            if total > 0:
                belief.p_in_attack /= total
                belief.p_benign /= total
                belief.p_oos /= total

        new_ledger._normalize_log_post()
        return new_ledger

    # ─── 溯因维护 ───

    def spawn_merge_cull(self, evidence: List[dict], trust, budget: int) -> List[str]:
        """
        溯因维护（§4）：孵化/合并/淘汰。

        Returns:
            变更日志列表
        """
        changes: List[str] = []
        probs = self._get_probabilities()

        # 淘汰：后验 < EPS_CULL 持续 CULL_PATIENCE 轮
        to_cull = []
        for expl in self.explanations:
            p = probs.get(expl.id, 0.0)
            if p < EPS_CULL:
                self._cull_tracker[expl.id] = self._cull_tracker.get(expl.id, 0) + 1
                if self._cull_tracker[expl.id] >= CULL_PATIENCE:
                    to_cull.append(expl.id)
            else:
                self._cull_tracker[expl.id] = 0

        for eid in to_cull:
            self.explanations = [e for e in self.explanations if e.id != eid]
            if eid in self.log_post:
                del self.log_post[eid]
            if eid in self._cull_tracker:
                del self._cull_tracker[eid]
            changes.append(f"culled:{eid}")

        if to_cull:
            self._normalize_log_post()

        # 合并：两解释后验分歧 < TAU_MERGE
        merged = set()
        expl_list = list(self.explanations)
        for i in range(len(expl_list)):
            if expl_list[i].id in merged:
                continue
            for j in range(i + 1, len(expl_list)):
                if expl_list[j].id in merged:
                    continue
                p_i = probs.get(expl_list[i].id, 0.0)
                p_j = probs.get(expl_list[j].id, 0.0)
                if abs(p_i - p_j) < TAU_MERGE and (p_i + p_j) > 0:
                    # 合并 j 到 i
                    merged_post = math.log(p_i + p_j) if (p_i + p_j) > 0 else -10.0
                    self.log_post[expl_list[i].id] = merged_post
                    if expl_list[j].id in self.log_post:
                        del self.log_post[expl_list[j].id]
                    merged.add(expl_list[j].id)
                    changes.append(f"merged:{expl_list[j].id}→{expl_list[i].id}")

        if merged:
            self.explanations = [e for e in self.explanations if e.id not in merged]
            self._normalize_log_post()

        # 孵化：检查是否有证据在所有解释下似然都很低
        # 简化实现：如果有证据的 max P(e|H) < TAU_SPAWN 且集合未满
        if len(self.explanations) < K_MAX and evidence:
            for event in evidence:
                if len(self.explanations) >= K_MAX:
                    break
                max_ll = -float('inf')
                for expl in self.explanations:
                    ll = self._log_likelihood(event, expl, trust)
                    max_ll = max(max_ll, ll)

                # 取 exp 转回概率空间比较
                if math.exp(max_ll) < TAU_SPAWN:
                    # 需要孵化，但需要 forge-resistant 或 ≥2 佐证
                    evidence_id = event.get("id", "")
                    et = trust.get_trust(evidence_id) if trust else None
                    if et and (et.is_forge_resistant() or et.corroboration >= 2):
                        new_id = f"H_spawn_{self.round}_{len(self.explanations) + 1}"
                        # 创建最小解释（后续会被更新填充）
                        new_expl = Explanation(
                            id=new_id,
                            title=f"Spawned from {event.get('technique_id', 'unknown')}",
                            current_technique=event.get("technique_id", ""),
                            stage=event.get("tactic"),
                            lifecycle_template=None,
                            predecessor_tactics=[],
                            technique_context=[],
                            raw_score=0.0,
                            prior_probability=EPS_CULL * 2,
                            features={},
                            support={"type": "spawned", "source_event": evidence_id},
                            recommended_log_sources=[],
                            caveats=["spawned explanation - needs evidence accumulation"],
                        )
                        self.explanations.append(new_expl)
                        self.log_post[new_id] = math.log(EPS_CULL * 2)
                        self._normalize_log_post()
                        changes.append(f"spawned:{new_id}")

        return changes

    # ─── 内部工具 ───

    def _normalize_log_post(self) -> None:
        """归一化对数后验（log-sum-exp）"""
        if not self.log_post:
            return
        max_lp = max(self.log_post.values())
        log_sum = max_lp + math.log(
            sum(math.exp(lp - max_lp) for lp in self.log_post.values())
        )
        for key in self.log_post:
            self.log_post[key] -= log_sum

    def _get_probabilities(self) -> Dict[str, float]:
        """将对数后验转为概率空间"""
        if not self.log_post:
            return {}
        max_lp = max(self.log_post.values())
        probs = {}
        total = 0.0
        for key, lp in self.log_post.items():
            p = math.exp(lp - max_lp)
            probs[key] = p
            total += p
        if total > 0:
            for key in probs:
                probs[key] /= total
        return probs
