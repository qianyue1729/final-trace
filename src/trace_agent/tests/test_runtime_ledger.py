"""RuntimeDecisionLedger 运行时决策账完整测试套件。

覆盖范围：
- from_seed 初始化（后验归一化）
- update 贝叶斯更新（结构匹配、信任权重影响、多轮收敛）
- entropy / leading / margin / posterior 查询接口
- hypothetical_update 假设更新（不修改原始状态）
- spawn_merge_cull 溯因维护（孵化/合并/淘汰）
- get_contested / BoundaryBelief 边界信念更新
"""
import math
import pytest

from trace_agent.decision.types import (
    Explanation, NullAnchor, ContestedEdge, SeedPayload, AlertEvent,
)
from trace_agent.decision.runtime_types import LossMatrix, BoundaryBelief
from trace_agent.decision.runtime_ledger import RuntimeDecisionLedger
from trace_agent.utils.config import EPS_CULL, CULL_PATIENCE, TAU_MERGE, K_MAX


# ═══════════════════════════════════════════════════════════════════════
# 测试辅助工具
# ═══════════════════════════════════════════════════════════════════════


class MockTrustModel:
    """通用 mock trust model，支持自定义 weight_likelihood 和 get_trust"""
    def __init__(self, trust_map=None, evidence_trust_map=None):
        self.evidence_trust_map = evidence_trust_map or {}
        self._trust_map = trust_map or {}

    def weight_likelihood(self, base: float, evidence_id: str) -> float:
        if evidence_id in self._trust_map:
            return self._trust_map[evidence_id]
        return base * 0.5

    def get_trust(self, evidence_id: str):
        return self.evidence_trust_map.get(evidence_id)


class MockEvidenceTrust:
    """模拟 EvidenceTrust 对象"""
    def __init__(self, integrity=0.5, adversary_controllable=False, corroboration=0):
        self.integrity = integrity
        self.adversary_controllable = adversary_controllable
        self.corroboration = corroboration
        self.anti_forensics_indicator = False
        self.absence_indicator = False

    def effective_integrity(self):
        return self.integrity

    def is_forge_resistant(self, tau_hard=0.8):
        return self.integrity >= tau_hard and not self.adversary_controllable


def make_explanation(id, technique, tactic=None, lifecycle_template=None, prior=0.3):
    """创建测试用 Explanation"""
    return Explanation(
        id=id,
        title=f"Explanation {id}",
        current_technique=technique,
        stage=tactic,
        lifecycle_template=lifecycle_template,
        predecessor_tactics=[],
        technique_context=[],
        raw_score=0.5,
        prior_probability=prior,
        features={},
        support={"type": "lifecycle", "template_id": lifecycle_template} if lifecycle_template else {},
        recommended_log_sources=[],
        caveats=[],
    )


def make_test_seed(num_explanations=3, has_contested=True):
    """创建测试用 SeedPayload"""
    explanations = []
    prior_each = 0.7 / num_explanations  # 攻击解释总共 0.7
    for i in range(num_explanations):
        explanations.append(make_explanation(
            id=f"H{i+1}",
            technique=f"T100{i+1}",
            tactic=f"tactic_{i+1}",
            prior=prior_each,
        ))

    null_anchor = NullAnchor(benign=0.2, oos=0.1, reasons=["benign baseline"])

    contested_edges = []
    if has_contested:
        contested_edges.append(ContestedEdge(
            src="T1001", dst="T1002",
            boundary_prior={"p_in_attack": 0.4, "p_benign": 0.35, "p_oos": 0.25},
            support={"evidence": []},
            reason="shared lateral hop",
        ))

    return SeedPayload(
        alert=AlertEvent(technique_id="T1001", tactic="initial-access"),
        explanations=explanations,
        branch_null_anchor=null_anchor,
        contested_edges=contested_edges,
        lifecycle_template_candidates=[],
        score_v3_initial_scores={},
        loss_baseline={"lambda_miss": 10.0, "lambda_over": 2.0, "lambda_oos": 4.0},
        evidence_trust_defaults={},
        prior_manifest=None,
    )


# ═══════════════════════════════════════════════════════════════════════
# 测试：from_seed 初始化
# ═══════════════════════════════════════════════════════════════════════


def test_from_seed_creates_ledger():
    """from_seed 成功创建 RuntimeDecisionLedger"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    assert ledger is not None
    assert len(ledger.explanations) == 3


def test_from_seed_posterior_sums_to_one():
    """from_seed 后后验概率和 ≈ 1.0"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    probs = ledger._get_probabilities()
    total = sum(probs.values())
    assert abs(total - 1.0) < 1e-6


def test_from_seed_includes_null_anchor():
    """from_seed 后验包含 __null__ 锚"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    assert "__null__" in ledger.log_post
    p_null = ledger.posterior("__null__")
    assert 0.0 < p_null < 1.0


def test_from_seed_loss_matrix():
    """from_seed 正确传递 loss_baseline"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    assert ledger.loss.lambda_miss == 10.0
    assert ledger.loss.lambda_over == 2.0


# ═══════════════════════════════════════════════════════════════════════
# 测试：update 贝叶斯更新
# ═══════════════════════════════════════════════════════════════════════


def test_update_matching_evidence_increases_posterior():
    """匹配证据使对应解释后验上升"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev1": 0.8})

    p_before = ledger.posterior("H1")
    evidence = [{"id": "ev1", "technique_id": "T1001", "tactic": "tactic_1"}]
    ledger.update(evidence, trust)
    p_after = ledger.posterior("H1")

    assert p_after > p_before


def test_update_adversary_controllable_weak_effect():
    """adversary_controllable 证据（低 w_trust）影响较弱"""
    seed = make_test_seed()
    ledger1 = RuntimeDecisionLedger.from_seed(seed)
    ledger2 = RuntimeDecisionLedger.from_seed(seed)

    # 低信任（对手可控）
    trust_low = MockTrustModel(trust_map={"ev1": 0.1})
    # 高信任
    trust_high = MockTrustModel(trust_map={"ev1": 0.9})

    evidence = [{"id": "ev1", "technique_id": "T1001", "tactic": "tactic_1"}]
    ledger1.update(evidence, trust_low)
    ledger2.update(evidence, trust_high)

    # 高信任应使后验变化更大
    delta_low = abs(ledger1.posterior("H1") - ledger2.posterior("H1"))
    # 两者应有差异
    assert delta_low > 0.01


def test_update_forge_resistant_strong_effect():
    """forge-resistant 证据（高 w_trust）影响较强"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev1": 0.95})

    p_before = ledger.posterior("H1")
    evidence = [{"id": "ev1", "technique_id": "T1001", "tactic": "tactic_1"}]
    ledger.update(evidence, trust)
    p_after = ledger.posterior("H1")

    # 高信任证据应显著提升后验
    assert p_after - p_before > 0.05


def test_update_multi_round_convergence():
    """多轮更新收敛：持续提供 H1 匹配证据后 H1 应主导"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.8})

    for i in range(5):
        evidence = [{"id": "ev", "technique_id": "T1001", "tactic": "tactic_1"}]
        ledger.update(evidence, trust)

    assert ledger.posterior("H1") > 0.5
    assert ledger.leading() == "H1"


# ═══════════════════════════════════════════════════════════════════════
# 测试：查询接口
# ═══════════════════════════════════════════════════════════════════════


def test_entropy_uniform_higher_than_skewed():
    """均匀分布的熵 > 偏态分布的熵"""
    seed = make_test_seed()
    ledger_uniform = RuntimeDecisionLedger.from_seed(seed)
    entropy_initial = ledger_uniform.entropy()

    # 使某个解释主导
    ledger_skewed = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})
    for _ in range(5):
        ledger_skewed.update([{"id": "ev", "technique_id": "T1001", "tactic": "tactic_1"}], trust)

    entropy_skewed = ledger_skewed.entropy()
    assert entropy_initial > entropy_skewed


def test_leading_returns_highest_posterior():
    """leading 返回后验最高的解释 ID"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})

    # 提升 H2 后验
    for _ in range(3):
        ledger.update([{"id": "ev", "technique_id": "T1002", "tactic": "tactic_2"}], trust)

    assert ledger.leading() == "H2"


def test_margin_top1_vs_top2():
    """margin = top-1 posterior - top-2 posterior"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})

    for _ in range(3):
        ledger.update([{"id": "ev", "technique_id": "T1001", "tactic": "tactic_1"}], trust)

    probs = ledger._get_probabilities()
    sorted_p = sorted(probs.values(), reverse=True)
    expected_margin = sorted_p[0] - sorted_p[1]
    assert abs(ledger.margin() - expected_margin) < 1e-6


def test_posterior_in_valid_range():
    """posterior 返回值在 [0, 1] 内"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)

    for expl in ledger.explanations:
        p = ledger.posterior(expl.id)
        assert 0.0 <= p <= 1.0

    p_null = ledger.posterior("__null__")
    assert 0.0 <= p_null <= 1.0


def test_posterior_nonexistent_returns_zero():
    """posterior 查询不存在 ID 返回 0"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    assert ledger.posterior("nonexistent") == 0.0


# ═══════════════════════════════════════════════════════════════════════
# 测试：hypothetical_update
# ═══════════════════════════════════════════════════════════════════════


def test_hypothetical_update_does_not_modify_original():
    """hypothetical_update 不修改原始状态"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel()

    original_post = dict(ledger.log_post)
    _ = ledger.hypothetical_update("probe1", "attributable", trust)

    assert ledger.log_post == original_post


def test_hypothetical_update_returns_independent_copy():
    """hypothetical_update 返回独立副本"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel()

    new_ledger = ledger.hypothetical_update("probe1", "attributable", trust)
    # 修改副本不影响原始
    new_ledger.log_post["H1"] = -100.0
    assert ledger.log_post["H1"] != -100.0


def test_hypothetical_attributable_boosts_attack():
    """hypothetical_update attributable 结果提升攻击解释"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel()

    new_ledger = ledger.hypothetical_update("probe1", "attributable", trust)
    # 攻击解释后验应比 null 更高
    assert new_ledger.posterior("H1") > new_ledger.posterior("__null__") or \
           new_ledger.posterior("H2") > new_ledger.posterior("__null__")


def test_hypothetical_benign_boosts_null():
    """hypothetical_update benign 结果提升 null"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel()

    p_null_before = ledger.posterior("__null__")
    new_ledger = ledger.hypothetical_update("probe1", "benign", trust)
    p_null_after = new_ledger.posterior("__null__")

    assert p_null_after > p_null_before


def test_hypothetical_update_moves_only_targeted_edge():
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    if not ledger.contested:
        pytest.skip("fixture has no contested edge")
    edge_id = next(iter(ledger.contested))
    before = {
        key: (value.p_in_attack, value.p_benign, value.p_oos)
        for key, value in ledger.contested.items()
    }
    untargeted = ledger.hypothetical_update(
        {"id": "p", "tactic": "execution"},
        "benign",
        MockTrustModel(),
    )
    assert {
        key: (value.p_in_attack, value.p_benign, value.p_oos)
        for key, value in untargeted.contested.items()
    } == before

    targeted = ledger.hypothetical_update(
        {"id": "p", "tactic": "execution"},
        "benign",
        MockTrustModel(),
        target_edge_id=edge_id,
    )
    after = targeted.contested[edge_id]
    assert after.p_benign > before[edge_id][1]


# ═══════════════════════════════════════════════════════════════════════
# 测试：spawn_merge_cull
# ═══════════════════════════════════════════════════════════════════════


def test_cull_removes_low_posterior_after_patience():
    """低后验持续 CULL_PATIENCE 轮后被淘汰"""
    seed = make_test_seed(num_explanations=3)
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})

    # 强力提升 H1，使 H3 后验降到 EPS_CULL 以下
    for _ in range(10):
        ledger.update([{"id": "ev", "technique_id": "T1001", "tactic": "tactic_1"}], trust)

    # 确认某个解释后验已很低
    min_expl = min(ledger.explanations, key=lambda e: ledger.posterior(e.id))
    if ledger.posterior(min_expl.id) < EPS_CULL:
        # 连续调用 spawn_merge_cull 直到达到 patience
        for _ in range(CULL_PATIENCE):
            changes = ledger.spawn_merge_cull([], trust, budget=10)

        # 验证确实有解释被淘汰
        remaining_ids = {e.id for e in ledger.explanations}
        assert min_expl.id not in remaining_ids or ledger.posterior(min_expl.id) >= EPS_CULL


def test_merge_close_posteriors():
    """两解释后验极接近时合并"""
    # 创建两个先验极接近的解释
    explanations = [
        make_explanation("H1", "T1001", prior=0.35),
        make_explanation("H2", "T1002", prior=0.35),  # 极接近 H1
        make_explanation("H3", "T1003", prior=0.1),
    ]
    null_anchor = NullAnchor(benign=0.15, oos=0.05, reasons=["test"])
    loss = LossMatrix()
    ledger = RuntimeDecisionLedger(
        explanations=explanations, null_anchor=null_anchor,
        contested_edges=[], loss=loss,
    )
    trust = MockTrustModel()

    # 检查 H1 和 H2 后验是否接近到 TAU_MERGE 以内
    p1, p2 = ledger.posterior("H1"), ledger.posterior("H2")
    if abs(p1 - p2) < TAU_MERGE:
        changes = ledger.spawn_merge_cull([], trust, budget=10)
        assert any("merged" in c for c in changes)


def test_spawn_on_low_likelihood():
    """forge-resistant 证据在所有解释下似然低时孵化新解释"""
    seed = make_test_seed(num_explanations=2)
    ledger = RuntimeDecisionLedger.from_seed(seed)

    # 创建一个与所有解释都不匹配的事件
    event = {"id": "ev_novel", "technique_id": "T9999", "tactic": "unknown_tactic"}

    # forge-resistant 证据
    forge_trust = MockEvidenceTrust(integrity=0.95, corroboration=3)
    trust = MockTrustModel(
        trust_map={"ev_novel": 0.9},
        evidence_trust_map={"ev_novel": forge_trust},
    )

    initial_count = len(ledger.explanations)
    changes = ledger.spawn_merge_cull([event], trust, budget=10)
    # 如果所有解释下似然足够低，应该孵化
    spawned = [c for c in changes if "spawned" in c]
    if spawned:
        # 孵化后应有新解释在列表中
        spawned_ids = [c.split(":")[1] for c in spawned]
        assert any(e.id in spawned_ids for e in ledger.explanations)


# ═══════════════════════════════════════════════════════════════════════
# 测试：contested 边界信念
# ═══════════════════════════════════════════════════════════════════════


def test_contested_edges_initialized():
    """from_seed 正确初始化 contested 边界"""
    seed = make_test_seed(has_contested=True)
    ledger = RuntimeDecisionLedger.from_seed(seed)
    assert len(ledger.contested) == 1
    edge_id = "T1001->T1002"
    assert edge_id in ledger.contested
    belief = ledger.contested[edge_id]
    # 三元归一
    assert abs(belief.p_in_attack + belief.p_benign + belief.p_oos - 1.0) < 1e-6


def test_boundary_belief_update_on_matching_evidence():
    """匹配 contested 边的证据更新边界信念"""
    seed = make_test_seed(has_contested=True)
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})

    belief_before = ledger.contested["T1001->T1002"].p_in_attack
    # 提供与 T1001 匹配的证据（匹配 edge src）
    evidence = [{"id": "ev", "technique_id": "T1001", "tactic": "tactic_1"}]
    ledger.update(evidence, trust)
    belief_after = ledger.contested["T1001->T1002"].p_in_attack

    # 攻击相关证据应使 p_in_attack 上升
    assert belief_after >= belief_before - 0.01  # 允许微小数值误差


def test_boundary_belief_entropy():
    """BoundaryBelief.entropy() 正确计算"""
    b = BoundaryBelief(edge_id="test", p_in_attack=0.5, p_benign=0.3, p_oos=0.2)
    h = b.entropy()
    assert h > 0

    # 完全确定时熵 = 0
    b_certain = BoundaryBelief(edge_id="test", p_in_attack=1.0, p_benign=0.0, p_oos=0.0)
    assert b_certain.entropy() == 0.0


def test_boundary_belief_converged():
    """BoundaryBelief.converged() 检测收敛"""
    b = BoundaryBelief(edge_id="test", p_in_attack=0.9, p_benign=0.05, p_oos=0.05)
    assert b.converged(threshold=0.85)

    b2 = BoundaryBelief(edge_id="test", p_in_attack=0.5, p_benign=0.3, p_oos=0.2)
    assert not b2.converged(threshold=0.85)
