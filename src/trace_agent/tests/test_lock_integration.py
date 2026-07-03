"""LOCK 运行时端到端集成测试套件。

覆盖范围：
- create_lock_runtime 工厂函数正确创建三个组件
- 完整单轮 LOCK：seed → ingest → update → scan obligations → voi 排序 → should_stop
- 多轮收敛：entropy 下降、margin 上升
- 停止触发：积累足够证据后 should_stop 返回 True
- 硬义务续跑：有反取证义务时 should_stop = False
- forge-resistant 证据优势：高信任证据主导后验
- 边界信念收敛：contested 边界经过更新后收敛
- 原有 EvidenceTrust 测试回归：确认 import 不破坏原有功能
"""
import math
import pytest
from pathlib import Path

from trace_agent import (
    create_lock_runtime, create_evidence_trust_model,
    RuntimeDecisionLedger, ObligationLedger, LossMatrix,
    EvidenceTrustModel, EvidenceTrust, BoundaryBelief,
    voi, bayes_risk, should_stop, predict_outcomes,
)
from trace_agent.decision.types import (
    Explanation, NullAnchor, ContestedEdge, SeedPayload, AlertEvent,
)
from trace_agent.decision.runtime_types import StopDecision, VOIResult
from trace_agent.probe.voi_engine import decision_robust


# ═══════════════════════════════════════════════════════════════════════
# 测试辅助
# ═══════════════════════════════════════════════════════════════════════


class MockTrustModel:
    def __init__(self, trust_map=None, evidence_trust_map=None):
        self.evidence_trust_map = evidence_trust_map or {}
        self._trust_map = trust_map or {}

    def weight_likelihood(self, base: float, evidence_id: str) -> float:
        return self._trust_map.get(evidence_id, base * 0.5)

    def get_trust(self, evidence_id: str):
        return self.evidence_trust_map.get(evidence_id)


def make_explanation(id, technique, tactic=None, lifecycle_template=None, prior=0.3):
    return Explanation(
        id=id, title=f"Expl {id}", current_technique=technique,
        stage=tactic, lifecycle_template=lifecycle_template,
        predecessor_tactics=[], technique_context=[],
        raw_score=0.5, prior_probability=prior,
        features={}, support={"type": "lifecycle", "template_id": lifecycle_template} if lifecycle_template else {},
        recommended_log_sources=[], caveats=[],
    )


def make_test_seed():
    """创建用于集成测试的 SeedPayload"""
    explanations = [
        make_explanation("H1", "T1566", tactic="initial-access", lifecycle_template="commodity_malware_v1", prior=0.35),
        make_explanation("H2", "T1190", tactic="initial-access", prior=0.25),
        make_explanation("H3", "T1078", tactic="initial-access", prior=0.1),
    ]
    null_anchor = NullAnchor(benign=0.2, oos=0.1, reasons=["baseline noise"])
    contested_edges = [
        ContestedEdge(
            src="T1566", dst="T1059",
            boundary_prior={"p_in_attack": 0.4, "p_benign": 0.35, "p_oos": 0.25},
            support={"evidence": []}, reason="lateral hop ambiguity",
        ),
    ]
    return SeedPayload(
        alert=AlertEvent(technique_id="T1566", tactic="initial-access"),
        explanations=explanations,
        branch_null_anchor=null_anchor,
        contested_edges=contested_edges,
        lifecycle_template_candidates=[{"template_id": "commodity_malware_v1"}],
        score_v3_initial_scores={"H1": 0.7, "H2": 0.5, "H3": 0.3},
        loss_baseline={"lambda_miss": 10.0, "lambda_over": 2.0, "lambda_oos": 4.0},
        evidence_trust_defaults={"default_integrity": 0.5},
        prior_manifest=None,
    )


# ═══════════════════════════════════════════════════════════════════════
# 测试：create_lock_runtime
# ═══════════════════════════════════════════════════════════════════════


def test_create_lock_runtime_returns_three_components():
    """工厂函数正确创建三个组件"""
    seed = make_test_seed()
    data_dir = Path(__file__).resolve().parent.parent / 'data'
    ledger, obligations, trust = create_lock_runtime(seed, data_dir=data_dir)

    assert isinstance(ledger, RuntimeDecisionLedger)
    assert isinstance(obligations, ObligationLedger)
    assert isinstance(trust, EvidenceTrustModel)


def test_create_lock_runtime_posterior_valid():
    """工厂创建后的 ledger 后验有效"""
    seed = make_test_seed()
    data_dir = Path(__file__).resolve().parent.parent / 'data'
    ledger, _, _ = create_lock_runtime(seed, data_dir=data_dir)

    probs = ledger._get_probabilities()
    total = sum(probs.values())
    assert abs(total - 1.0) < 1e-6


# ═══════════════════════════════════════════════════════════════════════
# 测试：完整单轮 LOCK
# ═══════════════════════════════════════════════════════════════════════


def test_full_single_round_lock():
    """seed → update → scan obligations → voi 排序 → should_stop"""
    seed = make_test_seed()
    data_dir = Path(__file__).resolve().parent.parent / 'data'
    ledger, obligations, trust = create_lock_runtime(seed, data_dir=data_dir)

    # 1. 注入证据并更新后验
    evidence = [
        {"id": "ev1", "source": "sysmon", "technique_id": "T1566", "tactic": "initial-access"},
    ]
    ledger.update(evidence, trust)
    assert ledger.round == 1

    # 2. 扫描义务
    graph = {"nodes": [], "edges": []}
    new_obs = obligations.scan(graph, ledger, trust, {})
    # 结果可为空或非空取决于当前状态

    # 3. VOI 计算
    loss = ledger.loss
    risk = bayes_risk(ledger, loss)
    assert risk >= 0

    # 4. should_stop
    budget = {"remaining": 5, "total": 10}
    stop_decision = should_stop(ledger, {}, budget, obligations, loss)
    assert isinstance(stop_decision, StopDecision)


# ═══════════════════════════════════════════════════════════════════════
# 测试：多轮收敛
# ═══════════════════════════════════════════════════════════════════════


def test_multi_round_convergence():
    """多轮 update 后 entropy 下降，margin 上升"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.8})

    entropy_initial = ledger.entropy()
    margin_initial = ledger.margin()

    # 持续提供 H1 匹配证据
    for i in range(8):
        evidence = [{"id": "ev", "technique_id": "T1566", "tactic": "initial-access"}]
        ledger.update(evidence, trust)

    entropy_final = ledger.entropy()
    margin_final = ledger.margin()

    # 多轮后应收敛：熵下降，margin 上升
    assert entropy_final < entropy_initial
    assert margin_final > margin_initial


# ═══════════════════════════════════════════════════════════════════════
# 测试：停止触发
# ═══════════════════════════════════════════════════════════════════════


def test_stop_after_sufficient_evidence():
    """积累足够证据后 should_stop 返回 True"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})
    loss = LossMatrix()
    obligations = ObligationLedger()

    # 大量一致性证据 → 收敛
    for _ in range(15):
        ledger.update([{"id": "ev", "technique_id": "T1566", "tactic": "initial-access"}], trust)

    budget = {"remaining": 5, "total": 20}
    result = should_stop(ledger, {}, budget, obligations, loss)
    # 收敛后应该停止（robust 或 voi_floor）
    assert result.should_stop is True
    assert result.reason in ("robust", "voi_floor")


# ═══════════════════════════════════════════════════════════════════════
# 测试：硬义务续跑
# ═══════════════════════════════════════════════════════════════════════


def test_hard_obligation_prevents_stop():
    """有反取证义务时 should_stop = False"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})
    loss = LossMatrix()

    # 使 ledger 收敛
    for _ in range(10):
        ledger.update([{"id": "ev", "technique_id": "T1566", "tactic": "initial-access"}], trust)

    # 添加硬义务
    from trace_agent.decision.runtime_types import Obligation, ObligationType
    obligations = ObligationLedger()
    obligations.obligations.append(Obligation(
        id="af1", type=ObligationType.ANTI_FORENSICS,
        anchor="anti_forensics:ev_tampered", sla_rounds=3, hard=True,
        created_round=0, deadline_round=10,
    ))

    budget = {"remaining": 5, "total": 20}
    result = should_stop(ledger, {}, budget, obligations, loss)
    # 硬义务阻止停止
    assert result.should_stop is False


# ═══════════════════════════════════════════════════════════════════════
# 测试：forge-resistant 证据优势
# ═══════════════════════════════════════════════════════════════════════


def test_forge_resistant_evidence_dominates():
    """高信任证据主导后验"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)

    # 先给 H2 一些低信任证据
    trust_low = MockTrustModel(trust_map={"ev_low": 0.1})
    for _ in range(3):
        ledger.update([{"id": "ev_low", "technique_id": "T1190", "tactic": "initial-access"}], trust_low)

    p_h2_after_low = ledger.posterior("H2")

    # 再给 H1 高信任证据
    trust_high = MockTrustModel(trust_map={"ev_high": 0.95})
    for _ in range(3):
        ledger.update([{"id": "ev_high", "technique_id": "T1566", "tactic": "initial-access"}], trust_high)

    # H1 应最终超过 H2
    assert ledger.posterior("H1") > ledger.posterior("H2")


# ═══════════════════════════════════════════════════════════════════════
# 测试：边界信念收敛
# ═══════════════════════════════════════════════════════════════════════


def test_boundary_belief_convergence():
    """contested 边界经过更新后收敛"""
    seed = make_test_seed()
    ledger = RuntimeDecisionLedger.from_seed(seed)
    trust = MockTrustModel(trust_map={"ev": 0.9})

    edge_id = "T1566->T1059"
    assert edge_id in ledger.contested

    # 持续提供与 edge src (T1566) 匹配的证据
    for _ in range(10):
        ledger.update([{"id": "ev", "technique_id": "T1566", "tactic": "initial-access"}], trust)

    belief = ledger.contested[edge_id]
    # 边界信念三元归一化
    total = belief.p_in_attack + belief.p_benign + belief.p_oos
    assert abs(total - 1.0) < 1e-6

    # 应该向某个方向收敛（最大概率上升）
    max_p = max(belief.p_in_attack, belief.p_benign, belief.p_oos)
    assert max_p > 0.4  # 比初始的 0.4 有增长趋势


# ═══════════════════════════════════════════════════════════════════════
# 测试：原有 EvidenceTrust 测试回归
# ═══════════════════════════════════════════════════════════════════════


def test_evidence_trust_import_not_broken():
    """确认 import 不破坏原有功能"""
    from trace_agent import (
        EvidenceTrustModel, LogSourceRegistry, DownweightEngine,
        AntiForensicsScanner, EvidenceTrust, TrustContext,
        TrustRevision, TrustTier, LogSourceSpec, VetoGates,
    )
    # 验证类型可用
    assert EvidenceTrustModel is not None
    assert LogSourceRegistry is not None
    assert EvidenceTrust is not None


def test_create_evidence_trust_model_still_works():
    """create_evidence_trust_model 工厂函数仍正常工作"""
    data_dir = Path(__file__).resolve().parent.parent / 'data'
    model = create_evidence_trust_model(data_dir=data_dir)
    assert isinstance(model, EvidenceTrustModel)
    assert model.tau_hard == 0.8


def test_evidence_trust_weight_likelihood():
    """EvidenceTrustModel.weight_likelihood 基本功能"""
    data_dir = Path(__file__).resolve().parent.parent / 'data'
    model = create_evidence_trust_model(data_dir=data_dir)

    # 未注册证据 → 返回原始 base
    result = model.weight_likelihood(1.0, "unknown_evidence")
    assert result == 1.0


def test_full_lock_pipeline_with_real_data():
    """使用真实数据的完整 LOCK pipeline"""
    seed = make_test_seed()
    data_dir = Path(__file__).resolve().parent.parent / 'data'
    ledger, obligations, trust = create_lock_runtime(seed, data_dir=data_dir)
    loss = ledger.loss

    # 多轮循环
    for round_num in range(3):
        evidence = [
            {"id": f"ev_{round_num}", "source": "sysmon",
             "technique_id": "T1566", "tactic": "initial-access"},
        ]
        ledger.update(evidence, trust)

        # 扫描义务
        graph = {"nodes": [], "edges": []}
        obligations.scan(graph, ledger, trust, {})

        # 停止判断
        budget = {"remaining": 10 - round_num, "total": 10}
        stop = should_stop(ledger, {}, budget, obligations, loss)
        if stop.should_stop:
            break

    # 验证基本合理性
    assert ledger.round >= 1
    assert ledger.entropy() >= 0
    assert 0 <= ledger.margin() <= 1.0
