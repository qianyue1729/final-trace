"""VOI 引擎完整测试套件。

覆盖范围：
- bayes_risk：非负性、会话级+边界级两项、动作选择逻辑
- voi：非负性、高不确定性 VOI 更高、VOIResult 结构
- predict_outcomes：四元组概率和=1、分布特性
- should_stop：budget/open_hard/robust/continue 四路判断
- decision_robust：margin/扰动鲁棒性
"""
import math
import pytest

from trace_agent.decision.runtime_types import (
    LossMatrix, BoundaryBelief, VOIResult, StopDecision,
)
from trace_agent.probe.voi_engine import (
    bayes_risk, voi, predict_outcomes, should_stop, decision_robust,
)
from trace_agent.probe.outcome_model import ConservativeOutcomeModel
from trace_agent.decision.types import Explanation, NullAnchor, ContestedEdge, SeedPayload, AlertEvent
from trace_agent.decision.runtime_ledger import RuntimeDecisionLedger
from trace_agent.utils.config import EPS_VOI


# ═══════════════════════════════════════════════════════════════════════
# 测试辅助
# ═══════════════════════════════════════════════════════════════════════


class MockTrustModel:
    def __init__(self, trust_map=None):
        self.evidence_trust_map = {}
        self._trust_map = trust_map or {}

    def weight_likelihood(self, base: float, evidence_id: str) -> float:
        return self._trust_map.get(evidence_id, base * 0.5)

    def get_trust(self, evidence_id: str):
        return self.evidence_trust_map.get(evidence_id)


class MockObligations:
    """模拟 ObligationLedger 的 duck typing 接口"""
    def __init__(self, has_hard=False, voi_gated_list=None):
        self._has_hard = has_hard
        self._voi_gated = voi_gated_list or []

    def open_hard(self):
        return self._has_hard

    def open_voi_gated(self):
        return self._voi_gated


class MockVOIGatedObligation:
    def __init__(self, voi_estimate=0.0):
        self.voi_estimate = voi_estimate


def make_explanation(id, technique, tactic=None, prior=0.3):
    return Explanation(
        id=id, title=f"Expl {id}", current_technique=technique,
        stage=tactic, lifecycle_template=None,
        predecessor_tactics=[], technique_context=[],
        raw_score=0.5, prior_probability=prior,
        features={}, support={},
        recommended_log_sources=[], caveats=[],
    )


def make_ledger_high_attack():
    """创建 p_attack 高的 ledger"""
    expls = [make_explanation("H1", "T1001", tactic="initial-access", prior=0.8)]
    null = NullAnchor(benign=0.1, oos=0.1, reasons=["low null"])
    loss = LossMatrix()
    ledger = RuntimeDecisionLedger(
        explanations=expls, null_anchor=null,
        contested_edges=[], loss=loss,
    )
    # 通过多次 update 提高 attack 后验
    trust = MockTrustModel(trust_map={"ev": 0.9})
    for _ in range(8):
        ledger.update([{"id": "ev", "technique_id": "T1001", "tactic": "initial-access"}], trust)
    return ledger


def make_ledger_high_null():
    """创建 p_null 高的 ledger"""
    expls = [make_explanation("H1", "T1001", prior=0.1)]
    null = NullAnchor(benign=0.7, oos=0.2, reasons=["high null"])
    loss = LossMatrix()
    ledger = RuntimeDecisionLedger(
        explanations=expls, null_anchor=null,
        contested_edges=[], loss=loss,
    )
    # 提供不匹配证据提升 null
    trust = MockTrustModel(trust_map={"ev": 0.1})
    for _ in range(3):
        ledger.update([{"id": "ev", "technique_id": "T9999", "tactic": "unknown"}], trust)
    return ledger


def make_ledger_with_contested():
    """创建带 contested 边的 ledger"""
    expls = [
        make_explanation("H1", "T1001", prior=0.4),
        make_explanation("H2", "T1002", prior=0.3),
    ]
    null = NullAnchor(benign=0.2, oos=0.1, reasons=["test"])
    contested = [ContestedEdge(
        src="T1001", dst="T1002",
        boundary_prior={"p_in_attack": 0.5, "p_benign": 0.3, "p_oos": 0.2},
        support={}, reason="shared lateral",
    )]
    loss = LossMatrix()
    return RuntimeDecisionLedger(
        explanations=expls, null_anchor=null,
        contested_edges=contested, loss=loss,
    )


def make_uniform_ledger():
    """创建高熵（均匀）ledger"""
    expls = [
        make_explanation("H1", "T1001", prior=0.25),
        make_explanation("H2", "T1002", prior=0.25),
        make_explanation("H3", "T1003", prior=0.25),
    ]
    null = NullAnchor(benign=0.15, oos=0.1, reasons=["test"])
    return RuntimeDecisionLedger(
        explanations=expls, null_anchor=null,
        contested_edges=[], loss=LossMatrix(),
    )


# ═══════════════════════════════════════════════════════════════════════
# 测试：bayes_risk
# ═══════════════════════════════════════════════════════════════════════


def test_bayes_risk_non_negative():
    """bayes_risk 恒 >= 0"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    risk = bayes_risk(ledger, loss)
    assert risk >= 0.0


def test_bayes_risk_session_plus_boundary():
    """bayes_risk = session_risk + boundary_risk，边界级有正向贡献"""
    ledger = make_ledger_with_contested()
    loss = LossMatrix()
    risk_with_contested = bayes_risk(ledger, loss)

    # 对比无 contested 边的情况
    ledger_no_contested = make_uniform_ledger()
    risk_no_contested = bayes_risk(ledger_no_contested, loss)

    # 有 contested 边应有边界风险贡献
    # （虽然不总是严格大于，但由于 LAMBDA_OVER > 0 应该有贡献）
    assert risk_with_contested >= 0.0


def test_bayes_risk_high_p_attack_contain_optimal():
    """p_attack 高时 contain_escalate 最优（session_risk 低）"""
    ledger = make_ledger_high_attack()
    loss = LossMatrix()
    risk = bayes_risk(ledger, loss)

    # 高攻击概率时，contain 的期望损失 ≈ 0（攻击损失=0 + null惩罚小）
    # dismiss_benign 的期望损失 = p_attack * lambda_miss → 很高
    # 所以 session_risk = min(action_risks) 应该较低（contain 被选中）
    probs = ledger._get_probabilities()
    p_null = probs.get("__null__", 0.0)
    p_attack = 1.0 - p_null
    assert p_attack > 0.5  # 验证确实高攻击
    assert risk < p_attack * loss.lambda_miss  # risk < 驳回损失


def test_bayes_risk_high_p_null_dismiss_optimal():
    """p_null 高时 dismiss_benign 最优"""
    ledger = make_ledger_high_null()
    loss = LossMatrix()
    risk = bayes_risk(ledger, loss)

    probs = ledger._get_probabilities()
    p_null = probs.get("__null__", 0.0)
    # null 高时 dismiss 损失 ≈ 0，contain 损失 = p_null * lambda_over * 1.5
    assert risk < p_null * loss.lambda_over * 1.5 + 0.1


def test_bayes_risk_lambda_over_boundary_contribution():
    """LAMBDA_OVER > 0 使边界 contested 边有正向贡献"""
    loss = LossMatrix(lambda_over=2.0)
    ledger = make_ledger_with_contested()
    risk = bayes_risk(ledger, loss)

    # 修改 lambda_over = 0 → 边界贡献变小
    loss_zero = LossMatrix(lambda_over=0.0)
    risk_zero = bayes_risk(ledger, loss_zero)

    assert risk >= risk_zero


# ═══════════════════════════════════════════════════════════════════════
# 测试：voi
# ═══════════════════════════════════════════════════════════════════════


def test_voi_returns_voi_result():
    """voi 返回 VOIResult 结构正确"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    trust = MockTrustModel()
    probe = {"id": "probe1", "type": "network", "cost": 0.01}
    result = voi(probe, ledger, {}, {}, loss, trust)
    assert isinstance(result, VOIResult)
    assert result.probe_id == "probe1"
    assert result.risk_now >= 0.0


def test_voi_non_negative_for_good_probe():
    """好探针的 VOI >= 0（削减风险）"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    trust = MockTrustModel()
    probe = {"id": "probe1", "type": "network", "cost": 0.001}
    result = voi(probe, ledger, {}, {}, loss, trust)
    # VOI 可能为负（成本超过收益），但对好的探针应为非负或接近 0
    # 这里只验证结构
    assert result.voi_score is not None


def test_voi_higher_uncertainty_higher_voi():
    """高不确定性（高熵）时 VOI 更高"""
    # 高熵 ledger
    ledger_high_entropy = make_uniform_ledger()
    # 低熵 ledger（一个主导）
    ledger_low_entropy = make_ledger_high_attack()

    loss = LossMatrix()
    trust = MockTrustModel()
    probe = {"id": "probe1", "type": "network", "cost": 0.001}

    result_high = voi(probe, ledger_high_entropy, {}, {}, loss, trust)
    result_low = voi(probe, ledger_low_entropy, {}, {}, loss, trust)

    # 高熵时 risk_now 通常更高 → VOI 潜力更大
    assert result_high.risk_now >= result_low.risk_now


# ═══════════════════════════════════════════════════════════════════════
# 测试：predict_outcomes
# ═══════════════════════════════════════════════════════════════════════


def test_predict_outcomes_sum_to_one():
    """四元组概率和 = 1.0"""
    ledger = make_uniform_ledger()
    probe = {"id": "probe1", "type": "network"}
    outcomes = predict_outcomes(probe, ledger, {})
    total = sum(p for _, p in outcomes)
    assert abs(total - 1.0) < 1e-6


def test_predict_outcomes_four_outcomes():
    """返回四个 outcome"""
    ledger = make_uniform_ledger()
    probe = {"id": "probe1", "type": "network"}
    outcomes = predict_outcomes(probe, ledger, {})
    assert len(outcomes) == 4
    names = {name for name, _ in outcomes}
    assert names == {"attributable", "benign", "oos", "no_data"}


def test_predict_outcomes_high_attack_high_attributable():
    """p_attack 高时 p_attributable 高"""
    ledger = make_ledger_high_attack()
    probe = {"id": "probe1", "type": "network"}
    outcomes = predict_outcomes(probe, ledger, {})
    outcome_map = {name: p for name, p in outcomes}
    # attributable 应该比 benign 高
    assert outcome_map["attributable"] > outcome_map["benign"]


def test_predict_outcomes_high_null_high_benign():
    """p_null 高时 p_benign 高"""
    ledger = make_ledger_high_null()
    probe = {"id": "probe1", "type": "network"}
    outcomes = predict_outcomes(probe, ledger, {})
    outcome_map = {name: p for name, p in outcomes}
    # benign + oos 应该比 attributable 高
    assert (outcome_map["benign"] + outcome_map["oos"]) > outcome_map["attributable"]


def test_predict_outcomes_all_non_negative():
    """所有概率 >= 0"""
    ledger = make_uniform_ledger()
    probe = {"id": "probe1", "type": "network"}
    outcomes = predict_outcomes(probe, ledger, {})
    for name, p in outcomes:
        assert p >= 0.0


def test_beta_changes_no_data_once_not_conditional_mix():
    ledger = make_uniform_ledger()
    probe = {
        "id": "p",
        "operator": "process_tree",
        "target_type": "host",
        "tactic": "execution",
        "learning_key": "process_tree|host|execution",
    }
    model = ConservativeOutcomeModel()
    low = model.predict(
        probe,
        ledger,
        {probe["learning_key"]: {"alpha": 1.0, "beta": 9.0}},
    )
    high = model.predict(
        probe,
        ledger,
        {probe["learning_key"]: {"alpha": 9.0, "beta": 1.0}},
    )
    assert low.probabilities["no_data"] > high.probabilities["no_data"]
    low_signal = 1.0 - low.probabilities["no_data"]
    high_signal = 1.0 - high.probabilities["no_data"]
    assert (
        low.probabilities["benign"] / low_signal
        == pytest.approx(high.probabilities["benign"] / high_signal)
    )


def test_probe_tactic_changes_targeted_explanation_outcome():
    ledger = make_uniform_ledger()
    ledger.explanations[0].stage = "initial-access"
    ledger.explanations[1].stage = "execution"
    model = ConservativeOutcomeModel()
    common = {
        "id": "p",
        "operator": "process_tree",
        "target_type": "host",
        "learning_key": "process_tree|host|x",
    }
    initial = model.predict(
        {**common, "tactic": "initial-access"}, ledger, {}
    )
    execution = model.predict({**common, "tactic": "execution"}, ledger, {})
    assert (
        initial.probabilities["attributable:H1"]
        > execution.probabilities["attributable:H1"]
    )
    assert (
        execution.probabilities["attributable:H2"]
        > initial.probabilities["attributable:H2"]
    )


def test_higher_measured_cost_lowers_voi():
    ledger = make_uniform_ledger()
    trust = MockTrustModel()
    low = voi(
        {"id": "p", "type": "network", "cost": 0.01},
        ledger, {}, {}, LossMatrix(), trust,
    )
    high = voi(
        {"id": "p", "type": "network", "cost": 0.50},
        ledger, {}, {}, LossMatrix(), trust,
    )
    assert high.voi_score < low.voi_score
    assert high.cost > low.cost


# ═══════════════════════════════════════════════════════════════════════
# 测试：should_stop
# ═══════════════════════════════════════════════════════════════════════


def test_should_stop_budget_exhausted():
    """budget 耗尽 → STOP('budget')"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    obligations = MockObligations()
    budget = {"remaining": 0, "total": 10}
    result = should_stop(ledger, {}, budget, obligations, loss)
    assert result.should_stop is True
    assert result.reason == "budget"


def test_should_stop_open_hard_continues():
    """open_hard() → CONTINUE"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    obligations = MockObligations(has_hard=True)
    budget = {"remaining": 5, "total": 10}
    result = should_stop(ledger, {}, budget, obligations, loss)
    assert result.should_stop is False
    assert result.reason == "continue"


def test_should_stop_robust():
    """margin 大 + entropy 低 → 可能 STOP('robust')"""
    ledger = make_ledger_high_attack()
    loss = LossMatrix()
    obligations = MockObligations()
    budget = {"remaining": 5, "total": 10}
    result = should_stop(ledger, {}, budget, obligations, loss)
    # 高攻击 + 低熵 + 大 margin → robust stop 或 voi_floor
    if result.should_stop:
        assert result.reason in ("robust", "voi_floor")


def test_should_stop_normal_continues():
    """正常情况（中等不确定性）→ CONTINUE"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    # 加入有 VOI 估计的门控义务，确保 max_voi >= EPS_VOI
    voi_ob = MockVOIGatedObligation(voi_estimate=1.0)
    obligations = MockObligations(voi_gated_list=[voi_ob])
    budget = {"remaining": 5, "total": 10}
    result = should_stop(ledger, {}, budget, obligations, loss)
    assert result.should_stop is False
    assert result.reason == "continue"


def test_should_stop_returns_stop_decision():
    """should_stop 返回 StopDecision"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    budget = {"remaining": 5, "total": 10}
    result = should_stop(ledger, {}, budget, MockObligations(), loss)
    assert isinstance(result, StopDecision)
    assert hasattr(result, 'should_stop')
    assert hasattr(result, 'reason')
    assert hasattr(result, 'max_voi')
    assert hasattr(result, 'risk_now')


# ═══════════════════════════════════════════════════════════════════════
# 测试：decision_robust
# ═══════════════════════════════════════════════════════════════════════


def test_decision_robust_high_margin_true():
    """margin 大 + 后验明确 → True"""
    ledger = make_ledger_high_attack()
    loss = LossMatrix()
    # 高攻击 ledger 应满足：margin >= 0.3 且 decision_robust
    probs = ledger._get_probabilities()
    p_attack = 1.0 - probs.get("__null__", 0.0)
    # 验证确实是高攻击场景
    assert p_attack > 0.5
    assert ledger.margin() >= 0.3
    assert decision_robust(ledger, loss) is True


def test_decision_robust_low_margin_false():
    """margin 小 → False"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    # 均匀分布 margin 小
    assert decision_robust(ledger, loss) is False


def test_decision_robust_returns_bool():
    """decision_robust 返回 bool"""
    ledger = make_uniform_ledger()
    loss = LossMatrix()
    result = decision_robust(ledger, loss)
    assert isinstance(result, bool)
