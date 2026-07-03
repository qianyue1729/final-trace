"""VOI 引擎 — RFC-004-02 §6/§7 期望决策风险削减 + 价值导向停止"""
from __future__ import annotations
import math
from typing import Dict, List, Optional, Tuple

from ..decision.runtime_types import LossMatrix, BoundaryBelief, VOIResult, StopDecision
from .outcome_model import ConservativeOutcomeModel
from ..utils.config import EPS_VOI, ROBUSTNESS_PERTURBATION

# 会话级动作集
SESSION_ACTIONS = ["monitor", "contain_escalate", "dismiss_benign"]


# ═══════════════════════════════════════════════════════════════════════════════
# §6 核心：贝叶斯决策风险
# ═══════════════════════════════════════════════════════════════════════════════


def bayes_risk(ledger, loss: LossMatrix) -> float:
    """
    总风险 = 会话级处置风险 + Σ 边界归属风险 (§6)

    Args:
        ledger: RuntimeDecisionLedger（duck typing）
        loss: LossMatrix

    Returns:
        float >= 0  总贝叶斯决策风险
    """
    # (1) 会话级风险：对每个动作计算期望损失，取最优动作
    probs = ledger._get_probabilities()

    # 分离 null 和攻击解释的后验
    p_null = probs.get("__null__", 0.0)
    p_attack = 1.0 - p_null  # 所有攻击解释的总后验

    # 各动作的期望损失：
    #   monitor:          延迟处置 → 攻击漏检有部分代价，良性代价极低
    #   contain_escalate: 遏制 → 若真攻击则最优(0)，若良性则过反应
    #   dismiss_benign:   驳回 → 若真攻击则 LAMBDA_MISS 全额代价
    action_risks: Dict[str, float] = {
        "monitor": p_attack * loss.lambda_miss * 0.3 + p_null * 0.1,
        "contain_escalate": p_attack * 0.0 + p_null * loss.lambda_over * 1.5,
        "dismiss_benign": p_attack * loss.lambda_miss + p_null * 0.0,
    }

    session_risk = min(action_risks.values())

    # (2) 边界级风险：每条 contested 边取最优归属动作
    contested = ledger.get_contested()
    boundary_risk = 0.0
    for edge_id, belief in contested.items():
        # 纳入此边的代价（如果实际是 benign/oos）
        include_cost = belief.p_benign * loss.lambda_over + belief.p_oos * loss.lambda_oos
        # 剪掉此边的代价（如果实际是攻击）
        prune_cost = belief.p_in_attack * loss.lambda_miss
        # 最优动作的残余风险
        boundary_risk += min(include_cost, prune_cost)

    total = session_risk + boundary_risk
    # 确保非负（数学上恒成立，防御性断言）
    return max(0.0, total)


# ═══════════════════════════════════════════════════════════════════════════════
# §6 核心：VOI 一步前瞻
# ═══════════════════════════════════════════════════════════════════════════════


def voi(probe: dict, ledger, beta: dict, calib: dict,
        loss: LossMatrix, trust, graph_stats=None) -> VOIResult:
    """
    期望决策风险削减 — 一步前瞻 (§6)

    支持双模计算：当 decision_voi 低于探索阈值且提供了 graph_stats 时，
    切换到 exploration 模式，基于信息增益评估探索价值。

    Args:
        probe: 探针 dict（需含 id, cost 等）
        ledger: RuntimeDecisionLedger
        beta: Beta 台账 dict（用于 predict_outcomes）
        calib: 标定 dict（用于 cost 估计）
        loss: LossMatrix
        trust: EvidenceTrustModel（传给 hypothetical_update）
        graph_stats: 图统计 dict（含 hosts, tactics_seen, tactics_per_host, node_count），
                     默认 None 时行为与原来完全一致。

    Returns:
        VOIResult
    """
    probe_id = probe.get("id", "")
    risk_now = bayes_risk(ledger, loss)

    # 预测探针可能结果
    prediction = ConservativeOutcomeModel().predict(probe, ledger, beta)

    # 计算期望后续风险
    exp_risk_after = 0.0
    for outcome, p_outcome in prediction.probabilities.items():
        if p_outcome <= 0:
            continue
        # 假设更新
        ledger_next = ledger.hypothetical_update(
            probe,
            outcome,
            trust,
            modeled_likelihoods=prediction.likelihoods[outcome],
            target_edge_id=prediction.target_edge_id,
        )
        risk_after = bayes_risk(ledger_next, loss)
        exp_risk_after += p_outcome * risk_after

    # 成本
    cost = _estimate_cost(probe, calib)

    decision_voi = (risk_now - exp_risk_after) - cost

    # 双模计算：当 decision_voi 很低时，切换到 exploration 模式
    # 阈值极低：仅在decision_voi几乎为0时才启用exploration_voi
    VOI_EXPLORE_THRESHOLD = 0.001
    if graph_stats is None or decision_voi > VOI_EXPLORE_THRESHOLD:
        voi_score = decision_voi
    else:
        explore_voi = _exploration_voi(probe, graph_stats)
        EXPLORE_WEIGHT = 0.5
        voi_score = max(decision_voi, explore_voi * EXPLORE_WEIGHT)

    return VOIResult(
        probe_id=probe_id,
        voi_score=voi_score,
        risk_now=risk_now,
        expected_risk_after=exp_risk_after,
        cost=cost,
        audit={
            "outcome_model_version": prediction.version,
            "outcome_model_status": prediction.status,
            "outcomes": dict(prediction.probabilities),
            "target_edge_id": prediction.target_edge_id,
            **prediction.audit,
        },
    )


# ═══════════════════════════════════════════════════════════════════════════════
# §6.1 结果预测
# ═══════════════════════════════════════════════════════════════════════════════


def predict_outcomes(probe: dict, ledger, beta: dict) -> List[Tuple[str, float]]:
    """
    预测探针可能结果的分布 (§6.1)

    结果空间: {attributable, benign, oos, no_data}
    P(outcome|p) = Σ_H P(H) · P(outcome|H, p)

    Beta 台账供 P(no_data)/灵敏度的收缩先验。

    Returns:
        四元组列表 [(outcome, probability), ...]，概率和 = 1.0
    """
    detailed = ConservativeOutcomeModel().predict(probe, ledger, beta)
    attributable = sum(
        probability
        for outcome, probability in detailed.probabilities.items()
        if outcome.startswith("attributable:")
    )
    return [
        ("attributable", attributable),
        ("benign", detailed.probabilities.get("benign", 0.0)),
        ("oos", detailed.probabilities.get("oos", 0.0)),
        ("no_data", detailed.probabilities.get("no_data", 0.0)),
    ]


# ═══════════════════════════════════════════════════════════════════════════════
# §7 价值导向停止
# ═══════════════════════════════════════════════════════════════════════════════


def compute_max_voi(
    candidates: list,
    ledger,
    beta: dict,
    calib: dict,
    loss: LossMatrix,
    trust,
    graph_stats=None,
    probe_to_dict=None,
) -> float:
    """扫描候选池计算 max VOI — RFC §7 停止判据。"""
    if not candidates:
        return 0.0
    max_score = 0.0
    for probe in candidates:
        try:
            if isinstance(probe, dict):
                pd = probe
            elif probe_to_dict is not None:
                pd = probe_to_dict(probe)
            else:
                pd = {
                    "id": getattr(probe, "id", ""),
                    "type": getattr(probe, "source", ""),
                    "target": getattr(probe, "target", ""),
                    "target_type": getattr(probe, "target_type", ""),
                    "operator": getattr(probe, "operator", ""),
                    "tactic": getattr(probe, "tactic", ""),
                    "learning_key": probe.learning_key() if hasattr(probe, "learning_key") else "",
                    "cost": 0.05,
                }
            result = voi(pd, ledger, beta, calib, loss, trust, graph_stats=graph_stats)
            max_score = max(max_score, result.voi_score)
        except Exception:
            continue
    return max_score


def should_stop(ledger, beta: dict, budget: dict,
                obligations, loss: LossMatrix,
                candidate_probes=None,
                trust=None,
                calib: Optional[dict] = None,
                graph_stats=None,
                probe_to_dict=None) -> StopDecision:
    """
    价值导向停止 (§7)

    停止条件（按优先级）：
    1. budget.exhausted → STOP("budget")
    2. obligations.open_hard() → CONTINUE（硬义务无条件续跑）
    3. max_voi < EPS_VOI → STOP("voi_floor")
    4. decision_robust(ledger, loss) → STOP("robust")

    Args:
        ledger: RuntimeDecisionLedger
        beta: Beta 台账 dict
        budget: 预算 dict（含 remaining / total）
        obligations: ObligationLedger（duck typing）
        loss: LossMatrix

    Returns:
        StopDecision
    """
    risk_now = bayes_risk(ledger, loss)

    # 1. 预算耗尽
    budget_remaining = (
        budget.get("remaining", float("inf"))
        if isinstance(budget, dict)
        else float("inf")
    )
    if budget_remaining <= 0:
        return StopDecision(
            should_stop=True,
            reason="budget",
            max_voi=0.0,
            risk_now=risk_now,
        )

    # 2. 硬义务未清 → 无条件续跑
    if obligations and hasattr(obligations, "open_hard") and obligations.open_hard():
        return StopDecision(
            should_stop=False,
            reason="continue",
            max_voi=float("inf"),  # 硬义务时不计 VOI
            risk_now=risk_now,
        )

    # 3. max_voi：优先扫描候选池，否则回退启发式
    if candidate_probes:
        max_voi_estimate = compute_max_voi(
            candidate_probes, ledger, beta, calib or {}, loss, trust,
            graph_stats=graph_stats, probe_to_dict=probe_to_dict,
        )
    else:
        entropy_val = ledger.entropy() if hasattr(ledger, "entropy") else 0.0
        margin_val = ledger.margin() if hasattr(ledger, "margin") else 1.0
        max_voi_estimate = entropy_val * (1.0 - margin_val) * loss.lambda_miss * 0.1

    # VOI 门控义务也贡献 max_voi
    if obligations and hasattr(obligations, "open_voi_gated"):
        voi_gated = obligations.open_voi_gated()
        for ob in voi_gated:
            max_voi_estimate = max(max_voi_estimate, ob.voi_estimate)

    if max_voi_estimate < EPS_VOI:
        return StopDecision(
            should_stop=True,
            reason="voi_floor",
            max_voi=max_voi_estimate,
            risk_now=risk_now,
        )

    # 4. 决策鲁棒性
    if decision_robust(ledger, loss):
        return StopDecision(
            should_stop=True,
            reason="robust",
            max_voi=max_voi_estimate,
            risk_now=risk_now,
        )

    return StopDecision(
        should_stop=False,
        reason="continue",
        max_voi=max_voi_estimate,
        risk_now=risk_now,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# §7 决策鲁棒性
# ═══════════════════════════════════════════════════════════════════════════════


def decision_robust(ledger, loss: LossMatrix) -> bool:
    """
    最优处置在后验置信区间扰动下不翻转 (§7)

    方法：对后验施加 ±ROBUSTNESS_PERTURBATION 扰动，
    检查最优动作是否改变。

    分两层判断：
    1. 决策级鲁棒：P_attack vs P_null 距决策边界远（>0.15），扰动不翻转
    2. 假说级鲁棒：攻击解释间 margin >= 0.3（决定具体归因）

    当决策级已鲁棒时跳过假说级检查（处置决策不受哪个攻击假说胜出影响）。

    Returns:
        True = 决策已鲁棒（停止安全）
        False = 决策仍不稳定（需继续探查）
    """
    probs = ledger._get_probabilities()
    p_null = probs.get("__null__", 0.0)
    p_attack = 1.0 - p_null

    # 当前最优动作
    current_best = _best_action(p_attack, p_null, loss)

    # 扰动检查：p_attack ± perturbation
    perturbation = ROBUSTNESS_PERTURBATION
    for delta in [perturbation, -perturbation]:
        p_attack_perturbed = max(0.0, min(1.0, p_attack + delta))
        p_null_perturbed = 1.0 - p_attack_perturbed
        perturbed_best = _best_action(p_attack_perturbed, p_null_perturbed, loss)
        if perturbed_best != current_best:
            return False  # 不鲁棒

    # 决策级鲁棒性：P_attack 或 P_null 远离决策边界 (>0.85 或 <0.15)
    # 此时无论哪个攻击假说胜出，处置决策（contain/dismiss）都不会翻转
    decision_margin = abs(p_attack - 0.5)  # 距不确定中点的距离
    if decision_margin >= 0.35:  # P_attack >= 0.85 or P_null >= 0.85
        return True  # 决策级鲁棒，跳过假说级 margin 检查

    # 假说级鲁棒：攻击解释间的置信度差距
    margin = ledger.margin() if hasattr(ledger, "margin") else 0.0
    if margin < 0.3:
        return False  # 处置决策在边界附近 + 假说竞争激烈

    return True


# ═══════════════════════════════════════════════════════════════════════════════
# §6.2 Exploration VOI（信息增益 fallback）
# ═══════════════════════════════════════════════════════════════════════════════


TACTIC_KILL_CHAIN = [
    "reconnaissance", "resource-development", "initial-access",
    "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact"
]


def _exploration_voi(probe: dict, graph_stats: dict) -> float:
    """基于信息增益的探索价值——当决策VOI很低时用作fallback排序"""
    tactic = probe.get("tactic", "")
    target = probe.get("target", "")

    # 1. Tactic novelty: 目标主机上是否已有此tactic
    tactics_per_host = graph_stats.get("tactics_per_host", {})
    tactics_on_target = tactics_per_host.get(target, set())
    if isinstance(tactics_on_target, list):
        tactics_on_target = set(tactics_on_target)
    novelty = 1.0 if tactic not in tactics_on_target else 0.3

    # 2. Host novelty: 目标主机是否已在图中
    hosts = graph_stats.get("hosts", set())
    if isinstance(hosts, list):
        hosts = set(hosts)
    host_novelty = 0.5 if target.lower() not in {h.lower() for h in hosts} else 0.1

    # 3. Gap relevance: 是否填补kill-chain gap
    gap_relevance = _gap_score(probe, graph_stats)

    # 加权组合，乘以priority_hint作为调制
    priority_hint = probe.get("priority_hint", 0.5)
    base = novelty * 0.3 + host_novelty * 0.3 + gap_relevance * 0.4
    return base * priority_hint


def _gap_score(probe: dict, graph_stats: dict) -> float:
    """评估probe是否填补kill-chain中的gap"""
    tactic = probe.get("tactic", "")
    if tactic not in TACTIC_KILL_CHAIN:
        return 0.2  # 未知tactic，给低分

    tactics_seen = graph_stats.get("tactics_seen", [])
    if isinstance(tactics_seen, list):
        tactics_seen = set(tactics_seen)

    if not tactics_seen:
        return 0.5  # 图为空，任何探索都有价值

    # 计算已见tactics在kill-chain中的位置
    seen_indices = sorted([TACTIC_KILL_CHAIN.index(t) for t in tactics_seen if t in TACTIC_KILL_CHAIN])
    if not seen_indices:
        return 0.5

    probe_idx = TACTIC_KILL_CHAIN.index(tactic)

    # Case 1: probe的tactic恰好在seen范围内的gap中
    min_seen, max_seen = seen_indices[0], seen_indices[-1]
    if min_seen < probe_idx < max_seen and tactic not in tactics_seen:
        return 1.0  # 填补内部gap，最高价值

    # Case 2: probe是chain的前后延伸（紧邻已见范围）
    if probe_idx == min_seen - 1 or probe_idx == max_seen + 1:
        return 0.6  # 链的延伸

    # Case 3: probe在已见范围之外较远
    return 0.2


# ═══════════════════════════════════════════════════════════════════════════════
# 内部工具
# ═══════════════════════════════════════════════════════════════════════════════


def _best_action(p_attack: float, p_null: float, loss: LossMatrix) -> str:
    """给定后验，计算最优动作（风险最小化）"""
    risks = {
        "monitor": p_attack * loss.lambda_miss * 0.3 + p_null * 0.1,
        "contain_escalate": p_attack * 0.0 + p_null * loss.lambda_over * 1.5,
        "dismiss_benign": p_attack * loss.lambda_miss + p_null * 0.0,
    }
    return min(risks, key=risks.get)


def _estimate_cost(probe: dict, calib: dict) -> float:
    """估计探针成本（标定后）"""
    return max(0.001, min(2.0, float(probe.get("cost", 0.10))))
