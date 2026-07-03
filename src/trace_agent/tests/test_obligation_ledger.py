"""ObligationLedger 义务台账完整测试套件。

覆盖范围：
- from_json 加载 lifecycle_templates.json
- scan_structural：恶意孤儿/悬空凭据 → 硬义务
- scan_lifecycle：required 阶段缺失 → VOI 门控义务
- scan_anti_forensics：反取证/缺失标记 → 硬义务
- scan_discriminative：margin < 0.15 → VOI 门控义务
- scan 去重（同 anchor 不重复生成）
- open_hard / open_voi_gated 接口
- discharge 关闭逻辑（lifecycle / discriminative / structural）
- cascade_on_revision 级联
- materialize_open 物化探针
- prioritize 排序
"""
import pytest
from pathlib import Path

from trace_agent.decision.runtime_types import (
    LossMatrix, Obligation, ObligationIntent, ObligationType,
)
from trace_agent.obligation_integration.obligation_ledger import ObligationLedger
from trace_agent.utils.config import DISCRIMINATIVE_MARGIN_THRESHOLD


# ═══════════════════════════════════════════════════════════════════════
# 测试辅助工具
# ═══════════════════════════════════════════════════════════════════════


class MockLedger:
    """模拟 RuntimeDecisionLedger 的 duck typing 接口"""
    def __init__(self, leading_id="H1", margin_val=0.3, explanations=None, posteriors=None):
        self._leading = leading_id
        self._margin = margin_val
        self.explanations = explanations or []
        self._posteriors = posteriors or {}

    def leading(self):
        return self._leading

    def margin(self):
        return self._margin

    def posterior(self, eid):
        return self._posteriors.get(eid, 0.5)


class MockExplanation:
    """模拟 Explanation"""
    def __init__(self, id, lifecycle_template=None, support=None):
        self.id = id
        self.lifecycle_template = lifecycle_template
        self.support = support or {}


class MockTrustForObligation:
    """模拟 EvidenceTrustModel 的义务扫描接口"""
    def __init__(self, trust_entries=None):
        self.evidence_trust_map = trust_entries or {}


class MockEvidenceTrustEntry:
    """模拟单条 EvidenceTrust"""
    def __init__(self, anti_forensics=False, absence=False):
        self.anti_forensics_indicator = anti_forensics
        self.absence_indicator = absence


class MockRevision:
    """模拟 TrustRevision"""
    def __init__(self, evidence_id, new_trust=None):
        self.evidence_id = evidence_id
        self.new_trust = new_trust


class MockNewTrust:
    """模拟修订后的信任"""
    def __init__(self, adversary_controllable=False, anti_forensics_indicator=False):
        self.adversary_controllable = adversary_controllable
        self.anti_forensics_indicator = anti_forensics_indicator


# ═══════════════════════════════════════════════════════════════════════
# 测试：from_json 加载
# ═══════════════════════════════════════════════════════════════════════


def test_from_json_loads_templates():
    """from_json 正确加载 lifecycle_templates.json"""
    templates_path = Path(__file__).resolve().parent.parent / 'data' / 'lifecycle_templates.json'
    ledger = ObligationLedger.from_json(templates_path)
    assert len(ledger.templates) > 0
    assert ledger.templates[0]["template_id"] == "commodity_malware_v1"


def test_from_json_loss_matrix():
    """from_json 可接受自定义 LossMatrix"""
    templates_path = Path(__file__).resolve().parent.parent / 'data' / 'lifecycle_templates.json'
    loss = LossMatrix(lambda_miss=20.0)
    ledger = ObligationLedger.from_json(templates_path, loss=loss)
    assert ledger.loss.lambda_miss == 20.0


# ═══════════════════════════════════════════════════════════════════════
# 测试：scan_structural
# ═══════════════════════════════════════════════════════════════════════


def test_scan_structural_true_orphan_fact():
    """Only a fact that explicitly requires a parent creates hard debt."""
    ledger = ObligationLedger()
    graph = {
        "nodes": [
            {
                "id": "node1",
                "fact_confirmed": True,
                "requires_parent": True,
                "host_id": "host-A",
            },
        ],
        "edges": [],
    }
    obs = ledger.scan_structural(graph, current_round=3)
    assert len(obs) >= 1
    assert obs[0].hard is True
    assert obs[0].type == ObligationType.STRUCTURAL
    assert "orphan" in obs[0].anchor
    assert obs[0].created_round == 3
    assert obs[0].intent.host_ids == ["host-A"]


def test_ordinary_frontier_leaf_creates_no_hard_orphan():
    ledger = ObligationLedger()
    graph = {
        "nodes": [
            {
                "id": "leaf",
                "fact_confirmed": True,
                "requires_parent": False,
                "host_id": "host-A",
            }
        ],
        "edges": [{"src": "root", "dst": "leaf"}],
    }
    assert ledger.scan_structural(graph, current_round=2) == []


def test_scan_structural_dangling_credential():
    """悬空凭据 → 硬义务"""
    ledger = ObligationLedger()
    graph = {
        "nodes": [
            {"id": "cred1", "type": "credential", "provenance_confirmed": False},
        ],
        "edges": [],
    }
    obs = ledger.scan_structural(graph)
    assert len(obs) >= 1
    assert any("credential" in o.anchor for o in obs)
    assert all(o.hard for o in obs)


def test_scan_structural_bridge_host():
    """桥接主机 → 硬义务"""
    ledger = ObligationLedger()
    graph = {
        "nodes": [
            {"id": "host1", "type": "host", "bridge_candidate": True},
        ],
        "edges": [],
    }
    obs = ledger.scan_structural(graph)
    assert len(obs) >= 1
    assert any("bridge" in o.anchor for o in obs)


# ═══════════════════════════════════════════════════════════════════════
# 测试：scan_lifecycle
# ═══════════════════════════════════════════════════════════════════════


def test_scan_lifecycle_required_stage_missing():
    """required 阶段缺失 → VOI 门控义务"""
    templates = [{
        "template_id": "test_template_v1",
        "stages": [
            {"stage": "initial_access", "required": True, "expected_tactics": ["initial-access"], "debt_policy": "hard"},
            {"stage": "execution", "required": True, "expected_tactics": ["execution"], "debt_policy": "hard"},
        ],
    }]
    ledger = ObligationLedger(lifecycle_templates=templates)

    mock_expl = MockExplanation("H1", lifecycle_template="test_template_v1")
    mock_ledger = MockLedger(
        leading_id="H1", margin_val=0.3,
        explanations=[mock_expl],
    )

    graph = {"nodes": [], "edges": []}
    obs = ledger.scan_lifecycle(mock_ledger, graph)
    # 两个 required 阶段都缺失 → 2 个义务
    assert len(obs) == 2
    assert all(o.type == ObligationType.LIFECYCLE for o in obs)
    assert all(o.hard is False for o in obs)  # lifecycle 统一走 VOI 门控


def test_scan_lifecycle_covered_stage_no_obligation():
    """已覆盖的 required 阶段不生成义务"""
    templates = [{
        "template_id": "test_template_v1",
        "stages": [
            {"stage": "initial_access", "required": True, "expected_tactics": ["initial-access"], "debt_policy": "hard"},
        ],
    }]
    ledger = ObligationLedger(lifecycle_templates=templates)

    mock_expl = MockExplanation("H1", lifecycle_template="test_template_v1")
    mock_ledger = MockLedger(leading_id="H1", explanations=[mock_expl])

    # 图中已有确认的 initial-access tactic
    graph = {
        "nodes": [{"id": "n1", "tactic": "initial-access", "fact_confirmed": True}],
        "edges": [],
    }
    obs = ledger.scan_lifecycle(mock_ledger, graph)
    assert len(obs) == 0


# ═══════════════════════════════════════════════════════════════════════
# 测试：scan_anti_forensics
# ═══════════════════════════════════════════════════════════════════════


def test_scan_anti_forensics_indicator():
    """反取证标记 → 硬义务"""
    trust = MockTrustForObligation(trust_entries={
        "ev1": MockEvidenceTrustEntry(anti_forensics=True),
    })
    ledger = ObligationLedger()
    obs = ledger.scan_anti_forensics(trust)
    assert len(obs) == 1
    assert obs[0].hard is True
    assert obs[0].type == ObligationType.ANTI_FORENSICS


def test_scan_anti_forensics_absence():
    """缺失标记 → 硬义务"""
    trust = MockTrustForObligation(trust_entries={
        "ev2": MockEvidenceTrustEntry(absence=True),
    })
    ledger = ObligationLedger()
    obs = ledger.scan_anti_forensics(trust)
    assert len(obs) == 1
    assert obs[0].hard is True


def test_scan_anti_forensics_none():
    """无反取证标记 → 不生成"""
    trust = MockTrustForObligation(trust_entries={
        "ev1": MockEvidenceTrustEntry(anti_forensics=False, absence=False),
    })
    ledger = ObligationLedger()
    obs = ledger.scan_anti_forensics(trust)
    assert len(obs) == 0


# ═══════════════════════════════════════════════════════════════════════
# 测试：scan_discriminative
# ═══════════════════════════════════════════════════════════════════════


def test_scan_discriminative_low_margin():
    """margin < 0.15 → VOI 门控义务"""
    ledger = ObligationLedger()
    mock_ledger = MockLedger(leading_id="H1", margin_val=0.05)
    obs = ledger.scan_discriminative(mock_ledger)
    assert len(obs) == 1
    assert obs[0].hard is False
    assert obs[0].type == ObligationType.DISCRIMINATIVE


def test_scan_discriminative_high_margin_no_obligation():
    """margin >= 0.15 → 不生成"""
    ledger = ObligationLedger()
    mock_ledger = MockLedger(leading_id="H1", margin_val=0.3)
    obs = ledger.scan_discriminative(mock_ledger)
    assert len(obs) == 0


# ═══════════════════════════════════════════════════════════════════════
# 测试：scan 去重
# ═══════════════════════════════════════════════════════════════════════


def test_scan_deduplication():
    """同 anchor 不重复生成"""
    trust = MockTrustForObligation(trust_entries={
        "ev1": MockEvidenceTrustEntry(anti_forensics=True),
    })
    ledger = ObligationLedger()
    mock_ledger = MockLedger(leading_id="H1", margin_val=0.3)
    graph = {"nodes": [], "edges": []}

    # 第一次扫描
    added1 = ledger.scan(graph, mock_ledger, trust, {})
    # 第二次扫描（同条件）
    added2 = ledger.scan(graph, mock_ledger, trust, {})

    # 第二次不应新增（去重）
    assert len(added2) == 0


# ═══════════════════════════════════════════════════════════════════════
# 测试：open_hard / open_voi_gated
# ═══════════════════════════════════════════════════════════════════════


def test_open_hard_with_hard_obligation():
    """有硬义务时 open_hard 返回 True"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="ob1", type=ObligationType.STRUCTURAL,
        anchor="test:ob1", sla_rounds=5, hard=True,
        created_round=0, deadline_round=5,
    ))
    assert ledger.open_hard() is True


def test_open_hard_no_hard():
    """无硬义务时 open_hard 返回 False"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="ob1", type=ObligationType.LIFECYCLE,
        anchor="test:ob1", sla_rounds=5, hard=False,
        created_round=0, deadline_round=5,
    ))
    assert ledger.open_hard() is False


def test_open_voi_gated_returns_non_hard():
    """open_voi_gated 返回非硬义务列表"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="ob1", type=ObligationType.STRUCTURAL,
        anchor="test:ob1", sla_rounds=5, hard=True,
        created_round=0, deadline_round=5,
    ))
    ledger.obligations.append(Obligation(
        id="ob2", type=ObligationType.LIFECYCLE,
        anchor="test:ob2", sla_rounds=5, hard=False,
        created_round=0, deadline_round=5,
    ))
    voi_gated = ledger.open_voi_gated()
    assert len(voi_gated) == 1
    assert voi_gated[0].id == "ob2"


# ═══════════════════════════════════════════════════════════════════════
# 测试：discharge
# ═══════════════════════════════════════════════════════════════════════


def test_discharge_lifecycle_stage_covered():
    """lifecycle 义务：对应阶段覆盖后关闭"""
    templates = [{
        "template_id": "tmpl1",
        "stages": [{"stage": "execution", "expected_tactics": ["execution"]}],
    }]
    ledger = ObligationLedger(lifecycle_templates=templates)
    ledger.obligations.append(Obligation(
        id="lc1", type=ObligationType.LIFECYCLE,
        anchor="lifecycle_gap:tmpl1:execution", sla_rounds=8, hard=False,
        created_round=0, deadline_round=8, explanation_id="H1",
        intent=ObligationIntent(
            affected_entity_ids=[],
            host_ids=["host-A"],
            question="cover execution",
            allowed_operators=["process_tree"],
            acceptance_criterion={
                "type": "tactic_observed",
                "expected_tactics": ["execution"],
                "stage": "execution",
            },
            reason_code="required_lifecycle_stage_missing",
        ),
    ))

    mock_ledger = MockLedger(leading_id="H1")
    graph = {
        "nodes": [{"id": "n1", "tactic": "execution", "fact_confirmed": True}],
        "edges": [],
    }
    discharged = ledger.discharge(graph, mock_ledger)
    assert "lc1" in discharged


def test_discharge_discriminative_margin_restored():
    """discriminative 义务：margin 恢复后关闭"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="disc1", type=ObligationType.DISCRIMINATIVE,
        anchor="discriminative_margin:H1:0.050", sla_rounds=6, hard=False,
        created_round=0, deadline_round=6,
    ))

    # margin 已恢复到阈值以上
    mock_ledger = MockLedger(margin_val=0.3)
    graph = {"nodes": [], "edges": []}
    discharged = ledger.discharge(graph, mock_ledger)
    assert "disc1" in discharged


def test_discharge_structural_orphan_resolved():
    """structural 义务：孤儿解决后关闭"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="str1", type=ObligationType.STRUCTURAL,
        anchor="malicious_orphan:node1", sla_rounds=5, hard=True,
        created_round=0, deadline_round=5,
        intent=ObligationIntent(
            affected_entity_ids=["node1"],
            host_ids=["host-A"],
            question="find parent",
            allowed_operators=["process_tree"],
            acceptance_criterion={
                "type": "supported_parent_edge",
                "node_id": "node1",
            },
            reason_code="orphan_fact_missing_parent",
        ),
    ))

    mock_ledger = MockLedger()
    # node1 现在有受支持的父边
    graph = {
        "nodes": [{"id": "node1"}],
        "edges": [{"src": "node0", "dst": "node1"}],
    }
    discharged = ledger.discharge(graph, mock_ledger)
    assert "str1" in discharged


# ═══════════════════════════════════════════════════════════════════════
# 测试：cascade_on_revision
# ═══════════════════════════════════════════════════════════════════════


def test_cascade_on_revision_upgrade_to_hard():
    """修订级联：新证据升级为反取证 → 义务升级为硬"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="ob1", type=ObligationType.LIFECYCLE,
        anchor="lifecycle_gap:tmpl1:ev_abc", sla_rounds=5, hard=False,
        created_round=0, deadline_round=5,
    ))

    new_trust = MockNewTrust(anti_forensics_indicator=True)
    revision = MockRevision("ev_abc", new_trust=new_trust)
    changes = ledger.cascade_on_revision([revision])
    assert any("cascade_upgrade" in c for c in changes)
    assert ledger.obligations[0].hard is True


# ═══════════════════════════════════════════════════════════════════════
# 测试：materialize_open
# ═══════════════════════════════════════════════════════════════════════


def test_materialize_open_returns_probes():
    """物化为探针候选"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="ob1", type=ObligationType.STRUCTURAL,
        anchor="malicious_orphan:node1", sla_rounds=5, hard=True,
        created_round=0, deadline_round=5,
        intent=ObligationIntent(
            affected_entity_ids=["node1"],
            host_ids=["host-A"],
            question="find parent",
            allowed_operators=["process_tree"],
            acceptance_criterion={
                "type": "supported_parent_edge",
                "node_id": "node1",
            },
            reason_code="orphan_fact_missing_parent",
        ),
    ))
    ledger.obligations.append(Obligation(
        id="ob2", type=ObligationType.LIFECYCLE,
        anchor="lifecycle_gap:tmpl1:execution", sla_rounds=8, hard=False,
        created_round=0, deadline_round=8,
        intent=ObligationIntent(
            affected_entity_ids=[],
            host_ids=["host-A"],
            question="cover execution",
            allowed_operators=["auth_log"],
            acceptance_criterion={
                "type": "tactic_observed",
                "expected_tactics": ["execution"],
            },
            reason_code="required_lifecycle_stage_missing",
        ),
    ))

    probes = ledger.materialize_open(
        {"nodes": [{"id": "n", "host_id": "host-A"}]},
        current_round=4,
    )
    assert len(probes) == 2
    # 硬义务优先级更高应排前面
    assert probes[0]["hard"] is True
    assert all(probe["target"] == "host-A" for probe in probes)
    assert {probe["operator"] for probe in probes} == {
        "process_tree",
        "auth_log",
    }


def test_unexecutable_hard_obligation_is_explicitly_blocked():
    ledger = ObligationLedger()
    obligation = Obligation(
        id="blocked",
        type=ObligationType.STRUCTURAL,
        anchor="legacy",
        sla_rounds=2,
        hard=True,
        created_round=1,
        deadline_round=3,
        intent=ObligationIntent(
            affected_entity_ids=["missing"],
            host_ids=[],
            question="resolve missing host",
            allowed_operators=["process_tree"],
            acceptance_criterion={"type": "supported_parent_edge"},
            reason_code="orphan_fact_missing_parent",
        ),
    )
    ledger.obligations.append(obligation)
    assert ledger.materialize_open({}, current_round=4) == []
    assert obligation.blocked_reason == "affected_host_unresolved"
    unresolved = ledger.unresolved(current_round=4)
    assert unresolved[0]["overdue"] is True
    assert unresolved[0]["blocked_reason"] == "affected_host_unresolved"


# ═══════════════════════════════════════════════════════════════════════
# 测试：prioritize
# ═══════════════════════════════════════════════════════════════════════


def test_prioritize_hard_first():
    """prioritize 排序：硬义务优先"""
    ledger = ObligationLedger()
    ledger.obligations.append(Obligation(
        id="soft", type=ObligationType.LIFECYCLE,
        anchor="lifecycle:a", sla_rounds=8, hard=False,
        created_round=1, deadline_round=9,
    ))
    ledger.obligations.append(Obligation(
        id="hard", type=ObligationType.STRUCTURAL,
        anchor="structural:b", sla_rounds=3, hard=True,
        created_round=1, deadline_round=4,
    ))
    ordered = ledger.prioritize()
    assert ordered[0].id == "hard"
