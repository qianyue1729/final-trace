"""端到端集成测试"""
import pytest
from pathlib import Path
from trace_agent import create_evidence_trust_model
from trace_agent.core.types import TrustContext, EvidenceTrust
from trace_agent.core.evidence_trust import EvidenceTrustModel
from trace_agent.veto_integration.veto_gates import VetoGates


class TestIntegration:
    @pytest.fixture
    def model(self):
        """使用真实 log_source_trust.json 创建模型"""
        data_dir = Path(__file__).resolve().parent.parent / 'data'
        return create_evidence_trust_model(data_dir=data_dir)

    @pytest.fixture
    def context_clean(self):
        return TrustContext(
            host="dc01",
            is_host_compromised=False,
            available_sources=["sysmon", "windows_event_log_security"],
            environment_profile="windows_enterprise",
            current_round=1,
        )

    @pytest.fixture
    def context_compromised(self):
        return TrustContext(
            host="victim01",
            is_host_compromised=True,
            available_sources=["sysmon", "windows_event_log_security", "bash_history"],
            environment_profile="windows_enterprise",
            current_round=1,
        )

    def test_full_pipeline_ingest(self, model, context_clean):
        """完整流程：set_context → ingest → 验证信任标注"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "sysmon", "host": "dc01",
             "timestamp": 1000, "event_type": "process_creation"},
            {"id": "ev002", "source": "windows_event_log_security", "host": "dc01",
             "timestamp": 1100, "event_type": "logon"},
        ]
        trust_list, mandate_ids = model.ingest(events)

        assert len(trust_list) == 2
        # sysmon: integrity=0.9, not controllable
        assert trust_list[0].integrity == 0.9
        assert trust_list[0].adversary_controllable is False
        assert trust_list[0].provenance == "sysmon"
        # windows_event_log_security: contextual + not compromised → not controllable
        assert trust_list[1].integrity == 0.6
        assert trust_list[1].adversary_controllable is False

    def test_forge_resistant_veto_eligible(self, model, context_clean):
        """sysmon 事件 → forge-resistant → 可硬 VETO"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "sysmon", "host": "dc01",
             "timestamp": 1000, "event_type": "process_creation"},
        ]
        trust_list, _ = model.ingest(events)
        sysmon_trust = trust_list[0]

        assert sysmon_trust.is_forge_resistant() is True
        assert VetoGates.can_hard_veto(sysmon_trust) is True

    def test_low_trust_veto_ineligible(self, model, context_clean):
        """bash_history 事件 → not forge-resistant → 不可硬 VETO"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "bash_history", "host": "dc01",
             "timestamp": 1000, "event_type": "command_history"},
        ]
        trust_list, _ = model.ingest(events)
        bash_trust = trust_list[0]

        assert bash_trust.is_forge_resistant() is False
        assert VetoGates.can_hard_veto(bash_trust) is False

    def test_host_compromise_cascade(self, model, context_compromised):
        """主机失陷 → 级联降权所有非豁免证据"""
        model.set_context(context_compromised)
        events = [
            {"id": "ev001", "source": "sysmon", "host": "victim01",
             "timestamp": 1000, "event_type": "process_creation"},
            {"id": "ev002", "source": "windows_event_log_security", "host": "victim01",
             "timestamp": 1100, "event_type": "logon"},
            {"id": "ev003", "source": "bash_history", "host": "victim01",
             "timestamp": 1200, "event_type": "command_history"},
        ]
        trust_list, _ = model.ingest(events)

        # sysmon 豁免，不降权
        assert trust_list[0].integrity == 0.9
        assert trust_list[0].downweight_applied is False

        # windows_event_log_security ×0.4
        assert trust_list[1].integrity == pytest.approx(0.6 * 0.4)
        assert trust_list[1].downweight_applied is True

        # bash_history ×0.2
        assert trust_list[2].integrity == pytest.approx(0.2 * 0.2)
        assert trust_list[2].downweight_applied is True

    def test_contradiction_revision(self, model, context_clean):
        """forge-resistant 否定低信任 → 修订"""
        model.set_context(context_clean)
        events = [
            {"id": "ev_high", "source": "sysmon", "host": "dc01",
             "timestamp": 1000, "event_type": "process_creation"},
            {"id": "ev_low", "source": "bash_history", "host": "dc01",
             "timestamp": 1100, "event_type": "command_history"},
        ]
        model.ingest(events)

        # 高信任否定低信任
        revision = model.revise_on_contradiction("ev_low", "ev_high")
        assert revision is not None
        assert revision.reason == "contradicted_by_forge_resistant"
        # 修订后 integrity 降为 base * 0.2
        revised = model.get_trust("ev_low")
        assert revised.integrity == pytest.approx(0.2 * 0.2)  # base=0.2, ×0.2
        assert revised.adversary_controllable is True

    def test_weight_likelihood_high_trust(self, model, context_clean):
        """高信任证据权重接近1"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "sysmon", "host": "dc01",
             "timestamp": 1000, "event_type": "process_creation"},
        ]
        model.ingest(events)

        # sysmon: effective_integrity=0.9, not controllable, corroboration=1 (no bonus)
        # weight = 0.9 (no penalty, no bonus)
        weighted = model.weight_likelihood(1.0, "ev001")
        assert weighted == pytest.approx(0.9)

    def test_weight_likelihood_low_trust(self, model, context_compromised):
        """低信任+可控证据权重很低"""
        model.set_context(context_compromised)
        events = [
            {"id": "ev001", "source": "bash_history", "host": "victim01",
             "timestamp": 1000, "event_type": "command_history"},
        ]
        model.ingest(events)

        # bash_history on compromised:
        #   integrity = 0.2*0.2 = 0.04, downweight_factor = 0.2
        #   effective_integrity = 0.04 * 0.2 = 0.008
        #   controllable=True → weight = 0.008 * 0.5 = 0.004
        #   max(0.01, 0.004) = 0.01 (floor)
        #   weighted = 1.0 * 0.01 = 0.01
        weighted = model.weight_likelihood(1.0, "ev001")
        assert weighted == pytest.approx(0.01)
        assert weighted < 0.1

    def test_empty_events(self, model, context_clean):
        """空事件列表不出错"""
        model.set_context(context_clean)
        trust_list, mandate_ids = model.ingest([])
        assert trust_list == []
        assert mandate_ids == []

    def test_unknown_source(self, model, context_clean):
        """未知来源 → 保守默认值"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "totally_unknown_source", "host": "dc01",
             "timestamp": 1000, "event_type": "something"},
        ]
        trust_list, _ = model.ingest(events)
        assert len(trust_list) == 1
        assert trust_list[0].integrity == 0.2  # UNKNOWN_SOURCE_INTEGRITY
        assert trust_list[0].adversary_controllable is True

    def test_factory_function_default(self):
        """工厂函数默认路径可用"""
        model = create_evidence_trust_model()
        assert isinstance(model, EvidenceTrustModel)
        assert len(model.registry.sources) == 14

    def test_ingest_without_context_raises(self, model):
        """未调 set_context 就 ingest → RuntimeError"""
        with pytest.raises(RuntimeError, match="Must call set_context"):
            model.ingest([{"id": "x", "source": "sysmon"}])

    def test_veto_gates_evaluate_eligibility(self, model, context_clean):
        """VetoGates.evaluate_veto_eligibility 功能验证"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "sysmon", "host": "dc01",
             "timestamp": 1000, "event_type": "process_creation"},
        ]
        trust_list, _ = model.ingest(events)
        sysmon_trust = trust_list[0]

        # temporal_order VETO (需要 forge-resistant)
        result = VetoGates.evaluate_veto_eligibility(sysmon_trust, "temporal_order")
        assert result["eligible"] is True
        assert result["action"] == "hard_veto"

        # invariant VETO (任意证据都可)
        result_inv = VetoGates.evaluate_veto_eligibility(sysmon_trust, "invariant")
        assert result_inv["eligible"] is True

    def test_veto_gates_downgrade_soft_prior(self, model, context_clean):
        """非 forge-resistant 证据的 soft prior 降级"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "bash_history", "host": "dc01",
             "timestamp": 1000, "event_type": "command_history"},
        ]
        trust_list, _ = model.ingest(events)
        bash_trust = trust_list[0]

        # 降级
        downgraded = VetoGates.downgrade_to_soft_prior(bash_trust, "test_reason")
        assert downgraded.integrity == pytest.approx(0.2 * 0.15)
        assert downgraded.downweight_factor == 0.15
        assert downgraded.adversary_controllable is True

    def test_contextual_controllable_on_compromised(self, model):
        """contextual 源在失陷主机上被视为可控"""
        ctx = TrustContext(
            host="victim01",
            is_host_compromised=True,
            available_sources=["windows_event_log_security"],
            environment_profile="windows_enterprise",
            current_round=1,
        )
        model.set_context(ctx)
        events = [
            {"id": "ev001", "source": "windows_event_log_security", "host": "victim01",
             "timestamp": 1000, "event_type": "logon"},
        ]
        trust_list, _ = model.ingest(events)
        # contextual + compromised → controllable before downweight
        # then downweight further applies
        assert trust_list[0].adversary_controllable is True

    def test_revise_on_host_compromise(self, model, context_clean):
        """revise_on_host_compromise 级联修订"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "windows_event_log_security", "host": "dc01",
             "timestamp": 1000, "event_type": "logon"},
        ]
        model.ingest(events)
        # 初始未降权
        assert model.get_trust("ev001").downweight_applied is False

        # 更新上下文为失陷
        compromised_ctx = TrustContext(
            host="dc01",
            is_host_compromised=True,
            available_sources=["windows_event_log_security"],
            environment_profile="windows_enterprise",
            current_round=2,
        )
        model.set_context(compromised_ctx)
        revisions = model.revise_on_host_compromise("dc01")
        assert len(revisions) >= 1
        # 验证修订后降权
        revised = model.get_trust("ev001")
        assert revised.downweight_applied is True
        assert revised.integrity == pytest.approx(0.6 * 0.4)

    def test_get_summary(self, model, context_clean):
        """get_summary 返回正确统计"""
        model.set_context(context_clean)
        events = [
            {"id": "ev001", "source": "sysmon", "host": "dc01",
             "timestamp": 1000, "event_type": "process_creation"},
            {"id": "ev002", "source": "bash_history", "host": "dc01",
             "timestamp": 1100, "event_type": "command_history"},
        ]
        model.ingest(events)
        summary = model.get_summary()
        assert summary["total_evidence"] >= 2
        assert summary["forge_resistant_count"] >= 1
