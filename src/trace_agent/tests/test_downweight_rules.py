"""测试 DownweightEngine"""
import pytest
from trace_agent.core.downweight_rules import DownweightEngine
from trace_agent.core.types import EvidenceTrust, TrustContext


@pytest.fixture
def engine():
    return DownweightEngine()


@pytest.fixture
def context_compromised():
    return TrustContext(
        host="victim01",
        is_host_compromised=True,
        available_sources=["sysmon", "windows_event_log_security"],
        environment_profile="windows_enterprise",
        current_round=1,
    )


@pytest.fixture
def context_clean():
    return TrustContext(
        host="clean01",
        is_host_compromised=False,
        available_sources=["sysmon"],
        environment_profile="windows_enterprise",
        current_round=1,
    )


class TestDownweightEngine:
    def test_no_downweight_uncompromised_host(self, engine, context_clean):
        """主机未失陷 → 不降权"""
        trust = EvidenceTrust(
            integrity=0.6,
            provenance="windows_event_log_security",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.6,
        )
        result = engine.apply(trust, {}, context_clean)
        assert result.integrity == 0.6
        assert result.downweight_applied is False

    def test_downweight_event_log_on_compromised(self, engine, context_compromised):
        """失陷主机 + windows_event_log_security → ×0.4"""
        trust = EvidenceTrust(
            integrity=0.6,
            provenance="windows_event_log_security",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.6,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.integrity == pytest.approx(0.6 * 0.4)
        assert result.downweight_applied is True
        assert result.downweight_factor == 0.4

    def test_downweight_bash_history_on_compromised(self, engine, context_compromised):
        """失陷主机 + bash_history → ×0.2"""
        trust = EvidenceTrust(
            integrity=0.2,
            provenance="bash_history",
            adversary_controllable=True,
            corroboration=1,
            base_integrity=0.2,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.integrity == pytest.approx(0.2 * 0.2)
        assert result.downweight_applied is True
        assert result.downweight_factor == 0.2

    def test_downweight_file_timestamp_on_compromised(self, engine, context_compromised):
        """失陷主机 + file_system_timestamp → ×0.3"""
        trust = EvidenceTrust(
            integrity=0.3,
            provenance="file_system_timestamp",
            adversary_controllable=True,
            corroboration=1,
            base_integrity=0.3,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.integrity == pytest.approx(0.3 * 0.3)
        assert result.downweight_applied is True
        assert result.downweight_factor == 0.3

    def test_no_downweight_exempt_sysmon(self, engine, context_compromised):
        """Sysmon 即使在失陷主机上也不降权"""
        trust = EvidenceTrust(
            integrity=0.9,
            provenance="sysmon",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.9,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.integrity == 0.9
        assert result.downweight_applied is False

    def test_no_downweight_exempt_edr(self, engine, context_compromised):
        """EDR kernel 不降权"""
        trust = EvidenceTrust(
            integrity=0.95,
            provenance="edr_kernel_process_event",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.95,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.integrity == 0.95
        assert result.downweight_applied is False

    def test_no_downweight_exempt_auditd(self, engine, context_compromised):
        """auditd 不降权"""
        trust = EvidenceTrust(
            integrity=0.75,
            provenance="auditd",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.75,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.integrity == 0.75
        assert result.downweight_applied is False

    def test_no_downweight_exempt_cloudtrail(self, engine, context_compromised):
        """cloudtrail_management_event 不降权"""
        trust = EvidenceTrust(
            integrity=0.9,
            provenance="cloudtrail_management_event",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.9,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.integrity == 0.9
        assert result.downweight_applied is False

    def test_adversary_controllable_set_on_downweight(self, engine, context_compromised):
        """降权后 adversary_controllable 应为 True"""
        trust = EvidenceTrust(
            integrity=0.6,
            provenance="windows_event_log_security",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.6,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.adversary_controllable is True

    def test_corroboration_bonus_single(self, engine):
        """单源佐证 = 0"""
        bonus = DownweightEngine.compute_corroboration_bonus(1)
        assert bonus == 0.0

    def test_corroboration_bonus_multi(self, engine):
        """≥2 源佐证 = 0.15"""
        bonus = DownweightEngine.compute_corroboration_bonus(2)
        assert bonus == 0.15
        bonus3 = DownweightEngine.compute_corroboration_bonus(5)
        assert bonus3 == 0.15

    def test_no_downweight_unknown_source_not_in_table(self, engine, context_compromised):
        """失陷主机 + 不在降权表中的源 → 不降权 (factor=1.0)"""
        trust = EvidenceTrust(
            integrity=0.5,
            provenance="some_unknown_source",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.5,
        )
        result = engine.apply(trust, {}, context_compromised)
        # factor=1.0 所以不走降权分支
        assert result.integrity == 0.5
        assert result.downweight_applied is False

    def test_base_integrity_preserved(self, engine, context_compromised):
        """降权后 base_integrity 保存原始值"""
        trust = EvidenceTrust(
            integrity=0.6,
            provenance="windows_event_log_security",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.6,
        )
        result = engine.apply(trust, {}, context_compromised)
        assert result.base_integrity == 0.6

    def test_apply_recompute(self, engine, context_compromised):
        """apply_recompute 从 base_integrity 重算"""
        trust = EvidenceTrust(
            integrity=0.6,
            provenance="windows_event_log_security",
            adversary_controllable=False,
            corroboration=1,
            base_integrity=0.6,
        )
        result = engine.apply_recompute(trust, "victim01", context_compromised)
        assert result.integrity == pytest.approx(0.6 * 0.4)
        assert result.downweight_applied is True
