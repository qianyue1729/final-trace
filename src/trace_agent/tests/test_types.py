"""测试 EvidenceTrust 数据类与方法"""
import pytest
from trace_agent.core.types import EvidenceTrust, TrustTier, LogSourceSpec, TrustContext, TrustRevision


class TestEvidenceTrust:
    def test_effective_integrity_no_downweight(self):
        """无降权时 effective_integrity = integrity (downweight_factor默认1.0)"""
        trust = EvidenceTrust(
            integrity=0.9,
            provenance="sysmon",
            adversary_controllable=False,
            corroboration=1,
        )
        assert trust.effective_integrity() == pytest.approx(0.9)

    def test_effective_integrity_with_downweight(self):
        """有降权时 effective_integrity = integrity * factor"""
        trust = EvidenceTrust(
            integrity=0.6,
            provenance="windows_event_log_security",
            adversary_controllable=True,
            corroboration=1,
            downweight_applied=True,
            downweight_factor=0.4,
        )
        assert trust.effective_integrity() == pytest.approx(0.6 * 0.4)

    def test_is_forge_resistant_true(self):
        """integrity >= 0.8 且 not controllable → forge-resistant"""
        trust = EvidenceTrust(
            integrity=0.9,
            provenance="sysmon",
            adversary_controllable=False,
            corroboration=1,
        )
        assert trust.is_forge_resistant() is True

    def test_is_forge_resistant_false_low_integrity(self):
        """integrity < 0.8 → not forge-resistant"""
        trust = EvidenceTrust(
            integrity=0.5,
            provenance="syslog",
            adversary_controllable=False,
            corroboration=1,
        )
        assert trust.is_forge_resistant() is False

    def test_is_forge_resistant_false_controllable(self):
        """integrity 高但 controllable → not forge-resistant"""
        trust = EvidenceTrust(
            integrity=0.95,
            provenance="some_source",
            adversary_controllable=True,
            corroboration=1,
        )
        assert trust.is_forge_resistant() is False

    def test_is_forge_resistant_boundary_exact(self):
        """integrity 恰好 = 0.8 → forge-resistant (边界)"""
        trust = EvidenceTrust(
            integrity=0.8,
            provenance="network_tap_flow",
            adversary_controllable=False,
            corroboration=1,
        )
        assert trust.is_forge_resistant() is True

    def test_is_forge_resistant_boundary_below(self):
        """integrity = 0.799 → not forge-resistant"""
        trust = EvidenceTrust(
            integrity=0.799,
            provenance="some_source",
            adversary_controllable=False,
            corroboration=1,
        )
        assert trust.is_forge_resistant() is False

    def test_default_fields(self):
        """验证默认字段值"""
        trust = EvidenceTrust(
            integrity=0.5,
            provenance="test",
            adversary_controllable=False,
            corroboration=1,
        )
        assert trust.absence_indicator is False
        assert trust.anti_forensics_indicator is False
        assert trust.base_integrity == 0.0
        assert trust.downweight_applied is False
        assert trust.downweight_factor == 1.0
        assert trust.source_chain == []
        assert trust.discovery_round == 0
        assert trust.last_revised_round == 0


class TestTrustTier:
    def test_tier_values(self):
        """验证枚举值正确"""
        assert TrustTier.FORGE_RESISTANT.value == "forge-resistant"
        assert TrustTier.HIGH.value == "high"
        assert TrustTier.MEDIUM.value == "medium"
        assert TrustTier.LOW.value == "low"

    def test_tier_from_string(self):
        """从字符串构造 TrustTier"""
        assert TrustTier("forge-resistant") == TrustTier.FORGE_RESISTANT
        assert TrustTier("high") == TrustTier.HIGH
        assert TrustTier("medium") == TrustTier.MEDIUM
        assert TrustTier("low") == TrustTier.LOW

    def test_tier_is_str(self):
        """TrustTier 继承自 str"""
        assert isinstance(TrustTier.FORGE_RESISTANT, str)
        assert TrustTier.HIGH == "high"


class TestLogSourceSpec:
    def test_construction(self):
        """LogSourceSpec 可正常构造"""
        spec = LogSourceSpec(
            source_id="sysmon",
            integrity=0.9,
            tier=TrustTier.FORGE_RESISTANT,
            adversary_controllable_base=False,
            hard_veto_allowed=True,
            platforms=["windows"],
            observes=["process_creation"],
            sigma_technique_coverage=50,
        )
        assert spec.source_id == "sysmon"
        assert spec.integrity == 0.9
        assert spec.tier == TrustTier.FORGE_RESISTANT


class TestTrustContext:
    def test_construction(self):
        """TrustContext 可正常构造"""
        ctx = TrustContext(
            host="dc01",
            is_host_compromised=True,
            available_sources=["sysmon", "auditd"],
            environment_profile="windows_enterprise",
            current_round=3,
        )
        assert ctx.host == "dc01"
        assert ctx.is_host_compromised is True
        assert ctx.current_round == 3


class TestTrustRevision:
    def test_construction(self):
        """TrustRevision 可正常构造"""
        old = EvidenceTrust(integrity=0.6, provenance="test", adversary_controllable=False, corroboration=1)
        new = EvidenceTrust(integrity=0.24, provenance="test", adversary_controllable=True, corroboration=1)
        rev = TrustRevision(
            evidence_id="ev001",
            round=2,
            old_trust=old,
            new_trust=new,
            reason="host_compromised",
        )
        assert rev.evidence_id == "ev001"
        assert rev.reason == "host_compromised"
        assert rev.cascading_vetos == []
