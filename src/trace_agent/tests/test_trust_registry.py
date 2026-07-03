"""测试 LogSourceRegistry"""
import pytest
import json
from pathlib import Path
from trace_agent.core.trust_registry import LogSourceRegistry
from trace_agent.core.types import TrustTier


@pytest.fixture
def registry_json(tmp_path):
    """创建临时注册表 JSON"""
    data = {
        "_comment": "test registry",
        "sysmon": {
            "integrity": 0.9,
            "tier": "forge-resistant",
            "adversary_controllable_base": False,
            "hard_veto_allowed": True,
            "platforms": ["windows"],
            "observes": ["process_creation", "network_connection"]
        },
        "bash_history": {
            "integrity": 0.2,
            "tier": "low",
            "adversary_controllable_base": True,
            "hard_veto_allowed": False,
            "platforms": ["linux", "macos"],
            "observes": ["command_history"]
        },
        "windows_event_log_security": {
            "integrity": 0.6,
            "tier": "medium",
            "adversary_controllable_base": "contextual",
            "hard_veto_allowed": False,
            "platforms": ["windows"],
            "observes": ["logon", "privilege_use"]
        }
    }
    path = tmp_path / "test_trust.json"
    path.write_text(json.dumps(data), encoding='utf-8')
    return path


class TestLogSourceRegistry:
    def test_load_success(self, registry_json):
        """成功加载 JSON"""
        reg = LogSourceRegistry(registry_json)
        assert len(reg.sources) == 3

    def test_skip_underscore_fields(self, registry_json):
        """跳过 _ 前缀字段"""
        reg = LogSourceRegistry(registry_json)
        assert "_comment" not in reg.sources

    def test_get_source_known(self, registry_json):
        """查询已知源"""
        reg = LogSourceRegistry(registry_json)
        spec = reg.get_source("sysmon")
        assert spec is not None
        assert spec.source_id == "sysmon"
        assert spec.integrity == 0.9
        assert spec.tier == TrustTier.FORGE_RESISTANT
        assert spec.adversary_controllable_base is False
        assert spec.hard_veto_allowed is True
        assert "windows" in spec.platforms

    def test_get_source_unknown(self, registry_json):
        """查询未知源返回 None"""
        reg = LogSourceRegistry(registry_json)
        assert reg.get_source("nonexistent_source") is None

    def test_list_forge_resistant(self, registry_json):
        """列出 forge-resistant 源"""
        reg = LogSourceRegistry(registry_json)
        fr = reg.list_forge_resistant()
        assert len(fr) == 1
        assert fr[0].source_id == "sysmon"

    def test_get_by_platform(self, registry_json):
        """按平台筛选"""
        reg = LogSourceRegistry(registry_json)
        windows_sources = reg.get_by_platform("windows")
        assert len(windows_sources) == 2  # sysmon + windows_event_log_security
        source_ids = [s.source_id for s in windows_sources]
        assert "sysmon" in source_ids
        assert "windows_event_log_security" in source_ids

    def test_get_by_platform_linux(self, registry_json):
        """按 linux 平台筛选"""
        reg = LogSourceRegistry(registry_json)
        linux_sources = reg.get_by_platform("linux")
        assert len(linux_sources) == 1
        assert linux_sources[0].source_id == "bash_history"

    def test_file_not_found(self, tmp_path):
        """文件不存在时抛异常"""
        fake_path = tmp_path / "nonexistent.json"
        with pytest.raises(FileNotFoundError):
            LogSourceRegistry(fake_path)

    def test_contextual_controllable(self, registry_json):
        """contextual 类型的 adversary_controllable_base 正确加载"""
        reg = LogSourceRegistry(registry_json)
        spec = reg.get_source("windows_event_log_security")
        assert spec is not None
        assert spec.adversary_controllable_base == "contextual"

    def test_load_real_registry(self):
        """加载真实 log_source_trust.json 验证兼容性"""
        real_path = Path(__file__).resolve().parent.parent / 'data' / 'log_source_trust.json'
        reg = LogSourceRegistry(real_path)
        # 真实文件有 14 个源 (排除 _ 前缀)
        assert len(reg.sources) == 14
        # 验证关键源存在
        assert reg.get_source("sysmon") is not None
        assert reg.get_source("edr_kernel_process_event") is not None
        assert reg.get_source("bash_history") is not None
        # _ 前缀被跳过
        assert reg.get_source("_sigma_mapping") is None
        assert reg.get_source("_comment") is None

    def test_summary(self, registry_json):
        """验证摘要功能"""
        reg = LogSourceRegistry(registry_json)
        summary = reg.summary()
        assert summary["total_sources"] == 3
        assert summary["forge_resistant"] == 1
        assert "windows" in summary["platforms_covered"]

    def test_get_expected_observations(self, registry_json):
        """验证按平台+源获取预期观测类型"""
        reg = LogSourceRegistry(registry_json)
        obs = reg.get_expected_observations("windows", "sysmon")
        assert "process_creation" in obs
        assert "network_connection" in obs
        # 错误平台返回空
        obs_bad = reg.get_expected_observations("linux", "sysmon")
        assert obs_bad == []
