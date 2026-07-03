"""测试 AntiForensicsScanner"""
import pytest
from trace_agent.core.anti_forensics import AntiForensicsScanner
from trace_agent.core.types import TrustContext


@pytest.fixture
def scanner():
    return AntiForensicsScanner()


@pytest.fixture
def windows_context():
    return TrustContext(
        host="dc01",
        is_host_compromised=False,
        available_sources=["sysmon", "auditd", "edr_kernel_process_event"],
        environment_profile="windows_enterprise",
        current_round=1,
    )


@pytest.fixture
def linux_context():
    return TrustContext(
        host="web01",
        is_host_compromised=False,
        available_sources=["auditd", "syslog"],
        environment_profile="linux_server",
        current_round=1,
    )


class TestAntiForensicsScanner:
    def test_time_gap_detected_medium(self, scanner):
        """检测到 >5min 的时间断层 → medium"""
        events = [
            {"timestamp": 1000, "event_type": "process_creation"},
            {"timestamp": 1400, "event_type": "network_connection"},  # 400s gap > 300s
        ]
        issues = scanner.scan_time_anomaly(events)
        assert len(issues) == 1
        assert issues[0]['severity'] == 'medium'
        assert issues[0]['type'] == 'time_gap'
        assert issues[0]['duration'] == 400

    def test_time_gap_detected_high(self, scanner):
        """检测到 >1h 的时间断层 → high"""
        events = [
            {"timestamp": 1000, "event_type": "process_creation"},
            {"timestamp": 5000, "event_type": "network_connection"},  # 4000s gap > 3600s
        ]
        issues = scanner.scan_time_anomaly(events)
        assert len(issues) == 1
        assert issues[0]['severity'] == 'high'
        assert issues[0]['duration'] == 4000

    def test_no_time_gap_normal_events(self, scanner):
        """正常时间间隔不报告"""
        events = [
            {"timestamp": 1000, "event_type": "process_creation"},
            {"timestamp": 1100, "event_type": "network_connection"},  # 100s < 300s
            {"timestamp": 1200, "event_type": "file_system"},
        ]
        issues = scanner.scan_time_anomaly(events)
        assert len(issues) == 0

    def test_single_event_no_gap(self, scanner):
        """单条事件不报告时间断层"""
        events = [
            {"timestamp": 1000, "event_type": "process_creation"},
        ]
        issues = scanner.scan_time_anomaly(events)
        assert len(issues) == 0

    def test_anti_forensics_log_cleared(self, scanner, windows_context):
        """Event ID 1102 检测为日志清除"""
        events = [
            {"event_id": 1102, "event_type": "log_event", "timestamp": 1000},
            {"event_id": 4624, "event_type": "logon", "timestamp": 1100},
        ]
        issues = scanner.scan_anti_forensics(windows_context, events)
        log_cleared = [i for i in issues if i['type'] == 'log_cleared']
        assert len(log_cleared) == 1
        assert log_cleared[0]['severity'] == 'critical'

    def test_anti_forensics_event_104(self, scanner, windows_context):
        """Event ID 104 检测为日志清除"""
        events = [
            {"event_id": 104, "event_type": "system_log", "timestamp": 1000},
            {"event_id": 4688, "event_type": "process_creation", "timestamp": 1100},
        ]
        issues = scanner.scan_anti_forensics(windows_context, events)
        log_cleared = [i for i in issues if i['type'] == 'log_cleared']
        assert len(log_cleared) == 1

    def test_anti_forensics_bash_history(self, scanner, linux_context):
        """bash_history cleared 检测"""
        events = [
            {"event_type": "history_cleared", "timestamp": 1000, "indicators": ["history_cleared"]},
            {"event_type": "process_creation", "timestamp": 1100},
        ]
        issues = scanner.scan_anti_forensics(linux_context, events)
        bash_issues = [i for i in issues if i['type'] == 'bash_history_cleared']
        assert len(bash_issues) >= 1
        assert bash_issues[0]['severity'] == 'high'

    def test_anti_forensics_timestamp_manipulation(self, scanner, windows_context):
        """时间戳操纵检测"""
        events = [
            {"event_type": "timestomp", "timestamp": 1000, "indicators": ["timestomp"]},
            {"event_type": "process_creation", "timestamp": 1100},
        ]
        issues = scanner.scan_anti_forensics(windows_context, events)
        ts_issues = [i for i in issues if i['type'] == 'timestamp_manipulation']
        assert len(ts_issues) >= 1
        assert ts_issues[0]['severity'] == 'high'

    def test_absence_with_sufficient_events(self, scanner, windows_context):
        """足够多事件但缺少预期类型 → 缺失报告"""
        # 提供 3 个事件但都不是 process_creation 类型
        # windows_context 有 sysmon 和 edr_kernel_process_event 可观测 process_creation
        events = [
            {"event_type": "network_connection", "timestamp": 1000},
            {"event_type": "network_connection", "timestamp": 1100},
            {"event_type": "network_connection", "timestamp": 1200},
        ]
        issues = scanner.scan_absence(windows_context, events)
        # 应检测到 process_creation 缺失（sysmon 可以观测但没看到）
        aspects = [i['aspect'] for i in issues]
        assert any("process_creation" in a for a in aspects)

    def test_absence_empty_events(self, scanner, windows_context):
        """空事件列表不报告缺失"""
        issues = scanner.scan_absence(windows_context, [])
        assert len(issues) == 0

    def test_absence_insufficient_events(self, scanner, windows_context):
        """少于 3 个事件不报告缺失"""
        events = [
            {"event_type": "network_connection", "timestamp": 1000},
            {"event_type": "network_connection", "timestamp": 1100},
        ]
        issues = scanner.scan_absence(windows_context, events)
        assert len(issues) == 0

    def test_no_absence_when_types_present(self, scanner, windows_context):
        """预期类型都出现时不报告缺失"""
        events = [
            {"event_type": "process_creation", "timestamp": 1000},
            {"event_type": "network_connection", "timestamp": 1100},
            {"event_type": "file_system", "timestamp": 1200},
            {"event_type": "registry_modification", "timestamp": 1300},
            {"event_type": "dns_query", "timestamp": 1400},
        ]
        issues = scanner.scan_absence(windows_context, events)
        assert len(issues) == 0

    def test_scan_anti_forensics_no_issues(self, scanner, windows_context):
        """无反取证迹象时返回空"""
        events = [
            {"event_id": 4688, "event_type": "process_creation", "timestamp": 1000},
            {"event_id": 4624, "event_type": "logon", "timestamp": 1100},
        ]
        issues = scanner.scan_anti_forensics(windows_context, events)
        assert len(issues) == 0

    def test_time_gap_unsorted_events(self, scanner):
        """事件时间戳无序时也能正确检测"""
        events = [
            {"timestamp": 5000, "event_type": "network_connection"},
            {"timestamp": 1000, "event_type": "process_creation"},  # 实际 gap 4000s
        ]
        issues = scanner.scan_time_anomaly(events)
        assert len(issues) == 1
        assert issues[0]['severity'] == 'high'
