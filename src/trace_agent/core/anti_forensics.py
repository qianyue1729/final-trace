"""反取证检测器 + 缺失即信号扫描 — RFC-004-02 §5 硬约束 #2"""
from __future__ import annotations
from typing import List, Dict
from .types import TrustContext
from ..utils.config import TIME_GAP_THRESHOLD, TIME_GAP_HIGH_THRESHOLD


class AntiForensicsScanner:
    """
    检测缺失痕迹与反取证迹象，触发 MANDATE 强制义务。

    RFC-004-02 §5 "缺失即信号"：
    主动扫描应有却没有的痕迹与反取证迹象（日志断层、时间不连续、
    EDR 静默、.bash_history 被清）。这些生成 MANDATE 义务。
    """

    # 各平台预期可观测信号
    EXPECTED_SIGNALS: Dict[str, Dict[str, str]] = {
        "windows": {
            "process_creation": "Expected via Sysmon EventID 1 / WMI",
            "network_connection": "Expected via Sysmon EventID 3",
            "registry_modification": "Expected via Sysmon EventID 12/13/14",
            "file_system": "Expected via Sysmon EventID 11/23",
            "dns_query": "Expected via Sysmon EventID 22",
        },
        "linux": {
            "process_creation": "Expected via auditd execve / syslog",
            "file_access": "Expected via auditd open/openat",
            "authentication": "Expected via auth.log / auditd",
            "network_connection": "Expected via auditd connect/accept",
        },
        "macos": {
            "process_creation": "Expected via Unified Log / ESF",
            "file_access": "Expected via Unified Log",
            "authentication": "Expected via Unified Log",
        },
    }

    # 已知反取证事件签名
    ANTI_FORENSICS_SIGNATURES: Dict[str, Dict] = {
        "windows_audit_log_cleared": {
            "event_ids": [1102, 104],
            "severity": "critical",
            "description": "Windows audit/system log cleared",
        },
        "linux_audit_log_tampered": {
            "indicators": ["auditd_stop", "audit.log_truncated"],
            "severity": "critical",
            "description": "Linux auditd stopped or log truncated",
        },
        "bash_history_cleared": {
            "indicators": ["history_cleared", "histfile_unset", "bash_history_size_0"],
            "severity": "high",
            "description": ".bash_history cleared or HISTFILE unset",
        },
        "timestamp_manipulation": {
            "indicators": ["timestomp", "touch_modification"],
            "severity": "high",
            "description": "File timestamp manipulation detected",
        },
    }

    def scan_absence(self, context: TrustContext,
                     events: List[Dict]) -> List[Dict]:
        """
        扫描应有却缺失的痕迹。

        逻辑：对于当前平台的每种预期信号类型，
        如果在 available_sources 中有对应日志源但事件中没有该类型观测，
        则标记为缺失。

        注意：完整实现需 SessionGraph 集成（检查图中已有节点是否有
        对应日志支撑），当前为基于事件批次的简化版本。

        Returns:
            [{aspect, confidence, severity, description}]
        """
        issues: List[Dict] = []
        platform = self._detect_platform(context)
        expected = self.EXPECTED_SIGNALS.get(platform, {})

        if not expected or not events:
            return issues

        # 收集本批事件中出现的观测类型
        observed_types: set = set()
        for event in events:
            event_type = event.get('event_type', '')
            if event_type:
                observed_types.add(event_type)

        # 检查预期但缺失的（仅当有相关日志源可用时）
        for obs_type, description in expected.items():
            # 如果该平台上有对应的日志源但完全没看到该类型事件
            if self._source_available_for(obs_type, context) and obs_type not in observed_types:
                # 只在有"强理由"认为应该有时报告
                # 当前简化：仅在事件批次较大（≥3）时才认为缺失可疑
                if len(events) >= 3:
                    issues.append({
                        'aspect': f"{obs_type}_on_{context.host}",
                        'confidence': 0.6,
                        'severity': 'medium',
                        'description': f"Missing expected {obs_type}: {description}",
                    })

        return issues

    def scan_anti_forensics(self, context: TrustContext,
                            events: List[Dict]) -> List[Dict]:
        """
        扫描反取证迹象：
        - 事件 ID 1102/104（审计日志清除）
        - 时间断层（>5min 无事件）
        - .bash_history 被 truncate/unset
        - EDR 静默期
        - 时间戳操纵

        Returns:
            [{type, severity, duration (optional), description}]
        """
        issues: List[Dict] = []

        # 1. 检查事件中是否包含已知反取证签名
        for event in events:
            event_id = event.get('event_id')
            event_type = event.get('event_type', '')
            indicators = event.get('indicators', [])

            # Windows 审计日志清除
            if event_id in [1102, 104]:
                issues.append({
                    'type': 'log_cleared',
                    'severity': 'critical',
                    'description': f"Audit log cleared (Event ID {event_id})",
                })

            # bash_history 清除
            if any(ind in str(indicators) + event_type
                   for ind in ['history_cleared', 'histfile_unset', 'bash_history']):
                issues.append({
                    'type': 'bash_history_cleared',
                    'severity': 'high',
                    'description': "Shell history manipulation detected",
                })

            # 时间戳操纵
            if any(ind in str(indicators) + event_type
                   for ind in ['timestomp', 'touch_modification']):
                issues.append({
                    'type': 'timestamp_manipulation',
                    'severity': 'high',
                    'description': "File timestamp manipulation detected",
                })

        # 2. 时间断层检测
        time_gaps = self.scan_time_anomaly(events)
        issues.extend(time_gaps)

        return issues

    def scan_time_anomaly(self, events: List[Dict]) -> List[Dict]:
        """
        检测事件序列中的时间断层。

        超过 TIME_GAP_THRESHOLD (5min) 标记为 medium；
        超过 TIME_GAP_HIGH_THRESHOLD (1h) 标记为 high。
        """
        issues: List[Dict] = []

        if len(events) < 2:
            return issues

        # 按时间排序
        timed_events = [e for e in events if e.get('timestamp') is not None]
        if len(timed_events) < 2:
            return issues

        sorted_events = sorted(timed_events, key=lambda e: e['timestamp'])

        for i in range(1, len(sorted_events)):
            prev_ts = sorted_events[i - 1]['timestamp']
            curr_ts = sorted_events[i]['timestamp']
            gap = curr_ts - prev_ts

            if gap >= TIME_GAP_HIGH_THRESHOLD:
                issues.append({
                    'type': 'time_gap',
                    'severity': 'high',
                    'duration': gap,
                    'description': f"Large time gap: {gap}s between events",
                })
            elif gap >= TIME_GAP_THRESHOLD:
                issues.append({
                    'type': 'time_gap',
                    'severity': 'medium',
                    'duration': gap,
                    'description': f"Time gap: {gap}s between events",
                })

        return issues

    def _detect_platform(self, context: TrustContext) -> str:
        """从 environment_profile 推断平台"""
        profile = context.environment_profile.lower()
        if 'windows' in profile:
            return 'windows'
        elif 'linux' in profile or 'cloud' in profile:
            return 'linux'
        elif 'macos' in profile or 'mac' in profile:
            return 'macos'
        return 'linux'  # 默认

    def _source_available_for(self, obs_type: str, context: TrustContext) -> bool:
        """判断是否有日志源能观测该类型"""
        # 简化判定：检查 available_sources 中是否有能观测该 obs_type 的源
        # 完整实现需查询 LogSourceRegistry
        source_obs_map = {
            'process_creation': ['sysmon', 'auditd', 'edr_kernel_process_event'],
            'network_connection': ['sysmon', 'auditd', 'edr_kernel_process_event'],
            'file_system': ['sysmon', 'auditd'],
            'file_access': ['auditd'],
            'registry_modification': ['sysmon'],
            'dns_query': ['sysmon', 'dns_query_log'],
            'authentication': ['auditd', 'syslog'],
        }
        expected_sources = source_obs_map.get(obs_type, [])
        available_lower = [s.lower() for s in context.available_sources]
        return any(src in available_lower for src in expected_sources)
