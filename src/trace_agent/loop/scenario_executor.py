"""ScenarioExecutor — 从 soar_mcp_env 场景 JSON 驱动取证的 ProbeExecutor"""
from __future__ import annotations

import copy
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Union

from .executor import ProbeExecutor
from .probe import Probe


# Technique prefix → tactic mapping
TECHNIQUE_TACTIC_MAP: dict[str, str] = {
    "T1566": "initial-access",
    "T1059": "execution",
    "T1053": "persistence",
    "T1548": "privilege-escalation",
    "T1055": "defense-evasion",
    "T1003": "credential-access",
    "T1016": "discovery",
    "T1021": "lateral-movement",
    "T1005": "collection",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1070": "defense-evasion",
    "T1078": "persistence",
    "T1071": "command-and-control",
    "T1047": "execution",
    "T1087": "discovery",
    "T1098": "persistence",
    "T1110": "credential-access",
    "T1190": "initial-access",
    "T1218": "defense-evasion",
    "T1486": "impact",
    "T1560": "collection",
    "T1569": "execution",
    "T1570": "lateral-movement",
    "T1068": "privilege-escalation",
    "T1082": "discovery",
    "T1505": "persistence",
}

# Action → fallback tactic mapping
ACTION_TACTIC_FALLBACK: dict[str, str] = {
    "EXEC": "execution",
    "FORK": "execution",
    "CONNECT": "lateral-movement",
    "DNS_QUERY": "command-and-control",
    "WRITE": "persistence",
    "OPEN_FILE": "collection",
    "AUTH": "credential-access",
    "LOGON": "credential-access",
    "INJECT": "defense-evasion",
    "READ": "collection",
}

# OCSF class_uid → log source mapping
OCSF_SOURCE_MAP: dict[int, str] = {
    2001: "process_tree",
    4001: "network_flow",
    6001: "file_monitoring",
    5002: "auth_log",
}

# Operator → matching actions
OPERATOR_ACTION_MAP: dict[str, list[str]] = {
    "process_tree": ["EXEC", "FORK", "INJECT"],
    "network_flow": ["CONNECT", "DNS_QUERY"],
    "auth_log": ["AUTH", "INJECT", "LOGON"],
    "file_hash_lookup": ["WRITE", "OPEN_FILE", "READ"],
    "persistence_scan": ["WRITE"],
    "registry_query": ["WRITE"],
    "credential_access_check": ["EXEC", "FORK"],
    "lateral_movement_check": ["INJECT", "CONNECT"],
    "dns_query": ["DNS_QUERY", "CONNECT"],
    "script_execution": ["EXEC", "FORK"],
}

# Max events returned per probe per round
MAX_EVENTS_PER_PROBE = 10

# Commit-on-confirm: only hard-commit refs after graph/discard or retry cap
MAX_RETRY_PER_REF = 3

# Time window advance per round (seconds)
TIME_WINDOW_STEP = 86400  # 24 hours — progressive discovery per round

# ─── Ranking v2 scoring constants ───
TACTIC_MATCH_WEIGHT: dict[str, float] = {
    "explicit": 2.2,
    "technique": 2.0,
    "action": 0.45,
    "none": 0.0,
}
TECHNIQUE_KNOWN_BONUS = 0.60
ANOMALY_MAX_BONUS = 0.75  # 弱 tie-breaker，不超过一个 operator 匹配


class ScenarioExecutor(ProbeExecutor):
    """从 SOAR 场景 JSON 数据驱动的 ProbeExecutor 实现。

    支持渐进式时间窗口发现、噪声注入和去重。
    """

    def __init__(
        self,
        scenario_path_or_data: Union[str, Path, dict],
        seed: int | None = None,
    ):
        """
        Args:
            scenario_path_or_data: Path to JSON file or pre-loaded dict
            seed: random seed for reproducibility
        """
        # Load scenario data
        if isinstance(scenario_path_or_data, dict):
            self._scenario = copy.deepcopy(scenario_path_or_data)
        else:
            path = Path(scenario_path_or_data)
            with open(path, "r", encoding="utf-8") as f:
                self._scenario = json.load(f)

        self._events: list[dict] = self._scenario.get("events", [])
        for event in self._events:
            event.pop("is_attack", None)
            attrs = event.get("attributes")
            if isinstance(attrs, dict):
                attrs.pop("is_attack", None)
        self._meta: dict = self._scenario.get("meta", {})

        # Build indexes
        self._index_by_host: dict[str, list[int]] = defaultdict(list)
        self._index_by_technique: dict[str, list[int]] = defaultdict(list)
        self._index_by_tactic: dict[str, list[int]] = defaultdict(list)
        self._index_by_action: dict[str, list[int]] = defaultdict(list)
        self._build_indexes()

        # Evidence lifecycle: fetch != permanent burn
        self._returned_committed: set[str] = set()
        self._returned_attempts: dict[str, int] = defaultdict(int)
        self._round_count: int = 0

        # Time cursor for progressive discovery
        self._all_timestamps: list[float] = sorted(
            self._parse_ts(e["ts"]) for e in self._events if e.get("ts")
        )
        self._time_cursor: float = (
            self._all_timestamps[0] if self._all_timestamps else 0.0
        )

    def _build_indexes(self) -> None:
        """Build event indexes by host, technique, tactic, and action.

        v2: 先运行 _normalize_event 统一标准化，然后用 _normalized_tactic 索引。
        """
        for idx, event in enumerate(self._events):
            # Evidence Normalization (Task 1)
            self._normalize_event(event)

            # Index by host_uid
            host = self._extract_host(event)
            if host:
                self._index_by_host[host].append(idx)

            # Index by technique (prefix without sub-technique)
            technique = event.get("technique")
            if technique:
                self._index_by_technique[technique].append(idx)
                # Also index by base technique (e.g. T1566.001 → T1566)
                base = technique.split(".")[0]
                if base != technique:
                    self._index_by_technique[base].append(idx)

            # Index by normalized tactic (replaces _infer_tactic)
            tactic = event.get("_normalized_tactic", "") or self._infer_tactic(event)
            if tactic:
                self._index_by_tactic[tactic].append(idx)

            # Index by action
            action = event.get("action")
            if action:
                self._index_by_action[action].append(idx)

    def _normalize_event(self, event: dict) -> None:
        """统一标准化事件元数据 — 对攻击和噪声一视同仁。

        写入 _normalized_tactic / _tactic_source / _technique_known / _anomaly_score。
        """
        explicit_tactic = (event.get("tactic") or "").strip()
        technique = (event.get("technique") or "").strip()
        base_technique = technique.split(".")[0] if technique else ""

        technique_tactic = (
            TECHNIQUE_TACTIC_MAP.get(technique)
            or TECHNIQUE_TACTIC_MAP.get(base_technique)
            or ""
        )
        action = (event.get("action") or "").strip()
        action_tactic = ACTION_TACTIC_FALLBACK.get(action, "")

        if explicit_tactic:
            normalized_tactic = explicit_tactic
            tactic_source = "explicit"
        elif technique_tactic:
            normalized_tactic = technique_tactic
            tactic_source = "technique"
        elif action_tactic:
            normalized_tactic = action_tactic
            tactic_source = "action"
        else:
            normalized_tactic = ""
            tactic_source = "none"

        event["_normalized_tactic"] = normalized_tactic
        event["_tactic_source"] = tactic_source
        event["_technique_known"] = bool(technique)
        event["_anomaly_score"] = max(0.0, min(1.0, float(event.get("anomaly_score", 0) or 0)))

    def execute_fanout(self, probes: list[Probe]) -> list[dict]:
        """并发扇出取证，返回原始事件列表。"""
        return self._execute_cached_fanout(probes, advance_time=True)

    def _execute_cached_fanout(
        self,
        probes: list[Probe],
        *,
        advance_time: bool,
    ) -> list[dict]:
        """Match probes against cached events, optionally advancing replay time."""
        self._round_count += 1

        if advance_time:
            self._time_cursor += TIME_WINDOW_STEP

        results: list[dict] = []

        for probe in probes:
            probe_results = self._execute_single_probe(probe)
            results.extend(probe_results)

        return results

    def known_hosts(self) -> list[str]:
        """场景内全部 host_uid（供 cross_host_probe_generator 使用）。"""
        hosts: set[str] = set()
        for event in self._events:
            host = self._extract_host(event)
            if host:
                hosts.add(host)
        return sorted(hosts)

    def _execute_single_probe(self, probe: Probe) -> list[dict]:
        """Execute a single probe, returning matched events.

        Ranking v2: 多信号分层评分，anomaly 只做弱 tie-breaker。
        """
        candidate_scores: dict[int, float] = {}

        # Strategy a: match by host_uid (highest priority)
        target_lower = probe.target.lower().strip()
        for host_key, indices in self._index_by_host.items():
            if host_key.lower() == target_lower:
                for idx in indices:
                    candidate_scores[idx] = candidate_scores.get(idx, 0) + 3.0

        # Strategy b: match by operator → action (取证算子匹配)
        operator_actions = OPERATOR_ACTION_MAP.get(probe.operator, [])
        for action in operator_actions:
            for idx in self._index_by_action.get(action, []):
                candidate_scores[idx] = candidate_scores.get(idx, 0) + 1.2

        # Strategy c: tactic 分源加权 + technique_known bonus + anomaly tie-breaker
        probe_tactic = probe.tactic.lower().strip()
        for idx in list(candidate_scores.keys()):
            event = self._events[idx]
            event_tactic = event.get("_normalized_tactic", "")
            tactic_source = event.get("_tactic_source", "none")

            # tactic 分源加权
            if event_tactic and event_tactic.lower() == probe_tactic:
                candidate_scores[idx] += TACTIC_MATCH_WEIGHT.get(tactic_source, 0.0)

            # technique 已知 bonus（有 technique 的事件比纯 action 噪声可信）
            if event.get("_technique_known") and event_tactic.lower() == probe_tactic:
                candidate_scores[idx] += TECHNIQUE_KNOWN_BONUS

            # anomaly 弱加权（tie-breaker，上限 ANOMALY_MAX_BONUS）
            anomaly = event.get("_anomaly_score", 0.0)
            candidate_scores[idx] += min(ANOMALY_MAX_BONUS, anomaly * ANOMALY_MAX_BONUS)

        # Filter: within time window and not already returned
        valid_candidates: list[tuple[int, float]] = []
        for idx, score in candidate_scores.items():
            event = self._events[idx]
            ref = event.get("raw_log_ref", "")
            if self._should_skip_ref(ref):
                continue
            ts = self._parse_ts(event.get("ts", ""))
            if ts <= self._time_cursor:
                valid_candidates.append((idx, score))

        # Sort by score descending, then by timestamp
        valid_candidates.sort(key=lambda x: (-x[1], self._parse_ts(self._events[x[0]].get("ts", ""))))

        # Take top MAX_EVENTS_PER_PROBE
        selected = valid_candidates[:MAX_EVENTS_PER_PROBE]

        # Convert to LOCK events
        results: list[dict] = []
        for idx, _score in selected:
            event = self._events[idx]
            ref = event.get("raw_log_ref", "")
            self._record_returned(ref)
            results.append(self._convert_event(event, probe))

        return results

    def _should_skip_ref(self, ref: str) -> bool:
        """Skip only permanently committed refs or refs that exceeded retry cap."""
        if not ref:
            return False
        if ref in self._returned_committed:
            return True
        return self._returned_attempts.get(ref, 0) >= MAX_RETRY_PER_REF

    def _record_returned(self, ref: str) -> None:
        """Mark ref as fetched this round; does not permanently burn."""
        if ref:
            self._returned_attempts[ref] += 1

    def commit_event_refs(self, refs: list[str]) -> None:
        """Permanently commit refs after graph entry or hard discard."""
        for ref in refs:
            if ref:
                self._returned_committed.add(ref)

    def _convert_event(self, scenario_event: dict, probe: Probe) -> dict:
        """将 SOAR EntityEvent 转换为 LOCK 兼容格式。"""
        safe_attribute_keys = {
            "src_ip", "dst_ip", "src_port", "dst_port", "user", "principal",
            "auth_outcome", "event_code", "logon_type", "status",
            "auth_package", "rule_id", "rule_level", "rule_description",
            "rule_groups",
        }
        telemetry_attributes = {
            key: value
            for key, value in (scenario_event.get("attributes") or {}).items()
            if key in safe_attribute_keys
        }
        return {
            "id": scenario_event.get("raw_log_ref", f"unknown_{id(scenario_event)}"),
            "technique": scenario_event.get("technique") or "T0000",
            "tactic": self._infer_tactic(scenario_event),
            "timestamp": self._parse_ts(scenario_event.get("ts", "")),
            "source": scenario_event.get("source") or self._infer_source(scenario_event),
            "target": self._extract_host(scenario_event),
            "probe_id": probe.id,
            "raw_data": {
                "action": scenario_event.get("action"),
                "src_entity": scenario_event.get("src_entity"),
                "dst_entity": scenario_event.get("dst_entity"),
            },
            "attributes": {
                **telemetry_attributes,
                "anomaly_score": scenario_event.get("anomaly_score", 0.0),
                "process_name": (
                    scenario_event.get("src_entity", {}).get("attrs", {}).get("name")
                ),
                "host_uid": self._extract_host(scenario_event),
                "ocsf_class_uid": scenario_event.get("ocsf_class_uid"),
                "raw_log_ref": scenario_event.get("raw_log_ref", ""),
            },
        }

    def _infer_tactic(self, event: dict) -> str:
        """从 technique 号段 + action 推导 tactic。"""
        technique = event.get("technique")
        if technique:
            # Try full technique first (e.g. T1566.001), then base (T1566)
            base = technique.split(".")[0]
            if technique in TECHNIQUE_TACTIC_MAP:
                return TECHNIQUE_TACTIC_MAP[technique]
            if base in TECHNIQUE_TACTIC_MAP:
                return TECHNIQUE_TACTIC_MAP[base]

        # Fallback: derive from action
        action = event.get("action", "")
        if action in ACTION_TACTIC_FALLBACK:
            return ACTION_TACTIC_FALLBACK[action]

        return "unknown"

    def _infer_source(self, event: dict) -> str:
        """从 ocsf_class_uid 推导 log source。"""
        ocsf_uid = event.get("ocsf_class_uid")
        if ocsf_uid and ocsf_uid in OCSF_SOURCE_MAP:
            return OCSF_SOURCE_MAP[ocsf_uid]
        # Fallback heuristic based on action
        action = event.get("action", "")
        if action in ("EXEC", "FORK", "INJECT"):
            return "process_tree"
        if action in ("CONNECT", "DNS_QUERY"):
            return "network_flow"
        if action in ("WRITE", "OPEN_FILE"):
            return "file_monitoring"
        if action == "AUTH":
            return "auth_log"
        return "unknown"

    @staticmethod
    def _parse_ts(ts_str: str) -> float:
        """ISO 8601 → Unix float. Handles 'Z' suffix."""
        if not ts_str:
            return 0.0
        try:
            # Handle ISO format with Z suffix
            cleaned = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return dt.timestamp()
        except (ValueError, TypeError):
            return 0.0

    @staticmethod
    def _extract_host(event: dict) -> str:
        """提取 host_uid（优先 src_entity.attrs.host_uid）。"""
        src = event.get("src_entity", {})
        src_host = src.get("attrs", {}).get("host_uid", "")
        if src_host:
            return src_host

        dst = event.get("dst_entity", {})
        dst_host = dst.get("attrs", {}).get("host_uid", "")
        if dst_host:
            return dst_host

        return ""

    def available(self) -> bool:
        """Check if executor is ready — always True if events loaded."""
        return len(self._events) > 0

    @property
    def stats(self) -> dict:
        """Return execution statistics."""
        return {
            "total_events": len(self._events),
            "returned_committed": len(self._returned_committed),
            "returned_attempts": len(self._returned_attempts),
            "rounds": self._round_count,
        }

    @property
    def meta(self) -> dict:
        """Return scenario metadata."""
        return self._meta

    def reset(self) -> None:
        """Reset executor state for re-running."""
        self._returned_committed.clear()
        self._returned_attempts.clear()
        self._round_count = 0
        self._time_cursor = (
            self._all_timestamps[0] if self._all_timestamps else 0.0
        )
