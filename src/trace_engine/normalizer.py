"""事件归一化 — SOAR 原始记录 → LOCK 场景事件（配置驱动字段映射）。

第三方 SOAR 的记录格式各异；本模块用点分路径把任意 JSON 记录
映射到 ScenarioExecutor 认识的 EntityEvent 形态，接新平台只改配置。
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from .config import NormalizerConfig


_EVALUATION_ONLY_FIELDS = {
    "is_attack",
    "ground_truth",
    "ground_truth_label",
    "evaluation_label",
    "expected_label",
}


def _strip_evaluation_fields(value: Any) -> Any:
    """Return a detached runtime value without evaluation answer-key fields."""
    if isinstance(value, dict):
        return {
            key: _strip_evaluation_fields(item)
            for key, item in value.items()
            if key not in _EVALUATION_ONLY_FIELDS
        }
    if isinstance(value, list):
        return [_strip_evaluation_fields(item) for item in value]
    return copy.deepcopy(value)


def _dig(record: dict, dotted: str) -> Any:
    """按点分路径取值；路径中任一层缺失返回 None。"""
    cur: Any = record
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _normalize_tactic(value: Any) -> str | None:
    """Normalize Wazuh/MITRE display names to the engine's tactic keys."""
    if value is None:
        return None
    text = str(value).strip().lower().replace("_", " ")
    return "-".join(text.split()) or None


def _telemetry_attributes(record: dict) -> dict[str, Any]:
    """Keep bounded correlation fields needed by graph and model judgement."""
    aliases = {
        "src_ip": ("src_ip", "srcip", "data.srcip"),
        "dst_ip": ("dst_ip", "dstip", "data.dstip"),
        "src_port": ("src_port", "srcport", "data.srcport"),
        "dst_port": ("dst_port", "dstport", "data.dstport"),
        "user": ("user", "dstuser", "srcuser", "data.dstuser", "data.srcuser"),
        "principal": ("principal",),
        "auth_outcome": ("auth_outcome",),
        "event_code": ("event_code",),
        "logon_type": ("logon_type",),
        "status": ("status",),
        "auth_package": ("auth_package",),
        "rule_id": ("rule_id", "rule.id"),
        "rule_level": ("rule_level", "rule.level"),
        "rule_description": ("rule_description", "rule.description"),
        "rule_groups": ("rule_groups", "rule.groups"),
        "src_process": ("src_process", "data.src_process"),
        "dst_process": ("dst_process", "data.dst_process"),
        "trace_step": ("trace_step", "data.trace_step"),
        "incident_id": ("incident_id", "data.incident_id"),
        "is_attack": ("is_attack", "data.is_attack"),
    }
    attributes: dict[str, Any] = {}
    for target, paths in aliases.items():
        for path in paths:
            value = _dig(record, path)
            if value not in (None, "", [], {}):
                attributes[target] = copy.deepcopy(value)
                break
    for field in (
        "src_process",
        "dst_process",
        "trace_step",
        "incident_id",
        "scenario",
        "is_attack",
        "src_entity_type",
        "dst_entity_type",
    ):
        value = _dig(record, field)
        if value not in (None, "", [], {}):
            attributes[field] = copy.deepcopy(value)
    return attributes


class EventNormalizer:
    """把 SOAR 返回的原始记录归一到场景事件 schema。

    输出保证包含 ScenarioExecutor 匹配内核需要的字段：
    raw_log_ref / ts / technique / tactic / action / anomaly_score /
    src_entity.attrs.host_uid
    """

    def __init__(self, config: NormalizerConfig | None = None):
        self.config = config or NormalizerConfig()

    def normalize(self, record: dict) -> dict:
        record = _strip_evaluation_fields(record)
        fm = self.config.field_map

        # 已经是场景事件形态（本地验收路径）→ 脱敏副本通过
        if "raw_log_ref" in record and ("src_entity" in record or "ts" in record):
            if "tactic" in record:
                record["tactic"] = _normalize_tactic(record.get("tactic"))
            return record

        ref = _dig(record, fm.get("ref", "raw_log_ref")) or self._synth_ref(record)
        host = (
            _dig(record, fm.get("host", "")) or
            _dig(record, fm.get("host_fallback", "")) or ""
        )
        technique = _dig(record, fm.get("technique", "technique"))
        if isinstance(technique, list):
            technique = technique[0] if technique else None
        tactic = _dig(record, fm.get("tactic", "tactic"))
        if isinstance(tactic, list):
            tactic = tactic[0] if tactic else None
        anomaly = _dig(record, fm.get("anomaly_score", "anomaly_score"))

        out: dict[str, Any] = {
            "raw_log_ref": str(ref),
            "ts": _dig(record, fm.get("timestamp", "ts")) or "",
            "technique": technique if technique else None,
            "tactic": _normalize_tactic(tactic),
            "action": _dig(record, fm.get("action", "action")) or "",
            "source": _dig(record, fm.get("source", "source")) or "",
            "anomaly_score": float(anomaly) if anomaly is not None else 0.0,
            "src_entity": {
                "type": str(_dig(record, "src_entity_type") or "process"),
                "id": f"{host}:{ref}",
                "attrs": {
                    "host_uid": str(host),
                    "name": (
                        _dig(record, fm.get("process_name", ""))
                        or _dig(record, "src_process")
                        or ""
                    ),
                },
            },
            "dst_entity": {},
            "attributes": _telemetry_attributes(record),
            "_raw": record,
        }
        dst_process = _dig(record, "dst_process")
        if dst_process:
            out["dst_entity"] = {
                "type": str(_dig(record, "dst_entity_type") or "process"),
                "id": f"{host}:{dst_process}",
                "attrs": {
                    "host_uid": str(host),
                    "name": str(dst_process),
                },
            }
        elif record.get("dst_entity"):
            out["dst_entity"] = record.get("dst_entity") or {}
        ocsf = _dig(record, fm.get("ocsf_class_uid", "ocsf_class_uid"))
        if ocsf is not None:
            out["ocsf_class_uid"] = ocsf
        return out

    def normalize_batch(self, records: list[dict]) -> list[dict]:
        return [self.normalize(r) for r in records]

    @staticmethod
    def _synth_ref(record: dict) -> str:
        """无稳定 ID 的记录用内容哈希合成去重键。"""
        digest = hashlib.sha1(
            json.dumps(record, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        return f"soar:{digest}"
