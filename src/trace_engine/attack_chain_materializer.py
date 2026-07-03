"""Materialize Wazuh events into SessionGraph-ready candidate chains."""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from typing import Any

from trace_agent.loop.scenario_executor import ScenarioExecutor

_EVT_NUM = re.compile(r"evt_(\d+)$", re.I)
_DEFAULT_TOP_K = 50
_PER_RULE_ID_CAP = 8
_PER_HOST_CAP = 20
_PER_RULE_GROUP_CAP = 15
_PER_MINUTE_CAP = 10
_PER_DECODER_CAP = 10
_SECURITY_RULE_GROUPS = frozenset(
    {
        "authentication",
        "authentication_failed",
        "authentication_failures",
        "authentication_success",
        "sysmon",
        "windows",
        "windows_security",
        "process",
        "network",
        "malware",
        "ids",
        "web",
    }
)


@dataclass(frozen=True)
class DiversityCaps:
    per_rule_id: int = _PER_RULE_ID_CAP
    per_host: int = _PER_HOST_CAP
    per_rule_group: int = _PER_RULE_GROUP_CAP
    per_minute: int = _PER_MINUTE_CAP
    per_decoder: int = _PER_DECODER_CAP


def _evt_order(raw_log_ref: str) -> int:
    match = _EVT_NUM.search(str(raw_log_ref or ""))
    return int(match.group(1)) if match else 999_999


def is_attack_event(event: dict[str, Any]) -> bool:
    ref = str(event.get("raw_log_ref") or "")
    if ref.startswith("attack:"):
        return True
    attrs = event.get("attributes") or {}
    if attrs.get("is_attack") is True:
        return True
    raw = event.get("_raw") or {}
    if raw.get("is_attack") is True:
        return True
    data = raw.get("data") if isinstance(raw.get("data"), dict) else {}
    return data.get("is_attack") is True


def _event_timestamp(event: dict[str, Any]) -> float:
    ts = event.get("ts") or event.get("timestamp") or ""
    return ScenarioExecutor._parse_ts(str(ts))


def _host_of(event: dict[str, Any]) -> str:
    return ScenarioExecutor._extract_host(event) or ""


def _trace_step(event: dict[str, Any]) -> int:
    raw = (event.get("attributes") or {}).get("trace_step")
    if raw in (None, ""):
        return 0
    try:
        return int(raw)
    except (TypeError, ValueError):
        return 0


def _event_attributes(event: dict[str, Any]) -> dict[str, Any]:
    return dict(event.get("attributes") or {})


def _rule_id(event: dict[str, Any]) -> str:
    attrs = _event_attributes(event)
    raw = event.get("_raw") or {}
    rule = raw.get("rule") if isinstance(raw.get("rule"), dict) else {}
    for source in (attrs, raw, rule):
        if not isinstance(source, dict):
            continue
        value = source.get("rule_id") or source.get("id")
        if value not in (None, ""):
            return str(value)
    return ""


def _decoder_name(event: dict[str, Any]) -> str:
    attrs = _event_attributes(event)
    raw = event.get("_raw") or {}
    for source in (attrs, raw):
        if not isinstance(source, dict):
            continue
        value = source.get("decoder") or source.get("decoder_name")
        if value not in (None, ""):
            return str(value)
    source = str(event.get("source") or attrs.get("source") or "")
    return source.lower()


def _primary_rule_group(event: dict[str, Any]) -> str:
    attrs = _event_attributes(event)
    groups = attrs.get("rule_groups") or []
    if isinstance(groups, str):
        return groups.lower()
    if isinstance(groups, (list, tuple)) and groups:
        return str(groups[0]).lower()
    return "unknown"


def _minute_bucket(event: dict[str, Any]) -> str:
    ts = _event_timestamp(event)
    if ts <= 0:
        return "unknown"
    minute = int(ts // 60)
    return str(minute)


def _rule_level(event: dict[str, Any]) -> float:
    attrs = _event_attributes(event)
    raw = event.get("_raw") or {}
    for source in (attrs, raw, raw.get("rule") if isinstance(raw.get("rule"), dict) else {}):
        if not isinstance(source, dict):
            continue
        value = source.get("rule_level") or source.get("level")
        if value not in (None, ""):
            try:
                return max(0.0, min(1.0, float(value) / 15.0))
            except (TypeError, ValueError):
                continue
    return 0.0


def _rule_level_raw(event: dict[str, Any]) -> float:
    attrs = _event_attributes(event)
    value = attrs.get("rule_level")
    if value in (None, ""):
        return 0.0
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _mitre_score(event: dict[str, Any]) -> float:
    attrs = _event_attributes(event)
    if event.get("technique") or attrs.get("mitre_technique"):
        return 1.0
    if event.get("tactic") or attrs.get("mitre_tactic"):
        return 0.5
    return 0.0


def _group_score(event: dict[str, Any]) -> float:
    attrs = _event_attributes(event)
    groups = attrs.get("rule_groups") or []
    if isinstance(groups, str):
        groups = [groups]
    if not isinstance(groups, (list, tuple, set)):
        return 0.0
    normalized = {str(group).lower() for group in groups}
    if normalized & _SECURITY_RULE_GROUPS:
        return 1.0
    return 0.0


def _entity_score(event: dict[str, Any], anchor: dict[str, Any]) -> float:
    score = 0.0
    host = _host_of(event).lower()
    anchor_host = str(anchor.get("host") or "").lower()
    if host and anchor_host and host == anchor_host:
        score += 0.45

    attrs = _event_attributes(event)
    for field, weight in (
        ("user", 0.2),
        ("src_ip", 0.2),
        ("dst_ip", 0.1),
    ):
        anchor_val = str(anchor.get(field) or "").lower()
        event_val = str(attrs.get(field) or "").lower()
        if anchor_val and event_val and anchor_val == event_val:
            score += weight

    anchor_process = str(anchor.get("process_name") or "").lower()
    process_name = str(
        attrs.get("process_name")
        or (event.get("src_entity") or {}).get("attrs", {}).get("name")
        or ""
    ).lower()
    if anchor_process and process_name and anchor_process == process_name:
        score += 0.15
    return min(score, 1.0)


def _temporal_score(event: dict[str, Any], anchor_ts: float) -> float:
    ts = _event_timestamp(event)
    if anchor_ts <= 0 or ts <= 0:
        return 0.0
    delta = abs(ts - anchor_ts)
    return max(0.0, 1.0 - (delta / 86400.0))


def _bootstrap_relevance_score(
    event: dict[str, Any],
    *,
    anchor: dict[str, Any],
) -> float:
    anchor_ts = float(anchor.get("timestamp") or 0)
    return (
        0.30 * _rule_level(event)
        + 0.25 * _mitre_score(event)
        + 0.20 * _temporal_score(event, anchor_ts)
        + 0.15 * _entity_score(event, anchor)
        + 0.10 * _group_score(event)
    )


def _event_usable_for_production(event: dict[str, Any]) -> bool:
    ref = str(event.get("raw_log_ref") or "")
    if not ref or is_attack_event(event):
        return False
    attrs = _event_attributes(event)
    if _event_timestamp(event) > 0:
        return True
    if _host_of(event):
        return True
    if attrs.get("rule_level") not in (None, ""):
        return True
    if attrs.get("rule_groups") or attrs.get("mitre_technique"):
        return True
    return False


def _anchor_from_alert_context(alert_context: dict[str, Any] | None) -> dict[str, Any]:
    alert_context = alert_context or {}
    attrs = alert_context.get("attributes") or {}
    src_entity = alert_context.get("src_entity") or {}
    src_attrs = src_entity.get("attrs") or {}
    return {
        "host": str(
            alert_context.get("asset")
            or alert_context.get("asset_id")
            or attrs.get("host_uid")
            or attrs.get("asset_id")
            or src_attrs.get("host_uid")
            or ""
        ),
        "timestamp": float(alert_context.get("timestamp") or alert_context.get("ts") or 0),
        "user": str(attrs.get("user") or ""),
        "src_ip": str(attrs.get("src_ip") or attrs.get("srcip") or ""),
        "dst_ip": str(attrs.get("dst_ip") or attrs.get("dstip") or ""),
        "process_name": str(
            attrs.get("process_name") or src_attrs.get("name") or ""
        ),
        "technique": str(alert_context.get("technique") or ""),
        "raw_log_ref": str(
            attrs.get("raw_log_ref") or alert_context.get("raw_log_ref") or ""
        ),
        "source": str(alert_context.get("log_source") or attrs.get("source") or "alert"),
    }


def _anchor_diagnostics(anchor: dict[str, Any]) -> dict[str, Any]:
    return {
        "anchor_ref": anchor.get("raw_log_ref") or None,
        "anchor_timestamp": anchor.get("timestamp") or None,
        "anchor_host": anchor.get("host") or None,
        "anchor_user": anchor.get("user") or None,
        "anchor_src_ip": anchor.get("src_ip") or None,
        "anchor_dst_ip": anchor.get("dst_ip") or None,
        "anchor_process": anchor.get("process_name") or None,
        "anchor_source": anchor.get("anchor_source") or "missing",
        "anchor_confidence": anchor.get("anchor_confidence") or "missing",
    }


def resolve_production_anchor(
    events: list[dict[str, Any]],
    alert_context: dict[str, Any] | None,
) -> dict[str, Any]:
    """Resolve bootstrap anchor and explain where it came from."""
    usable = [event for event in events if _event_usable_for_production(event)]
    anchor = _anchor_from_alert_context(alert_context)
    alert_ref = str(anchor.get("raw_log_ref") or "")
    alert_host = str(anchor.get("host") or "")
    alert_ts = float(anchor.get("timestamp") or 0)

    if alert_ref:
        for event in usable:
            if str(event.get("raw_log_ref") or "") == alert_ref:
                anchor = {
                    **_anchor_from_alert_context(alert_context),
                    **_event_anchor_fields(event),
                    "anchor_source": "matched_raw_log_ref",
                    "anchor_confidence": "high",
                }
                return anchor

    if alert_host or alert_ts > 0:
        anchor["anchor_source"] = "entry_alert_payload"
        anchor["anchor_confidence"] = "high" if alert_host and alert_ts > 0 else "medium"
        return anchor

    if usable:
        host_events = usable
        if alert_host:
            same_host = [
                event for event in usable if _host_of(event).lower() == alert_host.lower()
            ]
            if same_host:
                host_events = same_host

        severity_sorted = sorted(
            host_events,
            key=lambda event: (
                -_rule_level_raw(event),
                -_mitre_score(event),
                _event_timestamp(event),
            ),
        )
        best = severity_sorted[0]
        if _rule_level_raw(best) >= 8 or _mitre_score(best) >= 0.5:
            anchor = {
                **_event_anchor_fields(best),
                "anchor_source": "highest_severity_event",
                "anchor_confidence": "medium",
            }
            return anchor

        earliest = min(
            usable,
            key=lambda event: (
                _event_timestamp(event) if _event_timestamp(event) > 0 else float("inf"),
                str(event.get("raw_log_ref") or ""),
            ),
        )
        if _event_timestamp(earliest) > 0:
            anchor = {
                **_event_anchor_fields(earliest),
                "anchor_source": "earliest_case_event",
                "anchor_confidence": "medium",
            }
            return anchor

        host_counts = Counter(_host_of(event).lower() for event in usable if _host_of(event))
        centroid_host = host_counts.most_common(1)[0][0] if host_counts else ""
        timestamps = [ts for ts in (_event_timestamp(event) for event in usable) if ts > 0]
        centroid_ts = sorted(timestamps)[len(timestamps) // 2] if timestamps else 0.0
        anchor = {
            "host": centroid_host,
            "timestamp": centroid_ts,
            "user": "",
            "src_ip": "",
            "dst_ip": "",
            "process_name": "",
            "technique": "",
            "raw_log_ref": "",
            "source": "case_centroid",
            "anchor_source": "fallback_case_centroid",
            "anchor_confidence": "low",
        }
        return anchor

    anchor["anchor_source"] = "missing"
    anchor["anchor_confidence"] = "missing"
    return anchor


def _event_anchor_fields(event: dict[str, Any]) -> dict[str, Any]:
    attrs = _event_attributes(event)
    src_entity = event.get("src_entity") or {}
    src_attrs = src_entity.get("attrs") or {}
    return {
        "host": _host_of(event),
        "timestamp": _event_timestamp(event),
        "user": str(attrs.get("user") or ""),
        "src_ip": str(attrs.get("src_ip") or attrs.get("srcip") or ""),
        "dst_ip": str(attrs.get("dst_ip") or attrs.get("dstip") or ""),
        "process_name": str(
            attrs.get("process_name") or src_attrs.get("name") or ""
        ),
        "technique": str(event.get("technique") or attrs.get("mitre_technique") or ""),
        "raw_log_ref": str(event.get("raw_log_ref") or ""),
        "source": str(event.get("source") or attrs.get("source") or "wazuh"),
    }


def _diversity_blocked(
    event: dict[str, Any],
    *,
    counts: dict[str, Counter[str]],
    caps: DiversityCaps,
) -> bool:
    rule_id = _rule_id(event) or "unknown"
    host = _host_of(event).lower() or "unknown"
    group = _primary_rule_group(event)
    minute = _minute_bucket(event)
    decoder = _decoder_name(event) or "unknown"

    if counts["rule_id"][rule_id] >= caps.per_rule_id:
        return True
    if counts["host"][host] >= caps.per_host:
        return True
    if counts["group"][group] >= caps.per_rule_group:
        return True
    if counts["minute"][minute] >= caps.per_minute:
        return True
    if counts["decoder"][decoder] >= caps.per_decoder:
        return True
    return False


def _register_diversity(event: dict[str, Any], counts: dict[str, Counter[str]]) -> None:
    counts["rule_id"][_rule_id(event) or "unknown"] += 1
    counts["host"][_host_of(event).lower() or "unknown"] += 1
    counts["group"][_primary_rule_group(event)] += 1
    counts["minute"][_minute_bucket(event)] += 1
    counts["decoder"][_decoder_name(event) or "unknown"] += 1


def _select_candidates_with_diversity(
    scored: list[tuple[float, dict[str, Any]]],
    *,
    anchor_ref: str,
    top_k: int,
    caps: DiversityCaps,
) -> tuple[list[tuple[float, dict[str, Any]]], int, int]:
    selected: list[tuple[float, dict[str, Any]]] = []
    seen_refs: set[str] = set()
    counts: dict[str, Counter[str]] = {
        "rule_id": Counter(),
        "host": Counter(),
        "group": Counter(),
        "minute": Counter(),
        "decoder": Counter(),
    }
    dropped_by_budget = 0
    dropped_by_diversity = 0

    if anchor_ref:
        for score, event in scored:
            if str(event.get("raw_log_ref") or "") == anchor_ref:
                selected.append((score, event))
                seen_refs.add(anchor_ref)
                _register_diversity(event, counts)
                break

    for score, event in scored:
        ref = str(event.get("raw_log_ref") or "")
        if not ref or ref in seen_refs:
            continue
        if len(selected) >= top_k:
            dropped_by_budget += 1
            continue
        if _diversity_blocked(event, counts=counts, caps=caps):
            dropped_by_diversity += 1
            continue
        selected.append((score, event))
        seen_refs.add(ref)
        _register_diversity(event, counts)

    return selected, dropped_by_budget, dropped_by_diversity


def _selection_summary(selected: list[tuple[float, dict[str, Any]]]) -> dict[str, Any]:
    rule_ids = Counter(_rule_id(event) or "unknown" for _, event in selected)
    hosts = Counter(_host_of(event).lower() or "unknown" for _, event in selected)
    groups = Counter(_primary_rule_group(event) for _, event in selected)
    return {
        "top_rule_ids": [item[0] for item in rule_ids.most_common(5)],
        "top_hosts": [item[0] for item in hosts.most_common(5)],
        "top_rule_groups": [item[0] for item in groups.most_common(5)],
    }


def _eval_chain_mode(attacks: list[dict[str, Any]]) -> str:
    if any(str(event.get("raw_log_ref") or "").startswith("attack:") for event in attacks):
        return "eval_attack_prefix"
    return "eval_is_attack"


def _build_graph_event(
    event: dict[str, Any],
    *,
    explanation_ids: list[str],
    prev_id: str | None,
    prev_event: dict[str, Any] | None,
    production: bool,
    candidate_score: float | None = None,
) -> dict[str, Any]:
    ref = str(event.get("raw_log_ref") or "")
    host = _host_of(event)
    attrs = dict(_event_attributes(event))
    src_entity = event.get("src_entity") or {}
    src_attrs = src_entity.get("attrs") or {}
    dst_entity = event.get("dst_entity") or {}
    dst_attrs = dst_entity.get("attrs") or {}

    if host:
        attrs.setdefault("host_uid", host)
        attrs.setdefault("asset_id", host)
    if src_attrs.get("name"):
        attrs.setdefault("process_name", src_attrs.get("name"))
    if dst_attrs.get("name"):
        attrs.setdefault("dst_process_name", dst_attrs.get("name"))

    technique = str(event.get("technique") or attrs.get("mitre_technique") or "T0000")
    tactic = str(
        event.get("tactic")
        or event.get("_normalized_tactic")
        or attrs.get("mitre_tactic")
        or "unknown"
    )

    relation = "causes"
    if prev_event is not None:
        prev_host = _host_of(prev_event)
        if prev_host and host and prev_host.lower() != host.lower():
            relation = "lateral_to"
        elif production:
            relation = "precedes"

    if production:
        attrs["bootstrap_provenance"] = "production_candidate"
        if candidate_score is not None:
            attrs["candidate_score"] = round(candidate_score, 4)

    graph_event: dict[str, Any] = {
        "id": ref,
        "technique": technique,
        "tactic": tactic,
        "timestamp": _event_timestamp(event),
        "source": str(event.get("source") or "wazuh"),
        "trust_tier": "medium" if production else "high",
        "explanation_ids": explanation_ids,
        "_fact_confirmed": True,
        "_attribution_confirmed": not production,
        "_attribution_status": "CONTESTED" if production else "CONFIRMED",
        "attributes": attrs,
    }
    if prev_id:
        graph_event["parent_id"] = prev_id
        graph_event["relation"] = relation
    return graph_event


def materialize_attack_chain(
    events: list[dict[str, Any]],
    *,
    explanation_ids: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Turn eval-marked attack events into ordered graph nodes with chain edges."""
    explanation_ids = list(explanation_ids or [])
    attacks = [event for event in events if is_attack_event(event)]
    if not attacks:
        return []

    attacks.sort(
        key=lambda event: (
            _trace_step(event) or _evt_order(str(event.get("raw_log_ref") or "")),
            _event_timestamp(event),
            str(event.get("raw_log_ref") or ""),
        )
    )

    graph_events: list[dict[str, Any]] = []
    prev_id: str | None = None
    prev_event: dict[str, Any] | None = None

    for event in attacks:
        ref = str(event.get("raw_log_ref") or "")
        if not ref:
            continue
        graph_event = _build_graph_event(
            event,
            explanation_ids=explanation_ids,
            prev_id=prev_id,
            prev_event=prev_event,
            production=False,
        )
        graph_events.append(graph_event)
        prev_id = ref
        prev_event = event

    return graph_events


def materialize_production_candidate_chain(
    events: list[dict[str, Any]],
    *,
    alert_context: dict[str, Any] | None = None,
    explanation_ids: list[str] | None = None,
    top_k: int = _DEFAULT_TOP_K,
    diversity_caps: DiversityCaps | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Build a bounded candidate graph from production Wazuh fields only."""
    explanation_ids = list(explanation_ids or [])
    caps = diversity_caps or DiversityCaps()
    anchor = resolve_production_anchor(events, alert_context)
    usable = [event for event in events if _event_usable_for_production(event)]
    diagnostics: dict[str, Any] = {
        "candidate_chain_mode": "production_fallback",
        "candidate_chain_top_k": top_k,
        "candidate_chain_score_fields": [
            "rule_level",
            "mitre",
            "temporal",
            "entity",
            "group",
        ],
        "candidate_chain_events": 0,
        "candidate_chain_dropped_noise": 0,
        "candidate_chain_total_usable": len(usable),
        "candidate_chain_selected": 0,
        "candidate_chain_dropped_by_budget": 0,
        "candidate_chain_dropped_by_diversity": 0,
        "candidate_chain_empty_reason": None,
        **_anchor_diagnostics(anchor),
    }

    if not usable:
        diagnostics["candidate_chain_mode"] = "empty"
        diagnostics["candidate_chain_empty_reason"] = (
            "production_candidate_chain_empty: no usable timestamp/entity/rule fields"
        )
        return [], diagnostics

    scored: list[tuple[float, dict[str, Any]]] = []
    for event in usable:
        score = _bootstrap_relevance_score(event, anchor=anchor)
        scored.append((score, event))

    scored.sort(
        key=lambda item: (
            -item[0],
            _event_timestamp(item[1]),
            str(item[1].get("raw_log_ref") or ""),
        )
    )

    anchor_ref = str(anchor.get("raw_log_ref") or "")
    selected, dropped_by_budget, dropped_by_diversity = _select_candidates_with_diversity(
        scored,
        anchor_ref=anchor_ref,
        top_k=top_k,
        caps=caps,
    )

    selected.sort(
        key=lambda item: (
            _event_timestamp(item[1]),
            str(item[1].get("raw_log_ref") or ""),
        )
    )

    diagnostics["candidate_chain_selected"] = len(selected)
    diagnostics["candidate_chain_dropped_by_budget"] = dropped_by_budget
    diagnostics["candidate_chain_dropped_by_diversity"] = dropped_by_diversity
    diagnostics.update(_selection_summary(selected))

    if len(selected) < 2:
        diagnostics["candidate_chain_mode"] = "empty"
        diagnostics["candidate_chain_empty_reason"] = (
            "production_candidate_chain_empty: fewer than 2 candidate events after ranking"
        )
        diagnostics["candidate_chain_dropped_noise"] = max(0, len(events) - len(selected))
        return [], diagnostics

    graph_events: list[dict[str, Any]] = []
    prev_id: str | None = None
    prev_event: dict[str, Any] | None = None
    for score, event in selected:
        ref = str(event.get("raw_log_ref") or "")
        if not ref:
            continue
        graph_event = _build_graph_event(
            event,
            explanation_ids=explanation_ids,
            prev_id=prev_id,
            prev_event=prev_event,
            production=True,
            candidate_score=score,
        )
        graph_events.append(graph_event)
        prev_id = ref
        prev_event = event

    diagnostics["candidate_chain_events"] = len(graph_events)
    diagnostics["candidate_chain_dropped_noise"] = max(0, len(events) - len(selected))
    if not graph_events:
        diagnostics["candidate_chain_mode"] = "empty"
        diagnostics["candidate_chain_empty_reason"] = (
            "production_candidate_chain_empty: candidate events lacked stable refs"
        )
    return graph_events, diagnostics


def materialize_attack_chain_from_executor(
    executor: Any,
    *,
    explanation_ids: list[str] | None = None,
    alert_context: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    events = list(getattr(executor, "_events", []) or [])
    graph_events = materialize_attack_chain(events, explanation_ids=explanation_ids)

    if graph_events:
        attacks = [event for event in events if is_attack_event(event)]
        diagnostics = {
            "candidate_chain_mode": _eval_chain_mode(attacks),
            "candidate_chain_events": len(graph_events),
            "candidate_chain_top_k": len(graph_events),
            "candidate_chain_dropped_noise": max(0, len(events) - len(attacks)),
            "candidate_chain_score_fields": [],
            "candidate_chain_empty_reason": None,
        }
        setattr(executor, "_candidate_chain_diagnostics", diagnostics)
        return graph_events

    graph_events, diagnostics = materialize_production_candidate_chain(
        events,
        alert_context=alert_context,
        explanation_ids=explanation_ids,
        top_k=int(getattr(executor, "_production_candidate_top_k", _DEFAULT_TOP_K)),
        diversity_caps=getattr(executor, "_production_diversity_caps", None),
    )
    setattr(executor, "_candidate_chain_diagnostics", diagnostics)
    return graph_events
