"""CADETS normalization statistics for B1.5 stability reporting."""
from __future__ import annotations

from typing import Any

SUPPORTED_RELATIONS = frozenset(
    {
        "process_spawn",
        "execve",
        "file_read",
        "file_write",
        "network_connect",
        "process_inject_or_memory",
        "log_delete",
        "remote_service_create",
        "lateral_movement",
        "file_share",
    }
)


def _inc(bucket: dict[str, int], key: str, n: int = 1) -> None:
    bucket[key] = bucket.get(key, 0) + n


def collect_normalization_stats(
    raw: dict[str, Any],
    world_graph: dict[str, Any],
    *,
    dropped: dict[str, int] | None = None,
    source: str = "darpa_tc_cadets",
) -> dict[str, Any]:
    """Summarize how raw CADETS events map into graph replay nodes/edges."""
    events_in = len(raw.get("events") or [])
    events_kept = len(world_graph.get("nodes", []))

    entity_types: dict[str, int] = {"process": 0, "file": 0, "socket": 0, "user": 0, "host": 0, "service": 0}
    relations: dict[str, int] = {}
    roles: dict[str, int] = {}

    for event in raw.get("events") or []:
        rel = str(event.get("relation") or "unknown")
        _inc(relations, rel)
        role = str(event.get("role") or "unknown")
        _inc(roles, role)
        for side in ("subject", "object"):
            ent = event.get(side) or {}
            etype = str(ent.get("type") or "unknown")
            if etype in entity_types:
                _inc(entity_types, etype)
            else:
                _inc(entity_types, etype if etype in entity_types else "process")

    edge_roles: dict[str, int] = {}
    for edge in world_graph.get("edges", []):
        _inc(edge_roles, str(edge.get("role", "attack")))

    return {
        "source": source,
        "scenario_id": (raw.get("metadata") or {}).get("scenario_id"),
        "events_in": events_in,
        "events_kept": events_kept,
        "events_dropped": max(0, events_in - events_kept),
        "nodes": entity_types,
        "relations": relations,
        "roles": roles,
        "graph_edges": len(world_graph.get("edges", [])),
        "graph_edge_roles": edge_roles,
        "dropped_events": dict(dropped or {}),
    }


def audit_raw_events(raw: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Filter/validate events; return kept events + drop reasons."""
    kept: list[dict[str, Any]] = []
    dropped: dict[str, int] = {}

    for event in raw.get("events") or []:
        if not event.get("event_id"):
            _inc(dropped, "missing_event_id")
            continue
        relation = str(event.get("relation") or "")
        if relation and relation not in SUPPORTED_RELATIONS:
            _inc(dropped, "unsupported_relation")
            continue
        subject = event.get("subject") or {}
        obj = event.get("object") or {}
        if not subject.get("type"):
            _inc(dropped, "missing_subject")
            continue
        if not obj.get("type"):
            _inc(dropped, "missing_object")
            continue
        kept.append(event)
    return kept, dropped


def summarize_normalization_loss(stats: dict[str, Any]) -> dict[str, Any]:
    """B2.5-lite: aggregate drop/keep rates for cross-performer reporting."""
    events_in = int(stats.get("events_in") or 0)
    events_kept = int(stats.get("events_kept") or 0)
    events_dropped = int(stats.get("events_dropped") or max(0, events_in - events_kept))
    dropped = stats.get("dropped_events") or {}
    relations = stats.get("relations") or {}

    def rate(n: int) -> float | None:
        return round(n / events_in, 4) if events_in else None

    supported_hits = sum(relations.get(r, 0) for r in SUPPORTED_RELATIONS)
    relation_coverage = round(supported_hits / events_in, 4) if events_in else None

    return {
        "source": stats.get("source"),
        "events_in": events_in,
        "events_kept": events_kept,
        "events_dropped": events_dropped,
        "drop_rate": rate(events_dropped),
        "unsupported_relation_rate": rate(dropped.get("unsupported_relation", 0)),
        "missing_subject_rate": rate(dropped.get("missing_subject", 0)),
        "missing_object_rate": rate(dropped.get("missing_object", 0)),
        "missing_event_id_rate": rate(dropped.get("missing_event_id", 0)),
        "relation_coverage": relation_coverage,
        "dropped_events": dict(dropped),
    }


def aggregate_normalization_loss(stats_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize normalization loss across multiple fixtures/sources."""
    if not stats_list:
        return {"n": 0}

    totals = {"events_in": 0, "events_kept": 0, "events_dropped": 0}
    dropped: dict[str, int] = {}
    for stats in stats_list:
        loss = summarize_normalization_loss(stats)
        totals["events_in"] += loss["events_in"]
        totals["events_kept"] += loss["events_kept"]
        totals["events_dropped"] += loss["events_dropped"]
        for reason, count in (loss.get("dropped_events") or {}).items():
            dropped[reason] = dropped.get(reason, 0) + count

    merged = {**totals, "dropped_events": dropped, "source": stats_list[0].get("source")}
    return summarize_normalization_loss(merged)
