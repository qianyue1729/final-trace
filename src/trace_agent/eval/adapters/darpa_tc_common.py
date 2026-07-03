"""Shared DARPA TC provenance → graph replay logic (B2.0).

All performers (CADETS, THEIA, TRACE) normalize into the same event model and
graph fixture contract consumed by ``run_graph_case()``.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trace_agent.eval.adapters.base import ProvenanceAdapterConfig
from trace_agent.eval.adapters.normalization_stats import (
    aggregate_normalization_loss,
    audit_raw_events,
    collect_normalization_stats,
    summarize_normalization_loss,
)

RELATION_TECHNIQUE_MAP: dict[str, tuple[str, str]] = {
    "process_spawn": ("execution", "T1059"),
    "execve": ("execution", "T1059"),
    "file_write": ("execution", "T1059.001"),
    "file_read": ("collection", "T1005"),
    "network_connect": ("command-and-control", "T1071.001"),
    "process_inject_or_memory": ("credential-access", "T1003.001"),
    "log_delete": ("defense-evasion", "T1070.001"),
    "remote_service_create": ("lateral-movement", "T1021.002"),
    "lateral_movement": ("lateral-movement", "T1021.002"),
    "file_share": ("lateral-movement", "T1039"),
}

DEFAULT_REPLAY_CONFIG: dict[str, Any] = {
    "max_rounds": 12,
    "fanout_per_round": 3,
    "max_probes": 45,
    "min_attack_recall": 0.5,
    "max_benign_pollution": 0,
    "root_cause_k": 3,
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent.parent.parent


def performer_data_dir(performer: str) -> Path:
    return repo_root() / "tests" / "replay" / "data" / performer.lower()


def list_sample_paths(performer: str, pattern: str) -> list[Path]:
    d = performer_data_dir(performer)
    if not d.is_dir():
        return []
    return sorted(d.glob(pattern))


def parse_timestamp(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            pass
    return 0.0


def read_provenance_events(input_path: Path, *, max_events: int = 5000) -> dict[str, Any]:
    """Load DARPA TC subset JSON: ``{metadata, events, ground_truth?}``."""
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    all_events = list(payload.get("events") or [])[:max_events]
    kept, dropped = audit_raw_events({"events": all_events})
    return {
        "metadata": payload.get("metadata") or {},
        "events": kept,
        "events_raw_count": len(all_events),
        "dropped_events": dropped,
        "ground_truth": payload.get("ground_truth") or {},
    }


def infer_tactic_technique(event: dict[str, Any]) -> tuple[str, str]:
    if event.get("tactic") and event.get("technique"):
        return str(event["tactic"]), str(event["technique"])
    relation = str(event.get("relation") or "process_spawn")
    return RELATION_TECHNIQUE_MAP.get(relation, ("execution", "T1059"))


def event_source(event: dict[str, Any]) -> str:
    relation = str(event.get("relation") or "")
    if relation in ("network_connect", "lateral_movement"):
        return "network_connection"
    if relation in ("remote_service_create",):
        return "service_creation"
    if relation in ("file_write", "file_read", "file_share"):
        return "file_creation"
    if relation in ("log_delete",):
        return "process_creation"
    if relation in ("process_inject_or_memory",):
        return "process_access"
    return "process_creation"


def normalize_darpa_tc_world_graph(
    raw: dict[str, Any],
    *,
    performer: str,
    default_host: str,
) -> dict[str, Any]:
    """Map normalized DARPA TC events → ``world_graph`` nodes + edges."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen_edges: set[tuple[str, str]] = set()
    performer_key = performer.lower()

    for event in raw.get("events") or []:
        eid = event["event_id"]
        tactic, technique = infer_tactic_technique(event)
        host_id = event.get("host_id") or (event.get("subject") or {}).get("host_id") or default_host
        attrs: dict[str, Any] = {
            "host_id": host_id,
            "relation": event.get("relation"),
            "role": event.get("role", "unknown"),
            "subject_type": (event.get("subject") or {}).get("type"),
            "object_type": (event.get("object") or {}).get("type"),
            "performer": performer,
            performer_key: True,
        }
        for key in ("src_host", "dst_host", "edge_scope", "network_flow_id"):
            if event.get(key) is not None:
                attrs[key] = event[key]
        if event.get("src_host") and not event.get("host_id"):
            attrs["host_id"] = event["src_host"]
        nodes.append(
            {
                "id": eid,
                "technique": technique,
                "tactic": tactic,
                "timestamp": parse_timestamp(event.get("timestamp")),
                "source": event_source(event),
                "trust_tier": "high",
                "attributes": attrs,
            }
        )
        parent = event.get("parent_event_id")
        if parent:
            role = event.get("role", "attack")
            if role not in ("attack", "benign", "oos"):
                role = "attack"
            key = (parent, eid)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append(
                    {
                        "id": f"edge:{parent}->{eid}",
                        "src": parent,
                        "dst": eid,
                        "relation": event.get("relation", "causes"),
                        "role": role,
                        "edge_scope": event.get("edge_scope"),
                        "src_host": event.get("src_host"),
                        "dst_host": event.get("dst_host"),
                        "network_flow_id": event.get("network_flow_id"),
                    }
                )
    return {"nodes": nodes, "edges": edges}


def merged_ground_truth(raw: dict[str, Any], gt_path: Path | None) -> dict[str, Any]:
    gt = dict(raw.get("ground_truth") or {})
    if gt_path and gt_path.is_file():
        gt.update(json.loads(gt_path.read_text(encoding="utf-8")))
    return gt


def auto_entry_event_id(world_graph: dict[str, Any], strategy: str) -> str | None:
    nodes = world_graph.get("nodes", [])
    attack_edges = [e for e in world_graph.get("edges", []) if e.get("role", "attack") == "attack"]
    attack_ids = {n["id"] for n in nodes if n.get("attributes", {}).get("role") == "attack"}
    if not attack_ids:
        return nodes[-1]["id"] if nodes else None

    if strategy == "auto_terminal":
        attack_nodes = [n for n in nodes if n["id"] in attack_ids]
        attack_nodes.sort(key=lambda n: n["timestamp"])
        return attack_nodes[-1]["id"]

    if strategy == "auto_leaf":
        srcs = {e["src"] for e in attack_edges}
        dsts = {e["dst"] for e in attack_edges}
        leaves = [nid for nid in attack_ids if nid in dsts and nid not in srcs]
        if leaves:
            by_ts = {n["id"]: n["timestamp"] for n in nodes}
            leaves.sort(key=lambda i: by_ts.get(i, 0))
            return leaves[-1]
        return sorted(attack_ids)[-1]

    return None


def select_entry_alert(
    world_graph: dict[str, Any],
    ground_truth: dict[str, Any],
    *,
    strategy: str = "explicit",
) -> dict[str, Any]:
    nodes = {n["id"]: n for n in world_graph.get("nodes", [])}
    entry_id = ground_truth.get("entry_event_id")
    if not entry_id and strategy != "explicit":
        entry_id = auto_entry_event_id(world_graph, strategy)
    if not entry_id:
        attack_nodes = [n for n in world_graph["nodes"] if n.get("attributes", {}).get("role") == "attack"]
        entry_id = attack_nodes[-1]["id"] if attack_nodes else world_graph["nodes"][-1]["id"]
    node = nodes[entry_id]
    attrs = dict(node.get("attributes") or {})
    return {
        "event_id": entry_id,
        "technique_id": node["technique"],
        "tactic": node["tactic"],
        "platform": "linux",
        "log_source": node.get("source", "process_creation"),
        "timestamp": node["timestamp"],
        "anomaly_score": float(ground_truth.get("anomaly_score", 0.88)),
        "attributes": attrs,
        "selection_strategy": strategy,
    }


def pairs_from_edges(world_graph: dict[str, Any], *, role: str) -> list[list[str]]:
    by_id = {n["id"]: n for n in world_graph.get("nodes", [])}
    pairs: list[list[str]] = []
    for edge in world_graph.get("edges", []):
        if edge.get("role", "attack") != role:
            continue
        src = by_id.get(edge["src"])
        dst = by_id.get(edge["dst"])
        if src and dst:
            pairs.append([src["technique"], dst["technique"]])
    return pairs


def build_ground_truth_subgraph(
    world_graph: dict[str, Any],
    ground_truth: dict[str, Any],
) -> dict[str, Any]:
    attack_pairs = list(ground_truth.get("attack_technique_pairs") or [])
    benign_pairs = list(ground_truth.get("benign_technique_pairs") or [])
    oos_pairs = list(ground_truth.get("oos_technique_pairs") or [])

    if not attack_pairs:
        attack_pairs = pairs_from_edges(world_graph, role="attack")

    attack_edge_ids = [e["id"] for e in world_graph.get("edges", []) if e.get("role", "attack") == "attack"]
    benign_edge_ids = [e["id"] for e in world_graph.get("edges", []) if e.get("role") == "benign"]
    oos_edge_ids = [e["id"] for e in world_graph.get("edges", []) if e.get("role") == "oos"]

    root_causes = list(ground_truth.get("root_causes") or [])
    if not root_causes:
        roots = {e["src"] for e in world_graph.get("edges", []) if e.get("role") == "attack"}
        dsts = {e["dst"] for e in world_graph.get("edges", []) if e.get("role") == "attack"}
        root_causes = sorted(roots - dsts)

    attack_nodes = list(ground_truth.get("attack_event_ids") or [])
    if not attack_nodes:
        attack_nodes = [
            n["id"] for n in world_graph.get("nodes", []) if n.get("attributes", {}).get("role") == "attack"
        ]

    gt: dict[str, Any] = {
        "root_causes": root_causes,
        "attack_nodes": attack_nodes,
        "attack_edges": attack_pairs if attack_pairs else attack_edge_ids,
        "benign_edges": benign_pairs if benign_pairs else benign_edge_ids,
        "oos_edges": oos_pairs if oos_pairs else oos_edge_ids,
    }
    if ground_truth.get("attack_event_ids"):
        gt["attack_event_ids"] = ground_truth["attack_event_ids"]

    # B2.5-lite optional event-level GT (report-only; technique-pairs remain default)
    for key in (
        "attack_node_ids",
        "attack_edge_ids",
        "attack_hosts",
        "oos_hosts",
        "cross_host_attack_edges",
        "lateral_movement_pairs",
        "network_pivot_pairs",
        "benign_cross_host_pairs",
    ):
        if ground_truth.get(key) is not None:
            gt[key] = ground_truth[key]

    return gt


def build_replay_driver(
    world_graph: dict[str, Any],
    entry_alert: dict[str, Any],
    ground_truth_subgraph: dict[str, Any],
) -> dict[str, Any]:
    entry_id = entry_alert["event_id"]
    nodes_by_role: dict[str, list[str]] = {"attack": [], "benign": [], "oos": []}
    for node in world_graph.get("nodes", []):
        role = node.get("attributes", {}).get("role", "unknown")
        if role in nodes_by_role and node["id"] != entry_id:
            nodes_by_role[role].append(node["id"])

    attack_edges = [e for e in world_graph.get("edges", []) if e.get("role") == "attack"]
    dsts = {e["dst"] for e in attack_edges}
    roots = [e["src"] for e in attack_edges if e["src"] not in dsts]
    reveal: list[str] = []
    for rid in roots:
        if rid != entry_id and rid not in reveal:
            reveal.append(rid)
    for nid in nodes_by_role["attack"]:
        if nid not in reveal:
            reveal.append(nid)

    probe_bindings: list[dict[str, Any]] = []
    if roots:
        probe_bindings.append(
            {
                "match": {"operators": ["process_tree", "script_execution"], "tactics": ["execution", "initial-access"]},
                "reveals": [roots[0]],
            }
        )
    network_nodes = [
        n["id"]
        for n in world_graph.get("nodes", [])
        if n.get("attributes", {}).get("relation") == "network_connect" and n["id"] != entry_id
    ]
    if network_nodes:
        probe_bindings.append(
            {
                "match": {"operators": ["network_flow", "dns_query"], "tactics": ["command-and-control", "exfiltration"]},
                "reveals": network_nodes[:1],
            }
        )

    return {
        "mode": "offline",
        "entry_event_id": entry_id,
        "reveal_queue": reveal,
        "pollute_queue": nodes_by_role["benign"] + nodes_by_role["oos"],
        "probe_bindings": probe_bindings,
    }


def infer_expected_decision(ground_truth_subgraph: dict[str, Any], *, category: str = "attack-like") -> dict[str, Any]:
    if category == "benign":
        return {
            "action": "monitor",
            "allowed_actions": ["monitor", "dismiss", "dismiss_benign"],
            "must_include_technique_pairs": [],
            "must_exclude_technique_pairs": [],
            "counterfactuals": [],
        }

    attack_pairs = ground_truth_subgraph.get("attack_edges") or []
    must_include: list[list[str]] = []
    for item in attack_pairs[:2]:
        if isinstance(item, (list, tuple)) and len(item) == 2:
            must_include.append([str(item[0]), str(item[1])])

    must_exclude: list[list[str]] = []
    for key in ("benign_edges", "oos_edges"):
        for item in ground_truth_subgraph.get(key) or []:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                must_exclude.append([str(item[0]), str(item[1])])

    return {
        "action": "contain",
        "allowed_actions": ["contain", "contain_escalate", "escalate", "monitor", "spawn"],
        "must_include_technique_pairs": must_include,
        "must_exclude_technique_pairs": must_exclude,
        "counterfactuals": [],
    }


def assemble_graph_fixture(
    *,
    config: ProvenanceAdapterConfig,
    raw: dict[str, Any],
    gt_raw: dict[str, Any],
    world_graph: dict[str, Any],
    norm_stats: dict[str, Any],
    source: str,
    performer: str,
    title_prefix: str,
) -> dict[str, Any]:
    entry_alert = select_entry_alert(world_graph, gt_raw, strategy=config.entry_strategy)
    gt = build_ground_truth_subgraph(world_graph, gt_raw)
    replay_driver = build_replay_driver(world_graph, entry_alert, gt)
    meta = raw.get("metadata") or {}
    category = str(meta.get("category") or "attack-like")
    expected_decision = infer_expected_decision(gt, category=category)

    return {
        "case_id": config.scenario_id,
        "title": meta.get("title") or f"{title_prefix}: {config.scenario_id}",
        "category": category,
        "source": source,
        "label_quality": "ground_truth",
        "schema_version": "graph_replay_v1",
        "primary_tactic": entry_alert.get("tactic"),
        "entry_alert": entry_alert,
        "alert": {
            "technique_id": entry_alert["technique_id"],
            "tactic": entry_alert.get("tactic"),
            "platform": entry_alert.get("platform", "linux"),
            "log_source": entry_alert.get("log_source"),
            "anomaly_score": entry_alert.get("anomaly_score", 0.5),
            "attributes": entry_alert.get("attributes") or {},
        },
        "world_graph": world_graph,
        "ground_truth_subgraph": gt,
        "replay_driver": replay_driver,
        "replay_config": dict(DEFAULT_REPLAY_CONFIG),
        "expected_decision": expected_decision,
        "evaluation": {"calibration_eligible": False},
        "adapter_meta": {
            "performer": performer,
            "input_path": str(config.input_path),
            "event_count": len(raw.get("events") or []),
            "events_raw_count": raw.get("events_raw_count"),
            "normalization_stats": norm_stats,
            "entry_alert_strategy": config.entry_strategy,
        },
    }


def load_darpa_tc_graph_fixture(
    config: ProvenanceAdapterConfig,
    *,
    source: str,
    performer: str,
    default_host: str,
    title_prefix: str,
) -> dict[str, Any]:
    raw = read_provenance_events(config.input_path, max_events=config.max_events)
    gt_raw = merged_ground_truth(raw, config.ground_truth_path)
    world_graph = normalize_darpa_tc_world_graph(raw, performer=performer, default_host=default_host)
    norm_stats = collect_normalization_stats(raw, world_graph, dropped=raw.get("dropped_events"), source=source)
    return assemble_graph_fixture(
        config=config,
        raw=raw,
        gt_raw=gt_raw,
        world_graph=world_graph,
        norm_stats=norm_stats,
        source=source,
        performer=performer,
        title_prefix=title_prefix,
    )


def write_graph_fixture(fixture: dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(fixture, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def cross_performer_benchmark_markdown(
    cases: list[dict[str, Any]],
    *,
    fixtures: list[dict[str, Any]] | None = None,
) -> str:
    """B2.3/B2.5-lite cross-performer summary table for papers."""
    buckets: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        buckets.setdefault(case.get("source", "unknown"), []).append(case)

    fixture_by_id = {f["case_id"]: f for f in (fixtures or [])}

    def _norm_stats_for_case(case: dict[str, Any]) -> dict[str, Any]:
        meta = case.get("adapter_meta") or {}
        if meta.get("normalization_stats"):
            return meta["normalization_stats"]
        fx = fixture_by_id.get(case["case_id"])
        if fx:
            return (fx.get("adapter_meta") or {}).get("normalization_stats") or {}
        return {}

    lines = [
        "## Cross-performer benchmark (B2.3 / B2.5-lite)",
        "",
        "| source | cases | events_kept | drop_rate | root_hit@3 | recall | precision | pollution | probes | rounds |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    loss_lines = ["", "### Normalization loss by source", ""]

    for source in sorted(buckets):
        group = buckets[source]
        n = len(group)
        root_hits = [c["metrics"].get("root_cause_hit_at_k") for c in group]
        recalls = [c["metrics"].get("attack_subgraph_recall") for c in group if c["metrics"].get("attack_subgraph_recall") is not None]
        precisions = [c["metrics"].get("boundary_precision") for c in group if c["metrics"].get("boundary_precision") is not None]
        pollution = [c["metrics"]["benign_pollution_rate"]["count"] for c in group]
        probes = [c["metrics"]["probe_cost_to_decision"]["probes"] for c in group]
        rounds = [c["metrics"]["probe_cost_to_decision"]["rounds"] for c in group]

        stats_list = [_norm_stats_for_case(c) for c in group if _norm_stats_for_case(c)]
        agg_loss = aggregate_normalization_loss(stats_list) if stats_list else {}
        events_kept = agg_loss.get("events_kept")
        drop_rate = agg_loss.get("drop_rate")

        def fmt_rate(vals: list) -> str:
            if not vals:
                return "—"
            if all(isinstance(v, bool) for v in vals):
                return str(round(sum(1 for v in vals if v) / len(vals), 3))
            return str(round(sum(vals) / len(vals), 3))

        lines.append(
            f"| {source} | {n} | {events_kept if events_kept is not None else '—'} | "
            f"{drop_rate if drop_rate is not None else '—'} | {fmt_rate(root_hits)} | {fmt_rate(recalls)} | "
            f"{fmt_rate(precisions)} | {round(sum(pollution) / n, 2) if n else 0} | "
            f"{round(sum(probes) / n, 1) if n else 0} | {round(sum(rounds) / n, 1) if n else 0} |"
        )
        if agg_loss:
            loss_lines.append(
                f"- **{source}**: in={agg_loss.get('events_in')} kept={agg_loss.get('events_kept')} "
                f"dropped={agg_loss.get('events_dropped')} drop_rate={agg_loss.get('drop_rate')} "
                f"unsupported_relation={agg_loss.get('unsupported_relation_rate')} "
                f"missing_subject={agg_loss.get('missing_subject_rate')} "
                f"missing_object={agg_loss.get('missing_object_rate')} "
                f"relation_coverage={agg_loss.get('relation_coverage')}"
            )

    lines.extend(loss_lines)
    return "\n".join(lines)
