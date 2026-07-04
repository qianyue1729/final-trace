"""_helpers — 从 DecisionOrchestrator 提取的共享转换与辅助函数。

供 L/Veto/O/C/K 五个拍级执行器共用，避免循环导入。
"""
from __future__ import annotations

from typing import Any

from trace_agent.loop.generators import normalize_tactic


def graph_to_dict(graph, scenario_hosts: list) -> dict:
    """Convert SessionGraph to dict for ObligationLedger compatibility.

    Equivalent to DecisionOrchestrator._graph_to_dict().
    """
    nodes = []
    tactics_seen: set[str] = set()
    hosts_seen: set[str] = set()
    for node in graph._nodes.values():
        attrs = node.attributes or {}
        tactic = node.tactic or ""
        if tactic:
            tactics_seen.add(tactic)
        for key in ("host_uid", "asset_id", "host", "target"):
            val = attrs.get(key)
            if val:
                hosts_seen.add(str(val))
        nodes.append({
            "id": node.id,
            "technique": node.technique,
            "tactic": node.tactic,
            "timestamp": node.timestamp,
            "source": node.source,
            "trust_tier": node.trust_tier,
            "fact_confirmed": node.fact_confirmed,
            "attribution_status": node.attribution_status,
            "malicious_status": node.malicious_status,
            "malicious": node.malicious_status == "confirmed",
            "host_id": node.host_id,
            "entity_id": node.entity_id,
            "provenance": dict(node.provenance),
            "requires_parent": bool(attrs.get("requires_parent", False)),
            "type": "host" if attrs.get("host_uid") or attrs.get("host") else "event",
            "bridge_candidate": len(hosts_seen) > 1 and attrs.get("bridge_candidate", False),
            "provenance_confirmed": attrs.get("provenance_confirmed", False),
            "visibility_restored": attrs.get("visibility_restored", False),
            "source_unavailable_decision": attrs.get("source_unavailable_decision", False),
            "attributes": node.attributes,
        })
    edges = []
    for edge in graph._edges.values():
        edges.append({
            "id": edge.id,
            "src": edge.src,
            "dst": edge.dst,
            "relation": edge.relation,
            "tactic": "",
        })
    return {
        "nodes": nodes,
        "edges": edges,
        "known_hosts": list(scenario_hosts),
    }


def probe_to_dict(probe, calib) -> dict:
    """Convert Probe to dict for voi() compatibility.

    Equivalent to DecisionOrchestrator._probe_to_dict().
    """
    return {
        "id": probe.id,
        "type": probe.source,
        "target": probe.target,
        "target_type": probe.target_type,
        "operator": probe.operator,
        "tactic": probe.tactic,
        "learning_key": probe.learning_key(),
        "source": probe.source,
        "metadata": dict(probe.metadata),
        "cost": calib.cost(probe) if calib else 0.10,
    }


def beta_to_dict(beta) -> dict:
    """Convert BetaLedger to dict for voi()/should_stop() compatibility.

    Equivalent to DecisionOrchestrator._beta_to_dict().
    """
    result = {}
    for key in beta.all_keys():
        alpha, beta_val = beta.get_params(key)
        result[key] = {"alpha": alpha, "beta": beta_val}
    observations = [
        (key, values)
        for key, values in result.items()
        if not key.startswith("__")
    ]
    global_success = sum(max(0.0, v["alpha"] - 1.0) for _, v in observations)
    global_fail = sum(max(0.0, v["beta"] - 1.0) for _, v in observations)
    result["__global__"] = {
        "alpha": 1.0 + global_success,
        "beta": 1.0 + global_fail,
    }
    result["__tenant__:global"] = dict(result["__global__"])
    by_target: dict[str, list[dict]] = {}
    for key, values in observations:
        parts = key.split("|")
        if len(parts) >= 2:
            by_target.setdefault(parts[1], []).append(values)
    for target_type, values in by_target.items():
        result[f"__target_type__:{target_type}"] = {
            "alpha": 1.0 + sum(max(0.0, item["alpha"] - 1.0) for item in values),
            "beta": 1.0 + sum(max(0.0, item["beta"] - 1.0) for item in values),
        }
    return result


def calib_to_dict(calib) -> dict:
    """Expose versioned cost calibration for VOI audit and persistence."""
    return calib.to_dict() if calib else {}


def compute_graph_stats(graph) -> dict:
    """Build graph_stats dict for dual-mode VOI (exploration mode).

    Equivalent to DecisionOrchestrator._compute_graph_stats().
    """
    stats = graph.stats()
    hosts: set[str] = set()
    tactics_per_host: dict[str, set[str]] = {}
    for node in graph._nodes.values():
        attrs = node.attributes or {}
        host = ""
        for key in ("host_uid", "asset_id", "host", "target"):
            val = attrs.get(key)
            if val:
                host = str(val).lower()
                break
        if host:
            hosts.add(host)
            tactic = normalize_tactic(node.tactic or "")
            tactics_per_host.setdefault(host, set()).add(tactic)
    return {
        "hosts": hosts,
        "tactics_seen": set(normalize_tactic(t) for t in (stats.get("tactics_seen") or [])),
        "tactics_per_host": tactics_per_host,
        "node_count": stats.get("node_count", 0),
    }


def obligation_dicts_to_probes(raw: list[dict]):
    """义务物化 dict → Probe（进统一候选池 / O 拍预占）。

    Equivalent to DecisionOrchestrator._obligation_dicts_to_probes().
    """
    from trace_agent.loop.probe import Probe

    probes = []
    for ob in raw:
        target = str(ob.get("target") or "")
        operator = str(ob.get("operator") or "")
        tactic = str(ob.get("tactic") or "discovery")
        if not target or not operator:
            continue
        probe = Probe(
            id=ob.get("id", Probe.generate_id(target, operator, tactic)),
            target=target,
            target_type="host",
            operator=operator,
            tactic=tactic,
            source="obligation",
            metadata={
                "obligation_id": ob.get("obligation_id"),
                "hard": ob.get("hard", False),
                "reason_code": ob.get("reason_code"),
                "acceptance_criterion": ob.get("acceptance_criterion", {}),
            },
            priority_hint=float(ob.get("priority", 1.0)),
        )
        probes.append(probe)
    return probes


def probe_is_executable(probe, executor, known_hosts_lower: set, graph) -> bool:
    """义务/合成探针仅在其 target 可解析为已知或图中主机时入池。

    Equivalent to DecisionOrchestrator._probe_is_executable().
    """
    mcp_config = getattr(executor, "mcp_config", None)
    operator_registry = (
        getattr(mcp_config, "operator_datasource_map", {})
        if mcp_config is not None else {}
    )
    if operator_registry and probe.operator not in operator_registry:
        return False
    target_lower = (probe.target or "").lower().strip()
    if not target_lower or target_lower in ("unknown", "ledger"):
        return False
    if known_hosts_lower and target_lower in known_hosts_lower:
        return True
    if graph:
        for node in graph._nodes.values():
            attrs = node.attributes or {}
            for key in ("host_uid", "asset_id", "host", "target"):
                val = attrs.get(key)
                if val and str(val).lower() == target_lower:
                    return True
    return not known_hosts_lower


def has_initial_access_in_graph(graph) -> bool:
    """Check if initial-access tactic has been discovered in the graph."""
    tactics = {
        normalize_tactic(t)
        for t in (graph.stats().get("tactics_seen") or [])
    }
    return "initial-access" in tactics


def has_required_fields(event: dict) -> bool:
    """Check if event has the required fields for SessionGraph.add_events()."""
    return all(k in event for k in ("technique", "tactic", "timestamp", "source"))


def get_graph_hosts(graph) -> set[str]:
    """Extract all host identifiers from graph nodes."""
    graph_hosts: set[str] = set()
    if graph:
        for node in graph._nodes.values():
            attrs = node.attributes or {}
            for key in ("host_uid", "asset_id", "host", "target"):
                val = attrs.get(key)
                if val:
                    graph_hosts.add(str(val).lower())
    return graph_hosts
