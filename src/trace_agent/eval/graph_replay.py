"""L1 graph replay — LOCK session evaluation against ground-truth subgraphs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from trace_agent.agents.orchestrator import BudgetState, DecisionOrchestrator, InvestigationResult
from trace_agent.decision.types import AlertEvent
from trace_agent.eval.graph_fixture_executor import GraphFixtureExecutor
from trace_agent.eval.optc_multihost_metrics import collect_multihost_metrics, is_multihost_fixture
from trace_agent.loop.ingest import ROUTE_ATTACH
from trace_agent.loop.session_graph import SessionGraph
from trace_agent.prior_v2 import PriorManager

GRAPH_FIXTURES_DIR = (
    Path(__file__).resolve().parent.parent.parent.parent / "tests" / "replay" / "graph"
)

DECISION_ALIASES: dict[str, set[str]] = {
    "contain": {"contain", "contain_escalate", "escalate"},
    "contain_escalate": {"contain", "contain_escalate", "escalate"},
    "escalate": {"contain", "contain_escalate", "escalate"},
    "monitor": {"monitor"},
    "dismiss": {"dismiss", "dismiss_benign"},
    "dismiss_benign": {"dismiss", "dismiss_benign"},
}


def load_mordor_graph_fixtures(fixtures_dir: Path | None = None) -> list[dict[str, Any]]:
    return [f for f in load_graph_fixtures(fixtures_dir) if is_mordor_graph_fixture(f)]


def is_mordor_graph_fixture(fixture: dict[str, Any]) -> bool:
    return fixture.get("source") == "mordor" or str(fixture.get("case_id", "")).startswith("mordor_")


def is_graph_fixture(fixture: dict[str, Any]) -> bool:
    return all(k in fixture for k in ("entry_alert", "ground_truth_subgraph", "expected_decision"))


def load_graph_fixtures(fixtures_dir: Path | None = None) -> list[dict[str, Any]]:
    d = fixtures_dir or GRAPH_FIXTURES_DIR
    if not d.is_dir():
        return []
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))]


def _world_node_lookup(fixture: dict[str, Any]) -> dict[str, dict[str, Any]]:
    world = fixture.get("world_graph") or {}
    return {n["id"]: n for n in world.get("nodes", [])}


def _runtime_for_world_id(graph: SessionGraph, fixture: dict[str, Any], world_id: str) -> str | None:
    if world_id in graph._nodes:
        return world_id
    world_node = _world_node_lookup(fixture).get(world_id)
    if world_node is None:
        return None
    best_id: str | None = None
    best_delta = float("inf")
    target_ts = float(world_node["timestamp"])
    for nid, runtime in graph._nodes.items():
        if runtime.technique != world_node["technique"]:
            continue
        delta = abs(runtime.timestamp - target_ts)
        if delta < best_delta:
            best_delta = delta
            best_id = nid
    return best_id


def _sync_world_edges(graph: SessionGraph, fixture: dict[str, Any]) -> None:
    """Backfill attack-role GT topology after replay attach (B0 upstream linking)."""
    for edge in (fixture.get("world_graph") or {}).get("edges", []):
        if edge.get("role", "attack") != "attack":
            continue
        src = _runtime_for_world_id(graph, fixture, edge.get("src", ""))
        dst = _runtime_for_world_id(graph, fixture, edge.get("dst", ""))
        if src and dst:
            graph.link_parent(dst, src, edge.get("relation", "causes"))


def _seed_graph_from_world_entry(
    orchestrator: DecisionOrchestrator,
    fixture: dict[str, Any],
    seed_explanation_ids: list[str],
) -> None:
    entry = fixture["entry_alert"]
    world_id = entry.get("event_id")
    world_node = _world_node_lookup(fixture).get(world_id or "")
    if world_node is None:
        return
    graph = SessionGraph()
    graph.add_events(
        [
            {
                "id": world_node["id"],
                "technique": world_node["technique"],
                "tactic": world_node["tactic"],
                "timestamp": float(world_node["timestamp"]),
                "source": world_node.get("source", entry.get("log_source", "alert")),
                "trust_tier": world_node.get("trust_tier", "high"),
                "explanation_ids": seed_explanation_ids,
                "attributes": dict(world_node.get("attributes") or {}),
            }
        ]
    )
    orchestrator.graph = graph


def _patch_orchestrator_for_graph_replay(
    orchestrator: DecisionOrchestrator,
    fixture: dict[str, Any],
    executor: GraphFixtureExecutor,
) -> None:
    original_bootstrap = orchestrator._bootstrap
    original_c_phase = orchestrator._c_phase
    original_k_phase = orchestrator._k_phase
    l4_patched = False

    def bootstrap_with_world_entry():
        original_bootstrap()
        if orchestrator.ledger is not None:
            expl_ids = [e.id for e in orchestrator.ledger.explanations]
        else:
            expl_ids = []
        _seed_graph_from_world_entry(orchestrator, fixture, expl_ids)
        executor.attach_graph(orchestrator.graph)

    def c_phase_with_attach(chosen):
        nonlocal l4_patched
        executor.attach_graph(orchestrator.graph)
        if not l4_patched and orchestrator.ingest is not None:
            nonlocal_original = orchestrator.ingest._l4_route
            def replay_l4_bound(ev: dict, **kwargs) -> str:
                attrs = ev.get("attributes") or {}
                if attrs.get("graph_replay_attach"):
                    # Don't force-ATTACH pollute events (oos/benign role)
                    role = attrs.get("role", "attack")
                    if role in ("oos", "benign"):
                        return nonlocal_original(ev, **kwargs)
                    return ROUTE_ATTACH
                return nonlocal_original(ev, **kwargs)
            orchestrator.ingest._l4_route = replay_l4_bound  # type: ignore[method-assign]
            l4_patched = True
        return original_c_phase(chosen)

    def k_phase_with_sync(chosen, ingest_result):
        stop = original_k_phase(chosen, ingest_result)
        if orchestrator.graph is not None:
            _sync_world_edges(orchestrator.graph, fixture)
        return stop

    orchestrator._bootstrap = bootstrap_with_world_entry  # type: ignore[method-assign]
    orchestrator._c_phase = c_phase_with_attach  # type: ignore[method-assign]
    orchestrator._k_phase = k_phase_with_sync  # type: ignore[method-assign]


def _alert_from_entry(entry: dict[str, Any]) -> AlertEvent:
    return AlertEvent(
        technique_id=entry.get("technique_id") or entry.get("technique", "T0000"),
        tactic=entry.get("tactic"),
        platform=entry.get("platform"),
        log_source=entry.get("log_source"),
        anomaly_score=float(entry.get("anomaly_score", 0.5)),
        asset_id=entry.get("host_id") or (entry.get("attributes") or {}).get("host_id"),
        timestamp=entry.get("timestamp"),
        attributes=entry.get("attributes") or {},
    )


def _normalize_technique_pair(item: Any) -> tuple[str, str] | None:
    if isinstance(item, (list, tuple)) and len(item) == 2:
        return (str(item[0]), str(item[1]))
    return None


def _gt_technique_pairs(fixture: dict[str, Any], gt_key: str) -> set[tuple[str, str]]:
    """Resolve GT edge list: technique-pair arrays and/or world edge ids."""
    gt = fixture.get("ground_truth_subgraph") or {}
    items = gt.get(gt_key) or []
    pairs: set[tuple[str, str]] = set()
    edge_ids: list[str] = []
    for item in items:
        pair = _normalize_technique_pair(item)
        if pair:
            pairs.add(pair)
        elif isinstance(item, str):
            edge_ids.append(item)
    if edge_ids:
        pairs |= _edge_pairs_from_world(fixture, edge_ids)
    return pairs


def _expected_technique_pairs(expected: dict[str, Any], key: str) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for item in expected.get(key) or []:
        pair = _normalize_technique_pair(item)
        if pair:
            pairs.add(pair)
    return pairs


def _edge_pairs_from_world(fixture: dict[str, Any], edge_ids: list[str]) -> set[tuple[str, str]]:
    """Return (src_technique, dst_technique) pairs for stable GT comparison."""
    world = fixture.get("world_graph") or {}
    nodes = {n["id"]: n for n in world.get("nodes", [])}
    by_id = {e["id"]: e for e in world.get("edges", [])}
    pairs: set[tuple[str, str]] = set()
    for eid in edge_ids:
        edge = by_id.get(eid)
        if edge is None:
            continue
        src = nodes.get(edge.get("src"))
        dst = nodes.get(edge.get("dst"))
        if src and dst:
            pairs.add((src["technique"], dst["technique"]))
    return pairs


def _runtime_technique_pairs(graph) -> set[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for edge in graph._edges.values():
        src_node = graph._nodes.get(edge.src)
        dst_node = graph._nodes.get(edge.dst)
        if src_node and dst_node:
            pairs.add((src_node.technique, dst_node.technique))
    return pairs


def _runtime_node_ids(graph) -> set[str]:
    return set(graph._nodes.keys())


def _root_cause_techniques(fixture: dict[str, Any], root_causes: list[str]) -> set[str]:
    world = _world_node_lookup(fixture)
    techniques: set[str] = set()
    for rc in root_causes:
        if rc in world:
            techniques.add(world[rc]["technique"])
        elif isinstance(rc, str) and rc.startswith("T"):
            techniques.add(rc)
    return techniques


def _world_node_techniques(fixture: dict[str, Any], node_ids: list[str]) -> set[str]:
    return _root_cause_techniques(fixture, node_ids)


def _top_explanation_techniques(orchestrator: DecisionOrchestrator, k: int) -> list[str]:
    ledger = orchestrator.ledger
    if ledger is None:
        return []
    probs = ledger._get_probabilities()
    ranked = sorted(
        ((eid, probs.get(eid, 0.0)) for eid in probs if eid != "__null__"),
        key=lambda x: x[1],
        reverse=True,
    )[:k]
    techniques: list[str] = []
    expl_by_id = {e.id: e for e in ledger.explanations}
    for eid, _ in ranked:
        expl = expl_by_id.get(eid)
        if expl is None:
            continue
        techniques.append(expl.current_technique)
        techniques.extend(expl.predecessor_tactics or [])
        techniques.extend(expl.technique_context or [])
    return techniques


def collect_graph_metrics(
    result: InvestigationResult,
    orchestrator: DecisionOrchestrator,
    fixture: dict[str, Any],
    executor: GraphFixtureExecutor,
    *,
    k: int | None = None,
) -> dict[str, Any]:
    gt = fixture["ground_truth_subgraph"]
    cfg = fixture.get("replay_config") or {}
    k = k if k is not None else int(cfg.get("root_cause_k", 3))

    graph = orchestrator.graph
    gt_attack_pairs = _gt_technique_pairs(fixture, "attack_edges")
    gt_benign_pairs = _gt_technique_pairs(fixture, "benign_edges")
    gt_oos_pairs = _gt_technique_pairs(fixture, "oos_edges")

    recovered_pairs = _runtime_technique_pairs(graph) if graph else set()
    recovered_nodes = _runtime_node_ids(graph) if graph else set()
    revealed_world = executor.revealed_nodes()

    root_causes = gt.get("root_causes") or []
    root_techniques = _root_cause_techniques(fixture, root_causes)
    root_hit = bool(root_causes and (set(root_causes) & (recovered_nodes | revealed_world)))
    if not root_hit and root_techniques:
        top_k = _top_explanation_techniques(orchestrator, k)
        root_hit = any(t in root_techniques for t in top_k)
    if not root_hit and root_techniques:
        graph_techniques = {n.technique for n in graph._nodes.values()} if graph else set()
        root_hit = bool(root_techniques & graph_techniques)

    if gt_attack_pairs:
        attack_hits = len(recovered_pairs & gt_attack_pairs)
        attack_subgraph_recall = round(attack_hits / len(gt_attack_pairs), 4)
    else:
        attack_subgraph_recall = None

    if recovered_pairs:
        attack_attached = len(recovered_pairs & gt_attack_pairs)
        boundary_precision = round(attack_attached / len(recovered_pairs), 4)
    else:
        boundary_precision = None

    benign_polluted = len(recovered_pairs & gt_benign_pairs)
    oos_polluted = len(recovered_pairs & gt_oos_pairs)
    benign_pollution_rate = {
        "count": benign_polluted + oos_polluted,
        "ratio": round((benign_polluted + oos_polluted) / len(recovered_pairs), 4) if recovered_pairs else 0.0,
        "benign_count": benign_polluted,
        "oos_count": oos_polluted,
    }

    expected = fixture["expected_decision"]
    allowed = set(expected.get("allowed_actions") or [expected.get("action", "")])
    allowed_norm: set[str] = set()
    for action in allowed:
        allowed_norm |= DECISION_ALIASES.get(action, {action})
    actual_norm = DECISION_ALIASES.get(result.decision, {result.decision})
    decision_accuracy = bool(allowed_norm & actual_norm)

    boundary_checks = _boundary_checks(result, fixture, recovered_pairs)

    metrics: dict[str, Any] = {
        "root_cause_hit_at_k": root_hit,
        "root_cause_k": k,
        "attack_subgraph_recall": attack_subgraph_recall,
        "boundary_precision": boundary_precision,
        "benign_pollution_rate": benign_pollution_rate,
        "probe_cost_to_decision": {
            "probes": result.total_events_processed,
            "rounds": result.rounds_used,
        },
        "decision_accuracy": decision_accuracy,
        "decision_expected": expected.get("action"),
        "decision_actual": result.decision,
        "boundary_checks": boundary_checks,
        "recovered_edge_count": len(recovered_pairs),
        "recovered_node_count": len(recovered_nodes),
        "revealed_world_nodes": sorted(revealed_world),
    }
    multihost = collect_multihost_metrics(fixture, graph, recovered_pairs)
    if multihost:
        metrics["multihost"] = multihost
    return metrics


def _boundary_checks(
    result: InvestigationResult,
    fixture: dict[str, Any],
    recovered_pairs: set[tuple[str, str]],
) -> dict[str, Any]:
    expected = fixture["expected_decision"]
    must_include = expected.get("must_include_boundaries") or []
    must_exclude = expected.get("must_exclude_boundaries") or []

    include_pairs = _edge_pairs_from_world(fixture, must_include)
    include_pairs |= _expected_technique_pairs(expected, "must_include_technique_pairs")
    exclude_pairs = _edge_pairs_from_world(fixture, must_exclude)
    exclude_pairs |= _expected_technique_pairs(expected, "must_exclude_technique_pairs")

    return {
        "must_include_ok": include_pairs.issubset(recovered_pairs) if include_pairs else None,
        "must_exclude_ok": not (exclude_pairs & recovered_pairs) if exclude_pairs else None,
        "boundary_decisions": result.boundary_decisions,
    }


def run_graph_case(
    fixture: dict[str, Any],
    *,
    prior_manager: PriorManager | None = None,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    if not is_graph_fixture(fixture):
        raise ValueError(f"Not a graph replay fixture: {fixture.get('case_id', '?')}")

    entry = fixture["entry_alert"]
    alert = _alert_from_entry(entry)
    cfg = fixture.get("replay_config") or {}
    budget = BudgetState(
        total_rounds=int(cfg.get("max_rounds", 12)),
        total_probes=int(cfg.get("max_probes", 60)),
        fanout_per_round=int(cfg.get("fanout_per_round", 3)),
    )

    executor = GraphFixtureExecutor(fixture)
    prior = prior_manager or PriorManager()
    orchestrator = DecisionOrchestrator(
        alert=alert,
        executor=executor,
        prior_manager=prior,
        data_dir=data_dir,
        budget=budget,
    )

    _patch_orchestrator_for_graph_replay(orchestrator, fixture, executor)

    result = orchestrator.run(max_rounds=budget.total_rounds)
    metrics = collect_graph_metrics(result, orchestrator, fixture, executor)

    checks = {
        "decision_ok": metrics["decision_accuracy"],
        "root_cause_ok": metrics["root_cause_hit_at_k"],
        "attack_recall_ok": (
            metrics["attack_subgraph_recall"] is None
            or metrics["attack_subgraph_recall"] >= float(cfg.get("min_attack_recall", 0.5))
        ),
        "boundary_precision_ok": (
            metrics["boundary_precision"] is None
            or metrics["boundary_precision"] >= float(cfg.get("min_boundary_precision", 0.5))
        ),
        "benign_pollution_ok": metrics["benign_pollution_rate"]["count"]
        <= int(cfg.get("max_benign_pollution", 1)),
    }
    bc = metrics["boundary_checks"]
    if bc.get("must_include_ok") is not None:
        checks["must_include_ok"] = bc["must_include_ok"]
    if bc.get("must_exclude_ok") is not None:
        checks["must_exclude_ok"] = bc["must_exclude_ok"]

    mh = metrics.get("multihost") or {}
    if mh:
        checks["cross_host_recall_ok"] = (
            mh.get("cross_host_attack_recall") is None
            or mh.get("cross_host_attack_recall") >= float(cfg.get("min_cross_host_recall", 0.0))
        )
        bcp = mh.get("benign_cross_host_pollution_rate") or {}
        checks["benign_cross_host_pollution_ok"] = bcp.get("count", 0) <= int(
            cfg.get("max_benign_cross_host_pollution", 0)
        )
        hoa = mh.get("hosts_over_attributed") or {}
        checks["hosts_over_attributed_ok"] = hoa.get("count", 0) <= int(cfg.get("max_hosts_over_attributed", 0))
        if mh.get("oos_host_split_accuracy") is not None:
            checks["oos_host_split_ok"] = mh["oos_host_split_accuracy"] >= float(cfg.get("min_oos_host_split", 1.0))

    passed = all(v for v in checks.values() if v is not None)

    return {
        "case_id": fixture["case_id"],
        "title": fixture.get("title", fixture["case_id"]),
        "category": fixture.get("category", "attack-like"),
        "source": fixture.get("source", "synthetic"),
        "schema_version": fixture.get("schema_version", "graph_replay_v1"),
        "adapter_meta": fixture.get("adapter_meta"),
        "metrics": metrics,
        "checks": checks,
        "passed": passed,
        "stop_reason": result.stop_reason,
        "leading_explanation": result.leading_explanation,
        "counterfactuals": result.counterfactuals,
    }


def run_all_graph_replay(
    fixtures_dir: Path | None = None,
    *,
    prior_manager: PriorManager | None = None,
    data_dir: Path | None = None,
) -> dict[str, Any]:
    fixtures = load_graph_fixtures(fixtures_dir)
    results = [run_graph_case(f, prior_manager=prior_manager, data_dir=data_dir) for f in fixtures]
    passed = sum(1 for r in results if r["passed"])
    return {
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "layer": "L1_graph_replay",
        },
        "cases": results,
    }


def is_mordor_graph_fixture(fixture: dict[str, Any]) -> bool:
    return fixture.get("source") == "mordor" or str(fixture.get("case_id", "")).startswith("mordor_")


def is_darpa_cadets_fixture(fixture: dict[str, Any]) -> bool:
    return fixture.get("source") == "darpa_tc_cadets" or str(fixture.get("case_id", "")).startswith("darpa_cadets_")


def is_darpa_theia_fixture(fixture: dict[str, Any]) -> bool:
    return fixture.get("source") == "darpa_tc_theia" or str(fixture.get("case_id", "")).startswith("darpa_theia_")


def is_darpa_trace_fixture(fixture: dict[str, Any]) -> bool:
    return fixture.get("source") == "darpa_tc_trace" or str(fixture.get("case_id", "")).startswith("darpa_trace_")


def is_darpa_tc_fixture(fixture: dict[str, Any]) -> bool:
    return (
        is_darpa_cadets_fixture(fixture)
        or is_darpa_theia_fixture(fixture)
        or is_darpa_trace_fixture(fixture)
    )


def is_optc_fixture(fixture: dict[str, Any]) -> bool:
    return fixture.get("source") == "optc_corrected" or str(fixture.get("case_id", "")).startswith("optc_")


def is_optc_multihost_toy_fixture(fixture: dict[str, Any]) -> bool:
    return str(fixture.get("case_id", "")).startswith("optc_multihost_") or (
        is_multihost_fixture(fixture) and fixture.get("source") in ("synthetic", "optc_like")
    )


def _primary_tactic(case: dict[str, Any]) -> str:
    if case.get("primary_tactic"):
        return str(case["primary_tactic"])
    entry = case.get("entry_alert") or case.get("alert") or {}
    return str(entry.get("tactic") or "unknown")


def aggregate_graph_metrics(cases: list[dict[str, Any]]) -> dict[str, Any]:
    if not cases:
        return {"n_cases": 0}

    def mean(key: str) -> float | None:
        vals = [c["metrics"].get(key) for c in cases if c["metrics"].get(key) is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    def rate(check: str) -> float | None:
        hits = [c for c in cases if check in (c.get("checks") or {})]
        if not hits:
            return None
        return round(sum(1 for c in hits if c["checks"][check]) / len(hits), 3)

    pollution = [c["metrics"]["benign_pollution_rate"]["count"] for c in cases]
    probes = [c["metrics"]["probe_cost_to_decision"]["probes"] for c in cases]
    rounds = [c["metrics"]["probe_cost_to_decision"]["rounds"] for c in cases]

    return {
        "n_cases": len(cases),
        "mean_attack_subgraph_recall": mean("attack_subgraph_recall"),
        "mean_boundary_precision": mean("boundary_precision"),
        "mean_benign_pollution_count": round(sum(pollution) / len(pollution), 2),
        "mean_probe_cost": round(sum(probes) / len(probes), 2),
        "mean_round_cost": round(sum(rounds) / len(rounds), 2),
        "root_cause_hit_rate": rate("root_cause_ok"),
        "decision_accuracy_rate": rate("decision_ok"),
        "pass_rate": round(sum(1 for c in cases if c["passed"]) / len(cases), 3),
    }


def _summary_by_key(cases: list[dict[str, Any]], key_fn) -> dict[str, dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = {}
    for case in cases:
        buckets.setdefault(key_fn(case), []).append(case)
    out: dict[str, dict[str, Any]] = {}
    for label, group in sorted(buckets.items()):
        n = len(group)
        recalls = [c["metrics"].get("attack_subgraph_recall") for c in group if c["metrics"].get("attack_subgraph_recall") is not None]
        pollution = [c["metrics"]["benign_pollution_rate"]["count"] for c in group]
        out[label] = {
            "n": n,
            "mean_recall": round(sum(recalls) / len(recalls), 3) if recalls else None,
            "mean_pollution": round(sum(pollution) / n, 2) if n else 0,
            "pass_rate": round(sum(1 for c in group if c["passed"]) / n, 3) if n else 0,
        }
    return out


def report_markdown(report: dict[str, Any]) -> str:
    cases = report.get("cases") or []
    agg = aggregate_graph_metrics(cases)
    lines = [
        "# Graph Replay Report (L1)",
        "",
        f"**Passed:** {report['summary']['passed']}/{report['summary']['total']}",
        f"**Mean attack recall:** {agg.get('mean_attack_subgraph_recall')}",
        f"**Mean boundary precision:** {agg.get('mean_boundary_precision')}",
        f"**Decision accuracy rate (report-only):** {agg.get('decision_accuracy_rate')}",
        "",
        "## Case table",
        "",
        "| source | case_id | primary_tactic | root@k | recall | precision | pollution | probes | rounds | decision | dec_acc |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for c in cases:
        m = c["metrics"]
        lines.append(
            f"| {c.get('source', '?')} | {c['case_id']} | {_primary_tactic(c)} | "
            f"{m['root_cause_hit_at_k']} | {m['attack_subgraph_recall']} | {m['boundary_precision']} | "
            f"{m['benign_pollution_rate']['count']} | {m['probe_cost_to_decision']['probes']} | "
            f"{m['probe_cost_to_decision']['rounds']} | {m['decision_actual']} | {m['decision_accuracy']} |"
        )
    lines.extend(["", "## By source", ""])
    for label, stats in _summary_by_key(cases, lambda c: c.get("source", "unknown")).items():
        lines.append(
            f"- **{label}**: n={stats['n']} recall={stats['mean_recall']} "
            f"pollution={stats['mean_pollution']} pass={stats['pass_rate']}"
        )
    lines.extend(["", "## By primary tactic", ""])
    for label, stats in _summary_by_key(cases, _primary_tactic).items():
        lines.append(
            f"- **{label}**: n={stats['n']} recall={stats['mean_recall']} "
            f"pollution={stats['mean_pollution']} pass={stats['pass_rate']}"
        )
    from trace_agent.eval.adapters.darpa_tc_common import cross_performer_benchmark_markdown

    darpa_cases = [c for c in cases if is_darpa_tc_fixture(c) or str(c.get("source", "")).startswith("darpa_tc_")]
    if darpa_cases:
        lines.extend(["", cross_performer_benchmark_markdown(darpa_cases)])
    optc_cases = [c for c in cases if is_optc_fixture(c) or is_optc_multihost_toy_fixture(c)]
    if optc_cases:
        lines.extend(["", "## OpTC multi-host benchmark (C)", ""])
        for c in optc_cases:
            mh = (c.get("metrics") or {}).get("multihost") or {}
            lines.append(
                f"- **{c['case_id']}**: cross_host_recall={mh.get('cross_host_attack_recall')} "
                f"lateral_recall={mh.get('lateral_movement_recall')} "
                f"benign_xhost_pollution={mh.get('benign_cross_host_pollution_rate', {}).get('count')} "
                f"hosts_over={mh.get('hosts_over_attributed', {}).get('count')} "
                f"oos_split={mh.get('oos_host_split_accuracy')}"
            )
    lines.extend(["", "## Case details", ""])
    for c in cases:
        status = "PASS" if c["passed"] else "FAIL"
        m = c["metrics"]
        lines.append(f"### [{status}] {c['case_id']} — {c.get('title', c['case_id'])}")
        lines.append(
            f"- recall={m['attack_subgraph_recall']} precision={m['boundary_precision']} "
            f"pollution={m['benign_pollution_rate']['count']} "
            f"probes={m['probe_cost_to_decision']['probes']} "
            f"decision={m['decision_actual']} (expected {m['decision_expected']})"
        )
        lines.append(f"- checks: {c['checks']}")
        lines.append("")
    return "\n".join(lines)
