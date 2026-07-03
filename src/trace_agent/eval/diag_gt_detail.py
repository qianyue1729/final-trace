"""细粒度 GT 诊断：逐轮命中/漏失/主机分布/探针选择分析."""
from __future__ import annotations
import json, sys, os
from pathlib import Path
from collections import defaultdict

# Add parent to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step2_l_phase import _setup_orchestrator
from trace_agent.eval.lock_step3_veto_phase import _root_cause_info
from trace_agent.eval.lock_step5_c_phase import _align_executor_to_alert
from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.prior_v2 import PriorManager


def diag_scenario(scenario_id: str, prior_manager, max_rounds: int = 12):
    """Run scenario with detailed per-round GT tracking."""
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    _, registry_spec = load_scenario(scenario_id)
    root_info = _root_cause_info(scenario_data)
    _align_executor_to_alert(orch, scenario_data, registry_spec)

    orch.budget.total_rounds = max_rounds
    orch.budget.total_probes = max(orch.budget.total_probes, max_rounds * 12)

    # Build GT ref → metadata index
    gt_refs = list((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    event_index = {}
    for ev in scenario_data.get("events", []):
        ref = ev.get("raw_log_ref")
        if ref:
            event_index[str(ref)] = ev

    # GT refs grouped by host
    gt_by_host = defaultdict(list)
    for ref in gt_refs:
        ev = event_index.get(ref, {})
        host = ""
        for side in ("src_entity", "dst_entity"):
            entity = ev.get(side) or {}
            host = (entity.get("attrs") or {}).get("host_uid") or host
        gt_by_host[host or "unknown"].append(ref)

    print(f"\n{'='*80}")
    print(f"场景: {scenario_id} | GT总量: {len(gt_refs)} | GT主机分布:")
    for host, refs in sorted(gt_by_host.items()):
        print(f"  {host}: {len(refs)}条GT ({', '.join(refs[:3])}...)" if len(refs) > 3 else f"  {host}: {len(refs)}条GT ({', '.join(refs)})")
    print(f"入口: {triage.entry_ref} | 告警主机: {triage.alert.asset_id}")
    print(f"{'='*80}")

    # Run loop with detailed tracking
    prev_stats = orch.graph.stats()
    seen_hits = set()
    all_hosts_in_graph = set()

    for round_num in range(1, max_rounds + 1):
        if orch.budget.exhausted():
            break
        orch.budget.rounds_used += 1

        # L phase
        pool = orch._l_phase(prev_stats)
        pool_size = pool.size()

        # Veto phase
        pool = orch._veto_phase(pool)

        # O phase — track chosen probes
        chosen = orch._o_phase(pool)
        if not chosen:
            print(f"\nR{round_num}: 无候选探针，停止")
            break

        chosen_details = []
        for p in chosen:
            chosen_details.append({
                "id": p.id,
                "operator": p.operator,
                "target": getattr(p, "target", ""),
                "tactic": getattr(p, "tactic", ""),
                "source": getattr(p, "source", ""),
                "priority_hint": getattr(p, "priority_hint", 0),
            })

        # C phase
        ingest_result = orch._c_phase(chosen)

        # K phase
        stop_decision = orch._k_phase(chosen, ingest_result)

        # Track GT hits
        graph_ids = {n.id for n in orch.graph._nodes.values()}
        hit_refs = set(gt_refs) & graph_ids
        new_hits = hit_refs - seen_hits
        seen_hits = hit_refs

        # Track hosts
        for node in orch.graph._nodes.values():
            attrs = node.attributes or {}
            for key in ("host_uid", "asset_id", "host", "target"):
                val = attrs.get(key)
                if val:
                    all_hosts_in_graph.add(str(val).lower())

        # Confirmed events
        confirmed_count = len(getattr(ingest_result, "confirmed", []))
        graph_eligible_count = len(getattr(ingest_result, "graph_eligible", []))
        all_events_count = len(getattr(ingest_result, "all_events", []))
        routed = getattr(ingest_result, "routed", {})

        # Pool analysis: what's in the pool but not chosen?
        pool_drained = pool.drain() if hasattr(pool, "drain") else []
        pool_operators = defaultdict(int)
        pool_targets = set()
        for p in pool_drained:
            pool_operators[p.operator] += 1
            t = getattr(p, "target", "")
            if t:
                pool_targets.add(t)

        chosen_operators = defaultdict(int)
        chosen_targets = set()
        for cd in chosen_details:
            chosen_operators[cd["operator"]] += 1
            if cd["target"]:
                chosen_targets.add(cd["target"])

        print(f"\nR{round_num}: pool={pool_size} chosen={len(chosen)} confirmed={confirmed_count} "
              f"graph_eligible={graph_eligible_count} all_events={all_events_count}")
        print(f"  探针: {[(cd['operator'], cd['target']) for cd in chosen_details]}")
        print(f"  候选池算子分布: {dict(pool_operators)}")
        print(f"  候选池目标主机({len(pool_targets)}): {sorted(pool_targets)[:10]}")
        print(f"  选中目标主机: {sorted(chosen_targets)}")
        print(f"  路由: ATTACH={len(routed.get('ATTACH',[]))} WEAK={len(routed.get('WEAK',[]))} "
              f"PARK={len(routed.get('PARK',[]))} DISCARD={len(routed.get('DISCARD',[]))} "
              f"SPAWN={len(routed.get('SPAWN',[]))}")
        print(f"  GT命中: 新增{len(new_hits)} 累计{len(seen_hits)}/{len(gt_refs)} "
              f"({100*len(seen_hits)/len(gt_refs):.1f}%)")
        if new_hits:
            for ref in sorted(new_hits):
                ev = event_index.get(ref, {})
                tech = ev.get("technique", "?")
                host = ""
                for side in ("src_entity", "dst_entity"):
                    entity = ev.get(side) or {}
                    host = (entity.get("attrs") or {}).get("host_uid") or host
                print(f"    + {ref} | tech={tech} host={host}")
        print(f"  图中主机({len(all_hosts_in_graph)}): {sorted(all_hosts_in_graph)[:15]}")
        print(f"  节点数={orch.graph.stats().get('node_count',0)} stop={stop_decision.should_stop}({stop_decision.reason})")

        prev_stats = orch.graph.stats()

        if stop_decision.should_stop:
            break

    # Final summary
    graph_ids = {n.id for n in orch.graph._nodes.values()}
    final_hits = set(gt_refs) & graph_ids
    misses = set(gt_refs) - final_hits

    print(f"\n{'='*80}")
    print(f"最终结果: GT命中={len(final_hits)}/{len(gt_refs)} ({100*len(final_hits)/len(gt_refs):.1f}%)")
    print(f"图中主机({len(all_hosts_in_graph)}): {sorted(all_hosts_in_graph)}")

    # Miss analysis by host
    miss_by_host = defaultdict(list)
    for ref in sorted(misses):
        ev = event_index.get(ref, {})
        host = ""
        for side in ("src_entity", "dst_entity"):
            entity = ev.get(side) or {}
            host = (entity.get("attrs") or {}).get("host_uid") or host
        miss_by_host[host or "unknown"].append(ref)

    print(f"\n漏失GT ({len(misses)}条) 按主机:")
    for host, refs in sorted(miss_by_host.items()):
        in_graph = host.lower() in all_hosts_in_graph
        print(f"  {host} ({'已入图' if in_graph else '[!] 未入图'}): {len(refs)}条未命中")
        for ref in refs:
            ev = event_index.get(ref, {})
            tech = ev.get("technique", "?")
            tactic = ""
            t = ev.get("tactic", "")
            if not t:
                # try technique-to-tactic mapping
                t = "?"
            print(f"    - {ref} | tech={tech} tactic={t}")

    # Hosts with GT but not in graph
    # Fix: compare case-insensitively (graph hosts are lowercased, GT hosts may not be)
    gt_hosts_lower = {h.lower() for h in gt_by_host.keys() if h}
    # Build lowercase→original mapping for display
    gt_host_map = {h.lower(): h for h in gt_by_host.keys() if h}
    missing_hosts = gt_hosts_lower - all_hosts_in_graph - {"external", "unknown", ""}
    if missing_hosts:
        print(f"\n[!] 有GT但完全未入图的主机: {sorted(missing_hosts)}")
        for h in sorted(missing_hosts):
            orig = gt_host_map.get(h, h)
            refs = gt_by_host.get(orig, gt_by_host.get(h, []))
            print(f"  {h}: {len(refs)}条GT全部漏失")

    return {
        "scenario": scenario_id,
        "gt_total": len(gt_refs),
        "hits": len(final_hits),
        "coverage_pct": 100 * len(final_hits) / len(gt_refs) if gt_refs else 0,
        "hosts_in_graph": len(all_hosts_in_graph),
        "gt_hosts": len(gt_hosts_lower),
        "missing_hosts": sorted(missing_hosts),
    }


if __name__ == "__main__":
    prior_manager = PriorManager(load_prior_bundle())
    results = []
    for sid in ["pipeline_18", "apt_5host", "multipath_12host"]:
        r = diag_scenario(sid, prior_manager, max_rounds=12)
        results.append(r)

    print(f"\n{'='*80}")
    print("汇总:")
    print(f"{'场景':<20} {'GT总量':>8} {'命中':>8} {'覆盖率':>10} {'图主机':>8} {'GT主机':>8} {'漏失主机':>8}")
    for r in results:
        print(f"{r['scenario']:<20} {r['gt_total']:>8} {r['hits']:>8} {r['coverage_pct']:>9.1f}% "
              f"{r['hosts_in_graph']:>8} {r['gt_hosts']:>8} {len(r['missing_hosts']):>8}")
