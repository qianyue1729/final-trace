"""
Final LOCK loop test on real Wazuh scenario.
Pure ASCII version - simplified.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

print("="*75)
print("TEST: Complete LOCK Loop on Real Wazuh Scenario")
print("="*75)

# Load scenario
print("\n[1/4] Loading data...")
try:
    from trace_agent.eval.soar_integration_runner import load_scenario
    scenario_data, spec = load_scenario("pipeline_18")
    print("[OK] Loaded:", spec.get('name'))
    
    events = scenario_data.get("events", [])
    gt_refs = scenario_data.get("ground_truth", {}).get("attack_edge_refs", [])
    print("[OK] Events:", len(events), "| GT edges:", len(gt_refs))
    
except Exception as e:
    print("[ERROR]:", e)
    sys.exit(1)

# Create alert from first event
print("\n[2/4] Constructing alert seed...")
try:
    from trace_agent.decision.types import AlertEvent
    
    first_event = events[0] if events else {}
    technique = first_event.get("technique", "T1566") or "T1566"
    
    # Use Unix timestamp as float
    ts_float = 1704067200.0  # 2024-01-01 00:00:00 UTC (or use real value)
    
    # Determine tactic from technique
    TECH_TACTIC_MAP = {
        "T1566": "initial-access",
        "T1059": "execution",
        "T1053": "persistence",
        "T1003": "credential-access",
        "T1021": "lateral-movement",
        "T1041": "exfiltration",
        "T1071": "command-and-control",
    }
    tactic = TECH_TACTIC_MAP.get(technique.split(".")[0], "unknown")
    
    alert = AlertEvent(
        technique_id=technique,
        tactic=tactic,
        platform="windows",
        log_source="wazuh_security_events",
        timestamp=str(ts_float),  # Must be convertible to float by bootstrap
        anomaly_score=0.75,
    )
    print("[OK] Alert created:", technique, "->", tactic)
    
except Exception as e:
    print("[ERROR]:", e)
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Initialize executor
print("\n[3/4] Initializing executor...")
try:
    from trace_agent.loop.scenario_executor import ScenarioExecutor
    
    executor = ScenarioExecutor(scenario_data, seed=42)
    stats = executor.stats
    print("[OK] Executor ready:", stats.get('total_events'), "events indexed")
    
except Exception as e:
    print("[ERROR]:", e)
    sys.exit(1)

# Setup orchestrator and run
print("\n[4/4] Running LOCK loop...")
try:
    from trace_agent.data_loader import load_prior_bundle
    from trace_agent.prior_v2 import PriorManager
    from trace_agent.agents.orchestrator import DecisionOrchestrator, BudgetState
    
    bundle = load_prior_bundle()
    prior_manager = PriorManager(bundle)
    
    budget = BudgetState(
        total_rounds=50,
        total_probes=400,
        fanout_per_round=8,
    )
    
    orch = DecisionOrchestrator(
        alert=alert,
        executor=executor,
        prior_manager=prior_manager,
        budget=budget,
    )
    
    print("[OK] Orchestrator initialized")
    print("     Running bootstrap...")
    orch._bootstrap()
    print("[OK] Bootstrap complete - ready to run LOCK loop")
    
except Exception as e:
    print("[ERROR]:", e)
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Run the loop
print("\nRunning full LOCK cycle (up to 50 rounds):\n")
print("{:6} | {:12} | {:8} | {:8} | {:10} | {:10}".format(
    "ROUND", "POOL", "CHOSEN", "CONFIRMED", "NODES", "H1_POSTERIOR"))
print("-"*75)

rounds_history = []
stop_reason = None

try:
    while not orch.budget.exhausted():
        orch.budget.rounds_used += 1
        rnum = orch.budget.rounds_used
        
        pool = orch._l_phase(orch.graph.stats())
        pool_size = pool.size()
        
        pool_after_veto = orch._veto_phase(pool)
        
        chosen = orch._o_phase(pool_after_veto) if pool_after_veto.size() > 0 else []
        chosen_count = len(chosen) if chosen else 0
        
        ingest_result = orch._c_phase(chosen)
        confirmed_list = getattr(ingest_result, "confirmed", [])
        confirmed_count = len(confirmed_list)
        
        stop_decision = orch._k_phase(chosen, ingest_result)
        
        cur_graph = orch.graph.stats()
        leading_id = orch.ledger.leading()
        probs = orch.ledger._get_probabilities()
        h1_posterior = probs.get("H1", 0) or 0
        
        print("{:6} | {:12} | {:8} | {:8} | {:10} | {:10.4f}".format(
            rnum, pool_size, chosen_count, confirmed_count,
            cur_graph.get('node_count', 0), h1_posterior))
        
        rounds_history.append({
            "round": rnum,
            "pool_size": int(pool_size),
            "chosen": int(chosen_count),
            "confirmed": int(confirmed_count),
            "graph_nodes": int(cur_graph.get("node_count", 0)),
            "leading_hypothesis": leading_id,
            "posterior_H1": float(h1_posterior),
        })
        
        stop_reason = stop_decision.reason
        if stop_decision.should_stop:
            print("\n-> STOP:", stop_reason)
            break
    
    print("-"*75)
    
except Exception as e:
    print("\n[ERROR]:", e)
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Generate report
print("\nFINAL RESULTS\n")
print("="*75)

try:
    result = orch._build_result(stop_reason or "budget_exceeded")
    final_stats = orch.graph.stats()
    
    print("DECISION:", result.decision.upper())
    conf = result.confidence or 0
    print("CONFIDENCE: {:.2%}".format(conf) if conf else "CONFIDENCE: N/A")
    print("STOP REASON:", result.stop_reason)
    print("LEADING HYPOTHESIS:", result.leading_explanation)
    
    print("\nEXECUTION METRICS:")
    print("   Rounds:", orch.budget.rounds_used, "/", orch.budget.total_rounds)
    print("   Probes:", orch.budget.probes_used, "/", orch.budget.total_probes)
    print("   Graph nodes:", final_stats.get('node_count', 0))
    print("   Graph edges:", final_stats.get('edge_count', 0))
    
    print("\nGROUND TRUTH COVERAGE:")
    all_refs = set()
    for node in orch.graph._nodes.values():
        attrs = node.attributes or {}
        ref = attrs.get("raw_log_ref", "")
        if ref:
            all_refs.add(ref)
    
    hits = len(all_refs.intersection(set(gt_refs)))
    recall_pct = (hits / len(gt_refs) * 100) if gt_refs else 0
    print("   Hits:", hits, "/", len(gt_refs), "(", "{:.1f}%".format(recall_pct), ")")
    
    print("\nBAYESIAN CONVERGENCE (first 10 rounds):")
    for rd in rounds_history[:min(10, len(rounds_history))]:
        print("   Round {}: H1={:.4f}, Nodes={}".format(
            rd['round'], rd['posterior_H1'], rd['graph_nodes']))
    if len(rounds_history) > 10:
        print("   ... (+{} more)".format(len(rounds_history)-10))
    
    print("\nINTERPRETATION:")
    conf_val = conf if conf else 0
    level = "HIGH" if conf_val > 0.9 else "MEDIUM" if conf_val > 0.7 else "LOW"
    
    if result.decision == "contain_escalate":
        print("   Attack CONFIRMED (confidence {})".format(level))
        print("   Action: ESCALATE TO INCIDENT RESPONSE")
    elif result.decision == "dismiss_benign":
        print("   Benign activity (no escalation)")
    else:
        print("   Uncertain outcome - recommend extended monitoring")
    
    print("\n" + "="*75)
    print("LOCK LOOP TEST COMPLETED")
    print("="*75)
    
    # Save results
    import json
    output_file = Path(__file__).parent / "wazuh_real_lock_test_output.json"
    
    export_data = {
        "scenario": "pipeline_18",
        "decision": result.decision,
        "confidence": float(conf) if conf else None,
        "stop_reason": result.stop_reason,
        "rounds_completed": orch.budget.rounds_used,
        "probes_used": orch.budget.probes_used,
        "recall_coverage": float(recall_pct),
        "ground_truth_hits": hits,
        "total_gt_edges": len(gt_refs),
        "rounds_history": rounds_history,
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    print("\nResults saved to:", output_file)
    
except Exception as e:
    print("\n[ERROR] Report generation failed:", e)
    import traceback
    traceback.print_exc()
    sys.exit(1)
