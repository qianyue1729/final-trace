#!/usr/bin/env python3
"""Final complete LOCK loop test on real pipeline_18 scenario."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

print("="*80)
print("REAL WAZUH SCENARIO TEST - PIPELINE_18")
print("Full LOCK Loop Execution")
print("="*80)

# Step 1: Load scenario
print("\n[Step 1/4] Loading scenario data...")
try:
    from trace_agent.eval.soar_integration_runner import load_scenario
    
    scenario_data, spec = load_scenario("pipeline_18")
    print(f"[OK] Scenario loaded: {spec.get('name', 'N/A')}")
    print(f"   • Total events: {len(scenario_data.get('events', []))}")
    
    gt_refs = scenario_data.get("ground_truth", {}).get("attack_edge_refs", [])
    print(f"   • Ground truth attack edges: {len(gt_refs)}")
    
except Exception as e:
    print(f"[ERROR] Failed to load scenario: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Step 2: Initialize executor
print("\n[Step 2/4] Initializing scenario executor...")
try:
    from trace_agent.loop.scenario_executor import ScenarioExecutor
    
    executor = ScenarioExecutor(scenario_data, seed=42)
    stats = executor.stats
    print(f"[OK] Executor ready")
    print(f"   • Indexed events: {stats.get('total_events', 0)}")
    print(f"   • Available: {executor.available()}")
    
except Exception as e:
    print(f"[ERROR] Executor init failed: {e}")
    sys.exit(1)

# Step 3: Setup orchestrator
print("\n[Step 3/4] Setting up decision orchestrator...")
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
        min_rounds_before_robust=4,
        min_rounds_after_root=8,
    )
    
    orch = DecisionOrchestrator(
        executor=executor,
        prior_manager=prior_manager,
        budget=budget,
    )
    
    print(f"[OK] Orchestrator initialized")
    print(f"   • MAX rounds: {budget.total_rounds}")
    print(f"   • MAX probes: {budget.total_probes}")
    print(f"   • FAN-out: {budget.fanout_per_round}")
    
except Exception as e:
    print("\n[ERROR] Orchestrator setup failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Step 4: Run full LOCK loop with monitoring
print("\n[Step 4/4] Running complete LOCK loop...\n")
print("-"*80)
print("ROUND | PROBE POOL | SELECTED | CONFIRMED | GRAPH NODES | LEADING HYP | POSTERIOR")
print("-"*80)

rounds_history = []
stop_reason = None

try:
    while not orch.budget.exhausted():
        orch.budget.rounds_used += 1
        round_num = orch.budget.rounds_used
        
        # L phase: Probe selection
        pool = orch._l_phase(orch.graph.stats())
        pool_size = pool.size()
        
        # VETO phase: Filter out low-quality probes
        pool_after_veto = orch._veto_phase(pool)
        
        # O phase: Choose top candidates
        chosen = orch._o_phase(pool_after_veto) if pool_after_veto.size() > 0 else []
        chosen_count = len(chosen) if chosen else 0
        
        # C phase: Ingest and confirm events
        ingest_result = orch._c_phase(chosen)
        confirmed_list = getattr(ingest_result, "confirmed", [])
        confirmed_count = len(confirmed_list)
        
        # K phase: Stop decision
        stop_decision = orch._k_phase(chosen, ingest_result)
        
        # Gather statistics
        cur_graph = orch.graph.stats()
        leading_id = orch.ledger.leading()
        probs = orch.ledger._get_probabilities()
        h1_posterior = probs.get("H1", 0) or 0
        
        # Display round summary
        print(f"{round_num:5} | {pool_size:10} |    {chosen_count:3} |     {confirmed_count:5} | {cur_graph.get('node_count', 0):11} |       {leading_id:7} | {h1_posterior:.2%}")
        
        rounds_history.append({
            "round": round_num,
            "pool_size": pool_size,
            "chosen": chosen_count,
            "confirmed": confirmed_count,
            "graph_nodes": cur_graph.get("node_count", 0),
            "leading_hypothesis": leading_id,
            "posterior_H1": h1_posterior,
        })
        
        stop_reason = stop_decision.reason
        if stop_decision.should_stop:
            print(f"\n→ STOP triggered: {stop_reason}")
            break
    
except Exception as e:
    print("\n[ERROR] LOCK loop execution error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Final report
print("-"*80)
print("\n📊 FINAL INVESTIGATION REPORT")
print("="*80)

try:
    result = orch._build_result(stop_reason or "budget_exceeded")
    final_stats = orch.graph.stats()
    
    print("\n🎯 DECISION SUMMARY:")
    print(f"   Decision: {result.decision.upper()}")
    conf = result.confidence or 0
    print(f"   Confidence: {conf:.2%}" if conf else "   Confidence: N/A")
    print(f"   Stop reason: {result.stop_reason}")
    print(f"   Leading hypothesis: {result.leading_explanation}")
    
    print("\n📈 EXECUTION METRICS:")
    print(f"   Rounds completed: {orch.budget.rounds_used}/{orch.budget.total_rounds}")
    print(f"   Probes used: {orch.budget.probes_used}/{orch.budget.total_probes}")
    print(f"   Final graph nodes: {final_stats.get('node_count', 0)}")
    print(f"   Final graph edges: {final_stats.get('edge_count', 0)}")
    
    print("\n🎯 ATTACK RECALL (Ground Truth Coverage):")
    all_refs = set()
    for node in orch.graph._nodes.values():
        attrs = node.attributes or {}
        ref = attrs.get("raw_log_ref", "")
        if ref:
            all_refs.add(ref)
    
    hits = len(all_refs.intersection(set(gt_refs)))
    recall_pct = (hits / len(gt_refs) * 100) if gt_refs else 0
    print(f"   ✓ Ground truth matched: {hits}/{len(gt_refs)} events")
    print(f"   Recall coverage: {recall_pct:.1f}%")
    
    print("\n📈 BAYESIAN CONVERGENCE HISTORY:")
    for rd in rounds_history[:min(10, len(rounds_history))]:
        print(f"   Round {rd['round']}: H1 posterior={rd['posterior_H1']:.2%}, Nodes={rd['graph_nodes']}")
    if len(rounds_history) > 10:
        print(f"   ... (+{len(rounds_history)-10} more rounds)")
    
    print("\n💡 INTERPRETATION:")
    if result.decision == "contain_escalate":
        print(f"   ✦ Attack confirmed (Leading ID: {result.leading_explanation})")
        print(f"   ✦ Confidence level: {'High' if (conf or 0) > 0.9 else 'Medium' if (conf or 0) > 0.7 else 'Low'}")
        print(f"   ✦ Recommendation: ESCALATE TO INCIDENT RESPONSE")
    elif result.decision == "dismiss_benign":
        print(f"   ✦ Benign activity detected (Leading ID: {result.leading_explanation})")
        print(f"   ✦ No escalation required")
    else:
        print(f"   ✦ Uncertain outcome (Leading ID: {result.leading_explanation})")
        print(f"   ✦ Recommend extended monitoring")
    
    print("\n🛡️ NEXT ACTIONS:")
    if result.decision == "contain_escalate":
        print("   1. Isolate affected hosts immediately")
        print("   2. Preserve forensics evidence")
        print("   3. Block C2 indicators at firewall")
        print("   4. Trigger full incident response playbook")
    
    print("\n" + "="*80)
    print("LOCK LOOP TEST COMPLETED SUCCESSFULLY!")
    print("="*80)
    
    # Export results to JSON
    import json
    output_file = Path(__file__).parent / "wazuh_real_lock_test_output.json"
    
    export_data = {
        "scenario": "pipeline_18",
        "decision": result.decision,
        "confidence": float(conf) if conf else None,
        "stop_reason": result.stop_reason,
        "rounds_completed": orch.budget.rounds_used,
        "probes_used": orch.budget.probes_used,
        "graph_stats": final_stats,
        "recall_coverage": recall_pct,
        "ground_truth_hits": hits,
        "total_gt_edges": len(gt_refs),
        "rounds_history": rounds_history,
        "key_findings": [
            f"Attack recall: {recall_pct:.1f}%",
            f"Decision: {result.decision}",
            f"Confidence: {conf:.2%}" if conf else "Confidence: N/A",
        ]
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Results exported to: {output_file}")
    print("="*80)
    
except Exception as e:
    print(f"\n[ERROR] Result building failed: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
