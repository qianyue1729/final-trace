#!/usr/bin/env python3
"""Test complete LOCK loop on real Wazuh scenario - pipeline_18."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))

from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.loop.scenario_executor import ScenarioExecutor
from trace_agent.agents.orchestrator import DecisionOrchestrator, BudgetState
from trace_agent.data_loader import load_prior_bundle
from trace_agent.prior_v2 import PriorManager


def main():
    print("=" * 80)
    print("🔬 COMPLETE LOCK LOOP TRACING TEST")
    print("Scenario: pipeline_18 (Real Wazuh MCP)")
    print("=" * 80)
    
    # Step 1: Load scenario from soar_mcp_env
    print("\n[Step 1/6] Loading real scenario data...")
    try:
        scenario_data, spec = load_scenario("pipeline_18")
        print(f"✅ Loaded: {spec.get('name', 'pipeline_18')}")
        print(f"   • Events in dataset: {len(scenario_data.get('events', {}))}")
        
        gt_refs = scenario_data.get("ground_truth", {}).get("attack_edge_refs", [])
        print(f"   • Ground truth attack edges: {len(gt_refs)}")
    except Exception as e:
        print(f"❌ Error loading scenario: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Step 2: Initialize executor
    print("\n[Step 2/6] Initializing ScenarioExecutor...")
    try:
        executor = ScenarioExecutor(scenario_data, seed=42)
        exec_stats = executor.stats()
        print(f"✅ Executor ready")
        print(f"   • Total indexed events: {exec_stats.get('event_count', 0)}")
        print(f"   • Hosts discovered: {exec_stats.get('host_count', 0)}")
    except Exception as e:
        print(f"❌ Executor init failed: {e}")
        return
    
    # Step 3: Setup orchestrator
    print("\n[Step 3/6] Setting up Decision Orchestrator...")
    try:
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
        
        print("✅ Orchestrator initialized")
        print(f"   • MAX rounds: {budget.total_rounds}")
        print(f"   • MAX probes: {budget.total_probes}")
        print(f"   • FAN-out per round: {budget.fanout_per_round}")
        
    except Exception as e:
        print(f"❌ Orchestrator setup failed: {e}")
        return
    
    # Step 4: Bootstrap
    print("\n[Step 4/6] Bootstrapping investigation...")
    try:
        orch._bootstrap()
        bootstrap_stats = orch.graph.stats()
        print(f"✅ Bootstrap complete")
        print(f"   • Initial graph nodes: {bootstrap_stats.get('node_count', 0)}")
        print(f"   • Initial graph edges: {bootstrap_stats.get('edge_count', 0)}")
        print(f"   • Leading explanation: {orch.ledger.leading()}")
        
    except Exception as e:
        print(f"❌ Bootstrap failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Step 5: Run full LOCK loop
    print("\n[Step 5/6] Running complete LOCK loop...")
    print("-" * 80)
    print("ROUND | PHASE | PROBE POOL | SELECTED | CONFIRMED | GRAPH NODES | LEADING | POSTERIOR")
    print("-" * 80)
    
    rounds_data = []
    stop_reason = None
    
    try:
        while not orch.budget.exhausted():
            orch.budget.rounds_used += 1
            round_num = orch.budget.rounds_used
            
            # L phase
            pool = orch._l_phase(orch.graph.stats())
            pool_size = pool.size()
            
            # VETO phase
            pool_after_veto = orch._veto_phase(pool)
            veto_count = pool_size - pool_after_veto.size()
            
            # O phase
            chosen = orch._o_phase(pool_after_veto) if pool_after_veto.size() > 0 else []
            chosen_count = len(chosen) if chosen else 0
            
            # C phase
            ingest_result = orch._c_phase(chosen)
            confirmed_count = len(getattr(ingest_result, "confirmed", []))
            
            # K phase
            stop_decision = orch._k_phase(chosen, ingest_result)
            
            # Track stats
            cur_graph = orch.graph.stats()
            leading = orch.ledger.leading()
            probs = orch.ledger._get_probabilities()
            h1_posterior = probs.get("H1", 0)
            
            # Print round summary
            print(f"{round_num:5} |   K   | {pool_size:10} |  {chosen_count:6} |   {confirmed_count:7} | {cur_graph.get('node_count', 0):11} | {leading:7} | {h1_posterior:.2%}")
            
            rounds_data.append({
                "round": round_num,
                "pool_size": pool_size,
                "chosen": chosen_count,
                "confirmed": confirmed_count,
                "graph_nodes": cur_graph.get("node_count", 0),
                "leading": leading,
                "posterior_H1": h1_posterior,
            })
            
            stop_reason = stop_decision.reason
            if stop_decision.should_stop:
                print(f"\n→ Stop triggered: {stop_reason}")
                break
        
    except Exception as e:
        print(f"\n❌ LOCK loop execution failed: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # Step 6: Build and display final result
    print("\n[Step 6/6] Building final report...")
    try:
        result = orch._build_result(stop_reason or "budget")
        final_graph = orch.graph.stats()
        
        print("\n" + "=" * 80)
        print("📊 FINAL INVESTIGATION REPORT")
        print("=" * 80)
        
        print("\n🎯 Decision Summary:")
        print(f"   • Decision: {result.decision.upper()}")
        print(f"   • Confidence: {result.confidence:.2%}" if result.confidence else "   • Confidence: N/A")
        print(f"   • Stop reason: {result.stop_reason}")
        print(f"   • Leading explanation: {result.leading_explanation}")
        
        print("\n📈 Execution Metrics:")
        print(f"   • Rounds completed: {orch.budget.rounds_used}/{orch.budget.total_rounds}")
        print(f"   • Probes used: {orch.budget.probes_used}/{orch.budget.total_probes}")
        print(f"   • Final graph nodes: {final_graph.get('node_count', 0)}")
        print(f"   • Final graph edges: {final_graph.get('edge_count', 0)}")
        
        print("\n🎯 Truth Coverage (Estimated):")
        all_events_in_graph = set()
        for node in orch.graph._nodes.values():
            attrs = node.attributes or {}
            ref = attrs.get("raw_log_ref", "")
            if ref:
                all_events_in_graph.add(ref)
        
        hits = len(all_events_in_graph.intersection(set(gt_refs)))
        coverage_pct = (hits / len(gt_refs) * 100) if gt_refs else 0
        print(f"   • GT references matched: {hits}/{len(gt_refs)}")
        print(f"   • Recall coverage: {coverage_pct:.1f}%")
        
        print("\n📅 Posterior Evolution:")
        for rd in rounds_data[:10]:  # First 10 rounds
            print(f"   Round {rd['round']}: H1={rd['posterior_H1']:.2%}, Nodes={rd['graph_nodes']}")
        if len(rounds_data) > 10:
            print(f"   ... (+{len(rounds_data)-10} more rounds)")
        
        print("\n💡 Key Findings:")
        leading_id = result.leading_explanation
        if leading_id == "H1":
            print("   ✓ Attack hypothesis confirmed (T1059.001 PowerShell execution chain)")
        elif leading_id == "H2":
            print("⚠ Benign activity hypothesis favored (legitimate admin scripts?)")
        else:
            print(f"? Uncertain decision (leading ID: {leading_id})")
        
        print("\n🛡️ Recommended Actions:")
        if result.decision == "contain_escalate":
            print("   1. Isolate affected hosts immediately")
            print("   2. Escalate to incident response team")
            print("   3. Preserve forensics evidence")
            print("   4. Block identified C2 indicators")
        elif result.decision == "dismiss":
            print("   1. Document false positive")
            print("   2. Update detection rules")
            print("   3. Continue monitoring")
        
        print("\n" + "=" * 80)
        print("✅ LOCK LOOP TEST COMPLETED SUCCESSFULLY!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n❌ Result building failed: {e}")
        import traceback
        traceback.print_exc()
        return


if __name__ == "__main__":
    main()
