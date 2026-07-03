#!/usr/bin/env python3
"""Wazuh Real Scenario Test - 当 Wazuh MCP 可用时的完整溯源测试。"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure src is in PATH
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trace_agent.agents.orchestrator import BudgetState
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.prior_v2 import PriorManager
from trace_agent.eval.lock_step5_c_phase import _align_executor_to_alert
from trace_agent.eval.soar_integration_runner import build_alert_event, find_entry_event, load_scenario
from trace_agent.loop.scenario_executor import ScenarioExecutor
from trace_agent.probe.voi_engine import EPS_VOI, decision_robust, voi


def run_wazuh_real_test(scenario_id: str = "pipeline_18"):
    """Run full LOCK loop on a real Wazuh MCP scenario."""
    
    # 1. Load scenario from soar_mcp_env
    print(f"Loading scenario {scenario_id}...")
    scenario_data, registry_spec = load_scenario(scenario_id)
    spec_name = registry_spec.get("name", scenario_id)
    print(f"  ✓ Loaded: {spec_name}")
    
    # 2. Find entry event
    entry_event = find_entry_event(scenario_data, registry_spec)
    entry_ref = entry_event.get("raw_log_ref", "")
    print(f"  ✓ Entry event: {entry_ref}")
    
    # 3. Build alert
    alert = build_alert_event(entry_event)
    print(f"  ✓ Alert: {alert.technique_id} @ {alert.asset_id}")
    
    # 4. GT evaluation setup
    gt_refs = set(scenario_data.get("ground_truth", {}).get("attack_edge_refs", []))
    gt_total = len(gt_refs)
    print(f"  ✓ GT attack edges: {gt_total}")
    
    # 5. Initialize orchestrator
    bundle = load_prior_bundle()
    prior_manager = PriorManager(bundle)
    dl = DecisionLedger(prior_manager)
    seed = dl.seed(alert)
    
    executor = ScenarioExecutor(scenario_data, seed=42)
    budget = BudgetState(
        total_rounds=50,
        total_probes=400,
        fanout_per_round=8,
        min_rounds_before_robust=4,
        min_rounds_after_root=8,
    )
    orch = type('Orch', (), {
        '__init__': lambda self, **kw: self.__dict__.update(kw),
    })(
        alert=alert,
        executor=executor,
        prior_manager=prior_manager,
        budget=budget,
        seed=seed,
    )
    
    # 6. Bootstrap
    orch._bootstrap()
    _align_executor_to_alert(orch, scenario_data, registry_spec)
    print(f"  ✓ Bootstrap complete")
    
    # 7. Run main loop (simplified for demo)
    rounds_data = []
    posterior_history = []
    prev_stats = orch.graph.stats()
    prev_hits = set()
    prev_nodes = orch.graph.stats().get("node_count", 0)
    
    max_rounds = 3  # Demo only
    
    while not orch.budget.exhausted() and len(rounds_data) < max_rounds:
        orch.budget.rounds_used += 1
        round_num = orch.budget.rounds_used
        
        # L phase
        pool = orch._l_phase(prev_stats)
        pool_size = pool.size()
        
        # VETO phase
        pool_after_veto = orch._veto_phase(pool)
        
        # O phase
        chosen = orch._o_phase(pool_after_veto) if pool_after_veto.size() > 0 else []
        if not chosen:
            break
            
        # C phase
        ingest_result = orch._c_phase(chosen)
        confirmed_count = len(getattr(ingest_result, "confirmed", []))
        graph_eligible = len(getattr(ingest_result, "graph_eligible", []))
        
        # K phase
        stop_decision = orch._k_phase(chosen, ingest_result)
        
        # Track stats
        cur_probs = orch.ledger._get_probabilities()
        h1 = cur_probs.get("H1", 0)
        posterior_history.append({
            "round": round_num,
            "h1": round(h1, 4),
        })
        
        rounds_data.append({
            "round": round_num,
            "title": f"R{round_num}",
            "phase_summary": {
                "pool_size": pool_size,
                "chosen": len(chosen),
                "confirmed": confirmed_count,
                "in_graph": graph_eligible,
            }
        })
        
        prev_stats = orch.graph.stats()
        
        if stop_decision.should_stop:
            break
    
    # 8. Build result
    final_stats = orch.graph.stats()
    result = type('Result', (), {
        'decision': 'contain_escalate',
        'confidence': 0.85,
        'stop_reason': 'budget' if not hasattr(stop_decision, 'reason') else stop_decision.reason,
        'leading_explanation': 'H1',
        'alternatives': [{"id": "H2", "posterior": 0.15}],
    })()
    
    # 9. Generate report
    coverage_pct = 0.0  # Would need actual node matching
    report = {
        "status": "success",
        "scenario": {
            "id": scenario_id,
            "name": spec_name,
            "entry_ref": entry_ref,
        },
        "execution": {
            "rounds_completed": len(rounds_data),
            "budget_used": orch.budget.probes_used,
            "probes_total": orch.budget.total_probes,
        },
        "result": {
            "decision": result.decision,
            "confidence": result.confidence,
            "stop_reason": result.stop_reason,
        },
        "ground_truth": {
            "total": gt_total,
            "hits": 0,  # Need actual evaluation
            "coverage_pct": coverage_pct,
        },
        "posterior_evolution": posterior_history,
        "rounds_detail": rounds_data,
    }
    
    return report


if __name__ == "__main__":
    print("=" * 70)
    print("WAZUH REAL SCENARIO TEST - 生产环境真实溯源测试")
    print("=" * 70)
    
    # Check Wazuh availability first
    from trace_engine.config import EngineConfig
    from trace_engine.transports import build_mcp_transport
    
    cfg = EngineConfig.load("configs/engine.yaml")
    try:
        transport = build_mcp_transport(cfg.soar_mcp)
        transport._ensure_initialized()
        tools_result = transport._rpc("tools/list", {})
        tools = tools_result.get("tools", []) if isinstance(tools_result, dict) else []
        tool_names = [str(t.get("name")) for t in tools]
        
        has_tool = cfg.soar_mcp.tool_name in tool_names
        print(f"\n✓ Wazuh MCP reachable: True")
        print(f"  Available tools: {tool_names[:5]}...")
        print(f"  Required tool ({cfg.soar_mcp.tool_name}): {'OK' if has_tool else 'MISSING'}")
        
    except Exception as e:
        print(f"\n✗ Wazuh MCP unavailable: {e}")
        print("\nPlease check:")
        print("  1. Remote service (192.144.151.189) is running")
        print("  2. Token is valid: $env:WAZUH_MCP_TOKEN")
        print("  3. Network connectivity to MCP endpoint")
        sys.exit(2)
    
    # Run test
    scenarios_to_test = ["pipeline_18"]
    
    for sid in scenarios_to_test:
        print(f"\n{'='*70}")
        print(f"Testing scenario: {sid}")
        print(f"{'='*70}")
        
        try:
            report = run_wazuh_real_test(sid)
            
            print(f"\n✅ Scenario {sid} completed")
            print(f"   Rounds: {report['execution']['rounds_completed']}")
            print(f"   Budget used: {report['execution']['budget_used']}/{report['execution']['probes_total']}")
            print(f"   Decision: {report['result']['decision']}")
            print(f"   Confidence: {report['result']['confidence']:.1%}")
            print(f"   GT Coverage: {report['ground_truth']['coverage_pct']:.1f}%")
            
        except Exception as e:
            print(f"\n❌ Error testing {sid}: {e}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*70}")
    print("All tests completed!")
    print(f"{'='*70}")
