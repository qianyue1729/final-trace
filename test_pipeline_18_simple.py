#!/usr/bin/env python3
"""Simple pipeline_18 scenario validation."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

print("="*70)
print("WAZUH REAL SCENARIO TEST - Pipeline_18")
print("="*70)

try:
    from trace_agent.eval.soar_integration_runner import load_scenario
    print("\n[OK] Module imports successful")
    
    # Load scenario
    print("\nLoading scenario pipeline_18...")
    scenario_data, spec = load_scenario("pipeline_18")
    print(f"[OK] Scenario loaded: {spec.get('name', 'N/A')}")
    
    # Check stats
    events_dict = scenario_data.get("events", {})
    total_events = sum(len(ev_list) for ev_list in events_dict.values())
    gt_refs = scenario_data.get("ground_truth", {}).get("attack_edge_refs", [])
    
    print(f"\nScenario Statistics:")
    print(f"  • Total events: {total_events}")
    print(f"  • Ground truth edges: {len(gt_refs)}")
    print(f"  • Tags: {', '.join(spec.get('tags', []))}")
    
    # Show first few hosts
    print(f"\nSample Hosts:")
    host_list = list(events_dict.keys())[:5]
    for key in host_list:
        print(f"  • {key}: {len(events_dict[key])} events")
    
    print("\n✅ ALL CHECKS PASSED - Ready for full LOCK loop test")
    print("="*70)
    
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
