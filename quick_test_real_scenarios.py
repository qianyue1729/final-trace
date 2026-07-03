#!/usr/bin/env python3
"""Quick test to verify real Wazuh scenario data is accessible."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "src"))

from trace_agent.eval.soar_integration_runner import load_scenario

print("=" * 70)
print("REAL WAZUH SCENARIO DATA VALIDATION TEST")
print("=" * 70)
print()

scenarios = ["pipeline_18", "apt_5host", "multipath_12host"]

for sid in scenarios:
    print(f"\n📦 Testing scenario: {sid}")
    print("-" * 70)
    
    try:
        # Load scenario from soar_mcp_env
        scenario_data, spec = load_scenario(sid)
        
        # Basic validation
        events_count = len(scenario_data.get("events", {}))
        ground_truth_refs = scenario_data.get("ground_truth", {}).get("attack_edge_refs", [])
        gt_total = len(ground_truth_refs)
        
        print(f"✅ Successfully loaded!")
        print(f"   • Total events: {events_count}")
        print(f"   • Ground truth edges: {gt_total}")
        print(f"   • Scenario name: {spec.get('name', 'N/A')}")
        print(f"   • Tags: {', '.join(spec.get('tags', []))}")
        
        # Show entry event if available
        entry_event_ref = spec.get("entry_event_ref", "evt_001")
        all_events = list(scenario_data.get("events", {}).values())
        entry_events = [e for e_list in all_events for e in e_list 
                        if e.get("raw_log_ref") == entry_event_ref]
        
        if entry_events:
            entry_ev = entry_events[0]
            print(f"   • Entry event: {entry_event_ref} @ {entry_ev.get('target', 'N/A')}")
        
        # Sample a few events
        sample_hosts = set()
        sample_techniques = set()
        for ev_list in scenario_data.get("events", {}).values():
            for ev in ev_list[:2]:  # Just first 2 per host
                if ev.get("target"):
                    sample_hosts.add(ev["target"])
                if ev.get("technique"):
                    sample_techniques.add(ev["technique"])
        
        print(f"   • Unique hosts sampled: {len(sample_hosts)}")
        print(f"   • Techniques seen: {sorted(sample_techniques)[:8]}")
        
        print(f"\n  ✅ {sid} DATA OK - Ready for LOCK loop testing\n")
        
    except Exception as e:
        print(f"❌ Error loading {sid}: {e}")
        import traceback
        traceback.print_exc()

print("\n" + "=" * 70)
print("Real scenario data validation COMPLETE!")
print("=" * 70)
print()
print("Next steps:")
print("  1. Wait for Wazuh MCP service to recover")
print("  2. Run: python test_wazuh_real_scenario.py --scenario pipeline_18")
print("  3. Or use local demo: cd demo && python server.py")
print()
