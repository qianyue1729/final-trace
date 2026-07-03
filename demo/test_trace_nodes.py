"""Trace actual nodes entering the graph — show their technique/tactic."""
import sys
sys.path.insert(0, "src")
sys.path.insert(0, "demo")
from server import create_ransomware_scenario, create_demo_seed, BASE_TIME, SmartMockExecutor

from trace_agent.agents.orchestrator import DecisionOrchestrator, BudgetState
from trace_agent.decision.types import AlertEvent
from trace_agent.data_loader import load_prior_bundle
from trace_agent.prior_v2 import PriorManager

bundle = load_prior_bundle()
prior_manager = PriorManager(bundle)

alert = AlertEvent(
    technique_id="T1059.001",
    tactic="execution",
    asset_id="db-prod-01",
    timestamp=BASE_TIME + 120,
    log_source="sysmon-db-prod-01",
    attributes={"target": "db-prod-01", "asset_id": "db-prod-01"},
)

seed = create_demo_seed(alert)
scenario = create_ransomware_scenario()
executor = SmartMockExecutor(scenario, primary_host="db-prod-01", seed=42)

budget = BudgetState(
    total_rounds=5, total_probes=15, fanout_per_round=3,
    min_rounds_before_robust=2, min_rounds_after_root=2,
)

orch = DecisionOrchestrator(
    alert=alert, executor=executor, prior_manager=prior_manager,
    budget=budget, seed=seed,
)

orch._bootstrap()
print("=== BOOTSTRAP ===")
print(f"Graph after bootstrap: {orch.graph.stats()}")
for nid, node in orch.graph._nodes.items():
    print(f"  {nid}: technique={node.technique} tactic={node.tactic} source={node.source} attrs={node.attributes}")

prev_stats = orch.graph.stats()
EXPECTED_TECHNIQUES = {"T1566.001", "T1059.001", "T1053.005", "T1021.001", "T1071.001", "T1486"}
found_techniques = {node.technique for node in orch.graph._nodes.values()}

for round_num in range(1, 6):
    orch.budget.rounds_used += 1
    print(f"\n{'='*60}")
    print(f"ROUND {round_num}")
    print(f"{'='*60}")

    # L phase
    pool = orch._l_phase(prev_stats)
    print(f"\n  [L] Pool size: {pool.size()}")

    # VETO
    pool2 = orch._veto_phase(pool)

    # O phase - capture chosen probes
    pre_probes = pool2.peek()
    chosen = orch._o_phase(pool2)
    print(f"\n  [O] Chosen probes ({len(chosen)}):")
    for p in chosen:
        print(f"      op={p.operator:25s} target={p.target:25s} tactic={getattr(p,'tactic','')}")

    if not chosen:
        print("  [!] No probes chosen - stopping")
        break

    # C phase - trace what enters graph
    prev_node_ids = set(orch.graph._nodes.keys())
    ingest_result = orch._c_phase(chosen)
    new_node_ids = set(orch.graph._nodes.keys()) - prev_node_ids

    confirmed = list(getattr(ingest_result, "confirmed", []))
    graph_eligible = list(getattr(ingest_result, "graph_eligible", []))

    print(f"\n  [C] Raw events: {len(getattr(ingest_result, 'raw_events', []) if hasattr(ingest_result, 'raw_events') else '?')}")
    print(f"      Confirmed: {len(confirmed)}")
    print(f"      Graph eligible: {len(graph_eligible)}")
    print(f"      New graph nodes: {len(new_node_ids)}")

    for nid in sorted(new_node_ids):
        node = orch.graph._nodes[nid]
        found_techniques.add(node.technique)
        print(f"        {nid}: technique={node.technique:12s} tactic={node.tactic:22s} source={node.source}")

    # K phase
    stop_decision = orch._k_phase(chosen, ingest_result)
    print(f"\n  [K] Leading={orch.ledger.leading()} margin={orch.ledger.margin():.4f} stop={stop_decision.reason}")

    prev_stats = orch.graph.stats()

    if stop_decision.should_stop:
        print(f"\n  >>> STOP: {stop_decision.reason}")
        break

# Final check
print(f"\n\n{'='*60}")
print("攻击链覆盖评估")
print(f"{'='*60}")
print(f"\n期望技术 (6): {sorted(EXPECTED_TECHNIQUES)}")
print(f"实际发现 ({len(found_techniques)}): {sorted(found_techniques)}")
missing = EXPECTED_TECHNIQUES - found_techniques
covered = EXPECTED_TECHNIQUES & found_techniques
print(f"\n已覆盖 ({len(covered)}/6): {sorted(covered)}")
if missing:
    print(f"缺失 ({len(missing)}/6): {sorted(missing)}")
else:
    print(f"\n★ 全部 6 个攻击链技术均已入图!")

# Also check tactics
all_tactics = {node.tactic for node in orch.graph._nodes.values()}
expected_tactics = {"initial-access", "execution", "persistence", "lateral-movement", "command-and-control", "impact"}
print(f"\n期望战术 (6): {sorted(expected_tactics)}")
print(f"实际战术 ({len(all_tactics)}): {sorted(all_tactics)}")
missing_tactics = expected_tactics - all_tactics
if missing_tactics:
    print(f"缺失战术: {sorted(missing_tactics)}")
else:
    print(f"\n★ 全部 6 个攻击链战术均已覆盖!")

print(f"\n最终图: {orch.graph.stats()}")
