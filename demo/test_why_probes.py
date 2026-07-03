"""Debug: why only process_tree gets selected?"""
import sys
sys.path.insert(0, "src")
sys.path.insert(0, "demo")
from server import create_ransomware_scenario, create_demo_seed, BASE_TIME

from trace_agent.agents.orchestrator import DecisionOrchestrator, BudgetState
from trace_agent.decision.types import AlertEvent
from trace_agent.data_loader import load_prior_bundle
from trace_agent.loop.mock_executor import MockExecutor
from trace_agent.probe.voi_engine import voi
from trace_agent.prior_v2 import PriorManager

# Re-run session but trace probe selection details
import json

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
executor = MockExecutor(scenario, seed=42)

budget = BudgetState(
    total_rounds=5,
    total_probes=15,
    fanout_per_round=3,
    min_rounds_before_robust=2,
    min_rounds_after_root=2,
)

orch = DecisionOrchestrator(
    alert=alert,
    executor=executor,
    prior_manager=prior_manager,
    budget=budget,
    seed=seed,
)

orch._bootstrap()

# Run just R1 and check pool details
prev_stats = orch.graph.stats()
orch.budget.rounds_used += 1
pool = orch._l_phase(prev_stats)

print("=== R1 L-phase: Full candidate pool ===")
print(f"Pool size: {pool.size()}")
candidates = pool.peek()
# Count operators
from collections import Counter
ops = Counter(p.operator for p in candidates)
print(f"\nOperator distribution: {ops.most_common()}")
print(f"\nTarget distribution: {Counter(p.target for p in candidates).most_common()}")
print(f"\nTactic distribution: {Counter(getattr(p, 'tactic', '') for p in candidates).most_common()}")

print(f"\nFirst 20 candidates:")
for i, p in enumerate(candidates[:20]):
    print(f"  {i+1:>2}. op={p.operator:25s} target={p.target:25s} tactic={getattr(p,'tactic',''):20s} priority={p.priority_hint:.3f} src={p.source}")

# Now run O phase to see what gets selected and why
pool2 = orch._veto_phase(pool)
print(f"\n=== After VETO: {pool2.size()} candidates ===")
candidates_after_veto = pool2.peek()
ops2 = Counter(p.operator for p in candidates_after_veto)
print(f"Operator distribution after VETO: {ops2.most_common()}")

# Check which were vetoed
vetoed_ops = ops - ops2
print(f"Vetoed operators: {vetoed_ops}")

# Manually score some candidates
print(f"\n=== VOI scoring sample ===")
graph_stats = orch._compute_graph_stats()
sample = candidates_after_veto[:10]
for p in sample:
    try:
        probe_dict = orch._probe_to_dict(p)
        beta_dict = orch._beta_to_dict()
        calib_dict = orch._calib_to_dict()
        voi_result = voi(probe_dict, orch.ledger, beta_dict, calib_dict,
                        orch.loss, orch.trust, graph_stats=graph_stats)
        print(f"  op={p.operator:25s} target={p.target:25s} VOI={voi_result.voi_score:.4f} risk_now={voi_result.risk_now:.4f} expected_after={voi_result.expected_risk_after:.4f}")
    except Exception as e:
        print(f"  op={p.operator:25s} target={p.target:25s} ERROR: {e}")
