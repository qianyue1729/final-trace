"""Quick test: inspect the seed and traced session output."""
import sys
sys.path.insert(0, "src")

from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.prior_v2 import PriorManager

pm = PriorManager(load_prior_bundle())
alert = AlertEvent(
    technique_id="T1059.001",
    tactic="execution",
    asset_id="db-prod-01",
    timestamp=1700000120.0,
    log_source="sysmon-db-prod-01",
    attributes={"target": "db-prod-01"},
)
seed = DecisionLedger(pm).seed(alert)
for e in seed.explanations:
    print(f"{e.id}: {e.title}")
    print(f"  prior={e.prior_probability:.3f} stage={e.stage}")
    sources = [s.get("log_source") for s in e.recommended_log_sources[:5]]
    print(f"  recommended_log_sources: {sources}")
print(f"null_anchor: benign={seed.branch_null_anchor.benign} oos={seed.branch_null_anchor.oos}")
print(f"contested_edges: {len(seed.contested_edges)}")
