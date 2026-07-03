"""Quality gate and hard-veto safety tests."""
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.eval.quality_gates import run_quality_gates
from trace_agent.prior_v2 import PriorManager


def test_low_trust_source_cannot_hard_veto_attack_compatible_explanation():
    seed = DecisionLedger(PriorManager(load_prior_bundle())).seed(
        AlertEvent(
            "T1059.001",
            tactic="execution",
            platform="windows",
            log_source="file_system_timestamp",
            anomaly_score=0.2,
        )
    )
    qg = run_quality_gates(seed)
    assert qg["gates"]["hard_veto_safe"]
    assert qg["gates"]["max_prior_gate"]
    assert seed.branch_null_anchor.benign > 0


def test_semantic_firewall_blocks_sigma_causal():
    seed = DecisionLedger(PriorManager(load_prior_bundle())).seed(
        AlertEvent("T1059.001", tactic="execution", platform="windows", log_source="process_creation")
    )
    # poison one passport to simulate sigma-as-causal regression
    seed.explanations[0].support.setdefault("evidence_passport", {})["source_roles"] = {"sigma": "causal"}
    qg = run_quality_gates(seed)
    assert not qg["gates"]["semantic_firewall"]
