"""Runtime acceptance tests — real prior JSON → DecisionLedger.seed."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def ledger():
    bundle = load_prior_bundle()
    prior = PriorManager(bundle)
    return DecisionLedger(prior)


def test_seed_powershell_real_prior(ledger):
    alert = AlertEvent(
        technique_id="T1059.001",
        tactic="execution",
        platform="windows",
        log_source="process_creation",
        anomaly_score=0.85,
    )

    seed = ledger.seed(alert)

    assert 1 <= len(seed.explanations) <= 6
    assert seed.branch_null_anchor.benign > 0
    assert seed.branch_null_anchor.oos > 0
    assert seed.loss_baseline["LAMBDA_MISS"] > seed.loss_baseline["LAMBDA_OVER"]
    assert isinstance(seed.score_v3_initial_scores, dict)
    assert len(seed.score_v3_initial_scores) == len(seed.explanations)

    all_sources = [
        s["log_source"] for e in seed.explanations for s in e.recommended_log_sources
    ]

    assert any(
        "process" in s or "powershell" in s or "script" in s for s in all_sources
    )


def test_seed_linux_gtfobins_real_prior(ledger):
    alert = AlertEvent(
        technique_id="T1059.004",
        tactic="execution",
        platform="linux",
        log_source="auditd",
        anomaly_score=0.75,
    )

    seed = ledger.seed(alert)

    assert 1 <= len(seed.explanations) <= 6
    assert seed.branch_null_anchor.benign > 0
    assert seed.branch_null_anchor.oos > 0

    has_gtfobins = any(edge.support.get("gtfobins_dual_use") for edge in seed.contested_edges)

    has_linux_log_source = any(
        "auditd" in s["log_source"] or "process" in s["log_source"]
        for e in seed.explanations
        for s in e.recommended_log_sources
    )

    assert has_gtfobins or seed.branch_null_anchor.benign >= 0.25
    assert has_linux_log_source


def test_seed_smb_lateral_movement_real_prior(ledger):
    alert = AlertEvent(
        technique_id="T1021.002",
        tactic="lateral-movement",
        platform="windows",
        log_source="network_connection",
        anomaly_score=0.90,
    )

    seed = ledger.seed(alert)

    assert 1 <= len(seed.explanations) <= 6
    assert seed.branch_null_anchor.oos > 0
    assert seed.loss_baseline["LAMBDA_OOS"] > 0

    has_flow_support = any(
        e.support.get("l1_attack_flow_edges", 0) > 0
        or e.support.get("l2_attack_flow_edges", 0) > 0
        or e.support.get("flow_backed", False)
        for e in seed.explanations
    )

    assert has_flow_support or len(seed.contested_edges) > 0


def test_prior_manager_loads_real_products(ledger):
    prior = ledger.prior
    node = prior.technique_node("T1059.001")
    assert node is not None
    assert node.get("sigma_rules")
    preds = prior.predecessor_tactics("execution", top_k=3)
    assert preds
    assert any(p.get("support") for p in preds)
