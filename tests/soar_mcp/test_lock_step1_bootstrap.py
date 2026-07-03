"""Step 1 bootstrap tests against soar_mcp_env registered scenarios."""
from __future__ import annotations

import pytest

from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids, run_bootstrap_step


@pytest.fixture(scope="module")
def prior_manager():
    from trace_agent.data_loader import load_prior_bundle
    from trace_agent.prior_v2 import PriorManager

    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_bootstrap_step_structure(scenario_id: str, prior_manager):
    result = run_bootstrap_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)


def test_pipeline_18_db_prod_entry(prior_manager):
    """pipeline_18 入口为 DB-PROD-01 上的攻击边 evt_018（真实 MCP ground truth）。"""
    result = run_bootstrap_step("pipeline_18", prior_manager=prior_manager)
    assert result.triage.alert.asset_id.upper() == "DB-PROD-01"
    assert result.triage.alert.technique_id == "T1041"
    assert result.triage.entry_ref == "attack:idx_stress:evt_018"
    assert result.graph_stats["node_count"] >= 1
    assert result.ledger_snapshot["max_prior"] <= 0.55


def test_bootstrap_quality_gates(prior_manager):
    result = run_bootstrap_step("apt_5host", prior_manager=prior_manager)
    qg = next(c for c in result.checks if c.id == "quality_gates")
    assert qg.status == "pass"
