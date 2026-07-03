"""Step 4 O-phase tests against soar_mcp_env registered scenarios."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step4_o_phase import run_o_phase_step
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_o_phase_structure(scenario_id: str, prior_manager):
    result = run_o_phase_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    assert 0 < result.chosen_count <= result.fanout_budget


def test_pipeline_18_o_phase_voi_and_reachability(prior_manager):
    result = run_o_phase_step("pipeline_18", prior_manager=prior_manager)
    # 填满扇出槽（fanout=8），池排空，O 拍只读不计费
    assert 0 < result.chosen_count <= result.fanout_budget
    assert result.pool_size_after == 0
    assert result.budget_probes_used == 0
    rc = next(c for c in result.checks if c.id == "gt_root_cause_in_chosen")
    assert rc.status == "pass"
    ops = {c.operator for c in result.chosen}
    assert "auth_log" in ops


def test_o_phase_voi_monotonic(prior_manager):
    result = run_o_phase_step("apt_5host", prior_manager=prior_manager)
    voi_check = next(c for c in result.checks if c.id == "o_voi_sorted")
    assert voi_check.status == "pass"
    readonly = [c for c in result.checks if c.id.endswith("_readonly") or c.id == "o_no_c_budget_charge"]
    assert all(c.status == "pass" for c in readonly)


def test_multipath_auth_log_ranked_first(prior_manager):
    result = run_o_phase_step("multipath_12host", prior_manager=prior_manager)
    ops = {c.operator for c in result.chosen}
    assert "auth_log" in ops
    assert 0 < result.chosen_count <= result.fanout_budget
