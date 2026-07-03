"""Step 3 ②-phase tests against soar_mcp_env registered scenarios."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step3_veto_phase import (
    ROOT_CAUSE_REACH_OPERATORS,
    run_veto_phase_step,
)
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_veto_phase_structure(scenario_id: str, prior_manager):
    result = run_veto_phase_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    assert result.pool_size_after >= 1


def test_pipeline_18_root_cause_reachability(prior_manager):
    result = run_veto_phase_step("pipeline_18", prior_manager=prior_manager)
    rc = next(c for c in result.checks if c.id == "gt_root_cause_reachability")
    assert rc.status == "pass"
    assert result.root_cause_entity == "WS-USER-01"
    assert result.root_cause_technique == "T1566.001"
    ops = {p.operator for p in result.probes_after}
    assert ops & ROOT_CAUSE_REACH_OPERATORS
    assert result.pool_size_before == result.pool_size_after


def test_veto_phase_ledgers_readonly(prior_manager):
    result = run_veto_phase_step("apt_5host", prior_manager=prior_manager)
    readonly = [c for c in result.checks if c.id.startswith("v_") and c.id.endswith("_readonly")]
    assert all(c.status == "pass" for c in readonly)


def test_multipath_external_root_reachability(prior_manager):
    result = run_veto_phase_step("multipath_12host", prior_manager=prior_manager)
    rc = next(c for c in result.checks if c.id == "gt_root_cause_reachability")
    assert rc.status == "pass"
    assert result.root_cause_entity == "external"
