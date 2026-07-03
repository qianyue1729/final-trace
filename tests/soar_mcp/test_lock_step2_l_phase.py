"""Step 2 L-phase tests against soar_mcp_env registered scenarios."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import run_l_phase_step
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_l_phase_structure(scenario_id: str, prior_manager):
    result = run_l_phase_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    assert result.pool_size >= 1


def test_pipeline_18_l_phase_probes(prior_manager):
    result = run_l_phase_step("pipeline_18", prior_manager=prior_manager)
    assert result.pool_size >= 3
    assert result.prior_count >= 1
    assert result.gap_count >= 1
    assert "prior" in result.sources
    assert "rule_gap" in result.sources
    prior_targets = [p.target for p in result.probes if p.source == "prior"]
    assert any("DB-PROD-01" in t.upper() for t in prior_targets)


def test_l_phase_ledgers_readonly(prior_manager):
    result = run_l_phase_step("apt_5host", prior_manager=prior_manager)
    readonly = [c for c in result.checks if c.id.endswith("_readonly") or c.id == "l_no_probe_budget_consumed"]
    assert all(c.status == "pass" for c in readonly)
    assert result.budget_probes_used == 0


def test_l_phase_dedup_unique(prior_manager):
    result = run_l_phase_step("multipath_12host", prior_manager=prior_manager)
    keys = [p.dedup_key for p in result.probes]
    assert len(keys) == len(set(keys))
