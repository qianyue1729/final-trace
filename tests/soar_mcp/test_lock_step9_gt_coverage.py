"""Step 9 GT attack_edge_refs coverage tests."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step9_gt_coverage import (
    SCENARIO_GT_TOTALS,
    run_all_coverage,
    run_gt_coverage_step,
)
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_gt_coverage_structure(scenario_id: str, prior_manager):
    result = run_gt_coverage_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    assert result.gt_total == SCENARIO_GT_TOTALS[scenario_id]
    assert result.hits_count + result.misses_count == result.gt_total
    assert len(result.ref_records) == result.gt_total
    assert result.coverage_pct == round(100.0 * result.hits_count / result.gt_total, 2)


def test_pipeline_18_gt_total_18(prior_manager):
    result = run_gt_coverage_step("pipeline_18", prior_manager=prior_manager)
    assert result.gt_total == 18
    assert result.hits_count >= 1
    root_host = next(c for c in result.checks if c.id == "gt_root_host")
    assert root_host.status == "pass"


def test_extended_mode_more_rounds_pipeline_18(prior_manager):
    std = run_gt_coverage_step("pipeline_18", prior_manager=prior_manager)
    ext = run_gt_coverage_step("pipeline_18", prior_manager=prior_manager, extend_after_root=True)
    assert ext.mode == "extended"
    assert ext.rounds_used >= std.rounds_used
    assert ext.hits_count >= std.hits_count


def test_summary_all_scenarios(prior_manager):
    results = run_all_coverage(prior_manager=prior_manager)
    assert len(results) == 3
    totals = sum(r.gt_total for r in results)
    assert totals == 18 + 25 + 31
    for r in results:
        assert r.gt_total == SCENARIO_GT_TOTALS[r.scenario_id]
