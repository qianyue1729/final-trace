"""Step 5 C-phase tests against soar_mcp_env registered scenarios."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step5_c_phase import run_c_phase_step
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_c_phase_structure(scenario_id: str, prior_manager):
    result = run_c_phase_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    assert result.raw_fanout_count > 0
    assert result.probes_used == result.chosen_count


def test_pipeline_18_c_phase_mcp_fanout(prior_manager):
    result = run_c_phase_step("pipeline_18", prior_manager=prior_manager)
    assert result.raw_fanout_count >= 5
    assert sum(result.routed_counts.values()) >= max(1, int(result.raw_fanout_count * 0.85))
    progress = next(c for c in result.checks if c.id == "gt_root_cause_progress")
    assert progress.status in ("pass", "warn")


def test_apt_5host_hits_ground_truth_attack(prior_manager):
    result = run_c_phase_step("apt_5host", prior_manager=prior_manager)
    gt = next(c for c in result.checks if c.id == "gt_attack_ref_in_routed")
    assert gt.status == "pass"
    assert result.attack_ref_hits
    progress = next(c for c in result.checks if c.id == "gt_root_cause_progress")
    assert progress.status == "pass"


def test_c_phase_without_time_align_returns_empty_raw(prior_manager):
    result = run_c_phase_step("pipeline_18", prior_manager=prior_manager, align_time_to_alert=False)
    raw_check = next(c for c in result.checks if c.id == "c_raw_fanout_non_empty")
    # Without time alignment, raw may be 0 or small (depending on initial cursor)
    assert raw_check.status in ("skip", "pass")


def test_multipath_c_phase_attack_refs(prior_manager):
    result = run_c_phase_step("multipath_12host", prior_manager=prior_manager)
    assert len(result.attack_ref_hits) >= 1
    assert result.probes_used == result.chosen_count
