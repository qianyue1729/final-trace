"""Step 7 full LOCK loop tests against soar_mcp_env registered scenarios."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step7_full_loop import run_full_loop_step
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_full_loop_structure(scenario_id: str, prior_manager):
    result = run_full_loop_step(scenario_id, prior_manager=prior_manager, max_rounds=10)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    assert result.rounds_used >= 1
    assert result.probes_used > 0
    assert len(result.rounds) == result.rounds_used


def test_pipeline_18_full_loop_completes(prior_manager):
    result = run_full_loop_step("pipeline_18", prior_manager=prior_manager, max_rounds=10)
    assert result.stop_reason in ("robust", "budget", "voi_floor", "no_probes")
    assert result.node_count_final > 1
    progress = next(c for c in result.checks if c.id == "gt_root_cause_progress")
    assert progress.status in ("pass", "warn")


def test_apt_5host_multi_round_investigation(prior_manager):
    result = run_full_loop_step("apt_5host", prior_manager=prior_manager, max_rounds=10)
    assert result.rounds_used >= 1
    assert len(result.attack_ref_hits) >= 1
    gt = next(c for c in result.checks if c.id == "gt_attack_refs_in_graph")
    assert gt.status == "pass"
    assert "ws-user-01" in result.hosts_in_graph


def test_multipath_full_loop_gt_hits(prior_manager):
    result = run_full_loop_step("multipath_12host", prior_manager=prior_manager, max_rounds=10)
    assert len(result.attack_ref_hits) >= 1
    assert result.rounds_used >= 1
    assert result.rounds[-1].beta_keys >= 1


def test_full_loop_nodes_monotonic(prior_manager):
    result = run_full_loop_step("apt_5host", prior_manager=prior_manager, max_rounds=10)
    if len(result.rounds) >= 2:
        nodes = [r.node_count for r in result.rounds]
        assert nodes == sorted(nodes)


def test_full_loop_without_time_align(prior_manager):
    result = run_full_loop_step(
        "pipeline_18",
        prior_manager=prior_manager,
        align_time_to_alert=False,
        max_rounds=3,
    )
    graph_check = next(c for c in result.checks if c.id == "loop_graph_grew")
    assert graph_check.status == "skip"
