"""Step 6 K-phase tests against soar_mcp_env registered scenarios."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step6_k_phase import run_k_phase_step
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_k_phase_structure(scenario_id: str, prior_manager):
    result = run_k_phase_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    assert result.beta_keys_after >= 1 or result.chosen_count == 0
    assert result.stop_reason in ("budget", "voi_floor", "robust", "continue")


def test_pipeline_18_k_phase_learning(prior_manager):
    result = run_k_phase_step("pipeline_18", prior_manager=prior_manager)
    assert result.valid_confirmed_count >= 1
    assert result.node_count_after > result.node_count_before
    assert abs(result.margin_after - result.margin_before) > 1e-6
    assert len(result.beta_snapshots) == result.chosen_count
    assert all(s.observations >= 1 for s in result.beta_snapshots)
    assert result.stop_reason in ("robust", "continue", "voi_floor")
    # At least one technique should be in graph after K-phase learning
    assert len(result.techniques_in_graph) >= 1


def test_apt_5host_k_phase_gt_in_graph(prior_manager):
    result = run_k_phase_step("apt_5host", prior_manager=prior_manager)
    gt_graph = next(c for c in result.checks if c.id == "gt_attack_ref_in_graph")
    assert gt_graph.status == "pass"
    assert result.attack_refs_in_graph
    assert any(t.startswith("T1566") for t in result.techniques_in_graph)
    assert result.stop_reason in ("continue", "robust", "voi_floor")
    hits = [s for s in result.beta_snapshots if s.hit]
    assert hits
    assert all(s.observations >= 1 for s in result.beta_snapshots)


def test_multipath_k_phase_beta_and_graph(prior_manager):
    result = run_k_phase_step("multipath_12host", prior_manager=prior_manager)
    assert result.node_count_after >= 5
    assert result.beta_keys_after >= 1
    assert len(result.attack_refs_in_graph) >= 1
    beta_check = next(c for c in result.checks if c.id == "k_beta_alpha_beta_semantics")
    assert beta_check.status == "pass"


def test_k_phase_without_time_align_skips_graph(prior_manager):
    result = run_k_phase_step("pipeline_18", prior_manager=prior_manager, align_time_to_alert=False)
    graph_check = next(c for c in result.checks if c.id == "k_graph_adds_confirmed")
    assert graph_check.status == "skip"
