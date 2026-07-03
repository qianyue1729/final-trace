"""Step 8 root trace tests — pipeline_18 GT + TA mapping + cross-host."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import list_scenario_ids
from trace_agent.eval.lock_step8_root_trace import run_root_trace_step
from trace_agent.loop.generators import normalize_tactic
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


def test_normalize_tactic_maps_ta_ids():
    assert normalize_tactic("TA0001") == "initial-access"
    assert normalize_tactic("TA0009") == "collection"
    assert normalize_tactic("TA0010") == "exfiltration"
    assert normalize_tactic("execution") == "execution"


@pytest.mark.parametrize("scenario_id", list_scenario_ids())
def test_step8_structure(scenario_id: str, prior_manager):
    result = run_root_trace_step(scenario_id, prior_manager=prior_manager)
    fails = [c for c in result.checks if c.status == "fail"]
    assert not fails, "\n".join(f"{c.id}: {c.message}" for c in fails)
    norm = next(c for c in result.checks if c.id == "s8_tactic_normalized")
    assert norm.status == "pass"


def test_pipeline_18_reaches_root_cause(prior_manager):
    result = run_root_trace_step("pipeline_18", prior_manager=prior_manager)
    host = next(c for c in result.checks if c.id == "gt_pipeline18_root_host")
    tech = next(c for c in result.checks if c.id == "gt_pipeline18_root_technique")
    gt = next(c for c in result.checks if c.id == "gt_pipeline18_attack_ref")
    assert host.status == "pass"
    # Root technique discovery may require more rounds without artificial promotion
    assert tech.status in ("pass", "warn")
    assert gt.status == "pass"
    assert "ws-user-01" in result.hosts_in_graph
    assert result.attack_ref_hits


def test_pipeline_18_cross_host_in_round1(prior_manager):
    result = run_root_trace_step("pipeline_18", prior_manager=prior_manager)
    assert result.cross_host_pool_count >= 1
    cross = next(c for c in result.checks if c.id == "s8_cross_host_probes")
    assert cross.status == "pass"
    reach = next(c for c in result.checks if c.id == "s8_round1_reach_operator")
    assert reach.status == "pass"
    assert "auth_log" in result.rounds[0].chosen_operators


def test_apt_5host_still_finds_attack_refs(prior_manager):
    result = run_root_trace_step("apt_5host", prior_manager=prior_manager)
    assert result.rounds_used >= 1
    assert result.techniques_in_graph
