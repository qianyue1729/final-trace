"""P0 evidence lifecycle ablation — fact vs attribution, commit-on-confirm."""
from __future__ import annotations

import pytest

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step2_l_phase import _setup_orchestrator
from trace_agent.eval.lock_step5_c_phase import _align_executor_to_alert
from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.loop.probe import Probe
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def prior_manager():
    return PriorManager(load_prior_bundle())


def _ws_auth_probe() -> Probe:
    return Probe(
        id="test-ws-auth",
        target="WS-USER-01",
        target_type="host",
        operator="auth_log",
        tactic="initial-access",
        source="test",
    )


def _db_network_probe() -> Probe:
    return Probe(
        id="test-db-net",
        target="DB-PROD-01",
        target_type="host",
        operator="network_flow",
        tactic="exfiltration",
        source="test",
    )


def _gt_ws_refs(scenario_data: dict) -> list[str]:
    gt = set((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    return sorted(ref for ref in gt if "WS-USER-01" in ref or ref.endswith(("001", "002", "003", "004", "005", "006")))


def _is_gt_event(event: dict, scenario_data: dict) -> bool:
    gt = set((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    return str(event.get("id") or "") in gt


def test_mixed_fanout_uses_observable_graph_eligibility(prior_manager):
    """GT membership alone must not promote or commit WS evidence."""
    orch, scenario_data, triage = _setup_orchestrator("pipeline_18", prior_manager)
    _, registry_spec = load_scenario("pipeline_18")
    _align_executor_to_alert(orch, scenario_data, registry_spec)

    chosen = [_db_network_probe(), _ws_auth_probe()]
    ingest = orch._c_phase(chosen)

    ws_events = [
        e for e in ingest.all_events
        if (e.get("attributes") or {}).get("host_uid") == "WS-USER-01"
        and _is_gt_event(e, scenario_data)
    ]
    assert ws_events, "auth_log@WS should return attack events"

    graph_ws = [e for e in ingest.graph_eligible if e in ws_events]
    assert all(event.get("_l1_attachable") for event in graph_ws)
    assert all(
        event.get("_l2_trust_tier") in ("medium", "high", "forge_resistant")
        for event in graph_ws
    )

    # C 拍语义：已返回 ref 即提交（防止逐轮重复返回阻塞渐进发现）；
    # 关键不变量是 WEAK 攻击事实必须已进 graph_eligible（上面已断言），
    # 且 K 拍后落图（下面断言）——而非延迟提交。
    ws_ids = {e["id"] for e in ws_events}

    stop = orch._k_phase(chosen, ingest)
    assert stop.reason in ("continue", "robust", "voi_floor", "budget")

    graph_ids = {n.id for n in orch.graph._nodes.values()}
    hits = ws_ids & graph_ids
    assert hits == {event["id"] for event in graph_ws}

    committed_after = getattr(orch.executor, "_returned_committed", set())
    assert hits <= committed_after


def test_ungraphed_weak_attack_refetchable(prior_manager):
    """Case B: returned but not graph-eligible refs remain refetchable until commit."""
    orch, scenario_data, triage = _setup_orchestrator("pipeline_18", prior_manager)
    _, registry_spec = load_scenario("pipeline_18")
    _align_executor_to_alert(orch, scenario_data, registry_spec)

    probe = _ws_auth_probe()
    first = orch._c_phase([probe])
    weak_only = [
        e for e in first.routed.get("WEAK", [])
        if _is_gt_event(e, scenario_data) and not e.get("_graph_eligible")
    ]
    if not weak_only:
        pytest.skip("no ungraph-eligible weak attack in this draw")

    ref = weak_only[0]["id"]
    assert ref not in orch.executor._returned_committed

    second_raw = orch.executor.execute_fanout([probe])
    returned_ids = {e["id"] for e in second_raw}
    assert ref in returned_ids or orch.executor._returned_attempts.get(ref, 0) < 3


def test_pipeline_18_r1_k_materializes_only_graph_eligible(prior_manager):
    """K phase materializes C-phase eligibility without a GT recall quota."""
    orch, scenario_data, triage = _setup_orchestrator("pipeline_18", prior_manager)
    _, registry_spec = load_scenario("pipeline_18")
    _align_executor_to_alert(orch, scenario_data, registry_spec)

    chosen = [_db_network_probe(), _ws_auth_probe()]
    ingest = orch._c_phase(chosen)
    orch._k_phase(chosen, ingest)

    graph_ids = {n.id for n in orch.graph._nodes.values()}
    eligible_ids = {event["id"] for event in ingest.graph_eligible}
    assert eligible_ids <= graph_ids
