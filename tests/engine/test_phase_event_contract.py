from __future__ import annotations

from types import SimpleNamespace

from trace_agent.agents.lock_session import BudgetState, LOCKSession
from trace_agent.agents.progress_protocol import EventKind, Phase, build_phase_event
from trace_agent.decision.types import AlertEvent, Explanation, NullAnchor, SeedPayload
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.loop.probe import Probe
from trace_agent.phases.k_phase import KPhaseExecutor
from trace_agent.phases.veto_phase import VetoPhaseExecutor


def _seed() -> SeedPayload:
    alert = AlertEvent(
        technique_id="T1059.001",
        tactic="execution",
        asset_id="host-a",
    )
    explanations = [
        Explanation(
            id="H1",
            title="attack path",
            current_technique="T1059.001",
            stage="execution",
            lifecycle_template=None,
            predecessor_tactics=[],
            technique_context=[],
            raw_score=0.7,
            prior_probability=0.6,
            features={},
            support={"type": "test"},
            recommended_log_sources=[],
            caveats=[],
        )
    ]
    return SeedPayload(
        alert=alert,
        explanations=explanations,
        branch_null_anchor=NullAnchor(benign=0.25, oos=0.15, reasons=["test"]),
        contested_edges=[],
        lifecycle_template_candidates=[],
        score_v3_initial_scores={"H1": 0.6},
        loss_baseline={"lambda_miss": 10.0, "lambda_over": 2.0, "lambda_oos": 4.0},
        evidence_trust_defaults={},
        prior_manifest={},
    )


def _session() -> LOCKSession:
    seed = _seed()
    session = LOCKSession.from_seed(
        alert=seed.alert,
        budget=BudgetState(total_rounds=3, total_probes=10, fanout_per_round=2),
        config_dict={"seed": seed},
    )
    session.round = 1
    session.budget.rounds_used = 1
    session._scenario_hosts = ["host-a"]
    return session


def test_k_phase_event_has_decision_obligation_and_graph_fields():
    session = _session()
    probe = Probe(
        id="probe-1",
        target="host-a",
        target_type="host",
        operator="process_tree",
        tactic="execution",
        source="test",
    )
    session.data["chosen"] = [probe]
    session.data["ingest_result"] = SimpleNamespace(
        graph_eligible=[],
        confirmed=[],
        routed={},
        all_events=[],
    )

    result = KPhaseExecutor().execute(session)
    event = build_phase_event(Phase.K, EventKind.PHASE_END, result, session)
    payload = event.to_stream_dict()

    assert payload["explanations"]
    assert any(item["eid"] == "__null__" for item in payload["explanations"])
    assert isinstance(payload["margin"], float)
    assert isinstance(payload["entropy"], float)
    assert isinstance(payload["beta_updates"], list)
    assert isinstance(payload["obligations_open"], int)
    assert isinstance(payload["obligations_discharged"], int)
    assert isinstance(payload["obligations_overdue"], int)
    assert isinstance(payload["graph_node_count"], int)
    assert isinstance(payload["graph_edge_count"], int)
    assert isinstance(payload["graph_nodes"], list)
    assert isinstance(payload["graph_edges"], list)
    assert isinstance(payload["graph_truncated"], bool)
    for node in payload["graph_nodes"]:
        assert {"id", "technique", "tactic", "host", "timestamp", "attributed"} <= set(node)
    for edge in payload["graph_edges"]:
        assert {"source", "target", "relation"} <= set(edge)


def test_veto_phase_event_reasons_is_mapping():
    session = _session()
    pool = CandidatePool()
    pool.add([
        Probe(
            id="probe-unknown-host",
            target="host-b",
            target_type="host",
            operator="process_tree",
            tactic="execution",
            source="test",
        )
    ])
    session.data["pool"] = pool

    result = VetoPhaseExecutor().execute(session)
    event = build_phase_event(Phase.VETO, EventKind.PHASE_END, result, session)
    payload = event.to_stream_dict()

    assert isinstance(payload["veto_reasons"], dict)
    assert payload["veto_reasons"].get("unknown_host") == 1
    assert isinstance(payload["surviving_count"], int)
    assert isinstance(payload["mandated_count"], int)
    assert isinstance(payload["obligation_types"], dict)