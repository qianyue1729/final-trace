from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

import pytest

from trace_agent.loop.ingest import (
    ROUTE_ATTACH,
    ROUTE_PARK,
    ROUTE_SPAWN,
    ROUTE_WEAK,
)
from trace_agent.loop.llm_ingest import LLMIngestPipeline
from trace_agent.loop.session_graph import SessionGraph


@dataclass
class _TrustAssessment:
    integrity: float
    adversary_controllable: bool = False


class _Trust:
    def __init__(self, integrity: float = 0.9):
        self.integrity = integrity

    def assess(self, event):
        return _TrustAssessment(self.integrity)

    def weight_likelihood(self, likelihood, evidence_id):
        return likelihood * self.integrity


class _Ledger:
    def __init__(self, current_technique: str = "T1059.001"):
        self.round = 2
        self.null_anchor = SimpleNamespace(benign=0.35, oos=0.20)
        self.explanations = [
            SimpleNamespace(
                id="H1",
                title="execution chain",
                stage="execution",
                current_technique=current_technique,
                lifecycle_template="test-template",
                predecessor_tactics=[],
                technique_context=[
                    {
                        "src": "T1566.001",
                        "dst": "T1059.001",
                        "direction": "outgoing",
                        "probability": 0.7,
                        "boundary_prior": {
                            "p_in_attack": 0.55,
                            "p_benign": 0.30,
                            "p_oos": 0.15,
                        },
                    }
                ],
                features={"technique_fit": 0.8},
                support={"type": "lifecycle", "template_id": "test-template"},
                caveats=[],
            ),
            SimpleNamespace(
                id="H2",
                title="alternate chain",
                stage="execution",
                current_technique="T1021.001",
                lifecycle_template=None,
                predecessor_tactics=[],
                technique_context=[],
                features={},
                support={"type": "fallback"},
                caveats=[],
            ),
        ]

    def _log_likelihood(self, event, explanation, trust):
        return -2.4

    def posterior(self, explanation_id):
        return {"H1": 0.45, "H2": 0.30}.get(explanation_id, 0.0)

    def get_contested(self):
        return {}

    @staticmethod
    def edge_id_from_event(event, graph):
        return "T1566.001->T1059.001"

    def register_contested_edge(self, edge_id, prior):
        self.registered = (edge_id, prior)


class _LLM:
    def __init__(self, result):
        self.result = result
        self.context = None
        self.stats = {}

    def assess_judgement(self, context):
        self.context = context
        return self.result


def _event(event_id="candidate", technique="T1059.001", timestamp=1030.0):
    return {
        "id": event_id,
        "technique": technique,
        "tactic": "execution",
        "timestamp": timestamp,
        "source": "sysmon",
        "target": "host-a",
        "attributes": {"process_name": "powershell.exe", "asset_id": "host-a"},
    }


def _graph():
    graph = SessionGraph()
    graph.add_events(
        [
            {
                "id": "root",
                "technique": "T1566.001",
                "tactic": "initial-access",
                "timestamp": 1000.0,
                "source": "email",
                "trust_tier": "high",
                "explanation_ids": ["H1"],
                "attributes": {"asset_id": "host-a"},
            }
        ]
    )
    return graph


def test_compressed_context_preserves_candidate_parent_and_ids():
    graph = _graph()
    previous = "root"
    for index in range(1, 8):
        node_id = f"n{index}"
        graph.add_events(
            [
                {
                    "id": node_id,
                    "technique": f"T10{index:02d}",
                    "tactic": "execution",
                    "timestamp": 1000.0 + index,
                    "source": "sysmon",
                    "parent_id": previous,
                    "attributes": {"asset_id": "host-a"},
                }
            ]
        )
        previous = node_id

    event = _event()
    event["_l1_parent_candidates"] = ["n7"]
    context = graph.compressed_context(event, ["H1"], max_nodes=4, hops=2)

    selected_ids = {node["id"] for node in context["nodes"]}
    assert "n7" in selected_ids
    assert len(context["nodes"]) == 4
    assert context["compression"]["omitted_nodes"] == 4
    assert all(
        edge["src"] in selected_ids and edge["dst"] in selected_ids
        for edge in context["edges"]
    )


def test_llm_breaks_tie_but_cannot_create_attach_likelihood():
    graph = _graph()
    llm = _LLM(
        {
            "target_explanation": "H1",
            "parent_node_ids": ["root"],
            "relation": "causes",
            "belief": {"in_attack": 0.72, "benign": 0.18, "oos": 0.10},
            "scores": {"H1": 0.8, "H2": -2.0},
            "supporting_refs": ["root", "candidate"],
            "contradicting_refs": [],
            "reason_codes": ["TEMPORAL_FIT", "PROCESS_LINEAGE_FIT"],
            "missing_evidence": ["auth_log"],
            "confidence": 0.82,
        }
    )
    pipeline = LLMIngestPipeline(_Trust(0.9), graph, _Ledger(), llm)

    result = pipeline.triage(
        [_event()],
        alert_context={"host": "host-a", "tactic": "execution", "timestamp": 1030.0},
    )

    assert len(result.routed[ROUTE_ATTACH]) == 0
    assert len(result.routed[ROUTE_WEAK]) == 1
    routed = result.routed[ROUTE_WEAK][0]
    assert routed["parent_id"] == "root"
    assert routed["_l3_model_boundary_belief"]["p_in_attack"] == pytest.approx(0.72)
    assert routed["_l3_attribution_scores"] == {"H1": -2.4, "H2": -2.4}
    assert routed["_l3_model_scores"] == {"H1": 0.8, "H2": -2.0}
    assert routed["_l3_model_score_status"] == "uncalibrated"
    assert llm.context["compressed_attack_graph"]["candidate_parent_ids"] == ["root"]
    assert llm.context["prior_coverage"] == "matched"
    assert any(
        hit["prior_type"] == "technique_causal_edge"
        for hit in llm.context["prior_hits"]
    )
    assert set(llm.context["boundary_belief"]) == {
        "p_in_attack",
        "p_benign",
        "p_oos",
    }


def test_oos_requires_independent_corroboration_before_spawn():
    judgement = {
        "target_explanation": None,
        "parent_node_ids": [],
        "relation": None,
        "belief": {"in_attack": 0.10, "benign": 0.15, "oos": 0.75},
        "scores": {"H1": -2.8, "H2": -2.8},
        "supporting_refs": ["oos-park"],
        "reason_codes": ["OUT_OF_SCOPE"],
        "confidence": 0.8,
    }

    no_corroboration = LLMIngestPipeline(
        _Trust(0.5), SessionGraph(), _Ledger(), _LLM(judgement)
    ).triage([_event("oos-park", "T9999")])
    assert len(no_corroboration.routed[ROUTE_PARK]) == 1

    corroborated_event = _event("oos-spawn", "T9999")
    corroborated_event["attributes"]["independent_sources"] = ["edr", "network"]
    judgement["supporting_refs"] = ["oos-spawn"]
    corroborated = LLMIngestPipeline(
        _Trust(0.5), SessionGraph(), _Ledger(), _LLM(judgement)
    ).triage([corroborated_event])
    assert len(corroborated.routed[ROUTE_SPAWN]) == 1


def test_no_prior_hit_is_unknown_not_benign():
    llm = _LLM(
        {
            "belief": {"in_attack": 0.34, "benign": 0.33, "oos": 0.33},
            "scores": {"H1": -2.5, "H2": -2.5},
            "confidence": 0.4,
        }
    )
    ledger = _Ledger(current_technique="T1111")
    for explanation in ledger.explanations:
        explanation.technique_context = []
        explanation.support = {"type": "fallback"}
    pipeline = LLMIngestPipeline(_Trust(0.5), SessionGraph(), ledger, llm)
    pipeline.triage([_event("unknown", "T9999")])

    assert llm.context["prior_hits"] == []
    assert llm.context["prior_coverage"] == "unknown"


def test_t1110_judgement_context_includes_skill_guidance_and_auth_fields():
    llm = _LLM({"scores": {"H1": -2.4, "H2": -2.4}})
    event = _event("auth-candidate", "T1110.001")
    event["tactic"] = "credential-access"
    event["attributes"].update({
        "src_ip": "10.0.0.5",
        "user": "alice",
        "auth_outcome": "failure",
    })
    LLMIngestPipeline(
        _Trust(0.5),
        SessionGraph(),
        _Ledger(current_technique="T1110.001"),
        llm,
    ).triage([event])

    assert llm.context["investigation_guidance"][0]["id"] == (
        "skill-guidance:t1110-auth-chain"
    )
    assert llm.context["candidate_event"]["attributes"]["src_ip"] == "10.0.0.5"
    assert llm.context["candidate_event"]["attributes"]["user"] == "alice"
    assert llm.context["candidate_event"]["attributes"]["auth_outcome"] == "failure"


def test_off_mode_never_calls_model():
    llm = _LLM({"scores": {"H1": 1.0}})
    pipeline = LLMIngestPipeline(
        _Trust(0.5),
        SessionGraph(),
        _Ledger(),
        llm,
        mode="off",
    )
    pipeline.triage([_event("off", "T9999")])
    assert llm.context is None
    assert pipeline.llm_stats["l3_llm_calls"] == 0


def test_shadow_mode_cannot_change_rule_route():
    judgement = {
        "target_explanation": "H1",
        "belief": {"in_attack": 0.99, "benign": 0.005, "oos": 0.005},
        "scores": {"H1": 1.0, "H2": -3.0},
        "supporting_refs": ["shadow"],
        "confidence": 0.99,
    }
    rule_result = LLMIngestPipeline(
        _Trust(0.5),
        SessionGraph(),
        _Ledger(),
        None,
        mode="off",
    ).triage([_event("shadow", "T9999")])
    pipeline = LLMIngestPipeline(
        _Trust(0.5),
        SessionGraph(),
        _Ledger(),
        _LLM(judgement),
        mode="shadow",
    )
    shadow_result = pipeline.triage([_event("shadow", "T9999")])
    assert shadow_result.all_events[0]["_route_bucket"] == (
        rule_result.all_events[0]["_route_bucket"]
    )
    assert pipeline.llm_stats["audit"][0]["routing_delta"] is False


def test_case_call_budget_exhaustion_falls_back_to_rules():
    llm = _LLM({"scores": {"H1": 1.0}})
    pipeline = LLMIngestPipeline(
        _Trust(0.5),
        SessionGraph(),
        _Ledger(),
        llm,
        mode="assist",
        max_llm_per_case=0,
    )
    result = pipeline.triage([_event("budget", "T9999")])
    assert result.all_events
    assert llm.context is None
    assert pipeline.llm_stats["l3_llm_calls"] == 0
