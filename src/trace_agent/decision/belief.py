"""DecisionLedger — seed competing explanations from real prior products."""
from __future__ import annotations

import math
from typing import Any

from trace_agent.prior_v2 import PriorManager

from .boundary_context import adjust_boundary_prior
from .types import AlertEvent, ContestedEdge, Explanation, NullAnchor, SeedPayload
from trace_agent.eval.evidence_passport import build_mode_from_seed, enrich_seed

MAX_CONTESTED_EDGES = 8
MAX_INITIAL_P = 0.55

LINUX_DUAL_USE_TECHNIQUES = frozenset({"T1059", "T1059.004", "T1105", "T1005"})


def softmax(xs: list[float], temperature: float = 2.0) -> list[float]:
    if not xs:
        return []
    z = [x / max(temperature, 1e-6) for x in xs]
    m = max(z)
    exps = [math.exp(x - m) for x in z]
    total = sum(exps)
    return [x / total for x in exps]


class DecisionLedger:
    def __init__(self, prior_manager: PriorManager, ablation: dict[str, bool] | None = None):
        self.prior = prior_manager
        self.ablation = ablation or {}

    def seed(self, alert: AlertEvent, max_explanations: int = 6) -> SeedPayload:
        node = self.prior.technique_node(alert.technique_id)
        tactic = alert.tactic or (node or {}).get("tactic")
        if node and not alert.tactic:
            from trace_agent.prior_v2 import TACTIC_ID_TO_SHORT

            tactic = TACTIC_ID_TO_SHORT.get(node.get("tactic", ""), node.get("tactic"))

        predecessor_tactics = self.prior.predecessor_tactics(current_tactic=tactic, top_k=5)
        neighbors = self.prior.technique_neighbors(
            alert.technique_id, direction="both", top_k=12, platform=alert.platform
        )
        lifecycle_candidates = self.prior.lifecycle_candidates(
            alert.technique_id, tactic=tactic, top_k=5
        )
        log_sources = self.prior.recommended_log_sources(alert.technique_id, alert.platform)
        if self.ablation.get("no_sigma"):
            log_sources = [
                {**s, "sigma_rule_count": 0, "source": "node"}
                for s in log_sources
                if s.get("source") != "sigma"
            ] or [{"log_source": alert.log_source or "process_creation", "available": True, "trust": 0.5, "source": "node", "sigma_rule_count": 0}]
        avail_override = alert.attributes.get("available_log_sources")
        if avail_override:
            allowed = {str(x).lower() for x in avail_override}
            for s in log_sources:
                key = str(s.get("log_source", "")).lower()
                s["available"] = key in allowed

        explanations = self._build_explanations(
            alert=alert,
            node=node,
            predecessor_tactics=predecessor_tactics,
            neighbors=neighbors,
            lifecycle_candidates=lifecycle_candidates,
            log_sources=log_sources,
        )
        explanations = self._score_explanations(explanations, alert)
        explanations = explanations[:max_explanations]

        contested_edges = self._extract_contested_edges(alert=alert, neighbors=neighbors)
        null_anchor = self._compute_null_anchor(
            alert=alert, node=node, neighbors=neighbors, log_sources=log_sources
        )

        payload = SeedPayload(
            alert=alert,
            explanations=explanations,
            branch_null_anchor=null_anchor,
            contested_edges=contested_edges,
            lifecycle_template_candidates=lifecycle_candidates,
            score_v3_initial_scores={e.id: e.prior_probability for e in explanations},
            loss_baseline=self.prior.loss_baseline(),
            evidence_trust_defaults=self.prior.evidence_trust_defaults(),
            prior_manifest=self.prior.manifest(),
        )
        return enrich_seed(
            payload,
            log_sources,
            build_mode_from_seed(payload),
            prior=self.prior,
            ablation=self.ablation,
        )

    def _build_explanations(
        self,
        alert: AlertEvent,
        node: dict[str, Any] | None,
        predecessor_tactics: list[dict[str, Any]],
        neighbors: list[dict[str, Any]],
        lifecycle_candidates: list[dict[str, Any]],
        log_sources: list[dict[str, Any]],
    ) -> list[Explanation]:
        out: list[Explanation] = []
        tid = alert.technique_id

        if lifecycle_candidates and not self.ablation.get("no_lifecycle"):
            c = lifecycle_candidates[0]
            out.append(
                Explanation(
                    id="H1",
                    title=f"{tid} fits {c['template_id']}:{c['matched_stage']}",
                    current_technique=tid,
                    stage=c.get("matched_stage"),
                    lifecycle_template=c.get("template_id"),
                    predecessor_tactics=predecessor_tactics[:3],
                    technique_context=[],
                    raw_score=0.0,
                    prior_probability=0.0,
                    features={},
                    support={
                        "type": "lifecycle",
                        "template_id": c.get("template_id"),
                        "matched_stage": c.get("matched_stage"),
                        "debt_policy": c.get("debt_policy"),
                    },
                    recommended_log_sources=log_sources[:5],
                    caveats=[],
                )
            )

        flow_neighbors = [
            n
            for n in neighbors
            if (n.get("support") or {}).get("attack_flow", 0) > 0
        ]
        if flow_neighbors and not self.ablation.get("no_flow"):
            flow_count = sum((n.get("support") or {}).get("attack_flow", 0) for n in flow_neighbors)
            ctx = [
                {
                    "src": n["src"],
                    "dst": n["dst"],
                    "direction": n.get("direction"),
                    "probability": n.get("probability"),
                    "attack_flow": (n.get("support") or {}).get("attack_flow", 0),
                    "boundary_prior": n.get("boundary_prior"),
                    "support": n.get("support"),
                }
                for n in flow_neighbors[:5]
            ]
            out.append(
                Explanation(
                    id="H2",
                    title=f"{tid} in ATT&CK Flow-backed technique context",
                    current_technique=tid,
                    stage=None,
                    lifecycle_template=None,
                    predecessor_tactics=[],
                    technique_context=ctx,
                    raw_score=0.0,
                    prior_probability=0.0,
                    features={},
                    support={
                        "type": "technique_context",
                        "l2_attack_flow_edges": flow_count,
                        "flow_backed": True,
                    },
                    recommended_log_sources=log_sources[:5],
                    caveats=["sequence from ATT&CK Flow corpus, not live telemetry"],
                )
            )

        if predecessor_tactics and not self.ablation.get("no_flow"):
            top = predecessor_tactics[0]
            l1_flow = 0 if self.ablation.get("no_flow") else sum(
                (r.get("support") or {}).get("attack_flow_edges", 0) for r in predecessor_tactics
            )
            out.append(
                Explanation(
                    id="H3",
                    title=f"{tid} preceded by {top['prev_tactic']} (L1 tactic prior)",
                    current_technique=tid,
                    stage=alert.tactic,
                    lifecycle_template=None,
                    predecessor_tactics=predecessor_tactics[:3],
                    technique_context=[],
                    raw_score=0.0,
                    prior_probability=0.0,
                    features={},
                    support={
                        "type": "l1_predecessor",
                        "l1_attack_flow_edges": l1_flow,
                        "top_prev_tactic": top.get("prev_tactic"),
                        "top_probability": top.get("probability"),
                    },
                    recommended_log_sources=log_sources[:5],
                    caveats=["L1 uses reverse tactic matrix; STIX co-occurrence is weak prior"],
                )
            )

        tools = (node or {}).get("tools") or {}
        lolbas = tools.get("lolbas") or []
        gtfobins = tools.get("gtfobins") or []
        dual_neighbor = any(
            (n.get("support") or {}).get("lolbas_dual_use")
            or (n.get("support") or {}).get("gtfobins_dual_use")
            for n in neighbors
        )
        is_linux_dual = alert.platform and alert.platform.lower() == "linux" and any(
            tid == p or tid.startswith(p + ".") for p in LINUX_DUAL_USE_TECHNIQUES
        )
        high_benign = any(
            (n.get("boundary_prior") or {}).get("p_benign", 0) >= 0.35 for n in neighbors
        )

        if (lolbas or gtfobins or dual_neighbor or is_linux_dual or high_benign) and not self.ablation.get(
            "no_dual_use"
        ):
            out.append(
                Explanation(
                    id="H4",
                    title=f"{tid} dual-use / boundary-contested execution path",
                    current_technique=tid,
                    stage=alert.tactic,
                    lifecycle_template=None,
                    predecessor_tactics=[],
                    technique_context=[],
                    raw_score=0.0,
                    prior_probability=0.0,
                    features={},
                    support={
                        "type": "dual_use_boundary",
                        "lolbas": lolbas[:5],
                        "gtfobins": gtfobins[:5],
                        "boundary_risk": True,
                        "linux_dual_use_heuristic": is_linux_dual,
                    },
                    recommended_log_sources=log_sources[:5],
                    caveats=["dual-use tools elevate benign competition; context required"],
                )
            )

        if not out:
            out.append(
                Explanation(
                    id="H1",
                    title=f"{tid} generic technique-fit explanation",
                    current_technique=tid,
                    stage=alert.tactic,
                    lifecycle_template=None,
                    predecessor_tactics=predecessor_tactics[:2],
                    technique_context=[],
                    raw_score=0.0,
                    prior_probability=0.0,
                    features={},
                    support={"type": "fallback"},
                    recommended_log_sources=log_sources[:5],
                    caveats=["sparse prior coverage for this technique"],
                )
            )

        return out

    def _features_for_explanation(
        self, expl: Explanation, alert: AlertEvent, node: dict[str, Any] | None
    ) -> dict[str, float]:
        st = expl.support.get("type")
        preds = expl.predecessor_tactics
        tactic_fit = max((p.get("probability", 0) for p in preds), default=0.2) if preds else 0.2

        if st == "technique_context" or expl.support.get("flow_backed"):
            technique_fit = 0.8
        elif expl.technique_context or expl.support.get("type") == "fallback":
            technique_fit = 0.5 if expl.technique_context else 0.2
        else:
            technique_fit = 0.5

        if st == "lifecycle":
            lifecycle_fit = 0.9
        elif expl.lifecycle_template:
            lifecycle_fit = 0.7
        else:
            lifecycle_fit = 0.2

        env_fit = 0.4
        if node and alert.platform:
            plats = [p.lower() for p in node.get("platforms") or []]
            if alert.platform.lower() in plats or (
                alert.platform.lower() == "windows" and any("windows" in p for p in plats)
            ):
                env_fit = 0.8
            elif plats:
                env_fit = 0.1
        if alert.log_source and expl.recommended_log_sources:
            for ls in expl.recommended_log_sources:
                if alert.log_source.lower() in ls.get("log_source", "").lower():
                    env_fit = max(env_fit, 0.8 if ls.get("available") else 0.4)

        temporal_fit = 0.6 if expl.technique_context else 0.4

        stix_support = 0.0
        for p in preds:
            stix_support = max(stix_support, (p.get("support") or {}).get("stix_cooccurrence", 0))
        threat_prevalence = min(0.6, 0.3 + stix_support / 200.0) if stix_support else 0.3

        boundary_risk = 0.3
        if st == "dual_use_boundary" or expl.support.get("boundary_risk"):
            boundary_risk = 0.8

        return {
            "tactic_fit": tactic_fit,
            "technique_fit": technique_fit,
            "lifecycle_fit": lifecycle_fit,
            "environment_fit": env_fit,
            "temporal_fit": temporal_fit,
            "threat_prevalence": threat_prevalence,
            "boundary_risk": boundary_risk,
        }

    def _raw_score(self, features: dict[str, float]) -> float:
        weights = self.prior.score_weights()
        return sum(weights.get(k, 0.0) * features.get(k, 0.0) for k in weights)

    def _score_explanations(
        self, explanations: list[Explanation], alert: AlertEvent
    ) -> list[Explanation]:
        node = self.prior.technique_node(alert.technique_id)
        for e in explanations:
            e.features = self._features_for_explanation(e, alert, node)
            e.raw_score = self._raw_score(e.features)

        raw_scores = [e.raw_score for e in explanations]
        probs = softmax(raw_scores, self.prior.score_temperature())

        max_p = max(probs) if probs else 0
        if max_p > MAX_INITIAL_P:
            clipped = [min(p, MAX_INITIAL_P) for p in probs]
            remainder = 1.0 - sum(clipped)
            if remainder > 0 and clipped:
                bonus = remainder / len(clipped)
                probs = [p + bonus for p in clipped]
            else:
                probs = clipped

        for e, p in zip(explanations, probs):
            e.prior_probability = round(p, 4)
            e.investigation_prior_score = e.prior_probability
            e.calibrated_probability = None
            e.probability_status = "uncalibrated"
        return explanations

    def _edge_reason(self, edge: dict[str, Any]) -> str:
        reasons: list[str] = []
        support = edge.get("support") or {}
        bp = edge.get("boundary_prior") or {}

        if support.get("lolbas_dual_use"):
            reasons.append("LOLBAS dual-use ambiguity")
        if support.get("gtfobins_dual_use"):
            reasons.append("GTFOBins dual-use ambiguity")
        if support.get("attack_flow", 0) > 0:
            reasons.append("ATT&CK Flow temporal support")
        if support.get("sigma_overlap", 0) > 0:
            reasons.append("observable via Sigma-mapped log sources")
        if bp.get("p_oos", 0) >= 0.35:
            reasons.append("high out-of-scope prior")
        if bp.get("p_benign", 0) >= 0.35:
            reasons.append("high benign prior")

        return "; ".join(reasons) or "edge has boundary prior"

    def _extract_contested_edges(
        self, alert: AlertEvent, neighbors: list[dict[str, Any]]
    ) -> list[ContestedEdge]:
        selected: list[ContestedEdge] = []
        for n in neighbors:
            support = n.get("support") or {}
            bp = n.get("boundary_prior") or {}
            score = 0
            if bp:
                score += 1
            if support.get("lolbas_dual_use"):
                score += 3
            if support.get("gtfobins_dual_use"):
                score += 3
            if bp.get("p_benign", 0) >= 0.35:
                score += 2
            if bp.get("p_oos", 0) >= 0.35:
                score += 2
            if support.get("sigma_overlap", 0) > 0 and support.get("attack_flow", 0) == 0:
                score += 1
            if score == 0:
                continue
            build_bp = {
                "p_in_attack": float(bp.get("p_in_attack", 0.34)),
                "p_benign": float(bp.get("p_benign", 0.33)),
                "p_oos": float(bp.get("p_oos", 0.33)),
            }
            runtime_bp = adjust_boundary_prior(build_bp, alert, support)
            selected.append(
                ContestedEdge(
                    src=n["src"],
                    dst=n["dst"],
                    boundary_prior=runtime_bp,
                    support={**support, "build_boundary_prior": build_bp},
                    reason=self._edge_reason(n),
                )
            )
        selected.sort(
            key=lambda e: (
                e.support.get("lolbas_dual_use", False),
                e.support.get("gtfobins_dual_use", False),
                e.boundary_prior.get("p_benign", 0),
            ),
            reverse=True,
        )
        return selected[:MAX_CONTESTED_EDGES]

    def _compute_null_anchor(
        self,
        alert: AlertEvent,
        node: dict[str, Any] | None,
        neighbors: list[dict[str, Any]],
        log_sources: list[dict[str, Any]],
    ) -> NullAnchor:
        benign = 0.20
        oos = 0.15
        reasons: list[str] = []

        tools = (node or {}).get("tools") or {}
        if tools.get("lolbas"):
            benign += 0.15
            reasons.append("LOLBAS dual-use technique")
        if tools.get("gtfobins"):
            benign += 0.15
            reasons.append("GTFOBins dual-use technique")
        if alert.platform and alert.platform.lower() == "linux" and alert.technique_id.startswith("T1059"):
            benign += 0.10
            reasons.append("Linux shell execution (GTFOBins-class)")

        for n in neighbors:
            sup = n.get("support") or {}
            if sup.get("lolbas_dual_use"):
                benign += 0.10
                reasons.append("neighbor LOLBAS dual-use edge")
                break
        for n in neighbors:
            sup = n.get("support") or {}
            if sup.get("gtfobins_dual_use"):
                benign += 0.10
                reasons.append("neighbor GTFOBins dual-use edge")
                break

        for n in neighbors:
            bp = n.get("boundary_prior") or {}
            if bp.get("p_benign", 0) >= 0.35:
                benign += 0.05
                reasons.append("high benign boundary prior on neighbor edge")
                break

        alert_trust = 0.5
        if alert.log_source:
            for ls in log_sources:
                if alert.log_source.lower() in ls.get("log_source", "").lower():
                    alert_trust = float(ls.get("trust", 0.5))
                    break
        if alert_trust < 0.4:
            benign += 0.05
            reasons.append("low-trust or user-controllable log source")

        if node and alert.platform:
            plats = [p.lower() for p in node.get("platforms") or []]
            if plats and alert.platform.lower() not in plats and not any(
                alert.platform.lower() in p for p in plats
            ):
                oos += 0.10
                reasons.append("platform mismatch")

        if not self.prior.lifecycle_candidates(alert.technique_id, alert.tactic):
            oos += 0.05
            reasons.append("no lifecycle template match")

        for n in neighbors:
            bp = n.get("boundary_prior") or {}
            if bp.get("p_oos", 0) >= 0.35:
                oos += 0.10
                reasons.append("neighbor boundary prior suggests out-of-scope")
                break

        attrs = alert.attributes or {}
        profile = attrs.get("tenant_profile") or {}
        if profile.get("asset_role") in ("devops_server", "cicd_server", "backup_server"):
            benign += 0.08
            reasons.append("tenant profile: admin/devops baseline host")
        if profile.get("asset_role") == "finance_workstation":
            benign -= 0.03
            reasons.append("tenant profile: finance workstation (lower benign prior)")

        if attrs.get("weak_case_link") or attrs.get("concurrent_incident"):
            oos += 0.10
            reasons.append("weak case link or concurrent incident context")

        benign = min(max(benign, 0.05), 0.70)
        oos = min(max(oos, 0.05), 0.70)
        return NullAnchor(benign=round(benign, 3), oos=round(oos, 3), reasons=reasons)


# RFC-004-02 alias — seed_from_prior for backward compatibility
NarrativeBelief = DecisionLedger
