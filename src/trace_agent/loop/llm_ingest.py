"""LLM-assisted L3 attribution with bounded graph and prior context."""
from __future__ import annotations

from typing import Any, Optional

from .ingest import IngestPipeline, IngestResult
from trace_agent.llm.client import DeepSeekClient


class LLMIngestPipeline(IngestPipeline):
    """Use the LLM only for ambiguous explanation/boundary attribution."""

    def __init__(
        self,
        trust_model,
        graph,
        ledger=None,
        llm_client: Optional[DeepSeekClient] = None,
        mode: str = "assist",
        llm_threshold: float = -2.0,
        max_llm_per_round: int = 3,
        max_llm_per_case: int = 20,
        max_tokens_per_case: int = 20_000,
        max_graph_nodes: int = 40,
        ambiguity_margin: float = 0.35,
    ):
        super().__init__(trust_model, graph, ledger)
        self._llm = llm_client
        self._mode = mode if mode in ("off", "shadow", "assist") else "off"
        self._llm_threshold = llm_threshold
        self._llm_calls = 0
        self._max_llm_per_round = max_llm_per_round
        self._max_llm_per_case = max_llm_per_case
        self._max_tokens_per_case = max_tokens_per_case
        self._round_llm_count = 0
        self._max_graph_nodes = max_graph_nodes
        self._ambiguity_margin = ambiguity_margin
        self._active_alert_context: dict[str, Any] = {}
        self._audit: list[dict[str, Any]] = []
        self._provider_errors = 0

    def reset_round_budget(self) -> None:
        self._round_llm_count = 0

    def triage(
        self,
        raw_events: list[dict],
        probes=None,
        alert_context: Optional[dict[str, Any]] = None,
    ) -> IngestResult:
        self._active_alert_context = dict(alert_context or {})
        try:
            result = super().triage(raw_events, probes, alert_context)
            if self._mode == "shadow":
                self._run_shadow_judgements(result)
            elif self._mode == "assist":
                for event in result.all_events:
                    if event.get("_l3_llm_augmented"):
                        self._audit_judgement(
                            event,
                            {
                                "supporting_refs": event.get(
                                    "_l3_supporting_refs", []
                                ),
                                "reason_codes": event.get(
                                    "_l3_reason_codes", []
                                ),
                            },
                            rule_bucket=event.get(
                                "_l3_rule_route_preview"
                            ),
                            routing_delta=(
                                event.get("_l3_rule_route_preview")
                                != event.get("_route_bucket")
                            ),
                        )
            return result
        finally:
            self._active_alert_context = {}

    # ------------------------------------------------------------------
    # L3: explanation and boundary attribution
    # ------------------------------------------------------------------

    def _l3_attribution(self, event: dict) -> dict:
        event = super()._l3_attribution(event)
        scores = event.get("_l3_attribution_scores", {})
        event["_l3_rule_scores"] = dict(scores)
        event["_l3_rule_best_explanation"] = event.get(
            "_l3_best_explanation"
        )
        event["_l3_rule_route_preview"] = self._l4_route(
            event,
            alert_context=self._active_alert_context,
        )

        if (
            self._mode == "assist"
            and
            self._should_call_llm(scores)
            and self._llm is not None
            and self._round_llm_count < self._max_llm_per_round
            and self._llm_calls < self._max_llm_per_case
            and self._token_budget_available()
        ):
            judgement = self._call_llm_judgement(event)
            if judgement:
                self._llm_calls += 1
                self._round_llm_count += 1
                self._apply_judgement(event, scores, judgement)

        return event

    def _run_shadow_judgements(self, result: IngestResult) -> None:
        if self._llm is None:
            self._audit.append({
                "mode": "shadow",
                "status": "provider_unavailable",
                "routing_delta": False,
            })
            return
        candidates = [
            event for event in result.all_events
            if self._should_call_llm(
                event.get("_l3_attribution_scores", {})
            )
        ]
        candidates.sort(
            key=lambda event: (
                -float((event.get("attributes") or {}).get(
                    "anomaly_score", 0.0
                ) or 0.0),
                str(event.get("id") or ""),
            )
        )
        remaining_round = max(
            0, self._max_llm_per_round - self._round_llm_count
        )
        remaining_case = max(0, self._max_llm_per_case - self._llm_calls)
        if not self._token_budget_available():
            return
        for event in candidates[:min(remaining_round, remaining_case)]:
            rule_bucket = event.get("_route_bucket")
            judgement = self._call_llm_judgement(event)
            self._llm_calls += int(bool(judgement))
            self._round_llm_count += int(bool(judgement))

            # Compute hypothetical routing delta: what bucket would the model produce?
            routing_delta = False
            if judgement and judgement.get("scores"):
                model_scores = judgement.get("scores") or {}
                valid_ids = {expl.id for expl in self._ledger.explanations}
                model_scores = {
                    k: max(-3.0, min(1.0, float(v)))
                    for k, v in model_scores.items()
                    if k in valid_ids and isinstance(v, (int, float))
                }
                if model_scores:
                    # Temporarily swap scores to compute model's would-be route
                    original_scores = event.get("_l3_attribution_scores", {})
                    original_best = event.get("_l3_best_explanation")
                    merged = dict(original_scores)
                    merged.update(model_scores)
                    event["_l3_attribution_scores"] = merged
                    model_best = max(model_scores, key=model_scores.get)
                    if model_best:
                        event["_l3_best_explanation"] = model_best
                    model_bucket = self._l4_route(
                        event, alert_context=self._active_alert_context
                    )
                    # Restore original state — shadow must not mutate
                    event["_l3_attribution_scores"] = original_scores
                    event["_l3_best_explanation"] = original_best
                    routing_delta = model_bucket != rule_bucket

            self._audit_judgement(
                event,
                judgement,
                rule_bucket=rule_bucket,
                routing_delta=routing_delta,
            )

    def _token_budget_available(self) -> bool:
        if self._llm is None:
            return False
        stats = getattr(self._llm, "stats", {}) or {}
        return int(stats.get("total_tokens", 0)) < self._max_tokens_per_case

    def _should_call_llm(self, scores: dict[str, float]) -> bool:
        if not scores:
            return True
        ranked = sorted(scores.values(), reverse=True)
        if ranked[0] < self._llm_threshold:
            return True
        return len(ranked) > 1 and ranked[0] - ranked[1] < self._ambiguity_margin

    def _call_llm_judgement(self, event: dict) -> dict:
        if not self._ledger or not getattr(self._ledger, "explanations", None):
            return {}
        context = self._build_judgement_context(event)
        event["_l3_context_summary"] = {
            "graph_nodes": len(context["compressed_attack_graph"]["nodes"]),
            "graph_edges": len(context["compressed_attack_graph"]["edges"]),
            "prior_hits": len(context["prior_hits"]),
            "prior_coverage": context["prior_coverage"],
        }
        try:
            assess = getattr(self._llm, "assess_judgement", None)
            if callable(assess):
                return assess(context)
            # Compatibility with older clients and test doubles.
            scores = self._llm.assess_attribution(
                context["candidate_event"], context["explanations"]
            )
            return {"scores": scores}
        except Exception:
            self._provider_errors += 1
            return {}

    def _build_judgement_context(self, event: dict) -> dict:
        explanations = []
        explanation_ids = []
        for expl in self._ledger.explanations:
            explanation_ids.append(expl.id)
            posterior_fn = getattr(self._ledger, "posterior", None)
            posterior = posterior_fn(expl.id) if callable(posterior_fn) else None
            explanations.append(
                {
                    "id": expl.id,
                    "title": getattr(expl, "title", expl.id),
                    "posterior": posterior,
                    "current_stage": getattr(expl, "stage", None),
                    "current_technique": getattr(expl, "current_technique", ""),
                    "lifecycle_template": getattr(expl, "lifecycle_template", None),
                    "expected_prev": list(
                        getattr(expl, "predecessor_tactics", []) or []
                    )[:5],
                    "expected_next": list(
                        getattr(expl, "technique_context", []) or []
                    )[:8],
                    "features": dict(getattr(expl, "features", {}) or {}),
                    "support": dict(getattr(expl, "support", {}) or {}),
                    "caveats": list(getattr(expl, "caveats", []) or [])[:5],
                }
            )

        prior_hits = self._prior_hits(event)
        boundary = self._boundary_belief(event)
        event["_l3_prior_boundary"] = boundary
        graph_context = self._graph.compressed_context(
            event,
            explanation_ids,
            max_nodes=self._max_graph_nodes,
            hops=2,
        )

        attrs = event.get("attributes") or {}
        from .investigation_guidance import guidance_for

        investigation_guidance = guidance_for(
            event.get("tactic"),
            event.get("technique"),
        )
        parent_context = []
        for parent_id in event.get("_l1_parent_candidates", []):
            node = self._graph.get_node(parent_id)
            if node is None:
                continue
            parent_host = str(
                node.attributes.get("host_uid")
                or node.attributes.get("asset_id")
                or node.attributes.get("target")
                or ""
            ).lower()
            event_host = str(
                attrs.get("host_uid")
                or attrs.get("asset_id")
                or event.get("target")
                or ""
            ).lower()
            parent_context.append(
                {
                    "parent_id": parent_id,
                    "parent_technique": node.technique,
                    "relation": "causes",
                    "time_delta_sec": float(event.get("timestamp") or 0) - node.timestamp,
                    "same_host": bool(parent_host and parent_host == event_host),
                }
            )

        safe_attr_keys = {
            "host_uid",
            "asset_id",
            "host",
            "user",
            "principal",
            "process_name",
            "parent_process",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "action",
            "auth_outcome",
            "event_code",
            "logon_type",
            "status",
            "auth_package",
            "rule_id",
            "rule_level",
            "rule_description",
            "rule_groups",
            "anomaly_score",
            "independent_source_count",
            "independent_sources",
        }
        safe_attrs = {
            key: value
            for key, value in attrs.items()
            if key in safe_attr_keys
            and isinstance(value, (str, int, float, bool, list))
        }

        return {
            "task": (
                "Decide whether the candidate fact belongs to an existing attack "
                "explanation, is benign unrelated activity, or is malicious but "
                "out of scope for the current attack."
            ),
            "case": {
                "alert": dict(self._active_alert_context),
                "round": getattr(self._ledger, "round", 0),
            },
            "candidate_event": {
                "id": event.get("id"),
                "technique": event.get("technique"),
                "tactic": event.get("tactic"),
                "timestamp": event.get("timestamp"),
                "source": event.get("source"),
                "target": event.get("target"),
                "trust": {
                    "tier": event.get("_l2_trust_tier"),
                    "integrity": event.get("_l2_integrity"),
                    "adversary_controllable": event.get(
                        "_l2_adversary_controllable", False
                    ),
                },
                "attributes": safe_attrs,
            },
            "structural_candidates": parent_context,
            "compressed_attack_graph": graph_context,
            "explanations": explanations,
            "boundary_belief": boundary,
            "prior_hits": prior_hits,
            "prior_coverage": "matched" if prior_hits else "unknown",
            "investigation_guidance": investigation_guidance,
            "environment": {
                "platform": attrs.get("platform"),
                "asset_role": attrs.get("asset_role"),
                "available_log_sources": attrs.get("available_log_sources")
                or getattr(self._ledger, "visibility", {}).get(
                    "available_log_sources", []
                ),
            },
            "prior_manifest": dict(
                getattr(self._ledger, "prior_manifest", {}) or {}
            ),
        }

    def _prior_hits(self, event: dict) -> list[dict]:
        technique = event.get("technique") or event.get("technique_id") or ""
        tactic = event.get("tactic") or ""
        hits: list[dict] = []
        for expl in self._ledger.explanations:
            if technique and technique == getattr(expl, "current_technique", ""):
                hits.append(
                    {
                        "explanation_id": expl.id,
                        "prior_type": "current_technique",
                        "technique": technique,
                        "strength": (getattr(expl, "features", {}) or {}).get(
                            "technique_fit"
                        ),
                    }
                )
            for edge in list(getattr(expl, "technique_context", []) or []):
                if technique in (edge.get("src"), edge.get("dst")):
                    hits.append(
                        {
                            "explanation_id": expl.id,
                            "prior_type": "technique_causal_edge",
                            **{
                                key: edge.get(key)
                                for key in (
                                    "src",
                                    "dst",
                                    "direction",
                                    "probability",
                                    "attack_flow",
                                    "boundary_prior",
                                )
                                if edge.get(key) is not None
                            },
                        }
                    )
            for predecessor in list(
                getattr(expl, "predecessor_tactics", []) or []
            ):
                related = predecessor.get("related_techniques") or []
                if (
                    tactic
                    and tactic
                    in (
                        predecessor.get("prev_tactic"),
                        predecessor.get("next_tactic"),
                    )
                ) or technique in related:
                    hits.append(
                        {
                            "explanation_id": expl.id,
                            "prior_type": "tactic_transition",
                            **{
                                key: predecessor.get(key)
                                for key in (
                                    "prev_tactic",
                                    "next_tactic",
                                    "probability",
                                    "support",
                                )
                                if predecessor.get(key) is not None
                            },
                        }
                    )
            support = dict(getattr(expl, "support", {}) or {})
            if support.get("type") in {"lifecycle", "dual_use_boundary"}:
                hits.append(
                    {
                        "explanation_id": expl.id,
                        "prior_type": support["type"],
                        "support": support,
                    }
                )
        manifest = dict(getattr(self._ledger, "prior_manifest", {}) or {})
        source_version = (
            manifest.get("version")
            or manifest.get("bundle_version")
            or manifest.get("generated_at")
        )
        for index, hit in enumerate(hits):
            hit.setdefault(
                "prior_ref",
                f"prior:{hit.get('explanation_id', 'unknown')}:"
                f"{hit.get('prior_type', 'unknown')}:{index}",
            )
            if source_version is not None:
                hit.setdefault("source_version", source_version)
        return hits[:16]

    def _boundary_belief(self, event: dict) -> dict[str, float]:
        edge_id_fn = getattr(self._ledger, "edge_id_from_event", None)
        contested_fn = getattr(self._ledger, "get_contested", None)
        if callable(edge_id_fn) and callable(contested_fn):
            edge_id = edge_id_fn(event, self._graph)
            belief = contested_fn().get(edge_id)
            if belief is not None:
                return {
                    "p_in_attack": float(belief.p_in_attack),
                    "p_benign": float(belief.p_benign),
                    "p_oos": float(belief.p_oos),
                }

        technique = event.get("technique") or event.get("technique_id") or ""
        parent_ids = event.get("_l1_parent_candidates") or []
        parent_techniques = {
            self._graph.get_node(node_id).technique
            for node_id in parent_ids
            if self._graph.get_node(node_id) is not None
        }
        for expl in self._ledger.explanations:
            for edge in list(getattr(expl, "technique_context", []) or []):
                if (
                    edge.get("dst") == technique
                    and (not parent_techniques or edge.get("src") in parent_techniques)
                    and edge.get("boundary_prior")
                ):
                    return self._normalize_belief(edge["boundary_prior"])

        null_anchor = getattr(self._ledger, "null_anchor", None)
        benign = float(getattr(null_anchor, "benign", 0.33))
        oos = float(getattr(null_anchor, "oos", 0.33))
        return self._normalize_belief(
            {
                "p_in_attack": max(0.0, 1.0 - benign - oos),
                "p_benign": benign,
                "p_oos": oos,
            }
        )

    @staticmethod
    def _normalize_belief(raw: dict) -> dict[str, float]:
        values = {
            "p_in_attack": max(0.0, float(raw.get("p_in_attack", 0.34))),
            "p_benign": max(0.0, float(raw.get("p_benign", 0.33))),
            "p_oos": max(0.0, float(raw.get("p_oos", 0.33))),
        }
        total = sum(values.values()) or 1.0
        return {key: value / total for key, value in values.items()}

    def _apply_judgement(
        self,
        event: dict,
        rule_scores: dict[str, float],
        judgement: dict,
    ) -> None:
        llm_scores = judgement.get("scores") or {}
        valid_ids = {expl.id for expl in self._ledger.explanations}
        llm_scores = {
            key: max(-3.0, min(1.0, float(value)))
            for key, value in llm_scores.items()
            if key in valid_ids and isinstance(value, (int, float))
        }
        event["_l3_model_scores"] = dict(llm_scores)

        belief_raw = judgement.get("belief") or {}
        if belief_raw:
            belief = self._normalize_belief(
                {
                    "p_in_attack": belief_raw.get(
                        "in_attack", belief_raw.get("p_in_attack", 0.34)
                    ),
                    "p_benign": belief_raw.get(
                        "benign", belief_raw.get("p_benign", 0.33)
                    ),
                    "p_oos": belief_raw.get(
                        "oos", belief_raw.get("p_oos", 0.33)
                    ),
                }
            )
            event["_l3_model_boundary_belief"] = belief
        else:
            belief = event.get("_l3_prior_boundary") or {}

        valid_evidence_refs = {
            str(event.get("id")),
            *self._graph._nodes.keys(),
            *self._graph._edges.keys(),
        }
        supporting_refs = [
            str(value)[:160]
            for value in judgement.get("supporting_refs", [])[:12]
            if str(value) in valid_evidence_refs
        ]
        contradicting_refs = [
            str(value)[:160]
            for value in judgement.get("contradicting_refs", [])[:12]
            if str(value) in valid_evidence_refs
        ]
        target = judgement.get("target_explanation")
        rule_ranked = sorted(rule_scores.values(), reverse=True)
        explicit_tie = (
            len(rule_ranked) > 1
            and rule_ranked[0] - rule_ranked[1] < self._ambiguity_margin
        )
        can_break_tie = (
            explicit_tie
            and target in valid_ids
            and bool(supporting_refs)
        )
        if can_break_tie:
            event["_l3_best_explanation"] = target

        allowed_parents = set(event.get("_l1_parent_candidates") or [])
        model_parents = [
            parent_id
            for parent_id in judgement.get("parent_node_ids", [])
            if parent_id in allowed_parents
        ]
        if model_parents and supporting_refs:
            event["_l3_parent_node_ids"] = model_parents

        relation = judgement.get("relation")
        if (
            supporting_refs
            and relation in {"causes", "precedes", "lateral_to", "elevates_to"}
        ):
            event["_l3_relation"] = relation

        valid_prior_refs = {
            hit["prior_ref"] for hit in self._prior_hits(event) if hit.get("prior_ref")
        }
        prior_refs_used = [
            str(value)[:160]
            for value in judgement.get("prior_refs_used", [])[:12]
            if str(value) in valid_prior_refs
        ]
        confidence = max(
            0.0, min(1.0, float(judgement.get("confidence", 0.5)))
        )
        if not supporting_refs:
            confidence = min(confidence, 0.5)
        event["_l3_model_self_score"] = confidence
        event["_l3_model_score_status"] = "uncalibrated"
        event["_l3_reason_codes"] = [
            str(value)[:80] for value in judgement.get("reason_codes", [])[:8]
        ]
        event["_l3_supporting_refs"] = supporting_refs
        event["_l3_contradicting_refs"] = contradicting_refs
        event["_l3_prior_refs_used"] = prior_refs_used
        event["_l3_missing_evidence"] = [
            str(value)[:160] for value in judgement.get("missing_evidence", [])[:8]
        ]
        event["_l3_llm_augmented"] = True

    def _audit_judgement(
        self,
        event: dict,
        judgement: dict,
        *,
        rule_bucket: str | None,
        routing_delta: bool,
    ) -> None:
        model_scores = judgement.get("scores") or event.get(
            "_l3_model_scores", {}
        )
        rule_best = event.get("_l3_rule_best_explanation")
        model_target = judgement.get("target_explanation")
        if model_target is None and model_scores:
            model_target = max(model_scores, key=model_scores.get)
        supporting_refs = [
            str(value)
            for value in (
                judgement.get("supporting_refs")
                or event.get("_l3_supporting_refs", [])
            )
            if str(value) in {
                str(event.get("id")),
                *self._graph._nodes.keys(),
                *self._graph._edges.keys(),
            }
        ]
        self._audit.append({
            "mode": self._mode,
            "status": "accepted" if judgement else "fallback",
            "event_ref": str(event.get("id") or "")[:160],
            "rule_bucket": rule_bucket,
            "final_bucket": event.get("_route_bucket", rule_bucket),
            "routing_delta": bool(routing_delta),
            "rule_model_disagreement": bool(
                model_target and rule_best and model_target != rule_best
            ),
            "supporting_refs": supporting_refs[:12],
            "reason_codes": [
                str(value)[:80]
                for value in judgement.get("reason_codes", [])[:8]
            ],
            "model_score_status": "uncalibrated",
        })

    # L2 source integrity remains deterministic. Semantic plausibility must not
    # let the model promote or demote evidence provenance.
    def _l2_trust(self, event: dict) -> dict:
        return super()._l2_trust(event)

    def close(self) -> None:
        close = getattr(self._llm, "close", None)
        if callable(close):
            close()

    @property
    def llm_stats(self) -> dict:
        total_judgements = len(self._audit)
        disagreements = sum(
            1 for a in self._audit if a.get("rule_model_disagreement")
        )
        routing_deltas = sum(
            1 for a in self._audit if a.get("routing_delta")
        )
        client_stats = self._llm.stats if self._llm else {}
        if self._mode == "off":
            provider_status = "disabled"
        elif self._llm is None:
            provider_status = "unavailable"
        elif self._provider_errors or client_stats.get("errors"):
            provider_status = "degraded"
        else:
            provider_status = "ready"
        return {
            "mode": self._mode,
            "provider_status": provider_status,
            "l3_llm_calls": self._llm_calls,
            "provider_errors": self._provider_errors,
            "audit": list(self._audit),
            "client_stats": client_stats,
            "shadow_summary": {
                "total_judgements": total_judgements,
                "disagreement_count": disagreements,
                "disagreement_rate": (
                    round(disagreements / total_judgements, 4)
                    if total_judgements else None
                ),
                "routing_delta_count": routing_deltas,
                "routing_delta_rate": (
                    round(routing_deltas / total_judgements, 4)
                    if total_judgements else None
                ),
                "total_tokens": client_stats.get("total_tokens", 0),
                "total_calls": client_stats.get("total_calls", 0),
                "total_latency_ms": client_stats.get("total_latency_ms", 0),
                "avg_latency_ms": client_stats.get("avg_latency_ms", 0),
                "provider_errors": client_stats.get("errors", 0),
            },
        }
