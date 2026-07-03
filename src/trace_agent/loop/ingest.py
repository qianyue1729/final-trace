"""IngestPipeline — RFC-004-02 C 拍入图判假级联 (L0-L4) + 5桶路由"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from .session_graph import SessionGraph
from .probe import Probe


# 5-bucket routing destinations
ROUTE_ATTACH = "ATTACH"       # Strong attribution → attack graph
ROUTE_WEAK = "WEAK"           # Weak/contested association
ROUTE_PARK = "PARK"           # Inconclusive, park for later
ROUTE_DISCARD = "DISCARD"     # Noise, discard
ROUTE_SPAWN = "SPAWN"         # New threat indicator, spawn investigation

PROMOTABLE_TIERS = ("medium", "high", "forge_resistant")
TH_ATTR_ATTACH = -2.0
TH_ATTR_BACKWARD = -2.5

# Required fields for a valid event
_REQUIRED_FIELDS = {"id", "technique", "tactic", "timestamp", "source"}


def is_hard_vetoed(event: dict) -> bool:
    return bool(event.get("_hard_vetoed", False))


@dataclass
class IngestResult:
    """C 拍 triage 结果。"""
    confirmed: list[dict] = field(default_factory=list)          # attribution-confirmed
    graph_eligible: list[dict] = field(default_factory=list)     # fact-confirmed, K 拍入图
    routed: dict[str, list[dict]] = field(default_factory=dict)  # {bucket: [events]}
    trust_annotations: list[dict] = field(default_factory=list)  # 信任标注
    attribution_scores: list[dict] = field(default_factory=list) # L3 解释归属分数

    def __post_init__(self):
        for bucket in [ROUTE_ATTACH, ROUTE_WEAK, ROUTE_PARK, ROUTE_DISCARD, ROUTE_SPAWN]:
            self.routed.setdefault(bucket, [])

    @property
    def all_events(self) -> list[dict]:
        events: list[dict] = []
        for bucket_events in self.routed.values():
            events.extend(bucket_events)
        return events


class IngestPipeline:
    """L0-L4 入图判假级联 + 5桶路由。

    Processing stages:
    L0: Noise filtering (remove duplicates, malformed events)
    L1: Structural attachment (can this event connect to existing graph?)
    L2: Trust assessment (what's the evidence quality?)
    L3: Explanation attribution (which explanation does this support?)
    L4: Final routing to 5 buckets

    RFC-004-02 §3.1: "C 验真 · 扇出取证 → 入图判假级联
    L0去噪 / L1结构挂接 / L2信任 / L3解释归属 / L4
    路由 5 桶(ATTACH/弱挂/PARK/DISCARD/SPAWN)"
    """

    def __init__(self, trust_model, graph: SessionGraph, ledger=None):
        """
        Args:
            trust_model: EvidenceTrustModel (for L2 trust assessment)
            graph: SessionGraph (for L1 structural check)
            ledger: RuntimeDecisionLedger (for L3 explanation attribution, optional)
        """
        self._trust = trust_model
        self._graph = graph
        self._ledger = ledger
        self._seen_ids: set[str] = set()  # L0 dedup

    def triage(
        self,
        raw_events: list[dict],
        probes: Optional[list[Probe]] = None,
        alert_context: Optional[dict[str, Any]] = None,
    ) -> IngestResult:
        """Run full L0-L4 pipeline on raw events.

        Args:
            raw_events: Events from ProbeExecutor.execute_fanout()
            probes: The probes that generated these events (for attribution context)
            alert_context: Optional {host, tactic, timestamp} for backward provenance

        Returns:
            IngestResult with events routed to appropriate buckets
        """
        result = IngestResult()
        alert_context = alert_context or {}

        # Build probe lookup for cross-host detection in L1
        probe_map: dict[str, Probe] = {}
        if probes:
            for p in probes:
                probe_map[p.id] = p

        # L0: denoise
        clean_events = self._l0_denoise(raw_events)

        for event in clean_events:
            # Resolve probe context for this event (if available)
            probe_id = event.get("probe_id") or event.get("_probe_id")
            event_probe = probe_map.get(probe_id) if probe_id else None

            # L1: structural attachment
            event = self._l1_structural(event, probe=event_probe, alert_context=alert_context)

            # L2: trust assessment
            event = self._l2_trust(event)

            # L3: explanation attribution
            event = self._l3_attribution(event)

            # L4: routing
            bucket = self._l4_route(event, alert_context=alert_context)
            event["_route_bucket"] = bucket
            self._materialize_candidate_link(event, bucket)

            # Split fact vs attribution confirmation
            has_attribution = self._has_clear_attribution(event)
            if bucket == ROUTE_ATTACH:
                event["_fact_confirmed"] = True
                event["_attribution_confirmed"] = has_attribution
                event["_attribution_status"] = "CONFIRMED" if has_attribution else "CONTESTED"
                event["_graph_eligible"] = True
                if has_attribution:
                    result.confirmed.append(event)
            else:
                event["_fact_confirmed"] = False
                event["_attribution_confirmed"] = False
                event["_attribution_status"] = "UNSET"
                event["_graph_eligible"] = False

            # Store trust annotation
            result.trust_annotations.append({
                "event_id": event.get("id"),
                "trust_tier": event.get("_l2_trust_tier", "unknown"),
                "integrity": event.get("_l2_integrity", 0.0),
                "adversary_controllable": event.get("_l2_adversary_controllable", False),
            })

            # Store attribution scores if computed
            if event.get("_l3_attribution_scores"):
                result.attribution_scores.append({
                    "event_id": event.get("id"),
                    "best_explanation": event.get("_l3_best_explanation"),
                    "scores": event.get("_l3_attribution_scores"),
                    "is_boundary": event.get("_l3_is_boundary", False),
                    "boundary_belief": event.get("_l3_boundary_belief"),
                    "reason_codes": event.get("_l3_reason_codes", []),
                    "supporting_refs": event.get("_l3_supporting_refs", []),
                    "contradicting_refs": event.get("_l3_contradicting_refs", []),
                    "prior_refs_used": event.get("_l3_prior_refs_used", []),
                    "missing_evidence": event.get("_l3_missing_evidence", []),
                })

            # Route to bucket
            result.routed[bucket].append(event)

        self._register_contested_edges(result)
        self._finalize_graph_eligibility(result, probes, alert_context)
        return result

    def _register_contested_edges(self, result: IngestResult) -> None:
        """L3 解释归属 → 决策账 contested 运行时注册（RFC §4 边界 VOI 载体）。"""
        if self._ledger is None:
            return
        register = getattr(self._ledger, "register_contested_edge", None)
        edge_id_fn = getattr(self._ledger, "edge_id_from_event", None)
        if not callable(register) or not callable(edge_id_fn):
            return

        for event in result.all_events:
            bucket = event.get("_route_bucket", "")
            is_boundary = event.get("_l3_is_boundary", False)
            contested_attr = event.get("_attribution_status") == "CONTESTED"
            if bucket == "DISCARD":
                continue
            if not (is_boundary or bucket in ("WEAK", "PARK", "SPAWN") or contested_attr):
                continue

            edge_id = edge_id_fn(event, self._graph)
            register(edge_id, self._boundary_prior_for_event(event, bucket, is_boundary))

    def _boundary_prior_for_event(
        self, event: dict, bucket: str, is_boundary: bool
    ) -> dict[str, float]:
        """Prefer explicit prior-bundle/context belief over bucket constants."""
        prior = event.get("_l3_prior_boundary")
        if isinstance(prior, dict):
            keys = ("p_in_attack", "p_benign", "p_oos")
            if all(key in prior for key in keys):
                values = {key: max(0.0, float(prior[key])) for key in keys}
                total = sum(values.values()) or 1.0
                return {key: value / total for key, value in values.items()}

        if self._ledger is not None:
            edge_id_fn = getattr(self._ledger, "edge_id_from_event", None)
            contested_fn = getattr(self._ledger, "get_contested", None)
            if callable(edge_id_fn) and callable(contested_fn):
                belief = contested_fn().get(edge_id_fn(event, self._graph))
                if belief is not None:
                    return {
                        "p_in_attack": float(belief.p_in_attack),
                        "p_benign": float(belief.p_benign),
                        "p_oos": float(belief.p_oos),
                    }

            technique = event.get("technique_id") or event.get("technique") or ""
            parent_techniques = {
                node.technique
                for node_id in event.get("_l1_parent_candidates", [])
                if (node := self._graph.get_node(node_id)) is not None
            }
            for explanation in getattr(self._ledger, "explanations", []):
                for edge in getattr(explanation, "technique_context", []) or []:
                    edge_prior = edge.get("boundary_prior")
                    if (
                        edge.get("dst") == technique
                        and (
                            not parent_techniques
                            or edge.get("src") in parent_techniques
                        )
                        and isinstance(edge_prior, dict)
                    ):
                        keys = ("p_in_attack", "p_benign", "p_oos")
                        values = {
                            key: max(0.0, float(edge_prior.get(key, 0.0)))
                            for key in keys
                        }
                        total = sum(values.values()) or 1.0
                        return {
                            key: value / total for key, value in values.items()
                        }

        if bucket == ROUTE_SPAWN:
            return {"p_in_attack": 0.22, "p_benign": 0.28, "p_oos": 0.50}
        if is_boundary:
            return {"p_in_attack": 0.28, "p_benign": 0.48, "p_oos": 0.24}
        return {"p_in_attack": 0.34, "p_benign": 0.40, "p_oos": 0.26}

    def _materialize_candidate_link(self, event: dict, bucket: str) -> None:
        """Carry the selected candidate edge into K-phase graph insertion."""
        if not event.get("_l1_attachable"):
            return
        candidates = event.get("_l3_parent_node_ids") or event.get(
            "_l1_parent_candidates", []
        )
        if not candidates:
            return
        parent_id = candidates[0]
        if self._graph.get_node(parent_id) is None:
            return
        event["parent_id"] = parent_id
        event["relation"] = event.get("_l3_relation") or "causes"
        best = event.get("_l3_best_explanation")
        event["explanation_ids"] = [best] if best and bucket == ROUTE_ATTACH else []

    def _l0_denoise(self, events: list[dict]) -> list[dict]:
        """L0: Remove duplicates and malformed events."""
        clean: list[dict] = []
        for event in events:
            # Check required fields
            if not _REQUIRED_FIELDS.issubset(event.keys()):
                continue

            # Check for empty/None required values
            if any(not event.get(f) for f in _REQUIRED_FIELDS):
                continue

            # Dedup by event id
            eid = event["id"]
            if eid in self._seen_ids:
                continue
            self._seen_ids.add(eid)

            clean.append(event)
        return clean

    def _l1_structural(self, event: dict, probe=None, alert_context: Optional[dict] = None) -> dict:
        """L1: Check structural attachment to existing graph.

        Args:
            event: The event dict to check
            probe: Optional Probe object that generated this event (for cross-host detection)
            alert_context: Entry alert context for backward provenance attachment

        Returns event enriched with:
        - _l1_attachable: bool (can connect to graph)
        - _l1_parent_candidates: list[str] (potential parent node IDs)
        - _l1_temporal_fit: bool (timestamp consistent)
        """
        alert_context = alert_context or {}
        event_tactic = event.get("tactic", "")
        event_target = event.get("target", "")
        event_ts = event.get("timestamp", 0.0)

        parent_candidates: list[str] = []
        temporal_fit = False

        # Adaptive temporal window: wider when graph is small (bootstrapping)
        node_count = len(self._graph._nodes)

        if node_count <= 6:
            temporal_window = 7200    # 2 hours (bootstrap)
        elif node_count <= 10:
            temporal_window = 3600    # 1 hour (early growth)
        else:
            # 多主机场景需要更宽的时间窗
            host_count = self._compute_host_count()
            if host_count > 1:
                temporal_window = 1800  # 30 minutes (multi-host mature)
            else:
                temporal_window = 600   # 10 minutes (single-host mature)

        # 跨主机事件始终用宽窗口
        event_host = event.get("source_host", event.get("host", ""))
        probe_target = getattr(probe, "target", "") if probe else ""
        is_cross_host = (event_host and probe_target and event_host != probe_target)
        if is_cross_host:
            temporal_window = max(temporal_window, 3600)  # 跨主机至少1小时

        # Check frontier nodes for potential structural connections
        frontier = self._graph.frontier()
        for nid in frontier:
            node = self._graph.get_node(nid)
            if node is None:
                continue

            # Temporal proximity check (adaptive window)
            if abs(node.timestamp - event_ts) <= temporal_window:
                temporal_fit = True
                # Check if tactic progression makes sense or target matches
                if node.attributes.get("target") == event_target:
                    parent_candidates.append(nid)
                elif self._tactic_can_follow(node.tactic, event_tactic):
                    parent_candidates.append(nid)

        # Also check non-frontier nodes with matching target and close time
        if not parent_candidates:
            for nid in list(self._graph._nodes.keys()):
                node = self._graph.get_node(nid)
                if node is None:
                    continue
                if abs(node.timestamp - event_ts) <= temporal_window:
                    temporal_fit = True
                    if node.attributes.get("target") == event_target:
                        parent_candidates.append(nid)
                        break  # One match is enough for non-frontier

        # Bootstrap relaxation: 延长bootstrap松弛期，前6个节点允许宽松附着
        if not parent_candidates and node_count <= 6 and event_tactic:
            # Must pass tactic progression check to avoid attaching unrelated events
            for nid in frontier:
                node = self._graph.get_node(nid)
                if node and self._tactic_can_follow(node.tactic, event_tactic):
                    parent_candidates.append(nid)
                    temporal_fit = True
                    break
            # Very early bootstrap (≤1 node, i.e. only entry alert): allow unconditional attach
            if not parent_candidates and node_count <= 1 and frontier:
                parent_candidates.append(frontier[0])
                temporal_fit = True

        # Backward provenance: predecessor-stage events on other hosts may attach
        if not parent_candidates and alert_context:
            if self._is_backward_provenance_candidate(event, alert_context):
                for nid in frontier:
                    node = self._graph.get_node(nid)
                    if node is None:
                        continue
                    if abs(node.timestamp - event_ts) <= temporal_window:
                        parent_candidates.append(nid)
                        temporal_fit = True
                        break

        attachable = len(parent_candidates) > 0

        event["_l1_attachable"] = attachable
        event["_l1_parent_candidates"] = parent_candidates
        event["_l1_temporal_fit"] = temporal_fit
        return event

    def _l2_trust(self, event: dict) -> dict:
        """L2: Assess evidence trust/integrity.

        Returns event enriched with:
        - _l2_trust_tier: str ("forge_resistant"/"high"/"medium"/"low")
        - _l2_integrity: float
        - _l2_adversary_controllable: bool
        """
        if self._trust is None:
            event["_l2_trust_tier"] = "medium"
            event["_l2_integrity"] = 0.5
            event["_l2_adversary_controllable"] = False
            return event

        try:
            trust_obj = self._trust.assess(event)
            integrity = getattr(trust_obj, "integrity", 0.5)
            adversary_ctrl = getattr(trust_obj, "adversary_controllable", False)

            # Determine tier
            forge_resistant = False
            if hasattr(trust_obj, "is_forge_resistant"):
                try:
                    from trace_agent.utils.config import TAU_HARD
                    forge_resistant = trust_obj.is_forge_resistant(TAU_HARD)
                except Exception:
                    forge_resistant = integrity >= 0.8 and not adversary_ctrl
            else:
                forge_resistant = integrity >= 0.8 and not adversary_ctrl

            if forge_resistant:
                tier = "forge_resistant"
            elif integrity >= 0.6:
                tier = "high"
            elif integrity >= 0.3:
                tier = "medium"
            else:
                tier = "low"

            event["_l2_trust_tier"] = tier
            event["_l2_integrity"] = integrity
            event["_l2_adversary_controllable"] = adversary_ctrl
        except Exception:
            # Fallback for trust models that don't support .assess()
            event["_l2_trust_tier"] = "medium"
            event["_l2_integrity"] = 0.5
            event["_l2_adversary_controllable"] = False

        return event

    def _l3_attribution(self, event: dict) -> dict:
        """L3: Explanation attribution — which explanation does this support?

        Uses ledger._log_likelihood() style calculation to score event
        against each explanation. Results determine routing:
        - High attribution to one explanation → ATTACH
        - Low attribution to all → PARK or SPAWN
        - Only fits null anchor → boundary evidence

        Returns event enriched with:
        - _l3_best_explanation: str (explanation ID)
        - _l3_attribution_scores: dict[explanation_id → score]
        - _l3_is_boundary: bool
        """
        if self._ledger is None:
            event["_l3_best_explanation"] = None
            event["_l3_attribution_scores"] = {}
            event["_l3_is_boundary"] = False
            return event

        scores: dict[str, float] = {}
        explanations = getattr(self._ledger, "explanations", [])

        for explanation in explanations:
            try:
                score = self._ledger._log_likelihood(event, explanation, self._trust)
                scores[explanation.id] = score
            except Exception:
                scores[explanation.id] = -3.0  # floor value

        # Determine best explanation
        best_id = None
        best_score = -float("inf")
        for eid, score in scores.items():
            if score > best_score:
                best_score = score
                best_id = eid

        # Is this boundary evidence?  (all scores near floor → null fits best)
        is_boundary = all(s < -2.0 for s in scores.values()) if scores else False

        event["_l3_best_explanation"] = best_id
        event["_l3_attribution_scores"] = scores
        event["_l3_is_boundary"] = is_boundary
        return event

    def _l4_route(self, event: dict, alert_context: Optional[dict] = None) -> str:
        """L4: Final routing decision → bucket name.

        Rules:
        1. Malformed/duplicate → DISCARD  (already filtered in L0)
        2. High trust + structurally attachable + clear attribution → ATTACH
        2b. Medium trust + attachable + clear attribution (bootstrap phase) → ATTACH
        3. Attachable but low trust or weak attribution → WEAK
        4. Not attachable + looks malicious + no explanation fits → SPAWN
        5. Everything else → PARK
        """
        alert_context = alert_context or {}
        attachable = event.get("_l1_attachable", False)
        trust_tier = event.get("_l2_trust_tier", "low")
        integrity = event.get("_l2_integrity", 0.0)
        is_boundary = event.get("_l3_is_boundary", False)
        best_explanation = event.get("_l3_best_explanation")
        attribution_scores = event.get("_l3_attribution_scores", {})

        # Rule: high-quality trust tiers
        high_trust = trust_tier in ("forge_resistant", "high")
        medium_trust = trust_tier == "medium"

        # Rule: has clear attribution (best score above threshold)
        has_attribution = self._has_clear_attribution(event, alert_context=alert_context)

        # Rule 2: ATTACH — high trust + attachable + clear attribution
        if high_trust and attachable and has_attribution:
            return ROUTE_ATTACH

        # Rule 2b: ATTACH — medium trust + attachable + clear attribution (growth phase)
        if medium_trust and attachable and has_attribution:
            return ROUTE_ATTACH

        # Rule 3: WEAK — attachable but weak trust or weak attribution
        if attachable and (not has_attribution):
            return ROUTE_WEAK

        # Rule 4: SPAWN — not attachable, looks malicious, no explanation fits
        # Must also look credible (not adversary-controlled garbage)
        adversary_ctrl = event.get("_l2_adversary_controllable", False)
        if not attachable and not adversary_ctrl and integrity >= 0.3:
            if (
                (is_boundary or not has_attribution)
                and self._has_spawn_corroboration(event)
            ):
                return ROUTE_SPAWN

        # Rule 5: Everything else → PARK
        bucket = ROUTE_PARK
        return self._apply_trust_gated_veto(event, bucket)

    def _apply_trust_gated_veto(self, event: dict, bucket: str) -> str:
        """RFC §5：非抗伪证据不得触发硬删；对手可控时降级为 PARK。"""
        if bucket != ROUTE_DISCARD:
            return bucket

        adversary_ctrl = event.get("_l2_adversary_controllable", False)
        tier = event.get("_l2_trust_tier", "low")
        if adversary_ctrl or tier not in ("forge_resistant", "high"):
            event.pop("_hard_vetoed", None)
            return ROUTE_PARK

        event["_hard_vetoed"] = True
        return ROUTE_DISCARD

    def _has_clear_attribution(
        self,
        event: dict,
        alert_context: Optional[dict] = None,
    ) -> bool:
        attribution_scores = event.get("_l3_attribution_scores", {})
        if not attribution_scores:
            return False
        best_score = max(attribution_scores.values())
        if best_score > TH_ATTR_ATTACH:
            return True
        alert_context = alert_context or {}
        if self._is_backward_provenance_candidate(event, alert_context):
            return best_score > TH_ATTR_BACKWARD
        return False

    @staticmethod
    def _has_spawn_corroboration(event: dict) -> bool:
        """SPAWN requires forge resistance or at least two independent sources."""
        if event.get("_l2_trust_tier") == "forge_resistant":
            return True
        attrs = event.get("attributes") or {}
        sources = attrs.get("independent_sources") or []
        if isinstance(sources, (list, tuple, set)) and len(set(sources)) >= 2:
            return True
        try:
            return int(attrs.get("independent_source_count", 0)) >= 2
        except (TypeError, ValueError):
            return False

    def _finalize_graph_eligibility(
        self,
        result: IngestResult,
        probes: Optional[list[Probe]],
        alert_context: dict[str, Any],
    ) -> None:
        """Promote structurally supported WEAK evidence using observable signals."""
        by_probe: dict[str, list[dict]] = defaultdict(list)
        for evt in result.all_events:
            probe_id = evt.get("probe_id") or evt.get("_probe_id") or "__unknown__"
            by_probe[probe_id].append(evt)

        for group_events in by_probe.values():
            attach_in_group = [
                e for e in group_events if e.get("_route_bucket") == ROUTE_ATTACH
            ]
            weak_events = [
                e for e in group_events if e.get("_route_bucket") == ROUTE_WEAK
            ]
            # Promote qualifying WEAK facts.
            for evt in weak_events:
                if self._should_promote_weak_fact(evt, alert_context):
                    self._promote_weak_as_fact(evt)

        result.graph_eligible = [e for e in result.all_events if e.get("_graph_eligible")]

    def _should_promote_weak_fact(self, event: dict, alert_context: dict[str, Any]) -> bool:
        if event.get("_route_bucket") != ROUTE_WEAK:
            return False
        if not event.get("_l1_attachable", False):
            return False
        trust_tier = event.get("_l2_trust_tier", event.get("trust_tier", "low"))
        if trust_tier not in PROMOTABLE_TIERS:
            return False
        if is_hard_vetoed(event):
            return False
        return bool(
            event.get("_l1_parent_candidates")
            or self._is_backward_provenance_candidate(event, alert_context)
        )

    @staticmethod
    def _promote_weak_as_fact(event: dict) -> None:
        event["_fact_confirmed"] = True
        event["_graph_eligible"] = True
        event["_attribution_confirmed"] = False
        event["_attribution_status"] = "CONTESTED"

    @staticmethod
    def _is_backward_provenance_candidate(event: dict, alert_context: dict[str, Any]) -> bool:
        alert_host = str(alert_context.get("host") or "").lower()
        alert_tactic = str(alert_context.get("tactic") or "").lower()
        alert_ts = float(alert_context.get("timestamp") or 0.0)
        if not alert_host or not alert_tactic:
            return False

        attrs = event.get("attributes") or {}
        event_host = str(
            attrs.get("host_uid") or event.get("target") or event.get("source_host") or ""
        ).lower()
        event_tactic = str(event.get("tactic") or "").lower()
        event_ts = float(event.get("timestamp") or 0.0)

        # Allow alert host: the alert host can also have predecessor-stage events
        # (e.g., initial access happened on the same host before the alert fired)
        if alert_ts and event_ts > alert_ts + 60:
            return False
        if event_host != alert_host:
            return False
        return IngestPipeline._tactic_is_predecessor(event_tactic, alert_tactic)

    @staticmethod
    def _tactic_is_predecessor(event_tactic: str, alert_tactic: str) -> bool:
        tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]
        try:
            ei = tactic_order.index(event_tactic)
            ai = tactic_order.index(alert_tactic)
            return ei < ai
        except ValueError:
            return False

    def _compute_host_count(self) -> int:
        """Count unique hosts in the current graph for multi-host detection."""
        hosts: set[str] = set()
        for nid in list(self._graph._nodes.keys()):
            node = self._graph.get_node(nid)
            if node is None:
                continue
            host = node.attributes.get("host", node.attributes.get("source_host", ""))
            if host:
                hosts.add(host)
        return max(len(hosts), 1)  # At least 1

    @staticmethod
    def _tactic_can_follow(current_tactic: str, next_tactic: str) -> bool:
        """Check if tactic progression is plausible in attack lifecycle."""
        tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]
        try:
            ci = tactic_order.index(current_tactic)
            ni = tactic_order.index(next_tactic)
            # Allow same phase and forward progression (up to 4 steps);
            # no backward progression (prevents unrelated tactic attachment)
            diff = ni - ci
            return 0 <= diff <= 4
        except ValueError:
            # Unknown tactics — allow by default
            return True
