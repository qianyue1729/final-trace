"""c_phase — C 拍：扇出取证 + 证据信任入账 + 入图判假级联。

从 DecisionOrchestrator._c_phase() 与 _ingest_evidence_trust() 忠实提取，
通过 LOCKSession 读写状态。
"""
from __future__ import annotations

import logging
from typing import Any

from trace_agent.agents.lock_session import LOCKSession
from trace_agent.loop.generators import normalize_tactic

from .base import PhaseExecutor, PhaseResult

logger = logging.getLogger(__name__)


class CPhaseExecutor(PhaseExecutor):
    """C 拍：扇出取证 + 入图判假级联 + 路由分桶。"""

    def execute(self, session: LOCKSession) -> PhaseResult:
        """执行 C 拍。

        Args:
            session: LOCKSession，session.data["chosen"] 包含 O 拍选出的探针列表。
        """
        chosen = session.data.get("chosen", [])
        if not chosen:
            return PhaseResult(
                phase="C", success=True,
                data={"events_fetched": 0, "ingest_result": None},
                progress_event={"phase": "C", "status": "completed", "events": 0},
            )

        # 1. Compile selected probes to restricted MCP plans, or use templates.
        fetch_before = len(
            getattr(session.executor, "fetch_stats", {}).get(
                "query_diagnostics", []
            )
        )
        mcp_runtime = getattr(session, "mcp_runtime", None)
        if mcp_runtime is not None:
            raw_events = mcp_runtime.execute(session, chosen)
        else:
            raw_events = session.executor.execute_fanout(chosen)

        # 1a. Evidence trust ingest (RFC §5 — ②/C 前置信任)
        self._ingest_evidence_trust(session, raw_events)

        # 1b. Track dead probe pairs (returned 0 raw events)
        dead_pairs = getattr(session, "_dead_pairs", None)
        if dead_pairs is not None:
            probe_event_counts: dict[str, int] = {}
            for ev in raw_events:
                pid = ev.get("probe_id", "")
                if pid:
                    probe_event_counts[pid] = probe_event_counts.get(pid, 0) + 1
            for probe in chosen:
                if probe_event_counts.get(probe.id, 0) == 0:
                    key = ((probe.target or "").lower().strip(), probe.operator)
                    dead_pairs.add(key)

        # 2. Reset LLM round budget if LLMIngestPipeline
        if hasattr(session.ingest, "reset_round_budget"):
            session.ingest.reset_round_budget()

        # 3. Ingest pipeline (L0-L4 + 5-bucket routing)
        alert_context = {
            "host": session.alert.asset_id or "",
            "tactic": normalize_tactic(getattr(session.alert, "tactic", "") or ""),
            "timestamp": float(getattr(session.alert, "timestamp", 0) or 0),
        }
        result = session.ingest.triage(raw_events, chosen, alert_context=alert_context)

        # 3b. Commit triaged refs：仅 graph_eligible / DISCARD
        try:
            from trace_agent.loop.ingest import ROUTE_DISCARD as _ROUTE_DISCARD
            if hasattr(session.executor, "commit_event_refs"):
                to_commit: list[str] = []
                for ev in result.all_events:
                    eid = str(ev.get("id", ""))
                    if not eid:
                        continue
                    bucket = ev.get("_route_bucket", "")
                    if bucket == _ROUTE_DISCARD or ev.get("_graph_eligible") or ev.get("_fact_confirmed"):
                        to_commit.append(eid)
                if to_commit:
                    session.executor.commit_event_refs(to_commit)
        except Exception:
            pass

        # 4. Record host rotation state for staleness bonus
        host_last_probed = getattr(session, "_host_last_probed", None)
        if host_last_probed is not None:
            for probe in chosen:
                host_lower = (probe.target or "").lower().strip()
                if host_lower:
                    host_last_probed[host_lower] = session.budget.rounds_used

        # 5. Update budget
        session.budget.probes_used += len(chosen)

        # Extract routed counts
        routed = getattr(result, "routed", {}) or {}
        all_events = getattr(result, "all_events", []) or []
        model_judgement = getattr(
            session.ingest, "llm_stats", {"mode": "off"}
        )

        # Build wazuh_queries for frontend visibility
        wazuh_queries = []
        probe_event_counts_final: dict[str, int] = {}
        for ev in raw_events:
            pid = ev.get("probe_id", "")
            if pid:
                probe_event_counts_final[pid] = probe_event_counts_final.get(pid, 0) + 1
        fetch_stats = getattr(session.executor, "fetch_stats", {})
        current_query_diagnostics = list(
            fetch_stats.get("query_diagnostics", [])
        )[fetch_before:]
        # Per-probe records: divide shared fetch evenly among co-grouped probes,
        # plus track the full shared_records for dedup visibility.
        records_by_probe: dict[str, int] = {}
        shared_records_by_probe: dict[str, int] = {}
        query_group_size_by_probe: dict[str, int] = {}
        for diagnostic in current_query_diagnostics:
            records = int(diagnostic.get("records", 0) or 0)
            probe_ids = diagnostic.get("probe_ids", [])
            group_size = max(1, len(probe_ids))
            fair_share = records // group_size
            for probe_id in probe_ids:
                records_by_probe[probe_id] = (
                    records_by_probe.get(probe_id, 0) + fair_share
                )
                shared_records_by_probe[probe_id] = records
                query_group_size_by_probe[probe_id] = group_size
        compiler_audit = (
            mcp_runtime.audit[-1]
            if mcp_runtime is not None and mcp_runtime.audit
            else None
        )
        model_executed_probe_ids = {
            str(plan.get("source_probe_id") or "")
            for plan in (compiler_audit or {}).get("plans", [])
            if plan.get("execution_status") == "ok"
        }
        for probe in chosen:
            if probe.id in model_executed_probe_ids:
                continue
            wazuh_queries.append({
                "operator": probe.operator,
                "target": probe.target or "",
                "events_returned": probe_event_counts_final.get(probe.id, 0),
                "events_matched": probe_event_counts_final.get(probe.id, 0),
                "records_returned": records_by_probe.get(probe.id, 0),
                "shared_records": shared_records_by_probe.get(probe.id, 0),
                "query_group_size": query_group_size_by_probe.get(probe.id, 1),
                "elapsed_ms": 0,  # Not tracked individually yet
                "source": "template",
                "transport": type(
                    getattr(session.executor, "transport", None)
                ).__name__,
            })
        if compiler_audit:
            chosen_by_id = {probe.id: probe for probe in chosen}
            for plan in compiler_audit.get("plans", []):
                if not plan.get("accepted"):
                    continue
                source_probe = chosen_by_id.get(plan.get("source_probe_id"))
                wazuh_queries.append({
                    "operator": (
                        source_probe.operator if source_probe else ""
                    ),
                    "target": source_probe.target if source_probe else "",
                    "events_returned": plan.get("hits", 0),
                    "events_matched": probe_event_counts_final.get(
                        plan.get("source_probe_id", ""), 0
                    ),
                    "records_returned": plan.get("hits", 0),
                    "elapsed_ms": plan.get("latency_ms", 0),
                    "source": "model_plan",
                    "transport": type(
                        getattr(session.executor, "transport", None)
                    ).__name__,
                    "mcp_tool": plan.get("mcp_tool", ""),
                    "query_preview": plan.get("query_preview", ""),
                    "validator_reasons": plan.get(
                        "validator_reasons", []
                    ),
                })

        # Extract LLM judgements from ingest audit
        llm_judgements = []
        audit = model_judgement.get("audit", []) if isinstance(model_judgement, dict) else []
        for entry in audit[-10:]:
            llm_judgements.append({
                "event_ref": entry.get("event_ref", ""),
                "verdict": entry.get("verdict") or entry.get("status", "unknown"),
                "confidence": entry.get("confidence", 0.0),
                "reasoning": entry.get("reasoning") or entry.get("explanation", ""),
            })

        # Build triage_pipeline summary (L0-L4 visibility)
        triage_events: list[dict] = []
        for ev in all_events:
            triage_events.append({
                "id": str(ev.get("id", "")),
                "technique": ev.get("technique", ""),
                "tactic": ev.get("_normalized_tactic", ""),
                "host": ev.get("source_host", ev.get("host", "")),
                "action": ev.get("action", ""),
                "bucket": ev.get("_route_bucket", ""),
                "trust_tier": ev.get("_l2_trust_tier", ""),
                "integrity": round(float(ev.get("_l2_integrity", 0) or 0), 2),
                "attribution_status": ev.get("_attribution_status", ""),
                "graph_eligible": bool(ev.get("_graph_eligible")),
                "probe_id": ev.get("probe_id", ""),
            })
        trust_tier_dist: dict[str, int] = {}
        attr_status_dist: dict[str, int] = {}
        for ev in all_events:
            tier = ev.get("_l2_trust_tier", "unknown") or "unknown"
            trust_tier_dist[tier] = trust_tier_dist.get(tier, 0) + 1
            attr_st = ev.get("_attribution_status", "UNSET") or "UNSET"
            attr_status_dist[attr_st] = attr_status_dist.get(attr_st, 0) + 1
        triage_pipeline = {
            "raw_events": len(raw_events),
            "l0_clean": len(all_events),
            "filtered": len(raw_events) - len(all_events),
            "trust_tier_distribution": trust_tier_dist,
            "attribution_status_distribution": attr_status_dist,
            "events": triage_events,
        }

        return PhaseResult(
            phase="C",
            success=True,
            data={
                "events_fetched": len(raw_events),
                "ingest_result": result,
                "routed": routed,
                "model_judgement": model_judgement,
                "attached": len(routed.get("ATTACH", [])),
                "parked": len(routed.get("PARK", [])),
                "discarded": len(routed.get("DISCARD", [])),
                "spawned": len(routed.get("SPAWN", [])),
                "weak_attached": len(routed.get("WEAK", [])),
                "wazuh_queries": wazuh_queries,
                "llm_judgements": llm_judgements,
                "mcp_compiler_audit": compiler_audit,
                "query_diagnostics": current_query_diagnostics,
                "triage_pipeline": triage_pipeline,
            },
            progress_event={
                "phase": "C",
                "status": "completed",
                "events": len(all_events),
                "attached": len(routed.get("ATTACH", [])),
                "model_judgement": model_judgement,
            },
        )

    def _ingest_evidence_trust(self, session: LOCKSession, raw_events: list[dict]) -> None:
        """C 拍前批量入账证据信任 — 驱动 L2/似然/MANDATE/反取证义务。

        Faithful port from DecisionOrchestrator._ingest_evidence_trust().
        """
        if not raw_events or not hasattr(session.trust, "set_context"):
            return
        try:
            from trace_agent.core.types import TrustContext

            # 图内已有攻击链阶段时，告警主机视为可能失陷
            tactics = session.graph.stats().get("tactics_seen") or [] if session.graph else []
            compromised = len(tactics) >= 2

            ctx = TrustContext(
                host=session.alert.asset_id or "",
                is_host_compromised=compromised,
                available_sources=list({
                    ev.get("source", "") for ev in raw_events if ev.get("source")
                }),
                environment_profile="production",
                current_round=session.budget.rounds_used,
            )
            session.trust.set_context(ctx)
            trust_events = []
            for ev in raw_events:
                attrs = ev.get("attributes") or {}
                trust_events.append({
                    "id": ev.get("id", ""),
                    "source": ev.get("source", ""),
                    "host": (
                        ev.get("source_host")
                        or ev.get("host")
                        or attrs.get("host_uid")
                        or attrs.get("asset_id")
                        or session.alert.asset_id
                        or ""
                    ),
                    "timestamp": ev.get("timestamp", 0),
                    "event_type": ev.get("tactic") or ev.get("technique", ""),
                    "indicators": attrs.get("anti_forensics_indicators") or [],
                })
            if hasattr(session.trust, "ingest"):
                session.trust.ingest(trust_events)
        except Exception as exc:
            logger.warning("[CPhase] evidence trust ingest failed: %s", exc)
