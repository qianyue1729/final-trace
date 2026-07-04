"""Phase-level LOCK tools for the Deep Agent.

Each tool maps to one LOCK phase (L / Veto / O / C / K) or a full loop.
A session is initialised once via ``init_investigation`` and reused across
subsequent phase calls within the same thread.

Config / runner loading **reuses** the helpers in ``tools.py``
(``_scenario_runner``, ``_production_runner``) — no duplicate logic here.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from langchain_core.tools import tool
from langgraph.prebuilt import ToolRuntime

from .project import PROJECT_ROOT, ensure_core_importable

ensure_core_importable()

from trace_agent.agents.lock_session import LOCKSession, BudgetState
from trace_agent.agents.modular_orchestrator import ModularOrchestrator
from trace_agent.agents.progress_protocol import (
    Phase,
    EventKind,
    build_phase_event,
)
from trace_agent.decision.types import AlertEvent
from trace_agent.loop.model_probe_planner import NullProbePlanner
from trace_agent.phases.base import PhaseResult
from trace_engine.runner import InvestigationRunner, build_alert

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────
# Helpers — JSON serialisation
# ──────────────────────────────────────────────────────────────

def _json(data: Any) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, default=str)


# ──────────────────────────────────────────────────────────────
# Session management
# ──────────────────────────────────────────────────────────────

@dataclass
class SessionContext:
    """An active investigation session bound to one thread."""

    session_id: str
    orch: ModularOrchestrator
    lock_session: LOCKSession
    runner: InvestigationRunner
    created_at: float = field(default_factory=time.time)
    current_phase: Optional[str] = None
    scenario_id: Optional[str] = None
    alert: Optional[AlertEvent] = None
    # Accumulated round diagnostics for compact_report
    _round_diagnostics: list[dict] = field(default_factory=list)
    _voi_audit: list[dict] = field(default_factory=list)
    _planner_audit: list[dict] = field(default_factory=list)


_sessions: dict[str, SessionContext] = {}
_sessions_lock = threading.Lock()


def _get_session(session_id: str) -> Optional[SessionContext]:
    with _sessions_lock:
        return _sessions.get(session_id)


def _store_session(ctx: SessionContext) -> None:
    with _sessions_lock:
        _sessions[ctx.session_id] = ctx


def _remove_session(session_id: str) -> Optional[SessionContext]:
    with _sessions_lock:
        return _sessions.pop(session_id, None)


# ──────────────────────────────────────────────────────────────
# Progress streaming
# ──────────────────────────────────────────────────────────────

def _stream_progress(runtime: ToolRuntime | None, event: dict[str, Any]) -> None:
    """Send a progress event via *runtime.stream_writer* (best-effort)."""
    if runtime is None:
        return
    writer = getattr(runtime, "stream_writer", None)
    if not callable(writer):
        return
    try:
        writer({
            "kind": "lock_phase",
            "tool_call_id": getattr(runtime, "tool_call_id", ""),
            **event,
        })
    except Exception:
        pass


def _phase_progress_cb(runtime: ToolRuntime | None, tool_name: str):
    """Return a progress callback that wraps LOCK progress events."""
    writer = runtime.stream_writer if runtime is not None else None
    tool_call_id = runtime.tool_call_id if runtime is not None else None

    def emit(event: dict[str, Any]) -> None:
        if writer is None:
            return
        try:
            writer({
                "kind": "lock_progress",
                "tool_name": tool_name,
                "tool_call_id": tool_call_id,
                **event,
            })
        except Exception:
            pass

    return emit


# ──────────────────────────────────────────────────────────────
# Runner reuse — lazy imports from tools.py to avoid circular
# (tools.py imports PHASE_TOOLS from this module for TRACE_TOOLS)
# ──────────────────────────────────────────────────────────────


def _get_scenario_runner():
    from .tools import _scenario_runner
    return _scenario_runner()


def _get_production_runner():
    from .tools import _production_runner
    return _production_runner()


def _get_compact_report():
    from .tools import _compact_report
    return _compact_report


# ──────────────────────────────────────────────────────────────
# Internal: build runner for init_investigation
# ──────────────────────────────────────────────────────────────

def _resolve_runner(
    *,
    scenario_id: str,
    use_scenario_backend: bool,
) -> InvestigationRunner:
    """Reuse cached scenario runner or build a fresh production runner."""
    if use_scenario_backend:
        return _get_scenario_runner()
    return _get_production_runner()


def _init_session_from_runner(
    runner: InvestigationRunner,
    alert_payload: dict[str, Any],
    *,
    scenario_id: Optional[str],
    max_rounds: int,
    progress_cb,
) -> tuple[ModularOrchestrator, LOCKSession, AlertEvent]:
    """Replicate the critical path of ``InvestigationRunner._run_inner``
    but produce a ``ModularOrchestrator`` + ``LOCKSession`` instead of
    running the loop.

    This guarantees config / executor / prior are **identical** to the
    black-box runner path — zero redundant initialisation code.
    """
    from trace_agent.data_loader import load_prior_bundle
    from trace_agent.decision.belief import DecisionLedger
    from trace_agent.prior_v2 import PriorManager

    config = runner.config

    # ── Alert enrichment (Plan 008) ──
    enrichment = None
    enricher = getattr(runner, "_alert_enricher", None)
    if enricher is not None:
        enrichment = enricher.enrich(alert_payload)
    elif not alert_payload.get("technique") and not alert_payload.get("technique_id"):
        from trace_engine.alert_enricher import AlertEnricher as _AE
        from trace_engine.runner import _TECHNIQUE_TACTIC
        fallback = _AE(technique_tactic_map=_TECHNIQUE_TACTIC)
        enrichment = fallback.enrich(alert_payload)

    alert = build_alert(alert_payload, enrichment=enrichment)

    # ── Executor ──
    executor, _scenario_data = runner._build_executor(scenario_id)

    # Demo profile diversity caps (production)
    if config.demo_profile.enabled and config.backend == "soar_mcp":
        from trace_engine.attack_chain_materializer import DiversityCaps
        demo = config.demo_profile
        executor._production_diversity_caps = DiversityCaps(
            per_rule_id=demo.diversity_per_rule_id_cap,
        )
        executor._production_candidate_top_k = demo.candidate_top_k

    # Availability check
    if not executor.available():
        transport_error = getattr(executor.transport, "last_error_code", None)
        raise ConnectionError(
            f"SOAR backend unavailable (backend={config.backend}, "
            f"endpoint={config.soar_mcp.endpoint}, "
            f"reason={transport_error or 'unknown'})"
        )

    # Time alignment
    alert_ts = float(alert.timestamp or 0)
    if alert_ts > 0:
        executor.align_to_alert(alert_ts)

    # Bootstrap (production only)
    if config.backend == "soar_mcp":
        executor.bootstrap_investigation(alert_payload)

    # ── Prior + Seed ──
    prior_manager = runner._prior_manager()
    dl = DecisionLedger(prior_manager)
    seed = dl.seed(alert)

    # ── Budget ──
    b = config.budget
    budget = BudgetState(
        total_rounds=max_rounds or b.total_rounds,
        total_probes=b.total_probes,
        fanout_per_round=b.fanout_per_round,
        min_rounds_before_robust=b.min_rounds_before_robust,
        min_rounds_after_root=b.min_rounds_after_root,
    )

    # ── LOCKSession.from_seed ──
    lock_session = LOCKSession.from_seed(
        alert=alert,
        prior_manager=prior_manager,
        budget=budget,
        executor=executor,
        config_dict={
            "seed": seed,
            "loss": None,
            "automation_policy": {
                "min_slice_support": config.calibration.min_slice_support,
                "min_precision": config.calibration.min_precision,
                "min_recall": config.calibration.min_recall,
                "contain_threshold": config.calibration.contain_threshold,
                "dismiss_threshold": config.calibration.dismiss_threshold,
            },
            "fanout_budget": b.fanout_per_round,
            "decision_calibrator": getattr(runner, "_decision_calibrator", None),
            "ingest_factory": getattr(runner, "_ingest_factory", None),
            "mcp_runtime": runner.build_mcp_runtime(),
            "progress_cb": progress_cb,
        },
    )

    # ── ModularOrchestrator ──
    orch = ModularOrchestrator(
        lock_session,
        probe_planner=runner.build_probe_planner(),
        planner_mode=config.model_planner.mode,
        planner_max_intents=config.model_planner.max_intents_per_round,
        planner_cost_budget=config.model_planner.cost_budget_per_round,
        planner_max_graph_nodes=config.model_planner.max_graph_nodes,
        demo_profile_enabled=config.demo_profile.enabled,
        demo_plateau_rounds=config.demo_profile.plateau_rounds,
        demo_min_graph_nodes=config.demo_profile.min_graph_nodes,
        demo_min_graph_edges=config.demo_profile.min_graph_edges,
    )

    return orch, lock_session, alert


# ──────────────────────────────────────────────────────────────
# Build a report dict compatible with _compact_report
# ──────────────────────────────────────────────────────────────

def _build_report_from_session(
    ctx: SessionContext,
    *,
    elapsed: float,
) -> dict[str, Any]:
    """Construct a report dict mirroring InvestigationRunner._build_report
    so that ``_compact_report`` can process it identically."""
    from trace_engine.decision_guardrails import apply_decision_guardrails

    orch = ctx.orch
    session = ctx.lock_session
    config = ctx.runner.config

    # Build InvestigationResult via orchestrator
    result = orch._build_result(stop_reason="completed")

    # Graph serialisation
    graph_nodes = []
    if session.graph is not None:
        for nid, node in session.graph._nodes.items():
            attrs = node.attributes or {}
            graph_nodes.append({
                "id": str(nid),
                "technique": node.technique or "",
                "tactic": node.tactic or "",
                "host": str(
                    attrs.get("host_uid") or attrs.get("asset_id")
                    or attrs.get("target") or ""
                ),
                "timestamp": float(node.timestamp or 0),
                "attributed": bool(node.explanation_ids),
            })
    graph_edges = []
    if session.graph is not None:
        graph_edges = [
            {"source": str(e.src), "target": str(e.dst), "relation": e.relation}
            for e in session.graph._edges.values()
        ]

    confidence = {}
    if result.decision_confidence is not None:
        confidence = result.decision_confidence.to_dict()

    report: dict[str, Any] = {
        "status": "completed",
        "alert": ctx.alert.to_dict() if ctx.alert else {},
        "decision": {
            "action": result.decision,
            "confidence": (
                round(result.confidence, 4) if result.confidence is not None else None
            ),
            **confidence,
            "stop_reason": result.stop_reason,
            "leading_explanation": result.leading_explanation,
            "alternatives": result.alternatives,
            "boundary_decisions": result.boundary_decisions,
            "incomplete": result.incomplete,
            "unresolved_obligations": result.unresolved_obligations,
        },
        "usage": {
            "rounds": result.rounds_used,
            "events_processed": result.total_events_processed,
            "probes_used": session.budget.probes_used if session.budget else 0,
            "soar_fetch": getattr(session.executor, "fetch_stats", {}),
            "voi_audit": result.voi_audit,
            "model_planner": result.planner_audit,
            "model_judgement": getattr(
                session.ingest, "llm_stats", {"mode": "off"}
            ) if session.ingest else {"mode": "off"},
            "model_mcp_compiler": getattr(
                session.mcp_runtime,
                "stats",
                {"mode": "off", "provider_status": "disabled"},
            ),
            "round_diagnostics": list(result.round_diagnostics),
            "elapsed_seconds": round(elapsed, 2),
        },
        "graph": {
            "nodes": graph_nodes,
            "edges": graph_edges,
            "attributed_node_count": sum(
                1 for n in graph_nodes if n["attributed"]
            ),
        },
    }
    report = apply_decision_guardrails(
        report,
        demo_profile=(
            config.demo_profile.enabled and config.demo_profile.guardrail_downgrade
        ),
    )
    if config.demo_profile.enabled:
        report["demo_profile"] = {
            "enabled": True,
            "plateau_rounds": config.demo_profile.plateau_rounds,
            "guardrail_downgrade": config.demo_profile.guardrail_downgrade,
        }
    return report


# ══════════════════════════════════════════════════════════════
# TOOL DEFINITIONS
# ══════════════════════════════════════════════════════════════

@tool
def init_investigation(
    technique: str,
    asset: str,
    scenario_id: str = "",
    backend: str = "auto",
    tactic: str = "",
    timestamp: str = "",
    log_source: str = "alert",
    anomaly_score: float = 0.5,
    max_rounds: int = 30,
    runtime: ToolRuntime = None,
) -> str:
    """Initialize a LOCK trace investigation session.

    Builds the alert, loads engine config, creates executor and LOCKSession,
    then seeds the decision ledger.  Returns a session_id for subsequent
    phase-level tool calls.

    backend="auto" preserves compatibility: a scenario_id selects local replay,
    while an empty scenario_id selects production. To query real Wazuh with a
    registered scenario scope, pass backend="soar_mcp" and scenario_id together.
    Production access requires TRACE_AGENT_ALLOW_PRODUCTION=1.

    Must be called before run_l_phase / run_veto_phase / … / run_full_loop.
    """
    if not technique.strip() or not asset.strip():
        return _json({"status": "error", "error": "technique and asset are required"})
    if not 0.0 <= anomaly_score <= 1.0:
        return _json({"status": "error", "error": "anomaly_score must be between 0 and 1"})
    if max_rounds < 1 or max_rounds > 100:
        return _json({"status": "error", "error": "max_rounds must be 1..100"})

    sid = scenario_id.strip()
    backend_mode = backend.strip().lower() or "auto"
    aliases = {"production": "soar_mcp", "wazuh": "soar_mcp"}
    backend_mode = aliases.get(backend_mode, backend_mode)
    if backend_mode not in {"auto", "scenario", "soar_mcp"}:
        return _json({
            "status": "error",
            "error": "backend must be auto, scenario, or soar_mcp",
        })
    use_scenario = (
        bool(sid) if backend_mode == "auto"
        else backend_mode == "scenario"
    )
    if use_scenario and not sid:
        return _json({
            "status": "error",
            "error": "scenario backend requires scenario_id",
        })

    # Production gate
    if not use_scenario:
        if os.getenv("TRACE_AGENT_ALLOW_PRODUCTION", "0") != "1":
            return _json({
                "status": "denied",
                "error": (
                    "Production tracing is disabled. Set "
                    "TRACE_AGENT_ALLOW_PRODUCTION=1 in the backend process, "
                    "or use backend='scenario' with a scenario_id."
                ),
            })

    # Build alert payload
    alert_payload: dict[str, Any] = {
        "technique": technique.strip(),
        "asset": asset.strip(),
        "tactic": tactic.strip() or None,
        "timestamp": timestamp.strip() or None,
        "log_source": log_source,
        "anomaly_score": anomaly_score,
    }

    # Resolve runner (reuse cached / fresh — no duplicate config logic)
    try:
        runner = _resolve_runner(scenario_id=sid, use_scenario_backend=use_scenario)
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to load engine config: {exc}"})

    # Progress callback
    progress = _phase_progress_cb(runtime, "init_investigation")
    progress({"stage": "queued", "status": "waiting"})

    try:
        orch, lock_session, alert = _init_session_from_runner(
            runner,
            alert_payload,
            scenario_id=sid or None,
            max_rounds=max_rounds,
            progress_cb=progress,
        )
    except ConnectionError as exc:
        return _json({"status": "error", "error": str(exc)})
    except Exception as exc:
        return _json({"status": "error", "error": f"Session init failed: {exc}"})

    session_id = str(uuid.uuid4())[:12]
    ctx = SessionContext(
        session_id=session_id,
        orch=orch,
        lock_session=lock_session,
        runner=runner,
        scenario_id=sid or None,
        alert=alert,
    )
    _store_session(ctx)

    progress({"stage": "initialized", "session_id": session_id})

    # Seed summary
    seed_summary: dict[str, Any] = {}
    if lock_session.seed is not None:
        seed_summary = {
            "explanation_count": len(lock_session.seed.explanations),
            "explanation_ids": [e.id for e in lock_session.seed.explanations],
            "null_anchor": (
                {"benign": lock_session.seed.branch_null_anchor.benign}
                if lock_session.seed.branch_null_anchor else None
            ),
        }

    return _json({
        "status": "initialized",
        "session_id": session_id,
        "scenario_id": sid or None,
        "backend": runner.config.backend,
        "backend_requested": backend_mode,
        "alert": alert.to_dict(),
        "budget": {
            "total_rounds": lock_session.budget.total_rounds if lock_session.budget else max_rounds,
            "total_probes": lock_session.budget.total_probes if lock_session.budget else 0,
        },
        "model_processing": {
            "planner": {
                "mode": runner.config.model_planner.mode,
                "provider_status": (
                    "ready"
                    if not isinstance(
                        ctx.orch.l_phase.probe_planner,
                        NullProbePlanner,
                    )
                    else "unavailable"
                ),
            },
            "judgement": getattr(
                lock_session.ingest,
                "llm_stats",
                {"mode": "off", "provider_status": "disabled"},
            ),
            "mcp_compiler": getattr(
                lock_session.mcp_runtime,
                "stats",
                {"mode": "off", "provider_status": "disabled"},
            ),
        },
        "seed_summary": seed_summary,
    })


def _require_session(session_id: str) -> SessionContext | str:
    """Return SessionContext or a JSON error string."""
    ctx = _get_session(session_id)
    if ctx is None:
        return _json({
            "status": "error",
            "error": (
                f"No active session '{session_id}'. "
                "Call init_investigation first."
            ),
        })
    return ctx


def _apply_phase_data_passing(
    ctx: SessionContext,
    phase_name: str,
    result: PhaseResult,
) -> None:
    """Mirror ModularOrchestrator.run_one_round inter-phase data passing."""
    session = ctx.lock_session
    if phase_name == "L":
        pool = result.data.get("pool")
        if pool is not None:
            session.data["pool"] = pool
    elif phase_name == "Veto":
        veto_pool = result.data.get("pool")
        if veto_pool is not None:
            session.data["pool"] = veto_pool
    elif phase_name == "O":
        session.data["chosen"] = result.data.get("chosen", [])
    elif phase_name == "C":
        session.data["ingest_result"] = result.data.get("ingest_result")
    elif phase_name == "K":
        session.prev_stats = session.graph.stats() if session.graph else {}
        ctx.orch._executed_phases = {"L", "Veto", "O", "C", "K"}


def _extract_stop_reason(result: PhaseResult) -> str:
    sd = result.data.get("stop_decision")
    if sd is not None:
        return getattr(sd, "reason", None) or result.data.get("reason", "unknown")
    return result.data.get("reason", "unknown")


def _stream_rich_phase_end(
    ctx: SessionContext,
    phase_name: str,
    result: PhaseResult,
    runtime: ToolRuntime | None,
    tool_name: str,
    rnd: int,
) -> None:
    """Build and stream a rich phase_end event for the frontend."""
    try:
        phase_enum = Phase(phase_name)
        rich_event = build_phase_event(
            phase=phase_enum,
            event_kind=EventKind.PHASE_END,
            result=result,
            session=ctx.lock_session,
            tool_name=tool_name,
            tool_call_id=getattr(runtime, "tool_call_id", "") if runtime else "",
        )
        rich_dict = rich_event.to_stream_dict()
        rich_dict["success"] = result.success
        rich_dict["should_stop"] = result.should_stop
        _stream_progress(runtime, rich_dict)
    except Exception:
        _stream_progress(runtime, {
            "event_kind": "phase_end",
            "phase": phase_name,
            "round": rnd,
            "success": result.success,
            "should_stop": result.should_stop,
            "tool_name": tool_name,
        })


def _stream_stop_decision(
    runtime: ToolRuntime | None,
    rnd: int,
    stop_reason: str,
    tool_name: str,
) -> None:
    _stream_progress(runtime, {
        "event_kind": "stop_decision",
        "phase": "K",
        "round": rnd,
        "decision": "stop",
        "stop_reason": stop_reason,
        "tool_name": tool_name,
    })


def _execute_and_stream_phase(
    ctx: SessionContext,
    phase_name: str,
    runtime: ToolRuntime | None,
    tool_name: str,
) -> PhaseResult:
    """Run one LOCK phase and stream rich lock_phase events (shared by both paths)."""
    session = ctx.lock_session
    if phase_name == "L":
        budget = session.budget
        if budget is not None:
            budget.rounds_used += 1
            session.round = budget.rounds_used

    rnd = session.round

    _stream_progress(runtime, {
        "event_kind": "phase_start",
        "phase": phase_name,
        "round": rnd,
        "tool_name": tool_name,
    })

    result = ctx.orch.run_phase(phase_name)
    ctx.current_phase = phase_name
    _apply_phase_data_passing(ctx, phase_name, result)
    _stream_rich_phase_end(ctx, phase_name, result, runtime, tool_name, rnd)

    if phase_name == "K" and result.should_stop:
        _stream_stop_decision(runtime, rnd, _extract_stop_reason(result), tool_name)

    return result


def _run_single_phase(
    ctx: SessionContext,
    phase_name: str,
    runtime: ToolRuntime | None,
    tool_name: str,
) -> str:
    """Execute one LOCK phase, stream progress, return JSON result."""
    try:
        result = _execute_and_stream_phase(ctx, phase_name, runtime, tool_name)
    except (ValueError, RuntimeError) as exc:
        return _json({"status": "error", "error": str(exc), "phase": phase_name})

    rnd = ctx.lock_session.round
    response: dict[str, Any] = {
        "status": "ok" if result.success else "error",
        "phase": phase_name,
        "round": rnd,
        "data": result.data,
        "should_stop": result.should_stop,
    }

    if phase_name == "K" and result.should_stop:
        response["stop_decision"] = {"reason": _extract_stop_reason(result)}

    return _json(response)


@tool
def run_l_phase(
    session_id: str,
    runtime: ToolRuntime = None,
) -> str:
    """Execute LOCK L phase: candidate generation.

    Generates candidate probes from prior knowledge and rule-based graph
    diagnostics, and deposits them into the unified candidate pool.

    Requires a valid session_id from init_investigation.
    """
    ctx = _require_session(session_id)
    if isinstance(ctx, str):
        return ctx
    return _run_single_phase(ctx, "L", runtime, "run_l_phase")


@tool
def run_veto_phase(
    session_id: str,
    runtime: ToolRuntime = None,
) -> str:
    """Execute LOCK Veto phase: evidence trust gate + VETO pruning + MANDATE obligations.

    Performs impossibility pruning (only anti-counterfactuals are hard-deleted)
    and materialises mandatory investigation obligations.

    Requires L phase to have been executed first.
    """
    ctx = _require_session(session_id)
    if isinstance(ctx, str):
        return ctx
    return _run_single_phase(ctx, "Veto", runtime, "run_veto_phase")


@tool
def run_o_phase(
    session_id: str,
    runtime: ToolRuntime = None,
) -> str:
    """Execute LOCK O phase: VOI ranking + fanout slot filling.

    Ranks candidate probes by decision risk reduction (VOI).  Obligation
    probes pre-occupy half the slots; remaining slots are filled by VOI order.

    Requires Veto phase to have been executed first.
    """
    ctx = _require_session(session_id)
    if isinstance(ctx, str):
        return ctx
    return _run_single_phase(ctx, "O", runtime, "run_o_phase")


@tool
def run_c_phase(
    session_id: str,
    runtime: ToolRuntime = None,
) -> str:
    """Execute LOCK C phase: fanout evidence collection + graph ingestion cascade.

    Concurrently executes selected probes, collects evidence, runs L0-L4
    ingestion cascade, and routes events into 5 buckets.

    Requires O phase to have been executed first.
    """
    ctx = _require_session(session_id)
    if isinstance(ctx, str):
        return ctx
    return _run_single_phase(ctx, "C", runtime, "run_c_phase")


@tool
def run_k_phase(
    session_id: str,
    runtime: ToolRuntime = None,
) -> str:
    """Execute LOCK K phase: learning + decision ledger update + stop decision.

    Performs serial graph ingestion, Bayesian decision ledger update
    (with null anchor), Beta ledger update, obligation discharge, and
    determines whether the investigation should stop.

    The response includes a ``should_stop`` flag and ``stop_decision`` when
    the investigation should conclude.

    Requires C phase to have been executed first.
    """
    ctx = _require_session(session_id)
    if isinstance(ctx, str):
        return ctx
    return _run_single_phase(ctx, "K", runtime, "run_k_phase")


@tool
def run_full_loop(
    session_id: str,
    max_rounds: int = 30,
    runtime: ToolRuntime = None,
) -> str:
    """Run the complete LOCK loop until stop conditions are met.

    This is the fast path — equivalent to repeatedly executing
    L → Veto → O → C → K rounds until stop conditions
    (decision robust / VOI < cost / budget exhausted / hard obligations clear).

    Requires a valid session_id from init_investigation.
    Returns the full investigation report in compact_report format.
    """
    ctx = _require_session(session_id)
    if isinstance(ctx, str):
        return ctx

    progress = _phase_progress_cb(runtime, "run_full_loop")
    ctx.lock_session.progress_cb = progress
    progress({"stage": "lock_loop", "status": "running"})

    if max_rounds is not None and ctx.lock_session.budget:
        ctx.lock_session.budget.total_rounds = max_rounds

    tool_name = "run_full_loop"
    t0 = time.time()
    try:
        while not ctx.orch._budget_exhausted():
            _execute_and_stream_phase(ctx, "L", runtime, tool_name)
            _execute_and_stream_phase(ctx, "Veto", runtime, tool_name)
            o_result = _execute_and_stream_phase(ctx, "O", runtime, tool_name)

            chosen = o_result.data.get("chosen", [])
            if not chosen:
                _stream_stop_decision(
                    runtime,
                    ctx.lock_session.round,
                    "no_probes",
                    tool_name,
                )
                break

            _execute_and_stream_phase(ctx, "C", runtime, tool_name)
            k_result = _execute_and_stream_phase(ctx, "K", runtime, tool_name)
            if k_result.should_stop:
                break
    except (ValueError, RuntimeError) as exc:
        return _json({
            "status": "error",
            "error": str(exc),
            "elapsed_seconds": round(time.time() - t0, 2),
        })
    except Exception as exc:
        return _json({
            "status": "error",
            "error": f"LOCK loop failed: {exc}",
            "elapsed_seconds": round(time.time() - t0, 2),
        })

    elapsed = time.time() - t0

    # Build report via shared helper (mirrors InvestigationRunner._build_report)
    report = _build_report_from_session(ctx, elapsed=elapsed)
    compact = _get_compact_report()(report)

    progress({
        "stage": "completed",
        "status": compact.get("status", "error"),
        "rounds": (compact.get("lock_loop") or {}).get("rounds_used"),
    })

    # Clean up session
    _remove_session(session_id)
    try:
        ctx.orch.close()
    except Exception:
        pass

    return _json(compact)


@tool
def close_investigation(
    session_id: str,
    runtime: ToolRuntime = None,
) -> str:
    """Close and clean up an investigation session without running the full loop.

    Call this to discard a session that was initialised but not completed.
    """
    ctx = _remove_session(session_id)
    if ctx is None:
        return _json({"status": "error", "error": f"No active session '{session_id}'"})
    try:
        ctx.orch.close()
    except Exception:
        pass
    return _json({"status": "closed", "session_id": session_id})


# ──────────────────────────────────────────────────────────────
# Exports
# ──────────────────────────────────────────────────────────────

PHASE_TOOLS = [
    init_investigation,
    run_l_phase,
    run_veto_phase,
    run_o_phase,
    run_c_phase,
    run_k_phase,
    run_full_loop,
    close_investigation,
]
