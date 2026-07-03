"""Post-investigation decision guardrails for production trace reports.

Prevents over-confident automated actions when telemetry, planner, or attack
chain evidence is insufficient.
"""
from __future__ import annotations

from typing import Any

CRITICAL_FAILURE_RATE = 0.20
SCORE_ACTION_THRESHOLD = 0.5

AFFIRMATIVE_ACTIONS = frozenset({
    "contain_escalate",
    "dismiss_benign",
    "escalate_incomplete",
})

# Demo profile: configuration gaps, not evidence failures.
DEMO_WARNING_FLAGS = frozenset({
    "planner_non_functional",
    "confidence_unavailable",
    "telemetry_coverage_insufficient",
    "score_action_mismatch",
    "investigation_budget_exhausted",
})

DEMO_GRAPH_NODE_MIN = 8
DEMO_GRAPH_EDGE_MIN = 6


def _query_failure_rate(soar_fetch: dict[str, Any]) -> float:
    queries = int(soar_fetch.get("queries") or 0)
    errors = int(soar_fetch.get("errors") or 0)
    if queries <= 0:
        return 0.0
    return errors / queries


def _planner_non_functional(planner_audit: list[dict[str, Any]]) -> bool:
    if not planner_audit:
        return False
    for entry in planner_audit:
        mode = str(entry.get("mode") or "").lower()
        if mode in ("off", "disabled"):
            continue
        if not entry.get("abstained") and int(entry.get("accepted") or 0) > 0:
            return False
    return True


def _lifecycle_obligation_unresolved(
    obligations: list[dict[str, Any]],
) -> bool:
    for item in obligations:
        oid = str(item.get("id") or "")
        otype = str(item.get("type") or "")
        if oid == "lifecycle_1" or otype in ("initial_access", "lifecycle"):
            if item.get("overdue") or int(item.get("attempts") or 0) > 0:
                return True
            if not item.get("resolved", False):
                return True
    return False


def collect_guardrail_flags(
    *,
    decision: dict[str, Any],
    usage: dict[str, Any],
    graph: dict[str, Any],
) -> list[str]:
    flags: list[str] = []
    soar_fetch = usage.get("soar_fetch") or {}
    planner_audit = usage.get("model_planner") or []
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    obligations = decision.get("unresolved_obligations") or []

    failure_rate = _query_failure_rate(soar_fetch)
    if failure_rate >= CRITICAL_FAILURE_RATE:
        flags.append("data_collection_critical_failure")

    if len(edges) == 0 and len(nodes) <= 1:
        flags.append("attack_chain_unresolved")

    if _lifecycle_obligation_unresolved(obligations):
        flags.append("obligation_lifecycle_1_unresolved")

    if _planner_non_functional(planner_audit):
        flags.append("planner_non_functional")

    if soar_fetch.get("coverage_truncated"):
        flags.append("telemetry_coverage_insufficient")

    score = float(decision.get("investigation_score") or 0.0)
    action = str(decision.get("action") or "")
    if action in AFFIRMATIVE_ACTIONS and score < SCORE_ACTION_THRESHOLD:
        flags.append("score_action_mismatch")

    if decision.get("confidence_status") == "unavailable":
        flags.append("confidence_unavailable")

    if decision.get("stop_reason") == "budget" and action in AFFIRMATIVE_ACTIONS:
        flags.append("investigation_budget_exhausted")

    return list(dict.fromkeys(flags))


def _demo_downgrade_flags(
    flags: list[str],
    *,
    action: str,
    graph: dict[str, Any],
) -> tuple[list[str], list[str]]:
    """Split flags into blocking (critical) vs warnings under demo profile."""
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    graph_meets_threshold = (
        len(nodes) >= DEMO_GRAPH_NODE_MIN and len(edges) >= DEMO_GRAPH_EDGE_MIN
    )

    warnings: list[str] = []
    blocking: list[str] = []
    for flag in flags:
        if flag not in DEMO_WARNING_FLAGS:
            blocking.append(flag)
            continue
        if flag == "telemetry_coverage_insufficient" and graph_meets_threshold:
            warnings.append(flag)
            continue
        if action == "escalate_incomplete":
            warnings.append(flag)
            continue
        blocking.append(flag)
    return blocking, warnings


def should_force_inconclusive(
    action: str,
    flags: list[str],
    *,
    demo_profile: bool = False,
    graph: dict[str, Any] | None = None,
) -> bool:
    if action == "inconclusive" or not flags:
        return False

    critical = {
        "data_collection_critical_failure",
        "attack_chain_unresolved",
        "obligation_lifecycle_1_unresolved",
        "planner_non_functional",
        "telemetry_coverage_insufficient",
        "score_action_mismatch",
        "confidence_unavailable",
        "investigation_budget_exhausted",
    }

    effective_flags = flags
    if demo_profile and action == "escalate_incomplete":
        blocking, _warnings = _demo_downgrade_flags(
            flags,
            action=action,
            graph=graph or {},
        )
        effective_flags = blocking

    if not critical.intersection(effective_flags):
        return False
    if action in AFFIRMATIVE_ACTIONS:
        return True
    if action == "monitor" and "data_collection_critical_failure" in effective_flags:
        return True
    return False


def apply_decision_guardrails(
    report: dict[str, Any],
    *,
    demo_profile: bool = False,
) -> dict[str, Any]:
    """Augment report decision with guardrail flags and safe overrides."""
    decision = dict(report.get("decision") or {})
    usage = report.get("usage") or {}
    graph = report.get("graph") or {}

    flags = collect_guardrail_flags(
        decision=decision,
        usage=usage,
        graph=graph,
    )
    if not flags:
        return report

    existing_reasons = list(decision.get("reason_codes") or [])
    merged_reasons = list(dict.fromkeys(existing_reasons + flags))
    decision["reason_codes"] = merged_reasons
    decision["guardrail_flags"] = flags

    action = str(decision.get("action") or "")
    if demo_profile and action == "escalate_incomplete":
        blocking, warnings = _demo_downgrade_flags(
            flags,
            action=action,
            graph=graph,
        )
        if warnings:
            decision["guardrail_warnings"] = warnings
        if blocking:
            decision["guardrail_blocking_flags"] = blocking

    if should_force_inconclusive(
        action,
        flags,
        demo_profile=demo_profile,
        graph=graph,
    ):
        decision["original_action"] = action
        decision["action"] = "inconclusive"
        decision["require_human_review"] = True
        decision["automation_eligible"] = False
        decision["incomplete"] = True
    elif demo_profile and action == "escalate_incomplete":
        decision["require_human_review"] = True
        decision["automation_eligible"] = False

    report = dict(report)
    report["decision"] = decision
    return report
