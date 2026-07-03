"""Run DecisionLedger.seed on fixture cases and check expectations."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent, SeedPayload
from trace_agent.prior_v2 import PriorManager

from .metrics import collect_metrics
from .visibility_metrics import collect_visibility_metrics
from .probe_metrics import collect_probe_metrics

try:
    from trace_agent.probe.voi import recommend_log_source_probes
except ImportError:
    recommend_log_source_probes = None  # type: ignore

try:
    from trace_agent.agents.orchestrator import TraceOrchestrator
except ImportError:
    TraceOrchestrator = None  # type: ignore

from trace_agent.eval.quality_gates import run_quality_gates

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "replay" / "fixtures"
LABELED_DIR = Path(__file__).resolve().parent.parent.parent.parent / "tests" / "replay" / "labeled"


def _alert_from_dict(d: dict[str, Any]) -> AlertEvent:
    return AlertEvent(
        technique_id=d["technique_id"],
        tactic=d.get("tactic"),
        platform=d.get("platform"),
        log_source=d.get("log_source"),
        anomaly_score=float(d.get("anomaly_score", 0.5)),
        asset_id=d.get("asset_id"),
        timestamp=d.get("timestamp"),
        attributes=d.get("attributes") or {},
    )


def _text_blob(seed: SeedPayload) -> str:
    parts = [
        e.title + " " + json.dumps(e.support, ensure_ascii=False) + " ".join(e.caveats)
        for e in seed.explanations
    ]
    parts.append(json.dumps(seed.branch_null_anchor.to_dict(), ensure_ascii=False))
    return " ".join(parts).lower()


def evaluate_expectations(seed: SeedPayload, fixture: dict[str, Any]) -> dict[str, bool]:
    m = collect_metrics(seed)
    blob = _text_blob(seed)
    checks: dict[str, bool] = {}
    exp = dict(fixture.get("expected_behavior") or fixture.get("expect") or {})

    if "min_benign_null" in exp:
        checks["benign_anchor_ok"] = seed.branch_null_anchor.benign >= exp["min_benign_null"]
    if "benign_anchor_min" in exp:
        checks["benign_anchor_ok"] = seed.branch_null_anchor.benign >= exp["benign_anchor_min"]
    if "max_benign_null" in exp:
        checks["benign_not_too_high"] = seed.branch_null_anchor.benign <= exp["max_benign_null"]
    if "min_oos_null" in exp:
        checks["oos_anchor_ok"] = seed.branch_null_anchor.oos >= exp["min_oos_null"]
    if "oos_anchor_min" in exp:
        checks["oos_anchor_ok"] = seed.branch_null_anchor.oos >= exp["oos_anchor_min"]
    if "max_max_prior" in exp:
        checks["entropy_ok"] = m["max_prior"] <= exp["max_max_prior"]

    if exp.get("explanation_types_any") or exp.get("top_k_should_include"):
        types = set(m["explanation_types"])
        want = exp.get("explanation_types_any") or exp.get("top_k_should_include")
        checks["top_k_hit"] = bool(types & set(want))

    if exp.get("explanation_title_contains_any"):
        titles = " ".join(e.title.lower() for e in seed.explanations)
        checks["top_k_hit"] = any(k.lower() in titles for k in exp["explanation_title_contains_any"])

    if exp.get("lifecycle_template_any"):
        got = set(m["lifecycle_templates"])
        checks["top_k_hit"] = bool(got & set(exp["lifecycle_template_any"]))

    if "min_contested_edges" in exp:
        checks["boundary_ok"] = m["contested_edge_count"] >= exp["min_contested_edges"]

    if exp.get("contested_gtfobins_or_dual_use") or exp.get("expected_boundary_flags"):
        checks["boundary_ok"] = any(
            e.support.get("gtfobins_dual_use") or e.support.get("lolbas_dual_use")
            for e in seed.contested_edges
        ) or any(e.support.get("type") == "dual_use_boundary" for e in seed.explanations)

    if exp.get("log_source_contains_any") or exp.get("expected_log_sources"):
        sources = " ".join(m["log_sources"]).lower()
        keys = exp.get("log_source_contains_any") or exp.get("expected_log_sources") or []
        checks["log_source_ok"] = any(k.lower() in sources for k in keys)

    if exp.get("caveat_contains_any"):
        caveats = " ".join(c for e in seed.explanations for c in e.caveats).lower()
        checks["caveat_ok"] = any(k.lower() in caveats or k.lower() in blob for k in exp["caveat_contains_any"])

    if exp.get("hard_veto_safe") or exp.get("must_not_hard_veto"):
        low_trust_keys = ("file_system_timestamp", "bash_history", "web_application_log")
        defaults = seed.evidence_trust_defaults
        alert_src = (seed.alert.log_source or "").lower()
        if any(t in alert_src for t in low_trust_keys):
            for key, meta in defaults.items():
                if alert_src in key.lower() or key.lower() in alert_src:
                    if meta.get("hard_veto_allowed"):
                        checks["hard_veto_safe"] = False
                        break
            else:
                checks["hard_veto_safe"] = True
        else:
            checks["hard_veto_safe"] = m["max_prior"] < 0.75

    checks["expected_hit"] = all(checks.values()) if checks else True
    return checks


def run_case(
    fixture: dict[str, Any],
    ledger: DecisionLedger,
    *,
    through_orchestrator: bool = False,
) -> dict[str, Any]:
    alert = _alert_from_dict(fixture["alert"])
    runtime_path = "direct"
    lock_phase = None
    obligation_count = 0
    recommended_probe_count = 0

    if through_orchestrator:
        if TraceOrchestrator is None:
            raise RuntimeError("TraceOrchestrator not available")
        state = TraceOrchestrator(ledger).initialize_case(alert)
        seed = state.decision_ledger_seed
        runtime_path = "orchestrator"
        lock_phase = state.phase
        obligation_count = len(state.obligation_ledger.get("items", []))
        recommended_probe_count = len(state.recommended_probes)
    else:
        seed = ledger.seed(alert)

    probes: list[dict[str, Any]] = []
    if recommend_log_source_probes and seed.explanations:
        probes = recommend_log_source_probes(alert, seed.explanations[0], ledger.prior)

    metrics = collect_metrics(seed)
    metrics.update(collect_visibility_metrics(seed, fixture, probes))
    metrics.update(collect_probe_metrics(probes, fixture))
    checks = evaluate_expectations(seed, fixture)
    qg = run_quality_gates(seed)
    qg["case_id"] = fixture["case_id"]
    return {
        "case_id": fixture["case_id"],
        "title": fixture.get("title", fixture["case_id"]),
        "category": fixture.get("category", "attack-like"),
        "source": fixture.get("source", "synthetic"),
        "label_quality": fixture.get("label_quality", "synthetic"),
        "calibration_eligible": (fixture.get("evaluation") or {}).get("calibration_eligible", False),
        "evaluation": fixture.get("evaluation") or {},
        "probe_ground_truth": fixture.get("probe_ground_truth"),
        "alert": alert.to_dict(),
        "metrics": metrics,
        "checks": checks,
        "quality_gates": qg,
        "passed": checks.get("expected_hit", False) and qg["gates"]["all_pass"],
        "runtime_path": runtime_path,
        "lock_phase": lock_phase,
        "obligation_count": obligation_count,
        "recommended_probe_count": recommended_probe_count,
        "recommended_probes": probes[:5],
        "null_reasons": seed.branch_null_anchor.reasons,
        "explanations": [
            {"id": e.id, "title": e.title, "prior": e.prior_probability, "support_type": e.support.get("type")}
            for e in seed.explanations
        ],
    }


def load_fixtures(fixtures_dir: Path | None = None) -> list[dict[str, Any]]:
    d = fixtures_dir or FIXTURES_DIR
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(d.glob("*.json"))]


def run_all(
    fixtures_dir: Path | None = None,
    ledger: DecisionLedger | None = None,
    *,
    through_orchestrator: bool = False,
) -> dict[str, Any]:
    ledger = ledger or DecisionLedger(PriorManager())
    results = [
        run_case(f, ledger, through_orchestrator=through_orchestrator)
        for f in load_fixtures(fixtures_dir)
    ]
    passed = sum(1 for r in results if r["passed"])
    return {
        "summary": {
            "total": len(results),
            "passed": passed,
            "failed": len(results) - passed,
            "runtime_path": "orchestrator" if through_orchestrator else "direct",
        },
        "cases": results,
    }


def report_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Prior Replay Report",
        "",
        f"**Passed:** {report['summary']['passed']}/{report['summary']['total']} "
        f"({report['summary'].get('runtime_path', 'direct')})",
        "",
    ]
    for c in report["cases"]:
        status = "PASS" if c["passed"] else "FAIL"
        m = c["metrics"]
        lines.append(f"## [{status}] {c['case_id']} — {c['title']}")
        lines.append(
            f"- max_prior={m['max_prior']} entropy={m['entropy']} "
            f"benign={m['null_benign']} oos={m['null_oos']} "
            f"contested={m['contested_edge_count']} log_sources={m['log_source_count']}"
        )
        lines.append(f"- checks: {c['checks']}")
        lines.append("")
    return "\n".join(lines)
