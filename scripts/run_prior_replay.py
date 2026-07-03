#!/usr/bin/env python3
"""Run replay + quality gates + optional prior diff."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trace_agent.eval.prior_diff import report_markdown as diff_md, run_diff  # noqa: E402
from trace_agent.eval.prior_replay import report_markdown, run_all  # noqa: E402
from trace_agent.eval.quality_gates import report_markdown as qg_md  # noqa: E402
from trace_agent.eval.calibration_lite import collect_calibration, report_markdown as cal_md  # noqa: E402
from trace_agent.eval.calibration import run_calibration, report_markdown as brier_md  # noqa: E402
from trace_agent.eval.failure_analysis import analyze_failures, report_markdown as fail_md  # noqa: E402
from trace_agent.eval.prior_replay import load_fixtures, FIXTURES_DIR  # noqa: E402
from trace_agent.eval.ablation_replay import run_ablation, report_markdown as ablation_md  # noqa: E402
from trace_agent.reporting.explanation_card import render_seed_cards  # noqa: E402
from trace_agent.data_loader import load_prior_bundle  # noqa: E402
from trace_agent.decision.belief import DecisionLedger  # noqa: E402
from trace_agent.prior_v2 import PriorManager  # noqa: E402
from trace_agent.eval.prior_replay import _alert_from_dict, run_case  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--through-orchestrator", action="store_true")
    p.add_argument("--prior-diff", action="store_true")
    p.add_argument("--ablation", action="store_true")
    args = p.parse_args()

    fixtures_dir = ROOT / "tests" / "replay" / "fixtures"
    report = run_all(fixtures_dir, through_orchestrator=args.through_orchestrator)
    qg_results = [c["quality_gates"] for c in report["cases"]]

    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    suf = "_orchestrator" if args.through_orchestrator else ""
    (out / f"prior_replay_report{suf}.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (out / f"prior_replay_report{suf}.md").write_text(report_markdown(report), encoding="utf-8")
    (out / f"prior_quality_gate_report{suf}.md").write_text(qg_md(qg_results), encoding="utf-8")
    cal = collect_calibration(report)
    (out / f"prior_calibration_lite{suf}.json").write_text(json.dumps(cal, indent=2), encoding="utf-8")
    (out / f"prior_calibration_lite{suf}.md").write_text(cal_md(cal), encoding="utf-8")
    fail = analyze_failures(report)
    (out / f"prior_failure_analysis{suf}.json").write_text(json.dumps(fail, indent=2), encoding="utf-8")
    (out / f"prior_failure_analysis{suf}.md").write_text(fail_md(fail), encoding="utf-8")

    brier = run_calibration(report, load_fixtures(fixtures_dir))
    (out / f"prior_calibration{suf}.json").write_text(json.dumps(brier, indent=2), encoding="utf-8")
    (out / f"prior_calibration{suf}.md").write_text(brier_md(brier), encoding="utf-8")

    labeled_dir = ROOT / "tests" / "replay" / "labeled"
    ledger = DecisionLedger(PriorManager(load_prior_bundle()))
    if labeled_dir.is_dir():
        labeled_report = run_all(labeled_dir, ledger)
        brier_l = run_calibration(labeled_report, load_fixtures(labeled_dir))
        (out / "prior_calibration_labeled.json").write_text(json.dumps(brier_l, indent=2), encoding="utf-8")
        (out / "prior_calibration_labeled.md").write_text(brier_md(brier_l), encoding="utf-8")

    if args.ablation:
        ab = run_ablation(fixtures_dir)
        (out / "prior_ablation_sanity.json").write_text(json.dumps(ab, indent=2), encoding="utf-8")
        (out / "prior_ablation_sanity.md").write_text(ablation_md(ab), encoding="utf-8")
        (out / "ablation_replay_report.md").write_text(ablation_md(ab), encoding="utf-8")

    cards = []
    for fx in sorted(fixtures_dir.glob("*.json")):
        case = json.loads(fx.read_text(encoding="utf-8"))
        seed = ledger.seed(_alert_from_dict(case["alert"]))
        cards.append(f"# {case['case_id']}\n\n{render_seed_cards(seed)}")
    if cards:
        (out / f"explanation_cards{suf}.md").write_text("\n\n---\n\n".join(cards), encoding="utf-8")

    if args.prior_diff:
        diff = run_diff()
        (out / "prior_diff_report.json").write_text(json.dumps(diff, indent=2), encoding="utf-8")
        (out / "prior_diff_report.md").write_text(diff_md(diff), encoding="utf-8")

    print(f"Replay: {report['summary']['passed']}/{report['summary']['total']}")
    return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
