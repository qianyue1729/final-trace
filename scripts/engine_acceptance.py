"""trace-engine 三场景验收 — 走生产执行器路径（SoarMcpProbeExecutor）。

与 GT 对账，验收线：决策 contain_escalate 且 recall ≥ 0.9。

Usage:
    python scripts/engine_acceptance.py
    python scripts/engine_acceptance.py --scenario pipeline_18
"""
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_engine.config import EngineConfig
from trace_engine.runner import InvestigationRunner

SCENARIOS = ["pipeline_18", "apt_5host", "multipath_12host"]
RECALL_FLOOR = 0.9


def run_one(runner: InvestigationRunner, scenario_id: str) -> tuple[bool, str]:
    scenario_data, spec = load_scenario(scenario_id)
    entry = find_entry_event(scenario_data, spec)
    alert = build_alert_event(entry)
    payload = {
        "technique": alert.technique_id,
        "asset": alert.asset_id,
        "tactic": alert.tactic,
        "timestamp": alert.timestamp,
        "log_source": alert.log_source,
        "anomaly_score": alert.anomaly_score,
        "attributes": alert.attributes,
    }

    t0 = time.time()
    report = runner.run(payload, scenario_id=scenario_id)
    elapsed = time.time() - t0

    if report.get("status") != "completed":
        return False, f"ERROR: {report.get('error')}"

    decision = report["decision"]["action"]
    gt = report["ground_truth_eval"]
    recall = gt["recall"] or 0.0
    ok = decision == "contain_escalate" and recall >= RECALL_FLOOR
    line = (
        f"decision={decision:<18} recall={gt['gt_hits']}/{gt['gt_total']} "
        f"({recall:.1%})  rounds={report['usage']['rounds']:<3} "
        f"soar_queries={report['usage']['soar_fetch'].get('queries', 0):<4} "
        f"{elapsed:.1f}s"
    )
    if gt["missed_refs"]:
        line += f"\n    missed: {gt['missed_refs'][:6]}"
    return ok, line


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default=None, choices=SCENARIOS)
    args = parser.parse_args()

    cfg = EngineConfig()
    cfg.backend = "scenario"
    runner = InvestigationRunner(cfg)

    targets = [args.scenario] if args.scenario else SCENARIOS
    print(f"{'='*74}\n  trace-engine 三场景验收（生产执行器路径）  验收线 recall≥{RECALL_FLOOR:.0%}\n{'='*74}")

    all_ok = True
    for sid in targets:
        ok, line = run_one(runner, sid)
        all_ok &= ok
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {sid:<20} {line}")

    print("=" * 74)
    print("验收结果:", "全部通过" if all_ok else "存在失败")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
