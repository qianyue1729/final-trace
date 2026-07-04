#!/usr/bin/env python3
"""ProvSec 场景 LOCK 循环集成测试 — 验证 Log4j JNDI 攻击链溯源能力。"""
import json, time, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from trace_agent.eval.soar_integration_runner import (
    load_scenario, find_entry_event, build_alert_event,
)
from trace_engine.config import EngineConfig
from trace_engine.runner import InvestigationRunner

SCENARIO_ID = "provsec_case_05"
MAX_ROUNDS = 25

# ── 使用 soar_integration_runner 加载入口 alert（与 replay 测试相同路径）
data, spec = load_scenario(SCENARIO_ID)
entry = find_entry_event(data, spec)
alert = build_alert_event(entry)

payload = {
    "technique": alert.technique_id,
    "asset": alert.asset_id,
    "tactic": alert.tactic,
    "timestamp": alert.timestamp,
    "log_source": alert.log_source or "alert",
    "anomaly_score": alert.anomaly_score or 0.8,
    "attributes": alert.attributes or {},
}

print(f">>> 场景: {SCENARIO_ID} (ProvSec Log4j)")
print(f"    入口: {payload['asset']} / {payload['technique']} ({payload['tactic']})")
print(f"    时间: {entry.get('ts')}")
print(f"    轮次: max_rounds={MAX_ROUNDS}")
print()
sys.stdout.flush()

cfg = EngineConfig()
cfg.backend = "scenario"
runner = InvestigationRunner(cfg)

t0 = time.time()
report = runner.run(payload, scenario_id=SCENARIO_ID, max_rounds=MAX_ROUNDS)
elapsed = time.time() - t0

status = report.get("status", "?")
decision = report.get("decision") or {}
usage = report.get("usage") or {}
graph = report.get("graph") or {}
gt = report.get("ground_truth_eval") or {}

print()
print("=" * 52)
print(f"  状态  : {status}")
print(f"  耗时  : {elapsed:.1f}s")
print(f"  轮次  : {usage.get('rounds_used','?')}   探针: {usage.get('probes_used','?')}")
print(f"  决策  : {decision.get('verdict','?')}   置信: {decision.get('confidence','?')}")
print(f"  图    : 节点 {graph.get('node_count',0)}  边 {graph.get('edge_count',0)}")
if gt:
    r = gt.get("recall", 0) or 0
    p = gt.get("precision", 0) or 0
    f = gt.get("f1", 0) or 0
    print(f"  GT    : recall={r:.1%}  precision={p:.1%}  f1={f:.1%}")
    print(f"  命中  : {gt.get('hit_count',0)}/{gt.get('gt_count',0)}")
if report.get("error"):
    print(f"  错误  : {report['error']}")
print("=" * 52)

# 保存完整报告
out = Path("reports/_provsec_lock_run_latest.json")
out.parent.mkdir(exist_ok=True)
out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str))
print(f"\n完整报告已保存到 {out}")

sys.exit(0 if status == "completed" else 1)
