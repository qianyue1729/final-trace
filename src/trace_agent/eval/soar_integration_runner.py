"""SOAR + LLM 端到端集成测试运行器

对 soar_mcp_env 场景数据运行 RFC-004-02 LOCK 循环，
接入 DeepSeek LLM 做 C 拍 triage，对比 ground_truth 评估决策质量。

Usage:
    python -m trace_agent.eval.soar_integration_runner
    python -m trace_agent.eval.soar_integration_runner --scenario pipeline_18
    python -m trace_agent.eval.soar_integration_runner --no-llm
"""
from __future__ import annotations

import json
import time
import sys
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional


# ═══════════════════════════════════════════════════════════════════
# 路径常量
# ═══════════════════════════════════════════════════════════════════

SOAR_ENV_DIR = Path(__file__).resolve().parent.parent.parent.parent / "soar_mcp_env"
SCENARIOS_DIR = SOAR_ENV_DIR / "scenarios"
REGISTRY_PATH = SOAR_ENV_DIR / "registry.json"
RESULTS_DIR = SOAR_ENV_DIR / "results"


# ═══════════════════════════════════════════════════════════════════
# Technique → Tactic 映射表
# ═══════════════════════════════════════════════════════════════════

TECHNIQUE_TACTIC_MAP: dict[str, str] = {
    "T1566": "initial-access",
    "T1059": "execution",
    "T1053": "persistence",
    "T1548": "privilege-escalation",
    "T1055": "defense-evasion",
    "T1003": "credential-access",
    "T1016": "discovery",
    "T1021": "lateral-movement",
    "T1005": "collection",
    "T1041": "exfiltration",
    "T1048": "exfiltration",
    "T1070": "defense-evasion",
    "T1078": "persistence",
    "T1071": "command-and-control",
    "T1047": "execution",
    "T1087": "discovery",
    "T1098": "persistence",
    "T1110": "credential-access",
    "T1190": "initial-access",
    "T1218": "defense-evasion",
    "T1486": "impact",
    "T1560": "collection",
    "T1569": "execution",
    "T1570": "lateral-movement",
}


# ═══════════════════════════════════════════════════════════════════
# 数据类
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ScenarioMetrics:
    """单个场景的评估指标"""
    scenario_id: str
    decision: str                    # contain_escalate / monitor / dismiss_benign / error
    decision_correct: bool           # 攻击场景应为 contain_escalate
    confidence: float
    stop_reason: str
    rounds_used: int
    probes_used: int

    # 攻击覆盖率
    total_attack_edges: int          # ground_truth 中的攻击事件数
    found_attack_edges: int          # 被图捕获的攻击事件数
    recall: float                    # found / total

    # 精确率（图中事件有多少是攻击）
    total_graph_events: int
    attack_in_graph: int
    precision: float

    f1: float

    # 性能
    elapsed_seconds: float
    llm_calls: int = 0
    llm_tokens: int = 0

    # 详情
    leading_explanation: str = ""
    alternatives: list = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════
# 核心函数
# ═══════════════════════════════════════════════════════════════════

def load_scenario(scenario_id: str) -> tuple[dict, dict]:
    """加载场景数据和注册表配置。

    Returns:
        (scenario_data, registry_spec)
    """
    if not REGISTRY_PATH.exists():
        raise FileNotFoundError(f"Registry not found: {REGISTRY_PATH}")

    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    scenarios = registry.get("scenarios", {})

    if scenario_id not in scenarios:
        raise KeyError(
            f"Scenario '{scenario_id}' not in registry. "
            f"Available: {list(scenarios.keys())}"
        )

    spec = scenarios[scenario_id]
    scenario_file = SOAR_ENV_DIR / spec["file"]

    if not scenario_file.exists():
        raise FileNotFoundError(f"Scenario file not found: {scenario_file}")

    scenario_data = json.loads(scenario_file.read_text(encoding="utf-8"))
    return scenario_data, spec


def find_entry_event(scenario_data: dict, registry_spec: dict) -> dict:
    """在场景 events 中找到 entry_alert_ref 对应的事件。

    优先使用 registry 中的 entry_alert_ref 覆盖值，
    否则使用 meta.entry_alert_ref。
    """
    # 确定 entry ref
    entry_ref = registry_spec.get("entry_alert_ref")
    if not entry_ref:
        entry_ref = scenario_data.get("meta", {}).get("entry_alert_ref")

    if not entry_ref:
        # 无明确入口 → 使用第一个攻击事件
        for event in scenario_data.get("events", []):
            if event.get("raw_log_ref", "").startswith("attack:"):
                return event
        # 没有攻击事件 → 使用第一个事件
        events = scenario_data.get("events", [])
        if events:
            return events[0]
        raise ValueError("Scenario has no events")

    # 在 events 中查找 matching raw_log_ref
    for event in scenario_data.get("events", []):
        if event.get("raw_log_ref") == entry_ref:
            return event

    # 如果没找到精确匹配，放宽搜索
    for event in scenario_data.get("events", []):
        ref = event.get("raw_log_ref", "")
        if entry_ref in ref or ref in entry_ref:
            return event

    raise ValueError(
        f"Entry alert ref '{entry_ref}' not found in scenario events"
    )


def _parse_timestamp(ts_str: str | None) -> str | None:
    """将 ISO 8601 时间戳转为 unix epoch 字符串（兼容 orchestrator float 转换）。"""
    if not ts_str:
        return None
    try:
        from datetime import datetime
        cleaned = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(cleaned)
        return str(dt.timestamp())
    except (ValueError, TypeError):
        return ts_str


def build_alert_event(scenario_event: dict):
    """从场景事件构建 AlertEvent。"""
    from trace_agent.decision.types import AlertEvent

    technique = scenario_event.get("technique", "T0000")
    base_technique = technique.split(".")[0]

    # 推导 tactic
    tactic = TECHNIQUE_TACTIC_MAP.get(technique)
    if not tactic:
        tactic = TECHNIQUE_TACTIC_MAP.get(base_technique, "execution")

    # 提取 host_uid
    src_entity = scenario_event.get("src_entity", {})
    asset_id = src_entity.get("attrs", {}).get("host_uid", "")
    if not asset_id:
        dst_entity = scenario_event.get("dst_entity", {})
        asset_id = dst_entity.get("attrs", {}).get("host_uid", "")

    # 时间戳 → unix epoch string (兼容 float() 转换)
    timestamp = _parse_timestamp(scenario_event.get("ts"))

    # anomaly_score
    anomaly_score = scenario_event.get("anomaly_score", 0.5)

    # 属性
    attributes = {
        "action": scenario_event.get("action"),
        "process_name": src_entity.get("attrs", {}).get("name"),
        "raw_log_ref": scenario_event.get("raw_log_ref", ""),
        "ocsf_class_uid": scenario_event.get("ocsf_class_uid"),
    }

    return AlertEvent(
        technique_id=technique,
        tactic=tactic,
        platform=None,
        log_source=_infer_log_source(scenario_event),
        asset_id=asset_id,
        timestamp=timestamp,
        anomaly_score=anomaly_score,
        attributes=attributes,
    )


def _infer_log_source(event: dict) -> str:
    """从 ocsf_class_uid 或 action 推导 log source。"""
    ocsf_map = {2001: "process_tree", 4001: "network_flow",
                6001: "file_monitoring", 5002: "auth_log"}
    ocsf_uid = event.get("ocsf_class_uid")
    if ocsf_uid and ocsf_uid in ocsf_map:
        return ocsf_map[ocsf_uid]
    action = event.get("action", "")
    if action in ("EXEC", "FORK", "INJECT"):
        return "process_tree"
    if action in ("CONNECT", "DNS_QUERY"):
        return "network_flow"
    if action in ("WRITE", "OPEN_FILE"):
        return "file_monitoring"
    if action == "AUTH":
        return "auth_log"
    return "unknown"


def run_scenario_test(
    scenario_id: str,
    use_llm: bool = True,
    max_rounds: int = 30,
    verbose: bool = True,
) -> ScenarioMetrics:
    """运行单个场景的完整 LOCK 循环测试。

    Steps:
    1. 加载场景
    2. 找 entry event → 构建 AlertEvent
    3. 创建 ScenarioExecutor
    4. 创建 LLM client (if use_llm)
    5. 创建 DecisionOrchestrator
    6. 通过 ingest_factory 注入 LLMIngestPipeline
    7. orchestrator.run()
    8. 评估 result vs ground_truth
    9. 返回 ScenarioMetrics
    """
    from trace_agent.loop.scenario_executor import ScenarioExecutor
    from trace_agent.agents.orchestrator import (
        DecisionOrchestrator, InvestigationResult, BudgetState,
    )

    t0 = time.time()
    llm_client = None

    if verbose:
        print(f"\n{'='*60}")
        print(f"  场景: {scenario_id}")
        print(f"{'='*60}")

    # ── Step 1: 加载场景 ──
    scenario_data, registry_spec = load_scenario(scenario_id)
    run_config = registry_spec.get("run", {})
    events_count = len(scenario_data.get("events", []))

    if verbose:
        print(f"  事件数: {events_count}")
        print(f"  Ground truth 攻击边: "
              f"{len(scenario_data.get('ground_truth', {}).get('attack_edge_refs', []))}")

    # ── Step 2: 找 entry event → AlertEvent ──
    entry_event = find_entry_event(scenario_data, registry_spec)
    alert = build_alert_event(entry_event)

    if verbose:
        print(f"  入口告警: {alert.technique_id} @ {alert.asset_id}")
        print(f"  Tactic: {alert.tactic}")

    # ── Step 3: 创建 ScenarioExecutor ──
    executor = ScenarioExecutor(scenario_data, seed=42)

    # ── Step 3.5: 时间窗对齐到入口告警 ──
    alert_ts = float(alert.timestamp or 0)
    if alert_ts > 0 and hasattr(executor, "_time_cursor"):
        executor._time_cursor = alert_ts
        if verbose:
            print(f"  时间窗对齐: cursor={alert_ts:.0f}")

    # ── Step 4: 创建 LLM client ──
    if use_llm:
        try:
            from trace_agent.llm import create_llm_client
            llm_client = create_llm_client()
            if verbose:
                print(f"  LLM: DeepSeek 已连接")
        except Exception as e:
            if verbose:
                print(f"  LLM: 初始化失败 ({e})，降级为纯规则模式")
            llm_client = None

    # ── Step 5: 创建 Orchestrator ──
    budget = BudgetState(
        total_rounds=max_rounds,
        total_probes=max_rounds * 8,
        fanout_per_round=run_config.get("beam_width", 5),
    )
    ingest_factory = None
    if llm_client is not None:
        from trace_agent.loop.llm_ingest import LLMIngestPipeline

        ingest_factory = lambda trust, graph, ledger: LLMIngestPipeline(
            trust,
            graph,
            ledger,
            llm_client=llm_client,
            mode="assist",
        )

    orch = DecisionOrchestrator(
        alert=alert,
        executor=executor,
        prior_manager=None,
        budget=budget,
        ingest_factory=ingest_factory,
    )

    # ── Step 7: 运行 LOCK 循环 ──
    if verbose:
        print(f"  运行 LOCK 循环 (max_rounds={max_rounds})...")

    result: InvestigationResult = orch.run(max_rounds=max_rounds)

    elapsed = time.time() - t0

    if verbose:
        conf_str = f"{result.confidence:.3f}" if result.confidence is not None else "N/A"
        print(f"  Decision: {result.decision} (confidence={conf_str})")
        print(f"  Stop reason: {result.stop_reason}")
        print(f"  Rounds: {result.rounds_used}, Events: {result.total_events_processed}")
        print(f"  Elapsed: {elapsed:.1f}s")

    # ── Step 8: 评估 ──
    metrics = evaluate_result(result, orch, scenario_data, scenario_id, elapsed)

    # 补充 LLM 统计
    if llm_client is not None:
        client_stats = llm_client.stats
        metrics.llm_calls = client_stats.get("total_calls", 0)
        metrics.llm_tokens = client_stats.get("total_tokens", 0)

    if verbose:
        print(f"  Recall: {metrics.recall:.3f} | Precision: {metrics.precision:.3f} | F1: {metrics.f1:.3f}")
        correct_mark = "YES" if metrics.decision_correct else "NO"
        print(f"  Decision correct: {correct_mark}")

    return metrics


def evaluate_result(
    result,
    orchestrator,
    scenario_data: dict,
    scenario_id: str,
    elapsed: float,
) -> ScenarioMetrics:
    """对比 LOCK 结果与 ground_truth 计算指标。"""
    gt = scenario_data.get("ground_truth", {})
    attack_refs = set(gt.get("attack_edge_refs", []))
    total_attack_edges = len(attack_refs)

    # 从 orchestrator.graph 获取所有已确认的节点 ID
    graph_node_ids: set[str] = set()
    if orchestrator.graph is not None:
        graph_node_ids = set(orchestrator.graph._nodes.keys())

    total_graph_events = len(graph_node_ids)

    # 计算攻击覆盖
    found_attack_edges = len(graph_node_ids & attack_refs)
    attack_in_graph = sum(
        1 for nid in graph_node_ids if nid.startswith("attack:")
    )

    # Precision / Recall / F1
    precision = (attack_in_graph / total_graph_events) if total_graph_events > 0 else 0.0
    recall = (found_attack_edges / total_attack_edges) if total_attack_edges > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    # 决策正确性：已知攻击场景 → 应为 contain_escalate
    decision = result.decision or "unknown"
    decision_correct = (decision == "contain_escalate")

    return ScenarioMetrics(
        scenario_id=scenario_id,
        decision=decision,
        decision_correct=decision_correct,
        confidence=result.confidence or 0.0,
        stop_reason=result.stop_reason or "unknown",
        rounds_used=result.rounds_used,
        probes_used=result.total_events_processed,
        total_attack_edges=total_attack_edges,
        found_attack_edges=found_attack_edges,
        recall=recall,
        total_graph_events=total_graph_events,
        attack_in_graph=attack_in_graph,
        precision=precision,
        f1=f1,
        elapsed_seconds=elapsed,
        leading_explanation=result.leading_explanation,
        alternatives=result.alternatives,
    )


def run_all_scenarios(
    use_llm: bool = True,
    max_rounds: int = 30,
    verbose: bool = True,
) -> dict[str, ScenarioMetrics]:
    """运行全部三个场景。"""
    results: dict[str, ScenarioMetrics] = {}

    for scenario_id in ["pipeline_18", "apt_5host", "multipath_12host"]:
        try:
            metrics = run_scenario_test(
                scenario_id,
                use_llm=use_llm,
                max_rounds=max_rounds,
                verbose=verbose,
            )
            results[scenario_id] = metrics
        except Exception as e:
            error_msg = f"{type(e).__name__}: {e}"
            if verbose:
                print(f"\n  [ERROR] {scenario_id}: {error_msg}")
                traceback.print_exc()
            results[scenario_id] = ScenarioMetrics(
                scenario_id=scenario_id,
                decision="error",
                decision_correct=False,
                confidence=0.0,
                stop_reason="exception",
                rounds_used=0,
                probes_used=0,
                total_attack_edges=0,
                found_attack_edges=0,
                recall=0.0,
                total_graph_events=0,
                attack_in_graph=0,
                precision=0.0,
                f1=0.0,
                elapsed_seconds=0.0,
                errors=[error_msg],
            )

    return results


def save_results(
    results: dict[str, ScenarioMetrics],
    output_dir: Optional[Path] = None,
) -> Path:
    """保存结果到 JSON。"""
    if output_dir is None:
        output_dir = RESULTS_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    output_path = output_dir / f"lock_integration_{timestamp}.json"

    valid_results = {k: v for k, v in results.items() if v.decision != "error"}

    data = {
        "timestamp": timestamp,
        "scenarios": {k: asdict(v) for k, v in results.items()},
        "summary": {
            "total": len(results),
            "correct_decisions": sum(
                1 for v in results.values() if v.decision_correct
            ),
            "avg_recall": (
                sum(v.recall for v in valid_results.values())
                / max(1, len(valid_results))
            ),
            "avg_precision": (
                sum(v.precision for v in valid_results.values())
                / max(1, len(valid_results))
            ),
            "avg_f1": (
                sum(v.f1 for v in valid_results.values())
                / max(1, len(valid_results))
            ),
            "total_elapsed": sum(v.elapsed_seconds for v in results.values()),
            "total_llm_calls": sum(v.llm_calls for v in results.values()),
            "total_llm_tokens": sum(v.llm_tokens for v in results.values()),
        },
    }
    output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return output_path


def print_report(results: dict[str, ScenarioMetrics]) -> None:
    """打印汇总报告到 stdout。"""
    print("\n")
    print("=" * 72)
    print("  SOAR + LOCK Integration Report")
    print("=" * 72)

    # Table header
    header = (
        f"{'Scenario':<20} {'Decision':<18} {'Correct':^7} "
        f"{'Recall':>7} {'Prec':>7} {'F1':>7} "
        f"{'Rounds':>6} {'Time':>7}"
    )
    print(header)
    print("-" * 72)

    for sid, m in results.items():
        correct_mark = "Y" if m.decision_correct else "N"
        row = (
            f"{sid:<20} {m.decision:<18} {correct_mark:^6} "
            f"{m.recall:>7.3f} {m.precision:>7.3f} {m.f1:>7.3f} "
            f"{m.rounds_used:>5} {m.elapsed_seconds:>6.1f}s"
        )
        print(row)
        if m.errors:
            for err in m.errors:
                print(f"  └─ ERROR: {err}")

    print("-" * 72)

    # 汇总
    valid = [v for v in results.values() if v.decision != "error"]
    total = len(results)
    correct = sum(1 for v in results.values() if v.decision_correct)
    avg_recall = sum(v.recall for v in valid) / max(1, len(valid))
    avg_prec = sum(v.precision for v in valid) / max(1, len(valid))
    avg_f1 = sum(v.f1 for v in valid) / max(1, len(valid))
    total_time = sum(v.elapsed_seconds for v in results.values())
    total_llm = sum(v.llm_calls for v in results.values())

    print(f"  Decision correct: {correct}/{total}")
    print(f"  Avg Recall: {avg_recall:.3f}")
    print(f"  Avg Precision: {avg_prec:.3f}")
    print(f"  Avg F1: {avg_f1:.3f}")
    print(f"  Total time: {total_time:.1f}s")
    if total_llm > 0:
        print(f"  LLM calls: {total_llm}")
    print("=" * 72)


# ═══════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOAR + LLM LOCK 集成测试")
    parser.add_argument(
        "--scenario", type=str, default=None,
        help="单个场景ID (pipeline_18 / apt_5host / multipath_12host)",
    )
    parser.add_argument(
        "--no-llm", action="store_true",
        help="禁用 LLM（纯规则模式）",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=30,
        help="最大轮数 (default: 30)",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="减少输出",
    )
    args = parser.parse_args()

    use_llm = not args.no_llm

    if args.scenario:
        metrics = run_scenario_test(
            args.scenario,
            use_llm=use_llm,
            max_rounds=args.max_rounds,
            verbose=not args.quiet,
        )
        results = {args.scenario: metrics}
    else:
        results = run_all_scenarios(
            use_llm=use_llm,
            max_rounds=args.max_rounds,
            verbose=not args.quiet,
        )

    print_report(results)
    output_path = save_results(results)
    print(f"\nResults saved to: {output_path}")
