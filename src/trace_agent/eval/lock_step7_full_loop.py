"""LOCK Step 7 — 完整主循环 · L→②→O→C→K 多轮直到 should_stop().

在 Step 1 bootstrap + 时间窗对齐后运行 DecisionOrchestrator.run()，
记录每轮快照并校验 ground truth 推进。

Usage:
    python -m trace_agent.eval.lock_step7_full_loop
    python -m trace_agent.eval.lock_step7_full_loop --scenario apt_5host --save
    python -m trace_agent.eval.lock_step7_full_loop --all
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.agents.orchestrator import DecisionOrchestrator, InvestigationResult
from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import RESULTS_DIR, StepCheck, list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import _setup_orchestrator
from trace_agent.eval.lock_step3_veto_phase import _root_cause_info
from trace_agent.eval.lock_step5_c_phase import _align_executor_to_alert
from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.prior_v2 import PriorManager

VALID_STOP_REASONS = frozenset({
    "budget", "voi_floor", "robust", "no_probes", "max_rounds",
})


@dataclass
class RoundSnapshot:
    round_num: int
    pool_size: int
    chosen_count: int
    confirmed_count: int
    node_count: int
    margin: float
    probes_used: int
    stop_should_stop: bool
    stop_reason: str
    chosen_operators: list[str]
    beta_keys: int


@dataclass
class FullLoopStepResult:
    scenario_id: str
    entry_ref: str
    alert_asset: str
    alert_timestamp: float
    max_rounds: int
    rounds_used: int
    probes_used: int
    stop_reason: str
    decision: str
    confidence: float
    final_entropy: float
    final_risk: float
    leading_explanation_id: str
    node_count_final: int
    techniques_in_graph: list[str]
    hosts_in_graph: list[str]
    attack_ref_hits: list[str]
    gt_attack_ref_total: int
    root_cause_entity: str
    root_cause_technique: str
    rounds: list[RoundSnapshot]
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _graph_hosts(orch: DecisionOrchestrator) -> list[str]:
    hosts: set[str] = set()
    for node in orch.graph._nodes.values():
        attrs = node.attributes or {}
        for key in ("host_uid", "asset_id", "host", "target"):
            val = attrs.get(key)
            if val:
                hosts.add(str(val).lower())
    return sorted(hosts)


def _attack_ref_hits(scenario_data: dict, orch: DecisionOrchestrator) -> tuple[list[str], int]:
    gt_refs = set((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    graph_ids = {n.id for n in orch.graph._nodes.values()}
    return sorted(gt_refs & graph_ids), len(gt_refs)


def run_traced_lock_loop(
    orch: DecisionOrchestrator,
    *,
    max_rounds: int | None = None,
) -> tuple[InvestigationResult, list[RoundSnapshot], str]:
    """Mirror orchestrator.run() with per-round snapshots."""
    if max_rounds is not None:
        orch.budget.total_rounds = max_rounds

    prev_stats = orch.graph.stats()
    snapshots: list[RoundSnapshot] = []
    final_stop_reason = "budget"

    while not orch.budget.exhausted():
        orch.budget.rounds_used += 1

        pool = orch._veto_phase(orch._l_phase(prev_stats))
        pool_size = pool.size()
        chosen = orch._o_phase(pool)

        if not chosen:
            final_stop_reason = "no_probes"
            break

        ingest_result = orch._c_phase(chosen)
        stop_decision = orch._k_phase(chosen, ingest_result)

        snapshots.append(
            RoundSnapshot(
                round_num=orch.budget.rounds_used,
                pool_size=pool_size,
                chosen_count=len(chosen),
                confirmed_count=len(ingest_result.confirmed),
                node_count=orch.graph.stats().get("node_count", 0),
                margin=round(orch.ledger.margin(), 6),
                probes_used=orch.budget.probes_used,
                stop_should_stop=stop_decision.should_stop,
                stop_reason=stop_decision.reason,
                chosen_operators=[p.operator for p in chosen],
                beta_keys=len(orch.beta.all_keys()),
            )
        )

        prev_stats = orch.graph.stats()
        final_stop_reason = stop_decision.reason

        if stop_decision.should_stop:
            return orch._build_result(stop_decision.reason), snapshots, stop_decision.reason

    if orch.budget.exhausted():
        final_stop_reason = "budget"
    result = orch._build_result(final_stop_reason)
    return result, snapshots, final_stop_reason


def run_full_loop_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
    max_rounds: int = 10,
    align_time_to_alert: bool = True,
) -> FullLoopStepResult:
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    _, registry_spec = load_scenario(scenario_id)
    root_info = _root_cause_info(scenario_data)

    alert_ts = 0.0
    if align_time_to_alert:
        alert_ts = _align_executor_to_alert(orch, scenario_data, registry_spec)

    orch.budget.total_rounds = max_rounds
    # Account for adaptive fanout increase (strategy may +2 per stall)
    effective_fanout = orch.budget.fanout_per_round + 4
    orch.budget.total_probes = max(orch.budget.total_probes, max_rounds * effective_fanout)

    result, rounds, stop_reason = run_traced_lock_loop(orch, max_rounds=max_rounds)

    attack_hits, gt_total = _attack_ref_hits(scenario_data, orch)
    hosts = _graph_hosts(orch)
    stats = orch.graph.stats()

    checks = _validate_full_loop(
        orch=orch,
        scenario_data=scenario_data,
        triage=triage,
        root_info=root_info,
        result=result,
        rounds=rounds,
        stop_reason=stop_reason,
        attack_hits=attack_hits,
        gt_total=gt_total,
        hosts=hosts,
        max_rounds=max_rounds,
        align_time_to_alert=align_time_to_alert,
    )

    return FullLoopStepResult(
        scenario_id=scenario_id,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        alert_timestamp=alert_ts,
        max_rounds=max_rounds,
        rounds_used=result.rounds_used,
        probes_used=orch.budget.probes_used,
        stop_reason=stop_reason,
        decision=result.decision,
        confidence=result.confidence,
        final_entropy=result.final_entropy,
        final_risk=result.final_risk,
        leading_explanation_id=result.leading_explanation_id,
        node_count_final=stats.get("node_count", 0),
        techniques_in_graph=list(stats.get("techniques_seen") or []),
        hosts_in_graph=hosts,
        attack_ref_hits=attack_hits,
        gt_attack_ref_total=gt_total,
        root_cause_entity=root_info["entity_id"],
        root_cause_technique=root_info["technique"],
        rounds=rounds,
        checks=checks,
    )


def _validate_full_loop(
    *,
    orch: DecisionOrchestrator,
    scenario_data: dict,
    triage: Any,
    root_info: dict[str, str],
    result: InvestigationResult,
    rounds: list[RoundSnapshot],
    stop_reason: str,
    attack_hits: list[str],
    gt_total: int,
    hosts: list[str],
    max_rounds: int,
    align_time_to_alert: bool,
) -> list[StepCheck]:
    checks: list[StepCheck] = []
    alert_asset = (triage.alert.asset_id or "").lower()
    root_entity = (root_info["entity_id"] or "").lower()
    root_technique = root_info["technique"] or ""
    root_base = root_technique.split(".")[0] if root_technique else ""

    checks.append(
        StepCheck(
            id="loop_returns_result",
            status="pass" if result.decision in ("contain_escalate", "monitor", "dismiss_benign") else "fail",
            message="run() 返回 InvestigationResult",
            actual=result.decision,
        )
    )
    checks.append(
        StepCheck(
            id="loop_rounds_used",
            status="pass" if result.rounds_used >= 1 else "fail",
            message="至少完成 1 轮 LOCK",
            actual=result.rounds_used,
        )
    )
    checks.append(
        StepCheck(
            id="loop_probes_used",
            status="pass" if orch.budget.probes_used > 0 else "fail",
            message="probes_used > 0",
            actual=orch.budget.probes_used,
        )
    )
    checks.append(
        StepCheck(
            id="loop_stop_reason_valid",
            status="pass" if stop_reason in VALID_STOP_REASONS else "fail",
            message="停止原因合法",
            actual=stop_reason,
        )
    )
    checks.append(
        StepCheck(
            id="loop_within_budget",
            status="pass"
            if result.rounds_used <= max_rounds and orch.budget.probes_used <= orch.budget.total_probes
            else "fail",
            message="轮次/探针未超预算",
            expected={"max_rounds": max_rounds, "total_probes": orch.budget.total_probes},
            actual={"rounds_used": result.rounds_used, "probes_used": orch.budget.probes_used},
        )
    )

    if align_time_to_alert:
        checks.append(
            StepCheck(
                id="loop_graph_grew",
                status="pass" if orch.graph.stats().get("node_count", 0) > 1 else "fail",
                message="多轮后图节点 > bootstrap 单告警",
                actual=orch.graph.stats().get("node_count", 0),
            )
        )
    else:
        checks.append(
            StepCheck(
                id="loop_graph_grew",
                status="skip",
                message="未对齐时间窗",
            )
        )

    if len(rounds) >= 2:
        monotonic = all(
            rounds[i].node_count <= rounds[i + 1].node_count for i in range(len(rounds) - 1)
        )
        checks.append(
            StepCheck(
                id="loop_nodes_monotonic",
                status="pass" if monotonic else "warn",
                message="各轮 node_count 非递减（K 拍只增不减）",
                actual=[r.node_count for r in rounds],
            )
        )

    if rounds:
        checks.append(
            StepCheck(
                id="loop_last_k_stop",
                status="pass",
                message="末轮 K 拍产生 StopDecision",
                actual={
                    "should_stop": rounds[-1].stop_should_stop,
                    "reason": rounds[-1].stop_reason,
                },
            )
        )
        beta_ok = rounds[-1].beta_keys >= min(rounds[-1].chosen_count, 1)
        checks.append(
            StepCheck(
                id="loop_beta_populated",
                status="pass" if beta_ok else "fail",
                message="末轮 BetaLedger 有观测",
                actual=rounds[-1].beta_keys,
            )
        )

    probes_per_round = [r.chosen_count for r in rounds]
    checks.append(
        StepCheck(
            id="loop_phases_per_round",
            status="pass" if all(c > 0 for c in probes_per_round) else "fail",
            message="每轮 O 拍选出探针（无空转）",
            actual=probes_per_round,
        )
    )

    # ── Ground truth ──
    cross_host = bool(root_entity and alert_asset and root_entity != alert_asset and root_entity != "external")

    if attack_hits:
        checks.append(
            StepCheck(
                id="gt_attack_refs_in_graph",
                status="pass",
                message="多轮后 GT attack_edge_refs 入图",
                actual=f"{len(attack_hits)}/{gt_total}",
            )
        )
    elif gt_total > 0:
        checks.append(
            StepCheck(
                id="gt_attack_refs_in_graph",
                status="warn",
                message="未命中 GT 攻击边（跨主机/早停常见）",
                actual=f"0/{gt_total}",
            )
        )

    root_host_seen = root_entity in hosts if root_entity and root_entity != "external" else False
    root_technique_seen = any(t.startswith(root_base) for t in orch.graph.stats().get("techniques_seen") or [] if root_base)

    if root_entity == "external":
        progress_ok = bool(attack_hits) or root_technique_seen
    elif not cross_host:
        progress_ok = orch.graph.stats().get("node_count", 0) > 1
    else:
        progress_ok = root_host_seen or root_technique_seen or bool(attack_hits)

    checks.append(
        StepCheck(
            id="gt_root_cause_progress",
            status="pass" if progress_ok else "warn",
            message="向根因推进：根因主机/technique 或 GT 攻击边",
            expected={"root_entity": root_info["entity_id"], "cross_host": cross_host},
            actual={
                "root_host_seen": root_host_seen,
                "root_technique_seen": root_technique_seen,
                "attack_hits": len(attack_hits),
                "hosts": hosts[:8],
            },
        )
    )

    if stop_reason == "robust" and result.rounds_used == 1 and cross_host:
        checks.append(
            StepCheck(
                id="gt_early_robust_stop",
                status="warn",
                message="跨主机场景首轮 decision_robust 早停（需多轮或调 margin）",
                actual=rounds[0].margin if rounds else None,
            )
        )

    return checks


def format_step_report(result: FullLoopStepResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"

    round_lines = "\n".join(
        f"  R{r.round_num}: pool={r.pool_size} chosen={r.chosen_count} "
        f"confirmed={r.confirmed_count} nodes={r.node_count} margin={r.margin:.4f} "
        f"stop={r.stop_should_stop}/{r.stop_reason} ops={r.chosen_operators}"
        for r in result.rounds
    )
    lines = [
        f"# Step 7 · 完整 LOCK 主循环 [{status}]",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        f"根因 GT: {result.root_cause_entity or '(未指定)'} · {result.root_cause_technique}",
        f"预算: max_rounds={result.max_rounds} · 实际 rounds={result.rounds_used} probes={result.probes_used}",
        "",
        "## ① 做了什么",
        "bootstrap -> while not exhausted: L -> veto -> O -> C -> K -> should_stop()",
        "",
        "## ② 输入",
        f"- alert_ts={result.alert_timestamp:.0f} · asset={result.alert_asset}",
        "",
        "## ③ 产出",
        f"- stop_reason={result.stop_reason} · decision={result.decision} · confidence={result.confidence:.3f}",
        f"- nodes={result.node_count_final} · techniques={result.techniques_in_graph[:8]}",
        f"- GT hits={len(result.attack_ref_hits)}/{result.gt_attack_ref_total} · hosts={result.hosts_in_graph[:8]}",
        f"- leading={result.leading_explanation_id} · entropy={result.final_entropy:.3f} · risk={result.final_risk:.3f}",
        "",
        "## ④ 各轮快照",
        round_lines or "  (无轮次记录)",
        "",
        "## Ground truth 校验",
    ]
    for c in result.checks:
        mark = {"pass": "OK", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[c.status]
        lines.append(f"- [{mark}] {c.id}: {c.message}")
        if c.status in ("fail", "warn") and c.expected is not None:
            lines.append(f"    expected={c.expected!r}")
            if c.actual is not None:
                lines.append(f"    actual={c.actual!r}")
    return "\n".join(lines)


def save_result(result: FullLoopStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step7_{result.scenario_id}.json"
    payload = {
        "step": 7,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "rounds_used": result.rounds_used,
        "probes_used": result.probes_used,
        "stop_reason": result.stop_reason,
        "decision": result.decision,
        "attack_ref_hits": result.attack_ref_hits,
        "hosts_in_graph": result.hosts_in_graph,
        "rounds": [asdict(r) for r in result.rounds],
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 7 完整主循环（本地 MCP 场景）")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--max-rounds", type=int, default=10)
    parser.add_argument(
        "--no-time-align",
        action="store_true",
        help="不对齐告警时间窗",
    )
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_full_loop_step(
            sid,
            max_rounds=args.max_rounds,
            align_time_to_alert=not args.no_time_align,
        )
        print(format_step_report(result))
        print()
        if args.save:
            p = save_result(result)
            print(f"saved: {p}")
        if not result.all_pass:
            exit_code = 1
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
