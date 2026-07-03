"""LOCK Step 9 — 全场景 GT attack_edge_refs 覆盖率报告.

对三场景运行完整 LOCK 循环，统计 ground_truth.attack_edge_refs 入图命中率，
可选 extended 模式（min_rounds_after_root 扩图）。

Usage:
    python -m trace_agent.eval.lock_step9_gt_coverage
    python -m trace_agent.eval.lock_step9_gt_coverage --all --save
    python -m trace_agent.eval.lock_step9_gt_coverage --extend --save
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import RESULTS_DIR, StepCheck, list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import _setup_orchestrator
from trace_agent.eval.lock_step3_veto_phase import _root_cause_info, _technique_to_tactic
from trace_agent.eval.lock_step5_c_phase import _align_executor_to_alert
from trace_agent.eval.lock_step7_full_loop import RoundSnapshot
from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.prior_v2 import PriorManager

SCENARIO_GT_TOTALS = {
    "pipeline_18": 18,
    "apt_5host": 25,
    "multipath_12host": 31,
}


@dataclass
class GtRefRecord:
    ref: str
    hit: bool
    technique: str
    tactic: str
    host_uid: str
    step_index: int | None


@dataclass
class CoverageRoundPoint:
    round_num: int
    cumulative_hits: int
    node_count: int
    new_hits: list[str]


@dataclass
class GtCoverageResult:
    scenario_id: str
    mode: str
    entry_ref: str
    alert_asset: str
    gt_total: int
    hits_count: int
    misses_count: int
    coverage_pct: float
    root_cause_entity: str
    root_cause_technique: str
    root_host_hit: bool
    root_technique_hit: bool
    rounds_used: int
    probes_used: int
    stop_reason: str
    hits: list[str]
    misses: list[str]
    ref_records: list[GtRefRecord]
    coverage_curve: list[CoverageRoundPoint]
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _build_event_index(scenario_data: dict) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for ev in scenario_data.get("events", []):
        ref = ev.get("raw_log_ref")
        if ref:
            index[str(ref)] = ev
    return index


def _ref_metadata(ref: str, event_index: dict[str, dict]) -> dict[str, Any]:
    ev = event_index.get(ref) or {}
    technique = str(ev.get("technique") or "")
    tactic = _technique_to_tactic(technique).lower() if technique else ""
    host = ""
    for side in ("src_entity", "dst_entity"):
        entity = ev.get(side) or {}
        host = (entity.get("attrs") or {}).get("host_uid") or host
    step = ev.get("step_index")
    return {
        "technique": technique,
        "tactic": tactic,
        "host_uid": str(host or ""),
        "step_index": int(step) if step is not None else None,
    }


def _graph_ids(orch) -> set[str]:
    return {n.id for n in orch.graph._nodes.values()}


def _graph_hosts(orch) -> set[str]:
    hosts: set[str] = set()
    for node in orch.graph._nodes.values():
        attrs = node.attributes or {}
        for key in ("host_uid", "asset_id", "host", "target"):
            val = attrs.get(key)
            if val:
                hosts.add(str(val).lower())
    return hosts


def _graph_techniques(orch) -> set[str]:
    return set(orch.graph.stats().get("techniques_seen") or [])


def _run_traced_with_gt_tracking(
    orch,
    gt_refs: list[str],
    *,
    max_rounds: int,
) -> tuple[Any, list[RoundSnapshot], str, list[CoverageRoundPoint]]:
    """LOCK 主循环 + 每轮 K 拍后统计 GT 命中。"""
    gt_set = set(gt_refs)
    if max_rounds is not None:
        orch.budget.total_rounds = max_rounds

    prev_stats = orch.graph.stats()
    snapshots: list[RoundSnapshot] = []
    curve: list[CoverageRoundPoint] = []
    final_stop_reason = "budget"
    seen_hits: set[str] = set()

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

        graph_ids = _graph_ids(orch)
        hit_refs = gt_set & graph_ids
        new_hits = sorted(hit_refs - seen_hits)
        seen_hits = set(hit_refs)

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
        curve.append(
            CoverageRoundPoint(
                round_num=orch.budget.rounds_used,
                cumulative_hits=len(hit_refs),
                node_count=orch.graph.stats().get("node_count", 0),
                new_hits=new_hits,
            )
        )
        prev_stats = orch.graph.stats()
        final_stop_reason = stop_decision.reason
        if stop_decision.should_stop:
            return orch._build_result(stop_decision.reason), snapshots, stop_decision.reason, curve

    if orch.budget.exhausted():
        final_stop_reason = "budget"
    return orch._build_result(final_stop_reason), snapshots, final_stop_reason, curve


def run_gt_coverage_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
    max_rounds: int = 15,
    extend_after_root: bool = False,
    min_rounds_before_robust: int = 1,
    min_rounds_after_root: int = 1,
) -> GtCoverageResult:
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    _, registry_spec = load_scenario(scenario_id)
    root_info = _root_cause_info(scenario_data)
    _align_executor_to_alert(orch, scenario_data, registry_spec)

    # Time cursor is already aligned by _align_executor_to_alert above;
    # progressive discovery via TIME_WINDOW_STEP gives realistic per-round coverage.

    if extend_after_root:
        min_rounds_before_robust = max(min_rounds_before_robust, 3)
        min_rounds_after_root = max(min_rounds_after_root, 10)

    orch.budget.min_rounds_before_robust = min_rounds_before_robust
    orch.budget.min_rounds_after_root = min_rounds_after_root
    orch.budget.total_rounds = max_rounds
    orch.budget.total_probes = max(orch.budget.total_probes, max_rounds * orch.budget.fanout_per_round)

    gt_refs = list((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    event_index = _build_event_index(scenario_data)
    mode = "extended" if extend_after_root else "standard"

    result, rounds, stop_reason, coverage_curve = _run_traced_with_gt_tracking(
        orch, gt_refs, max_rounds=max_rounds,
    )
    graph_ids = _graph_ids(orch)
    hits = sorted(set(gt_refs) & graph_ids)
    misses = sorted(set(gt_refs) - set(hits))

    ref_records: list[GtRefRecord] = []
    for ref in gt_refs:
        meta = _ref_metadata(ref, event_index)
        ref_records.append(
            GtRefRecord(
                ref=ref,
                hit=ref in graph_ids,
                technique=meta["technique"],
                tactic=meta["tactic"],
                host_uid=meta["host_uid"],
                step_index=meta["step_index"],
            )
        )

    gt_total = len(gt_refs)
    hits_count = len(hits)
    coverage_pct = round(100.0 * hits_count / gt_total, 2) if gt_total else 0.0
    root_entity = (root_info["entity_id"] or "").lower()
    root_technique = root_info["technique"] or ""
    root_base = root_technique.split(".")[0] if root_technique else ""
    hosts = _graph_hosts(orch)
    techniques = _graph_techniques(orch)

    checks = _validate_coverage(
        scenario_id=scenario_id,
        mode=mode,
        gt_total=gt_total,
        hits_count=hits_count,
        coverage_pct=coverage_pct,
        root_entity=root_entity,
        root_technique=root_technique,
        root_host_hit=root_entity in hosts if root_entity and root_entity != "external" else True,
        root_technique_hit=any(t.startswith(root_base) for t in techniques if root_base),
        rounds_used=result.rounds_used,
        extend_after_root=extend_after_root,
    )

    return GtCoverageResult(
        scenario_id=scenario_id,
        mode=mode,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        gt_total=gt_total,
        hits_count=hits_count,
        misses_count=len(misses),
        coverage_pct=coverage_pct,
        root_cause_entity=root_info["entity_id"],
        root_cause_technique=root_technique,
        root_host_hit=root_entity in hosts if root_entity and root_entity != "external" else True,
        root_technique_hit=any(t.startswith(root_base) for t in techniques if root_base),
        rounds_used=result.rounds_used,
        probes_used=orch.budget.probes_used,
        stop_reason=stop_reason,
        hits=hits,
        misses=misses,
        ref_records=ref_records,
        coverage_curve=coverage_curve,
        checks=checks,
    )


def _validate_coverage(
    *,
    scenario_id: str,
    mode: str,
    gt_total: int,
    hits_count: int,
    coverage_pct: float,
    root_entity: str,
    root_technique: str,
    root_host_hit: bool,
    root_technique_hit: bool,
    rounds_used: int,
    extend_after_root: bool,
) -> list[StepCheck]:
    checks: list[StepCheck] = []
    expected_total = SCENARIO_GT_TOTALS.get(scenario_id, gt_total)

    checks.append(
        StepCheck(
            id="gt_ref_total",
            status="pass" if gt_total == expected_total else "warn",
            message="attack_edge_refs 数量与注册表一致",
            expected=expected_total,
            actual=gt_total,
        )
    )
    checks.append(
        StepCheck(
            id="gt_coverage_reported",
            status="pass",
            message="覆盖率 = hits / total",
            expected=f"{hits_count}/{gt_total}",
            actual=f"{coverage_pct}%",
        )
    )

    if hits_count == 0:
        checks.append(
            StepCheck(
                id="gt_min_hits",
                status="warn",
                message="未命中任何 GT 攻击边",
                actual=0,
            )
        )
    else:
        checks.append(
            StepCheck(
                id="gt_min_hits",
                status="pass",
                message="至少命中 1 条 GT 攻击边",
                actual=hits_count,
            )
        )

    if root_entity and root_entity != "external":
        checks.append(
            StepCheck(
                id="gt_root_host",
                status="pass" if root_host_hit else "warn",
                message="根因主机入图",
                expected=root_entity,
                actual=root_host_hit,
            )
        )
    if root_technique:
        checks.append(
            StepCheck(
                id="gt_root_technique",
                status="pass" if root_technique_hit else "warn",
                message="根因 technique 入图",
                expected=root_technique,
                actual=root_technique_hit,
            )
        )

    if extend_after_root:
        checks.append(
            StepCheck(
                id="gt_extend_mode",
                status="pass" if rounds_used >= 3 else "warn",
                message="extended 模式应跑多轮扩图",
                actual=rounds_used,
            )
        )

    return checks


def format_coverage_report(result: GtCoverageResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"

    hit_lines = ", ".join(result.hits[:8]) or "(none)"
    miss_lines = ", ".join(result.misses[:8]) or "(none)"
    if len(result.misses) > 8:
        miss_lines += f" ... +{len(result.misses) - 8} more"

    curve_lines = "\n".join(
        f"  R{p.round_num}: hits={p.cumulative_hits}/{result.gt_total} nodes={p.node_count}"
        for p in result.coverage_curve
    )

    lines = [
        f"# Step 9 · GT attack_edge_refs 覆盖率 [{status}] · {result.mode}",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        f"GT 总量: {result.gt_total} · 命中: {result.hits_count} · 未命中: {result.misses_count} · 覆盖率: {result.coverage_pct}%",
        f"轮次: {result.rounds_used} · probes: {result.probes_used} · stop: {result.stop_reason}",
        f"根因 GT: {result.root_cause_entity} · {result.root_cause_technique} · "
        f"host_hit={result.root_host_hit} tech_hit={result.root_technique_hit}",
        "",
        "## 命中 refs",
        hit_lines,
        "",
        "## 未命中 refs (sample)",
        miss_lines,
        "",
        "## 逐轮累计 (approx)",
        curve_lines or "  (无)",
        "",
        "## 校验",
    ]
    for c in result.checks:
        mark = {"pass": "OK", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[c.status]
        lines.append(f"- [{mark}] {c.id}: {c.message}")
    return "\n".join(lines)


def format_summary_table(results: list[GtCoverageResult]) -> str:
    lines = [
        "# Step 9 · GT 覆盖率汇总",
        "",
        "| 场景 | 模式 | GT 总量 | 命中 | 覆盖率 | 轮次 | 根因主机 | 根因 technique |",
        "|------|------|---------|------|--------|------|----------|----------------|",
    ]
    for r in results:
        lines.append(
            f"| {r.scenario_id} | {r.mode} | {r.gt_total} | {r.hits_count} | "
            f"{r.coverage_pct}% | {r.rounds_used} | {r.root_host_hit} | {r.root_technique_hit} |"
        )
    return "\n".join(lines)


def save_result(result: GtCoverageResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    suffix = result.mode
    out = path or RESULTS_DIR / f"lock_step9_{result.scenario_id}_{suffix}.json"
    payload = {
        "step": 9,
        "scenario_id": result.scenario_id,
        "mode": result.mode,
        "gt_total": result.gt_total,
        "hits_count": result.hits_count,
        "misses_count": result.misses_count,
        "coverage_pct": result.coverage_pct,
        "hits": result.hits,
        "misses": result.misses,
        "ref_records": [asdict(r) for r in result.ref_records],
        "coverage_curve": [asdict(p) for p in result.coverage_curve],
        "rounds_used": result.rounds_used,
        "stop_reason": result.stop_reason,
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_coverage_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def run_all_coverage(
    *,
    extend_after_root: bool = False,
    max_rounds: int = 15,
    prior_manager: PriorManager | None = None,
) -> list[GtCoverageResult]:
    prior = prior_manager or PriorManager(load_prior_bundle())
    return [
        run_gt_coverage_step(
            sid,
            prior_manager=prior,
            max_rounds=max_rounds,
            extend_after_root=extend_after_root,
        )
        for sid in list_scenario_ids()
    ]


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 9 GT attack_edge_refs 覆盖率")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--extend", action="store_true", help="根因后扩图 (min_rounds_after_root=10)")
    parser.add_argument("--max-rounds", type=int, default=15)
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    results: list[GtCoverageResult] = []
    exit_code = 0

    for sid in ids:
        result = run_gt_coverage_step(
            sid,
            max_rounds=args.max_rounds,
            extend_after_root=args.extend,
        )
        results.append(result)
        print(format_coverage_report(result))
        print()
        if args.save:
            p = save_result(result)
            print(f"saved: {p}")
        if not result.all_pass:
            exit_code = 1

    if args.all and len(results) > 1:
        summary = format_summary_table(results)
        print(summary)
        if args.save:
            summary_path = RESULTS_DIR / f"lock_step9_summary_{'extended' if args.extend else 'standard'}.md"
            summary_path.write_text(summary, encoding="utf-8")
            print(f"saved summary: {summary_path}")

    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
