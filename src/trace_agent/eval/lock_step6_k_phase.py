"""LOCK Step 6 — K 拍 · 入图 + 决策账更新 + Beta 学习 + should_stop().

Step 1→4→C 之后运行 _k_phase；校验 confirmed 入图、ledger 贝叶斯更新、Beta hit/miss、停止判定。

Usage:
    python -m trace_agent.eval.lock_step6_k_phase
    python -m trace_agent.eval.lock_step6_k_phase --scenario apt_5host --save
    python -m trace_agent.eval.lock_step6_k_phase --all
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.agents.orchestrator import _has_required_fields
from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import RESULTS_DIR, StepCheck, list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import _setup_orchestrator
from trace_agent.eval.lock_step3_veto_phase import _root_cause_info
from trace_agent.eval.lock_step4_o_phase import ChosenProbeSnapshot, _score_probe
from trace_agent.eval.lock_step5_c_phase import (
    _align_executor_to_alert,
    _flatten_routed,
    _run_through_o_phase,
)
from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.prior_v2 import PriorManager

VALID_STOP_REASONS = frozenset({"budget", "voi_floor", "robust", "continue"})


@dataclass
class BetaProbeSnapshot:
    operator: str
    tactic: str
    learning_key: str
    hit: bool
    alpha: float
    beta: float
    observations: int


@dataclass
class KPhaseStepResult:
    scenario_id: str
    entry_ref: str
    alert_asset: str
    alert_timestamp: float
    chosen_count: int
    chosen: list[ChosenProbeSnapshot]
    confirmed_count: int
    valid_confirmed_count: int
    node_count_before: int
    node_count_after: int
    margin_before: float
    margin_after: float
    beta_keys_before: int
    beta_keys_after: int
    beta_snapshots: list[BetaProbeSnapshot]
    calib_sources: list[str]
    stop_should_stop: bool
    stop_reason: str
    stop_max_voi: float
    stop_risk_now: float
    root_cause_entity: str
    root_cause_technique: str
    attack_ref_hits: list[str]
    attack_refs_in_graph: list[str]
    techniques_in_graph: list[str]
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _probe_hit(probe, confirmed: list[dict]) -> bool:
    return any(
        e.get("probe_id") == probe.id or e.get("tactic") == probe.tactic
        for e in confirmed
    )


def _beta_snapshots(orch, chosen: list, confirmed: list[dict]) -> list[BetaProbeSnapshot]:
    out: list[BetaProbeSnapshot] = []
    for probe in chosen:
        key = probe.learning_key()
        alpha, beta = orch.beta.get_params(key)
        hit = _probe_hit(probe, confirmed)
        out.append(
            BetaProbeSnapshot(
                operator=probe.operator,
                tactic=probe.tactic,
                learning_key=key,
                hit=hit,
                alpha=alpha,
                beta=beta,
                observations=orch.beta.total_observations(key),
            )
        )
    return out


def _graph_node_ids(orch) -> set[str]:
    return {n.id for n in orch.graph._nodes.values()}


def run_k_phase_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
    align_time_to_alert: bool = True,
) -> KPhaseStepResult:
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    _, registry_spec = load_scenario(scenario_id)
    root_info = _root_cause_info(scenario_data)

    alert_ts = 0.0
    if align_time_to_alert:
        alert_ts = _align_executor_to_alert(orch, scenario_data, registry_spec)

    node_before = orch.graph.stats().get("node_count", 0)
    margin_before = orch.ledger.margin()
    beta_before = len(orch.beta.all_keys())
    log_post_before = dict(getattr(orch.ledger, "log_post", {}) or {})

    chosen_raw = _run_through_o_phase(orch)
    chosen = [_score_probe(orch, p) for p in chosen_raw]
    ingest_result = orch._c_phase(chosen_raw)

    confirmed = ingest_result.confirmed
    graph_eligible = getattr(ingest_result, "graph_eligible", confirmed)
    valid_confirmed = [e for e in graph_eligible if _has_required_fields(e)]
    gt_refs = set((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    routed_flat = _flatten_routed(ingest_result)
    attack_ref_hits = sorted(
        {str(ev.get("id", "")) for _, ev in routed_flat if str(ev.get("id", "")) in gt_refs}
    )

    stop = orch._k_phase(chosen_raw, ingest_result)

    node_after = orch.graph.stats().get("node_count", 0)
    margin_after = orch.ledger.margin()
    beta_after = len(orch.beta.all_keys())
    log_post_after = dict(getattr(orch.ledger, "log_post", {}) or {})
    graph_ids = _graph_node_ids(orch)
    attack_refs_in_graph = sorted(gt_refs & graph_ids)
    techniques = list(orch.graph.stats().get("techniques_seen") or [])

    beta_snaps = _beta_snapshots(orch, chosen_raw, graph_eligible)
    calib_sources = sorted(getattr(orch.calib, "_source_stats", {}).keys())

    checks = _validate_k_phase(
        orch=orch,
        scenario_data=scenario_data,
        root_info=root_info,
        chosen=chosen_raw,
        confirmed=confirmed,
        valid_confirmed=valid_confirmed,
        graph_eligible=graph_eligible,
        stop=stop,
        beta_snaps=beta_snaps,
        attack_ref_hits=attack_ref_hits,
        attack_refs_in_graph=attack_refs_in_graph,
        techniques=techniques,
        node_before=node_before,
        node_after=node_after,
        margin_before=margin_before,
        margin_after=margin_after,
        log_post_before=log_post_before,
        log_post_after=log_post_after,
        beta_before=beta_before,
        beta_after=beta_after,
        calib_sources=calib_sources,
        align_time_to_alert=align_time_to_alert,
    )

    return KPhaseStepResult(
        scenario_id=scenario_id,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        alert_timestamp=alert_ts,
        chosen_count=len(chosen_raw),
        chosen=chosen,
        confirmed_count=len(confirmed),
        valid_confirmed_count=len(valid_confirmed),
        node_count_before=node_before,
        node_count_after=node_after,
        margin_before=margin_before,
        margin_after=margin_after,
        beta_keys_before=beta_before,
        beta_keys_after=beta_after,
        beta_snapshots=beta_snaps,
        calib_sources=calib_sources,
        stop_should_stop=stop.should_stop,
        stop_reason=stop.reason,
        stop_max_voi=stop.max_voi,
        stop_risk_now=stop.risk_now,
        root_cause_entity=root_info["entity_id"],
        root_cause_technique=root_info["technique"],
        attack_ref_hits=attack_ref_hits,
        attack_refs_in_graph=attack_refs_in_graph,
        techniques_in_graph=techniques,
        checks=checks,
    )


def _validate_k_phase(
    *,
    orch: Any,
    scenario_data: dict,
    root_info: dict[str, str],
    chosen: list,
    confirmed: list[dict],
    valid_confirmed: list[dict],
    graph_eligible: list[dict],
    stop: Any,
    beta_snaps: list[BetaProbeSnapshot],
    attack_ref_hits: list[str],
    attack_refs_in_graph: list[str],
    techniques: list[str],
    node_before: int,
    node_after: int,
    margin_before: float,
    margin_after: float,
    log_post_before: dict,
    log_post_after: dict,
    beta_before: int,
    beta_after: int,
    calib_sources: list[str],
    align_time_to_alert: bool,
) -> list[StepCheck]:
    checks: list[StepCheck] = []
    root_technique = root_info["technique"] or ""
    root_base = root_technique.split(".")[0] if root_technique else ""

    checks.append(
        StepCheck(
            id="k_prereq_c_executed",
            status="pass" if orch.budget.probes_used == len(chosen) else "fail",
            message="K 拍前 C 拍已执行（probes_used == len(chosen)）",
            expected=len(chosen),
            actual=orch.budget.probes_used,
        )
    )

    if align_time_to_alert and valid_confirmed:
        checks.append(
            StepCheck(
                id="k_graph_adds_confirmed",
                status="pass" if node_after > node_before else "fail",
                message="graph_eligible 经 _has_required_fields 后 graph.add_events 增节点",
                expected=f">{node_before}",
                actual=node_after,
            )
        )
    elif not valid_confirmed:
        checks.append(
            StepCheck(
                id="k_graph_adds_confirmed",
                status="skip",
                message="无 graph_eligible，图可不变",
                actual=node_after,
            )
        )
    else:
        checks.append(
            StepCheck(
                id="k_graph_adds_confirmed",
                status="skip",
                message="未对齐时间窗，首轮可能无 confirmed",
            )
        )

    if graph_eligible:
        ledger_changed = (
            abs(margin_after - margin_before) > 1e-9 or log_post_before != log_post_after
        )
        checks.append(
            StepCheck(
                id="k_ledger_bayesian_update",
                status="pass" if ledger_changed else "fail",
                message="graph_eligible 非空时 DecisionLedger.update 改变 margin 或 log_post",
                expected="changed",
                actual={
                    "margin_before": round(margin_before, 6),
                    "margin_after": round(margin_after, 6),
                },
            )
        )
    else:
        checks.append(
            StepCheck(
                id="k_ledger_bayesian_update",
                status="skip",
                message="无 graph_eligible，ledger 可不变",
            )
        )

    unique_keys = {p.learning_key() for p in chosen}
    checks.append(
        StepCheck(
            id="k_beta_keys_tracked",
            status="pass" if beta_after >= len(unique_keys) else "fail",
            message="BetaLedger 为每条 chosen 探针 learning_key 写入观测",
            expected=len(unique_keys),
            actual=beta_after,
        )
    )

    beta_obs_ok = all(s.observations >= 1 for s in beta_snaps)
    checks.append(
        StepCheck(
            id="k_beta_hit_miss_per_probe",
            status="pass" if beta_obs_ok else "fail",
            message="每条 chosen 探针 Beta total_observations >= 1",
            actual=[{"op": s.operator, "obs": s.observations, "hit": s.hit} for s in beta_snaps],
        )
    )

    hit_miss_ok = all(
        (s.alpha > 1.0 if s.hit else s.beta > 1.0) for s in beta_snaps
    )
    checks.append(
        StepCheck(
            id="k_beta_alpha_beta_semantics",
            status="pass" if hit_miss_ok else "fail",
            message="hit 增 alpha、miss 增 beta（相对先验 1,1）",
            actual=[{"op": s.operator, "alpha": s.alpha, "beta": s.beta, "hit": s.hit} for s in beta_snaps],
        )
    )

    if chosen:
        calib_ok = len(calib_sources) >= 1
        checks.append(
            StepCheck(
                id="k_calib_recorded",
                status="pass" if calib_ok else "fail",
                message="GenCalibration.record 按 probe.source 写入",
                actual=calib_sources,
            )
        )

    checks.append(
        StepCheck(
            id="k_should_stop_well_formed",
            status="pass" if stop.reason in VALID_STOP_REASONS else "fail",
            message="should_stop() 返回合法 StopDecision.reason",
            actual={
                "should_stop": stop.should_stop,
                "reason": stop.reason,
                "max_voi": round(stop.max_voi, 6),
                "risk_now": round(stop.risk_now, 6),
            },
        )
    )

    if attack_ref_hits:
        checks.append(
            StepCheck(
                id="gt_attack_ref_in_graph",
                status="pass" if attack_refs_in_graph else "fail",
                message="C 拍命中的 GT attack_edge_refs 经 K 拍入图",
                expected=attack_ref_hits[:5],
                actual=attack_refs_in_graph[:5],
            )
        )
    else:
        checks.append(
            StepCheck(
                id="gt_attack_ref_in_graph",
                status="warn",
                message="首轮未命中 GT 攻击边（跨主机常见）",
                actual=attack_refs_in_graph,
            )
        )

    root_technique_in_graph = any(
        t.startswith(root_base) for t in techniques if root_base
    )
    if attack_ref_hits and root_base:
        checks.append(
            StepCheck(
                id="gt_root_technique_in_graph",
                status="pass" if root_technique_in_graph else "warn",
                message="入图 techniques 含根因 technique 前缀",
                expected=root_technique,
                actual=techniques,
            )
        )

    if attack_ref_hits and not stop.should_stop:
        checks.append(
            StepCheck(
                id="gt_continue_when_attack_evidence",
                status="pass",
                message="命中 GT 攻击边且 margin 低时 should_stop=False（继续调查）",
                actual=stop.reason,
            )
        )
    elif attack_ref_hits and stop.should_stop:
        checks.append(
            StepCheck(
                id="gt_continue_when_attack_evidence",
                status="warn",
                message=f"命中 GT 但首轮停止（reason={stop.reason}，decision_robust 或 voi_floor）",
                actual=stop.reason,
            )
        )

    return checks


def format_step_report(result: KPhaseStepResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"

    chosen_lines = "\n".join(
        f"  - {c.operator} · {c.tactic} @ {c.target} (voi={c.voi_score})"
        for c in result.chosen
    )
    beta_lines = "\n".join(
        f"  - {b.operator}: hit={b.hit} beta({b.alpha},{b.beta}) obs={b.observations}"
        for b in result.beta_snapshots
    )
    lines = [
        f"# Step 6 · K 拍 · 学习 + 决策账 + 停止 [{status}]",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        f"根因 GT: {result.root_cause_entity or '(未指定)'} · {result.root_cause_technique}",
        f"时间窗对齐: alert_ts={result.alert_timestamp:.0f}",
        "",
        "## ① 做了什么",
        "_k_phase: graph.add_events -> ledger.update -> beta.update -> calib.record -> should_stop()",
        "",
        "## ② 输入",
        f"- confirmed {result.confirmed_count} (valid {result.valid_confirmed_count})",
        f"- chosen {result.chosen_count} 探针",
        chosen_lines,
        "",
        "## ③ 产出",
        f"- graph nodes: {result.node_count_before} -> {result.node_count_after}",
        f"- ledger margin: {result.margin_before:.4f} -> {result.margin_after:.4f}",
        f"- beta keys: {result.beta_keys_before} -> {result.beta_keys_after}",
        beta_lines,
        f"- calib sources: {result.calib_sources}",
        f"- stop: should_stop={result.stop_should_stop} reason={result.stop_reason}",
        f"- GT in graph: {result.attack_refs_in_graph[:5] or '[]'}",
        f"- techniques: {result.techniques_in_graph}",
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


def save_result(result: KPhaseStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step6_{result.scenario_id}.json"
    payload = {
        "step": 6,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "node_count_before": result.node_count_before,
        "node_count_after": result.node_count_after,
        "margin_before": result.margin_before,
        "margin_after": result.margin_after,
        "beta_keys_after": result.beta_keys_after,
        "stop": {
            "should_stop": result.stop_should_stop,
            "reason": result.stop_reason,
            "max_voi": result.stop_max_voi,
            "risk_now": result.stop_risk_now,
        },
        "attack_refs_in_graph": result.attack_refs_in_graph,
        "techniques_in_graph": result.techniques_in_graph,
        "beta_snapshots": [asdict(b) for b in result.beta_snapshots],
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 6 K-phase 测试（本地 MCP 场景）")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument(
        "--no-time-align",
        action="store_true",
        help="不对齐告警时间窗",
    )
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_k_phase_step(
            sid,
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
