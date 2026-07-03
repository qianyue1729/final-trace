"""LOCK Step 5 — C 拍 · 扇出取证 + L0–L4 入图判假.

Step 1→4 之后运行 _c_phase；对齐 MCP 时间窗后校验 ingest 路由与 ground truth 命中。

Usage:
    python -m trace_agent.eval.lock_step5_c_phase
    python -m trace_agent.eval.lock_step5_c_phase --scenario apt_5host --save
    python -m trace_agent.eval.lock_step5_c_phase --all
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import RESULTS_DIR, StepCheck, list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import _setup_orchestrator
from trace_agent.eval.lock_step3_veto_phase import _root_cause_info
from trace_agent.eval.lock_step4_o_phase import _score_probe, ChosenProbeSnapshot
from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_agent.loop.ingest import ROUTE_ATTACH, ROUTE_DISCARD, ROUTE_PARK, ROUTE_SPAWN, ROUTE_WEAK
from trace_agent.prior_v2 import PriorManager


@dataclass
class EventSnapshot:
    id: str
    technique: str
    tactic: str
    host_uid: str
    is_attack: bool
    route_bucket: str
    trust_tier: str
    probe_id: str


@dataclass
class CPhaseStepResult:
    scenario_id: str
    entry_ref: str
    alert_asset: str
    alert_timestamp: float
    chosen_count: int
    chosen: list[ChosenProbeSnapshot]
    raw_fanout_count: int
    routed_counts: dict[str, int]
    confirmed_count: int
    trust_annotation_count: int
    probes_used: int
    root_cause_entity: str
    root_cause_technique: str
    attack_ref_hits: list[str]
    hosts_seen: list[str]
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _align_executor_to_alert(orch, scenario_data: dict, registry_spec: dict) -> float:
    """MCP .harness：将 ScenarioExecutor 时间窗对齐到入口告警（否则首轮 raw=0）。"""
    entry = find_entry_event(scenario_data, registry_spec)
    alert = build_alert_event(entry)
    ts = float(alert.timestamp or 0)
    if ts > 0 and hasattr(orch.executor, "_time_cursor"):
        orch.executor._time_cursor = ts
    return ts


def _flatten_routed(ingest_result) -> list[tuple[str, dict]]:
    out: list[tuple[str, dict]] = []
    for bucket, events in ingest_result.routed.items():
        for ev in events:
            out.append((bucket, ev))
    return out


def _event_snapshot(bucket: str, ev: dict) -> EventSnapshot:
    attrs = ev.get("attributes") or {}
    return EventSnapshot(
        id=str(ev.get("id", "")),
        technique=str(ev.get("technique", "")),
        tactic=str(ev.get("tactic", "")),
        host_uid=str(attrs.get("host_uid") or ev.get("target") or ""),
        is_attack=bool(attrs.get("is_attack") or str(ev.get("id", "")).startswith("attack:")),
        route_bucket=bucket,
        trust_tier=str(ev.get("_l2_trust_tier", "unknown")),
        probe_id=str(ev.get("probe_id", "")),
    )


def _run_through_o_phase(orch) -> list:
    prev_stats = orch.graph.stats()
    pool = orch._veto_phase(orch._l_phase(prev_stats))
    return orch._o_phase(pool)


def run_c_phase_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
    align_time_to_alert: bool = True,
) -> CPhaseStepResult:
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    _, registry_spec = load_scenario(scenario_id)
    root_info = _root_cause_info(scenario_data)

    alert_ts = 0.0
    if align_time_to_alert:
        alert_ts = _align_executor_to_alert(orch, scenario_data, registry_spec)

    node_before = orch.graph.stats().get("node_count", 0)
    margin_before = orch.ledger.margin()
    beta_before = len(orch.beta.all_keys())
    probes_before = orch.budget.probes_used

    chosen_raw = _run_through_o_phase(orch)
    chosen = [_score_probe(orch, p) for p in chosen_raw]

    raw_fanout_count = 0
    original_fanout = orch.executor.execute_fanout

    def _counting_fanout(probes):
        nonlocal raw_fanout_count
        raw = original_fanout(probes)
        raw_fanout_count = len(raw)
        return raw

    orch.executor.execute_fanout = _counting_fanout  # type: ignore[method-assign]
    ingest_result = orch._c_phase(chosen_raw)
    orch.executor.execute_fanout = original_fanout  # type: ignore[method-assign]

    routed_flat = _flatten_routed(ingest_result)
    routed_counts = {k: len(ingest_result.routed.get(k, [])) for k in (
        ROUTE_ATTACH, ROUTE_WEAK, ROUTE_PARK, ROUTE_DISCARD, ROUTE_SPAWN
    )}
    snapshots = [_event_snapshot(b, ev) for b, ev in routed_flat]

    gt_refs = set((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    attack_ref_hits = sorted({s.id for s in snapshots if s.id in gt_refs})
    hosts_seen = sorted({s.host_uid for s in snapshots if s.host_uid})

    checks = _validate_c_phase(
        orch=orch,
        triage=triage,
        scenario_data=scenario_data,
        root_info=root_info,
        chosen=chosen_raw,
        ingest_result=ingest_result,
        snapshots=snapshots,
        raw_fanout_count=raw_fanout_count,
        routed_counts=routed_counts,
        attack_ref_hits=attack_ref_hits,
        hosts_seen=hosts_seen,
        node_before=node_before,
        margin_before=margin_before,
        beta_before=beta_before,
        probes_before=probes_before,
        align_time_to_alert=align_time_to_alert,
    )

    return CPhaseStepResult(
        scenario_id=scenario_id,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        alert_timestamp=alert_ts,
        chosen_count=len(chosen_raw),
        chosen=chosen,
        raw_fanout_count=raw_fanout_count,
        routed_counts=routed_counts,
        confirmed_count=len(ingest_result.confirmed),
        trust_annotation_count=len(ingest_result.trust_annotations),
        probes_used=orch.budget.probes_used,
        root_cause_entity=root_info["entity_id"],
        root_cause_technique=root_info["technique"],
        attack_ref_hits=attack_ref_hits,
        hosts_seen=hosts_seen,
        checks=checks,
    )


def _validate_c_phase(
    *,
    orch: Any,
    triage: Any,
    scenario_data: dict,
    root_info: dict[str, str],
    chosen: list,
    ingest_result: Any,
    snapshots: list[EventSnapshot],
    raw_fanout_count: int,
    routed_counts: dict[str, int],
    attack_ref_hits: list[str],
    hosts_seen: list[str],
    node_before: int,
    margin_before: float,
    beta_before: int,
    probes_before: int,
    align_time_to_alert: bool,
) -> list[StepCheck]:
    checks: list[StepCheck] = []
    alert_asset = (triage.alert.asset_id or "").lower()
    root_entity = (root_info["entity_id"] or "").lower()
    root_technique = root_info["technique"] or ""
    root_base = root_technique.split(".")[0] if root_technique else ""

    checks.append(
        StepCheck(
            id="c_chosen_executed",
            status="pass" if orch.budget.probes_used == probes_before + len(chosen) else "fail",
            message="C 拍 probes_used += len(chosen)",
            expected=probes_before + len(chosen),
            actual=orch.budget.probes_used,
        )
    )

    if align_time_to_alert:
        checks.append(
            StepCheck(
                id="c_raw_fanout_non_empty",
                status="pass" if raw_fanout_count > 0 else "fail",
                message="对齐告警时间窗后 execute_fanout 返回事件",
                actual=raw_fanout_count,
            )
        )
    else:
        checks.append(
            StepCheck(
                id="c_raw_fanout_non_empty",
                status="skip",
                message="未对齐时间窗（默认 cursor 可能 raw=0）",
            )
        )

    routed_total = sum(routed_counts.values())
    checks.append(
        StepCheck(
            id="c_ingest_routes_events",
            status="pass" if routed_total > 0 or raw_fanout_count == 0 else "fail",
            message="ingest.triage 将 raw 路由到 5 桶",
            actual=routed_counts,
        )
    )
    checks.append(
        StepCheck(
            id="c_trust_annotated",
            status="pass" if len(ingest_result.trust_annotations) == routed_total else "fail",
            message="每条路由事件有 L2 trust 标注",
            expected=routed_total,
            actual=len(ingest_result.trust_annotations),
        )
    )
    checks.append(
        StepCheck(
            id="c_graph_readonly",
            status="pass" if orch.graph.stats().get("node_count") == node_before else "fail",
            message="C 拍不入图（K 拍 add_events）",
        )
    )
    checks.append(
        StepCheck(
            id="c_ledger_readonly",
            status="pass" if abs(orch.ledger.margin() - margin_before) < 1e-9 else "fail",
            message="C 拍不更新 DecisionLedger（K 拍 update）",
        )
    )
    checks.append(
        StepCheck(
            id="c_beta_readonly",
            status="pass" if len(orch.beta.all_keys()) == beta_before else "fail",
            message="C 拍不更新 BetaLedger（K 拍 update）",
        )
    )

    if ingest_result.graph_eligible or ingest_result.confirmed:
        checks.append(
            StepCheck(
                id="c_confirmed_from_routing",
                status="pass",
                message="graph_eligible / attribution confirmed 已填充",
                actual={
                    "graph_eligible": len(ingest_result.graph_eligible),
                    "attribution_confirmed": len(ingest_result.confirmed),
                },
            )
        )

    # ── Ground truth ──
    if attack_ref_hits:
        checks.append(
            StepCheck(
                id="gt_attack_ref_in_routed",
                status="pass",
                message="路由结果命中 ground_truth.attack_edge_refs",
                actual=attack_ref_hits[:8],
            )
        )
    else:
        checks.append(
            StepCheck(
                id="gt_attack_ref_in_routed",
                status="warn",
                message="首轮 C 拍未命中 GT 攻击边（跨主机场景常见，需多轮）",
                actual=[],
            )
        )

    root_host_seen = any(h.lower() == root_entity for h in hosts_seen if root_entity)
    root_technique_seen = any(
        s.technique.startswith(root_base) for s in snapshots if root_base
    )
    cross_host = bool(root_entity and alert_asset and root_entity != alert_asset)

    if root_entity == "external":
        progress_ok = bool(attack_ref_hits) or any(s.is_attack for s in snapshots)
    elif not cross_host:
        progress_ok = routed_total > 0
    else:
        progress_ok = root_host_seen or root_technique_seen or bool(attack_ref_hits)

    checks.append(
        StepCheck(
            id="gt_root_cause_progress",
            status="pass" if progress_ok else "warn",
            message="向根因推进：根因主机/technique 出现或 GT 攻击边命中",
            expected={
                "root_entity": root_info["entity_id"],
                "root_technique": root_technique,
                "cross_host": cross_host,
            },
            actual={
                "root_host_seen": root_host_seen,
                "root_technique_seen": root_technique_seen,
                "attack_ref_hits": attack_ref_hits[:5],
                "hosts_seen": hosts_seen[:6],
            },
        )
    )

    reach_ops = {"auth_log", "lateral_movement_check", "network_flow", "dns_query", "email_gateway"}
    chosen_ops = {p.operator for p in chosen}
    if cross_host and not attack_ref_hits:
        checks.append(
            StepCheck(
                id="gt_root_cause_reachability_executed",
                status="pass" if chosen_ops & reach_ops else "warn",
                message="已执行探针含跨主机追根 operator（C 拍执行层）",
                actual=sorted(chosen_ops),
            )
        )

    return checks


def format_step_report(result: CPhaseStepResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"

    chosen_lines = "\n".join(
        f"  - {c.operator} · {c.tactic} @ {c.target}"
        for c in result.chosen
    )
    lines = [
        f"# Step 5 · C 拍 · 扇出取证 + 入图判假 [{status}]",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        f"根因 GT: {result.root_cause_entity or '(未指定)'} · {result.root_cause_technique}",
        f"时间窗对齐: alert_ts={result.alert_timestamp:.0f}",
        "",
        "## ① 做了什么",
        "execute_fanout(chosen) -> ingest.triage L0-L4 -> 5 桶路由；可选 WEAK 提升 confirmed。",
        "",
        "## ② 输入（读了什么）",
        f"- chosen {result.chosen_count} 条 MCP 探针",
        f"- ScenarioExecutor 场景 JSON（soar_mcp_env）",
        "",
        "## ③ 产出（生成了什么）",
        f"- raw_fanout: {result.raw_fanout_count} 条",
        f"- routed: {result.routed_counts}",
        f"- confirmed: {result.confirmed_count} · trust_annotations: {result.trust_annotation_count}",
        f"- probes_used: {result.probes_used}",
        f"- GT attack_ref 命中: {result.attack_ref_hits[:5] or '[]'}",
        f"- hosts_seen: {result.hosts_seen[:6]}",
        chosen_lines,
        "",
        "## ④ 怎么算的",
        "L0 去噪 -> L1 结构 -> L2 信任 -> L3 归属 -> L4 ATTACH/WEAK/PARK/DISCARD/SPAWN",
        "",
        "## ⑤ 维护了什么",
        "【图/决策/Beta】只读（本拍）",
        "【证据信任】ingest L2 标注",
        "【budget】probes_used 增加",
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


def save_result(result: CPhaseStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step5_{result.scenario_id}.json"
    payload = {
        "step": 5,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "raw_fanout_count": result.raw_fanout_count,
        "routed_counts": result.routed_counts,
        "confirmed_count": result.confirmed_count,
        "attack_ref_hits": result.attack_ref_hits,
        "hosts_seen": result.hosts_seen,
        "chosen": [asdict(c) for c in result.chosen],
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 5 C-phase 测试（本地 MCP 场景）")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument(
        "--no-time-align",
        action="store_true",
        help="不对齐告警时间窗（演示默认 cursor 下 raw=0）",
    )
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_c_phase_step(
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
