"""LOCK Step 8 — pipeline_18 多轮追根 · TA#### 映射 + 跨主机 targeting.

验证 normalize_tactic、cross_host_probe_generator、WEAK attack 提升、
backward_trace robust  override 对 pipeline_18 根因 GT 的推进效果。

Usage:
    python -m trace_agent.eval.lock_step8_root_trace
    python -m trace_agent.eval.lock_step8_root_trace --save
    python -m trace_agent.eval.lock_step8_root_trace --all
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import RESULTS_DIR, StepCheck, list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import _setup_orchestrator
from trace_agent.eval.lock_step3_veto_phase import _root_cause_info
from trace_agent.eval.lock_step5_c_phase import _align_executor_to_alert
from trace_agent.eval.lock_step7_full_loop import RoundSnapshot, run_traced_lock_loop
from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.loop.generators import (
    CROSS_HOST_REACH_OPERATORS,
    cross_host_probe_generator,
    normalize_tactic,
    prior_generator,
)
from trace_agent.prior_v2 import PriorManager

_TA_TACTIC_RE = re.compile(r"^ta\d{4}$", re.I)


@dataclass
class RootTraceStepResult:
    scenario_id: str
    entry_ref: str
    alert_asset: str
    root_cause_entity: str
    root_cause_technique: str
    rounds_used: int
    stop_reason: str
    hosts_in_graph: list[str]
    techniques_in_graph: list[str]
    attack_ref_hits: list[str]
    gt_attack_ref_total: int
    cross_host_pool_count: int
    prior_semantic_tactics: list[str]
    rounds: list[RoundSnapshot]
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _graph_hosts_from_orch(orch) -> list[str]:
    hosts: set[str] = set()
    for node in orch.graph._nodes.values():
        attrs = node.attributes or {}
        for key in ("host_uid", "asset_id", "host", "target"):
            val = attrs.get(key)
            if val:
                hosts.add(str(val).lower())
    return sorted(hosts)


def _attack_ref_hits(scenario_data: dict, orch) -> tuple[list[str], int]:
    gt_refs = set((scenario_data.get("ground_truth") or {}).get("attack_edge_refs") or [])
    graph_ids = {n.id for n in orch.graph._nodes.values()}
    return sorted(gt_refs & graph_ids), len(gt_refs)


def run_root_trace_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
    max_rounds: int = 10,
) -> RootTraceStepResult:
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    _, registry_spec = load_scenario(scenario_id)
    root_info = _root_cause_info(scenario_data)
    _align_executor_to_alert(orch, scenario_data, registry_spec)

    # L 拍快照：cross_host + prior tactic 语义化
    prev_stats = orch.graph.stats()
    prior_probes = prior_generator(orch.graph, orch.ledger, orch.prior_manager)
    known_hosts_fn = getattr(orch.executor, "known_hosts", None)
    known_hosts = known_hosts_fn() if callable(known_hosts_fn) else []
    cross_probes = cross_host_probe_generator(
        orch.graph,
        known_hosts,
        alert_asset=triage.alert.asset_id or "",
    )
    prior_tactics = sorted({p.tactic for p in prior_probes})

    orch.budget.total_rounds = max_rounds
    orch.budget.total_probes = max(orch.budget.total_probes, max_rounds * orch.budget.fanout_per_round)
    result, rounds, stop_reason = run_traced_lock_loop(orch, max_rounds=max_rounds)

    attack_hits, gt_total = _attack_ref_hits(scenario_data, orch)
    hosts = _graph_hosts_from_orch(orch)
    techniques = list(orch.graph.stats().get("techniques_seen") or [])

    checks = _validate_root_trace(
        scenario_id=scenario_id,
        root_info=root_info,
        triage=triage,
        prior_tactics=prior_tactics,
        cross_probes=cross_probes,
        known_hosts=known_hosts,
        rounds=rounds,
        stop_reason=stop_reason,
        hosts=hosts,
        techniques=techniques,
        attack_hits=attack_hits,
        gt_total=gt_total,
        rounds_used=result.rounds_used,
    )

    return RootTraceStepResult(
        scenario_id=scenario_id,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        root_cause_entity=root_info["entity_id"],
        root_cause_technique=root_info["technique"],
        rounds_used=result.rounds_used,
        stop_reason=stop_reason,
        hosts_in_graph=hosts,
        techniques_in_graph=techniques,
        attack_ref_hits=attack_hits,
        gt_attack_ref_total=gt_total,
        cross_host_pool_count=len(cross_probes),
        prior_semantic_tactics=prior_tactics,
        rounds=rounds,
        checks=checks,
    )


def _validate_root_trace(
    *,
    scenario_id: str,
    root_info: dict[str, str],
    triage: Any,
    prior_tactics: list[str],
    cross_probes: list,
    known_hosts: list[str],
    rounds: list[RoundSnapshot],
    stop_reason: str,
    hosts: list[str],
    techniques: list[str],
    attack_hits: list[str],
    gt_total: int,
    rounds_used: int,
) -> list[StepCheck]:
    checks: list[StepCheck] = []
    root_entity = (root_info["entity_id"] or "").lower()
    root_technique = root_info["technique"] or ""
    root_base = root_technique.split(".")[0] if root_technique else ""
    alert_asset = (triage.alert.asset_id or "").lower()
    cross_host = bool(root_entity and alert_asset and root_entity != alert_asset)

    # ── Step 8 机制校验 ──
    ta_raw = [t for t in prior_tactics if _TA_TACTIC_RE.match(t)]
    checks.append(
        StepCheck(
            id="s8_tactic_normalized",
            status="pass" if not ta_raw else "fail",
            message="prior_generator 产出语义 tactic（非 TA#### 原始 ID）",
            actual=prior_tactics[:8],
        )
    )
    checks.append(
        StepCheck(
            id="s8_normalize_tactic_map",
            status="pass" if normalize_tactic("TA0009") == "collection" else "fail",
            message="normalize_tactic TA0009 → collection",
            expected="collection",
            actual=normalize_tactic("TA0009"),
        )
    )

    if cross_host and known_hosts:
        ws_cross = [p for p in cross_probes if p.target.upper().startswith("WS-")]
        checks.append(
            StepCheck(
                id="s8_cross_host_probes",
                status="pass" if cross_probes else "fail",
                message="cross_host_probe_generator 对非告警主机产出探针",
                actual=len(cross_probes),
            )
        )
        checks.append(
            StepCheck(
                id="s8_ws_hosts_prioritized",
                status="pass" if ws_cross else "warn",
                message="跨主机候选优先 WS-* 工作站",
                actual=[p.target for p in cross_probes[:4]],
            )
        )
    else:
        checks.append(
            StepCheck(
                id="s8_cross_host_probes",
                status="skip",
                message="非跨主机场景跳过 cross_host 校验",
            )
        )

    if rounds:
        round1_ops = set(rounds[0].chosen_operators)
        if cross_host:
            checks.append(
                StepCheck(
                    id="s8_round1_reach_operator",
                    status="pass" if round1_ops & CROSS_HOST_REACH_OPERATORS else "warn",
                    message="首轮 O 拍含追根 operator（auth_log / lateral / network_flow）",
                    actual=sorted(round1_ops),
                )
            )

    # ── pipeline_18 GT 追根 ──
    if scenario_id == "pipeline_18":
        root_host_seen = root_entity in hosts
        root_technique_seen = any(t.startswith(root_base) for t in techniques if root_base)
        checks.append(
            StepCheck(
                id="gt_pipeline18_root_host",
                status="pass" if root_host_seen else "fail",
                message="pipeline_18 根因主机 WS-USER-01 入图",
                expected=root_info["entity_id"],
                actual=hosts,
            )
        )
        checks.append(
            StepCheck(
                id="gt_pipeline18_root_technique",
                status="pass" if root_technique_seen else "warn",
                message="pipeline_18 根因 technique T1566.001 入图",
                expected=root_technique,
                actual=techniques,
            )
        )
        checks.append(
            StepCheck(
                id="gt_pipeline18_attack_ref",
                status="pass" if attack_hits else "fail",
                message="pipeline_18 GT attack_edge_refs 至少命中 1 条",
                actual=f"{len(attack_hits)}/{gt_total}",
            )
        )
        checks.append(
            StepCheck(
                id="gt_pipeline18_multi_round_or_trace",
                status="pass" if root_host_seen and root_technique_seen else "warn",
                message="追根成功：根因主机+technique 同轮或跨轮达成",
                actual={"rounds_used": rounds_used, "stop_reason": stop_reason},
            )
        )
    elif attack_hits:
        checks.append(
            StepCheck(
                id="gt_attack_refs_in_graph",
                status="pass",
                message="GT attack_edge_refs 入图",
                actual=f"{len(attack_hits)}/{gt_total}",
            )
        )

    return checks


def format_step_report(result: RootTraceStepResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"
    round_lines = "\n".join(
        f"  R{r.round_num}: ops={r.chosen_operators} nodes={r.node_count} stop={r.stop_reason}"
        for r in result.rounds
    )
    lines = [
        f"# Step 8 · 追根 + TA 映射 [{status}]",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        f"告警: {result.alert_asset} · 根因 GT: {result.root_cause_entity} · {result.root_cause_technique}",
        "",
        "## 机制",
        f"- prior tactics: {result.prior_semantic_tactics[:8]}",
        f"- cross_host pool: {result.cross_host_pool_count} probes",
        f"- rounds: {result.rounds_used} · stop: {result.stop_reason}",
        f"- hosts: {result.hosts_in_graph}",
        f"- techniques: {result.techniques_in_graph}",
        f"- GT hits: {result.attack_ref_hits[:5]} ({len(result.attack_ref_hits)}/{result.gt_attack_ref_total})",
        "",
        "## 各轮",
        round_lines or "  (无)",
        "",
        "## 校验",
    ]
    for c in result.checks:
        mark = {"pass": "OK", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[c.status]
        lines.append(f"- [{mark}] {c.id}: {c.message}")
        if c.status in ("fail", "warn") and c.expected is not None:
            lines.append(f"    expected={c.expected!r}")
            if c.actual is not None:
                lines.append(f"    actual={c.actual!r}")
    return "\n".join(lines)


def save_result(result: RootTraceStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step8_{result.scenario_id}.json"
    payload = {
        "step": 8,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "rounds_used": result.rounds_used,
        "stop_reason": result.stop_reason,
        "hosts_in_graph": result.hosts_in_graph,
        "techniques_in_graph": result.techniques_in_graph,
        "attack_ref_hits": result.attack_ref_hits,
        "prior_semantic_tactics": result.prior_semantic_tactics,
        "cross_host_pool_count": result.cross_host_pool_count,
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 8 pipeline_18 追根验证")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    parser.add_argument("--max-rounds", type=int, default=10)
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_root_trace_step(sid, max_rounds=args.max_rounds)
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
