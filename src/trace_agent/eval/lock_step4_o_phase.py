"""LOCK Step 4 — O 拍 · VOI 排序 + fanout 填槽.

Step 1→2→3 之后运行 _o_phase；校验 VOI 排序、填槽预算与 gt_root_cause 选中前瞻。

Usage:
    python -m trace_agent.eval.lock_step4_o_phase
    python -m trace_agent.eval.lock_step4_o_phase --scenario pipeline_18 --save
    python -m trace_agent.eval.lock_step4_o_phase --all
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import RESULTS_DIR, StepCheck, list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import ProbeSnapshot, _probe_snapshot, _setup_orchestrator
from trace_agent.eval.lock_step3_veto_phase import (
    _check_gt_root_cause_reachability,
    _probe_reachability_match,
    _root_cause_info,
)
from trace_agent.probe.voi_engine import voi
from trace_agent.prior_v2 import PriorManager


@dataclass
class ChosenProbeSnapshot(ProbeSnapshot):
    voi_score: float = 0.0
    risk_now: float = 0.0
    expected_risk_after: float = 0.0
    cost: float = 0.0


@dataclass
class OPhaseStepResult:
    scenario_id: str
    entry_ref: str
    alert_asset: str
    fanout_budget: int
    pool_size_in: int
    chosen_count: int
    chosen: list[ChosenProbeSnapshot]
    voi_scores_all: list[dict[str, Any]]
    ledger_margin: float
    root_cause_entity: str
    root_cause_technique: str
    budget_probes_used: int
    pool_size_after: int
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _score_probe(orch, probe) -> ChosenProbeSnapshot:
    pd = orch._probe_to_dict(probe)
    vr = voi(
        pd,
        orch.ledger,
        orch._beta_to_dict(),
        orch._calib_to_dict(),
        orch.loss,
        orch.trust,
    )
    snap = _probe_snapshot(probe)
    return ChosenProbeSnapshot(
        **asdict(snap),
        voi_score=round(vr.voi_score, 6),
        risk_now=round(vr.risk_now, 6),
        expected_risk_after=round(vr.expected_risk_after, 6),
        cost=round(vr.cost, 6),
    )


def run_o_phase_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
) -> OPhaseStepResult:
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    root_info = _root_cause_info(scenario_data)
    fanout = orch.budget.fanout_per_round

    prev_stats = orch.graph.stats()
    node_before = prev_stats.get("node_count", 0)
    margin_before = orch.ledger.margin()
    beta_before = len(orch.beta.all_keys())

    pool = orch._veto_phase(orch._l_phase(prev_stats))
    pool_size_in = pool.size()
    survivors = pool.peek()
    scored_all = [_score_probe(orch, p) for p in survivors]

    chosen_raw = orch._o_phase(pool)
    chosen = [_score_probe(orch, p) for p in chosen_raw]

    checks = _validate_o_phase(
        orch=orch,
        triage=triage,
        scenario_data=scenario_data,
        root_info=root_info,
        fanout=fanout,
        pool_size_in=pool_size_in,
        survivors=survivors,
        scored_all=scored_all,
        chosen=chosen,
        node_before=node_before,
        margin_before=margin_before,
        beta_before=beta_before,
        pool_size_after=pool.size(),
    )

    return OPhaseStepResult(
        scenario_id=scenario_id,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        fanout_budget=fanout,
        pool_size_in=pool_size_in,
        chosen_count=len(chosen),
        chosen=chosen,
        voi_scores_all=[
            {
                "id": s.id,
                "operator": s.operator,
                "tactic": s.tactic,
                "voi_score": s.voi_score,
                "priority_hint": s.priority_hint,
            }
            for s in scored_all
        ],
        ledger_margin=round(margin_before, 4),
        root_cause_entity=root_info["entity_id"],
        root_cause_technique=root_info["technique"],
        budget_probes_used=orch.budget.probes_used,
        pool_size_after=pool.size(),
        checks=checks,
    )


def _validate_o_phase(
    *,
    orch: Any,
    triage: Any,
    scenario_data: dict,
    root_info: dict[str, str],
    fanout: int,
    pool_size_in: int,
    survivors: list,
    scored_all: list[ChosenProbeSnapshot],
    chosen: list[ChosenProbeSnapshot],
    node_before: int,
    margin_before: float,
    beta_before: int,
    pool_size_after: int,
) -> list[StepCheck]:
    checks: list[StepCheck] = []
    alert_asset = triage.alert.asset_id or ""

    checks.append(
        StepCheck(
            id="o_chosen_non_empty",
            status="pass" if chosen else "fail",
            message="O 拍选出至少 1 条探针",
            actual=len(chosen),
        )
    )
    checks.append(
        StepCheck(
            id="o_fanout_respected",
            status="pass" if 0 < len(chosen) <= fanout else "fail",
            message=f"选中数 ≤ fanout_per_round（={fanout}）",
            expected=f"1..{fanout}",
            actual=len(chosen),
        )
    )
    checks.append(
        StepCheck(
            id="o_chosen_subset_of_pool",
            status="pass"
            if all(
                any(c.dedup_key == p.dedup_key() for p in survivors)
                for c in chosen
            )
            else "fail",
            message="chosen 是 ② 拍幸存池子集",
        )
    )
    checks.append(
        StepCheck(
            id="o_pool_drained",
            status="pass" if pool_size_after == 0 else "fail",
            message="O 拍 drain 清空候选池",
            actual=pool_size_after,
        )
    )

    if len(chosen) >= 2:
        voi_seq = [c.voi_score for c in chosen]
        sorted_ok = all(voi_seq[i] >= voi_seq[i + 1] - 1e-9 for i in range(len(voi_seq) - 1))
        checks.append(
            StepCheck(
                id="o_voi_sorted",
                status="pass" if sorted_ok else "fail",
                message="chosen 按 VOI 降序（ties 允许相等）",
                actual=voi_seq,
            )
        )
        unique_voi = len(set(round(v, 6) for v in voi_seq))
        if unique_voi == 1 and len(scored_all) > 1:
            checks.append(
                StepCheck(
                    id="o_voi_discrimination",
                    status="warn",
                    message="全部候选 VOI 相同，排序退化为 priority_hint/稳定序",
                    actual=voi_seq[0],
                )
            )

    checks.append(
        StepCheck(
            id="o_no_c_budget_charge",
            status="pass" if orch.budget.probes_used == 0 else "fail",
            message="O 拍不消耗 probes_used（C 拍才计费）",
            actual=orch.budget.probes_used,
        )
    )
    checks.append(
        StepCheck(
            id="o_graph_readonly",
            status="pass" if orch.graph.stats().get("node_count") == node_before else "fail",
            message="O 拍不写入 SessionGraph",
        )
    )
    checks.append(
        StepCheck(
            id="o_ledger_readonly",
            status="pass" if abs(orch.ledger.margin() - margin_before) < 1e-9 else "fail",
            message="O 拍不更新 DecisionLedger（只读 VOI）",
        )
    )
    checks.append(
        StepCheck(
            id="o_beta_readonly",
            status="pass" if len(orch.beta.all_keys()) == beta_before else "fail",
            message="O 拍不写入 BetaLedger",
        )
    )

    schema_ok = all(c.id and c.operator and c.tactic and c.target for c in chosen)
    checks.append(
        StepCheck(
            id="o_chosen_schema",
            status="pass" if schema_ok else "fail",
            message="chosen 探针字段完整",
        )
    )

    reach_chosen = [
        c
        for c in chosen
        if _probe_reachability_match(
            c,
            root_entity=root_info["entity_id"],
            root_tactic=root_info["tactic"],
            alert_asset=alert_asset,
        )
    ]
    checks.append(
        StepCheck(
            id="gt_root_cause_in_chosen",
            status="pass" if reach_chosen else "fail",
            message="Top fanout 中至少 1 条可追根 operator/tactic（O 拍前瞻）",
            expected=root_info,
            actual=[
                {"operator": c.operator, "tactic": c.tactic, "target": c.target, "voi": c.voi_score}
                for c in reach_chosen
            ],
        )
    )

    pool_reach = _check_gt_root_cause_reachability(
        [_probe_snapshot(p) for p in survivors],
        alert_asset,
        root_info,
    )
    if pool_reach.status == "fail":
        checks.append(
            StepCheck(
                id="gt_root_cause_reachability_pool",
                status="fail",
                message="② 拍幸存池已无可追根探针（O 拍前提不满足）",
                actual=pool_reach.actual,
            )
        )

    return checks


def format_step_report(result: OPhaseStepResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"

    chosen_lines = "\n".join(
        f"  - {c.operator} · {c.tactic} @ {c.target}  VOI={c.voi_score:.4f}  prio={c.priority_hint:.2f}"
        for c in result.chosen
    )

    lines = [
        f"# Step 4 · O 拍 · VOI 排序 + 填槽 [{status}]",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        f"根因 GT: {result.root_cause_entity or '(未指定)'} · {result.root_cause_technique}",
        "",
        "## ① 做了什么",
        f"对 ② 拍幸存池按 VOI 降序排序，取 Top-{result.fanout_budget} 填入 fanout 槽位；pool.drain()。",
        "",
        "## ② 输入（读了什么）",
        f"- 幸存候选 {result.pool_size_in} 条 · margin={result.ledger_margin:.2%}",
        "- DecisionLedger + Beta + calib + trust（VOI 一步前瞻）",
        f"- fanout_per_round={result.fanout_budget}",
        "",
        "## ③ 产出（生成了什么）",
        f"- chosen {result.chosen_count} 条：",
        chosen_lines,
        f"- probes_used 仍为 {result.budget_probes_used}（C 拍才 +1）",
        "",
        "## ④ 怎么算的",
        "VOI(p) = risk_now - E[risk_after] - cost(p)",
        "risk = bayes_risk(session + contested boundaries)",
        "",
        "## ⑤ 维护了什么",
        "【图/决策/Beta】只读",
        "【候选池】drain 清空",
        "【义务】mandated 预占（当前实现未在 O 前 materialize 入池）",
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


def save_result(result: OPhaseStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step4_{result.scenario_id}.json"
    payload = {
        "step": 4,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "fanout_budget": result.fanout_budget,
        "pool_size_in": result.pool_size_in,
        "chosen_count": result.chosen_count,
        "chosen": [asdict(c) for c in result.chosen],
        "voi_scores_all": result.voi_scores_all,
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 4 O-phase 测试（本地 MCP 场景）")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_o_phase_step(sid)
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
