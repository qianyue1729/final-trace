"""LOCK Step 2 — L 拍 · prior_generator + rule_gap_generator 投候选.

在 Step 1 bootstrap 之后运行，泛化 soar_mcp_env 场景 + ground truth 校验。

Usage:
    python -m trace_agent.eval.lock_step2_l_phase
    python -m trace_agent.eval.lock_step2_l_phase --scenario pipeline_18 --save
    python -m trace_agent.eval.lock_step2_l_phase --all
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.agents.orchestrator import DecisionOrchestrator, BudgetState
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.eval.lock_step1_bootstrap import (
    RESULTS_DIR,
    StepCheck,
    list_scenario_ids,
    triage_entry,
)
from trace_agent.eval.soar_integration_runner import (
    TECHNIQUE_TACTIC_MAP,
    load_scenario,
)
from trace_agent.loop.generators import prior_generator, rule_gap_generator, cross_host_probe_generator, chain_follow_generator, structural_debt_generator, lifecycle_template_generator
from trace_agent.loop.probe import Probe
from trace_agent.loop.scenario_executor import ScenarioExecutor
from trace_agent.prior_v2 import PriorManager


@dataclass
class ProbeSnapshot:
    id: str
    target: str
    target_type: str
    operator: str
    tactic: str
    source: str
    dedup_key: str
    explanation_ids: list[str]
    priority_hint: float
    metadata: dict[str, Any]


@dataclass
class LPhaseStepResult:
    scenario_id: str
    entry_ref: str
    alert_asset: str
    alert_technique: str
    prev_stats: dict[str, Any]
    pool_size: int
    prior_count: int
    gap_count: int
    probes: list[ProbeSnapshot]
    sources: dict[str, int]
    ledger_leading: str
    ledger_margin: float
    graph_stats_after: dict[str, Any]
    beta_keys_after: int
    obligation_count_after: int
    budget_probes_used: int
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _probe_snapshot(p: Probe) -> ProbeSnapshot:
    return ProbeSnapshot(
        id=p.id,
        target=p.target,
        target_type=p.target_type,
        operator=p.operator,
        tactic=p.tactic,
        source=p.source,
        dedup_key=p.dedup_key(),
        explanation_ids=list(p.explanation_ids),
        priority_hint=p.priority_hint,
        metadata=dict(p.metadata or {}),
    )


def _technique_to_tactic(technique: str) -> str:
    base = technique.split(".")[0]
    return TECHNIQUE_TACTIC_MAP.get(technique) or TECHNIQUE_TACTIC_MAP.get(base, "")


def _kill_chain_tactics(scenario_data: dict) -> set[str]:
    gt = scenario_data.get("ground_truth") or {}
    events_by_ref = {
        e.get("raw_log_ref"): e
        for e in scenario_data.get("events", [])
        if e.get("raw_log_ref")
    }
    tactics: set[str] = set()
    for ref in gt.get("attack_edge_refs") or []:
        ev = events_by_ref.get(ref)
        if not ev or not ev.get("technique"):
            continue
        t = _technique_to_tactic(ev["technique"])
        if t:
            tactics.add(t.lower())
    return tactics


def _setup_orchestrator(
    scenario_id: str,
    prior_manager: PriorManager | None = None,
) -> tuple[DecisionOrchestrator, dict, Any]:
    triage = triage_entry(scenario_id)
    scenario_data, _ = load_scenario(scenario_id)
    prior = prior_manager or PriorManager(load_prior_bundle())
    seed = DecisionLedger(prior).seed(triage.alert)
    executor = ScenarioExecutor(scenario_data, seed=42)
    orch = DecisionOrchestrator(
        alert=triage.alert,
        executor=executor,
        prior_manager=prior,
        seed=seed,
        budget=BudgetState(total_rounds=50, total_probes=400, fanout_per_round=8),
    )
    orch._bootstrap()
    return orch, scenario_data, triage


def run_l_phase_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
) -> LPhaseStepResult:
    """Step 1 bootstrap 完成后执行 L 拍，校验候选池与只读账本。"""
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)

    prev_stats = orch.graph.stats()
    ledger_leading_before = orch.ledger.leading()
    margin_before = orch.ledger.margin()
    beta_keys_before = len(orch.beta.all_keys())
    obligation_before = len(orch.obligations.obligations)
    node_count_before = prev_stats.get("node_count", 0)

    prior_probes = prior_generator(orch.graph, orch.ledger, orch.prior_manager)
    gap_probes = rule_gap_generator(orch.graph, prev_stats)
    known_hosts_fn = getattr(orch.executor, "known_hosts", None)
    cross_probes: list = []
    chain_probes: list = []
    if callable(known_hosts_fn):
        cross_probes = cross_host_probe_generator(
            orch.graph,
            known_hosts_fn(),
            alert_asset=triage.alert.asset_id or "",
        )
    chain_probes = chain_follow_generator(orch.graph)
    debt_probes = structural_debt_generator(orch.graph, orch.ledger)
    lifecycle_probes = lifecycle_template_generator(orch.graph)
    pool = orch._l_phase(prev_stats)
    probes = pool.peek()

    graph_after = orch.graph.stats()
    checks = _validate_l_phase(
        triage=triage,
        scenario_data=scenario_data,
        prev_stats=prev_stats,
        prior_probes=prior_probes,
        gap_probes=gap_probes,
        cross_probes=cross_probes,
        chain_probes=chain_probes,
        debt_probes=debt_probes,
        lifecycle_probes=lifecycle_probes,
        pool_probes=probes,
        pool_size=pool.size(),
        ledger_leading_before=ledger_leading_before,
        ledger_leading_after=orch.ledger.leading(),
        margin_before=margin_before,
        margin_after=orch.ledger.margin(),
        node_count_before=node_count_before,
        node_count_after=graph_after.get("node_count", 0),
        beta_keys_before=beta_keys_before,
        beta_keys_after=len(orch.beta.all_keys()),
        obligation_before=obligation_before,
        obligation_after=len(orch.obligations.obligations),
        budget_probes_used=orch.budget.probes_used,
    )

    sources: dict[str, int] = {}
    for p in probes:
        sources[p.source] = sources.get(p.source, 0) + 1

    return LPhaseStepResult(
        scenario_id=scenario_id,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        alert_technique=triage.alert.technique_id,
        prev_stats=prev_stats,
        pool_size=pool.size(),
        prior_count=len(prior_probes),
        gap_count=len(gap_probes),
        probes=[_probe_snapshot(p) for p in probes],
        sources=sources,
        ledger_leading=orch.ledger.leading(),
        ledger_margin=round(orch.ledger.margin(), 4),
        graph_stats_after=graph_after,
        beta_keys_after=len(orch.beta.all_keys()),
        obligation_count_after=len(orch.obligations.obligations),
        budget_probes_used=orch.budget.probes_used,
        checks=checks,
    )


def _validate_l_phase(
    *,
    triage: Any,
    scenario_data: dict,
    prev_stats: dict,
    prior_probes: list[Probe],
    gap_probes: list[Probe],
    cross_probes: list[Probe],
    chain_probes: list[Probe],
    debt_probes: list[Probe],
    lifecycle_probes: list[Probe],
    pool_probes: list[Probe],
    pool_size: int,
    ledger_leading_before: str,
    ledger_leading_after: str,
    margin_before: float,
    margin_after: float,
    node_count_before: int,
    node_count_after: int,
    beta_keys_before: int,
    beta_keys_after: int,
    obligation_before: int,
    obligation_after: int,
    budget_probes_used: int,
) -> list[StepCheck]:
    alert = triage.alert
    checks: list[StepCheck] = []
    asset = (alert.asset_id or "").lower()

    checks.append(
        StepCheck(
            id="l_pool_non_empty",
            status="pass" if pool_size >= 1 else "fail",
            message="L 拍候选池非空",
            actual=pool_size,
        )
    )
    checks.append(
        StepCheck(
            id="l_prior_source",
            status="pass" if any(p.source == "prior" for p in pool_probes) else "fail",
            message="prior_generator 有产出（source=prior）",
            actual=sum(1 for p in pool_probes if p.source == "prior"),
        )
    )
    checks.append(
        StepCheck(
            id="l_rule_gap_source",
            status="pass" if any(p.source == "rule_gap" for p in pool_probes) else "warn",
            message="rule_gap_generator 有产出（bootstrap 单节点常靠 stagnation）",
            actual=sum(1 for p in pool_probes if p.source == "rule_gap"),
        )
    )
    max_pool = len(prior_probes) + len(gap_probes) + len(cross_probes) + len(chain_probes) + len(debt_probes) + len(lifecycle_probes)
    checks.append(
        StepCheck(
            id="l_pool_matches_generators",
            status="pass" if pool_size <= max_pool else "fail",
            message="_l_phase 池大小 ≤ prior + gap + cross_host + chain_follow + debt + lifecycle（去重后）",
            expected=f"<={max_pool}",
            actual=pool_size,
        )
    )

    schema_ok = all(
        p.id and p.target and p.operator and p.tactic and p.dedup_key()
        for p in pool_probes
    )
    checks.append(
        StepCheck(
            id="l_probe_schema",
            status="pass" if schema_ok else "fail",
            message="每条 Probe 含 id/target/operator/tactic/dedup_key",
        )
    )

    dedup_keys = [p.dedup_key() for p in pool_probes]
    checks.append(
        StepCheck(
            id="l_pool_deduped",
            status="pass" if len(dedup_keys) == len(set(dedup_keys)) else "fail",
            message="候选池 dedup_key 唯一",
            actual=len(dedup_keys),
        )
    )

    prior_on_asset = any(
        p.source == "prior" and asset and asset in p.target.lower()
        for p in pool_probes
    )
    checks.append(
        StepCheck(
            id="l_prior_targets_alert_asset",
            status="pass" if prior_on_asset else "fail",
            message="prior 探针 target 含告警资产",
            expected=alert.asset_id,
            actual=[p.target for p in pool_probes if p.source == "prior"][:5],
        )
    )

    origin_ok = any(
        p.source == "prior"
        and (p.metadata or {}).get("origin_technique") == alert.technique_id
        for p in prior_probes
    )
    checks.append(
        StepCheck(
            id="l_prior_from_frontier_technique",
            status="pass" if origin_ok else "warn",
            message="prior 沿 frontier technique 邻域延伸",
            expected=alert.technique_id,
        )
    )

    checks.append(
        StepCheck(
            id="l_graph_readonly",
            status="pass" if node_count_after == node_count_before else "fail",
            message="L 拍不写入 SessionGraph",
            expected=node_count_before,
            actual=node_count_after,
        )
    )
    checks.append(
        StepCheck(
            id="l_ledger_readonly",
            status="pass"
            if ledger_leading_before == ledger_leading_after and abs(margin_before - margin_after) < 1e-9
            else "fail",
            message="L 拍不更新 DecisionLedger",
        )
    )
    checks.append(
        StepCheck(
            id="l_beta_readonly",
            status="pass" if beta_keys_after == beta_keys_before == 0 else "fail",
            message="L 拍不写入 BetaLedger",
            actual={"before": beta_keys_before, "after": beta_keys_after},
        )
    )
    checks.append(
        StepCheck(
            id="l_obligations_readonly",
            status="pass" if obligation_after == obligation_before else "fail",
            message="L 拍不扫描/写入义务账（② 拍职责）",
            actual=obligation_after,
        )
    )
    checks.append(
        StepCheck(
            id="l_no_probe_budget_consumed",
            status="pass" if budget_probes_used == 0 else "fail",
            message="L 拍不消耗探针预算（O/C 拍才消耗）",
            actual=budget_probes_used,
        )
    )

    kill_tactics = _kill_chain_tactics(scenario_data)
    probe_tactics = {p.tactic.lower().replace("_", "-") for p in pool_probes}
    # 归一化 ATT&CK id 风格 tactic（如 ta0007）— 用 metadata missing_tactic / neighbor
    for p in pool_probes:
        md = p.metadata or {}
        if md.get("missing_tactic"):
            probe_tactics.add(str(md["missing_tactic"]).lower())
    overlap = probe_tactics & kill_tactics
    checks.append(
        StepCheck(
            id="gt_probe_tactic_relevance",
            status="pass" if overlap else "warn",
            message="候选 tactic 与 ground_truth kill chain 有交集",
            expected=sorted(kill_tactics)[:10],
            actual=sorted(overlap),
        )
    )

    if prev_stats.get("frontier_count", 0) >= 1:
        checks.append(
            StepCheck(
                id="l_frontier_driven",
                status="pass" if prior_probes else "warn",
                message="frontier 存在时 prior_generator 应产出",
                actual=len(prior_probes),
            )
        )

    return checks


def format_step_report(result: LPhaseStepResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"
    probe_lines = "\n".join(
        f"  - [{p.source}] {p.target} · {p.operator} · {p.tactic} (prio={p.priority_hint:.2f})"
        for p in result.probes[:10]
    )
    if len(result.probes) > 10:
        probe_lines += f"\n  ... +{len(result.probes) - 10} more"

    lines = [
        f"# Step 2 · L 拍 · 选哪条（生成层投候选） [{status}]",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        "",
        "## ① 做了什么",
        "prior_generator + rule_gap_generator 向统一 CandidatePool 投掷探针，去重合并；尚未 VOI 排序。",
        "",
        "## ② 输入（读了什么）",
        f"- SessionGraph：{result.prev_stats['node_count']} 节点 · frontier={result.prev_stats['frontier_count']}",
        f"- 告警锚点：{result.alert_asset} · {result.alert_technique}",
        f"- DecisionLedger leading={result.ledger_leading} · margin={result.ledger_margin:.2%}",
        "- 上一轮 graph.stats()（bootstrap 后首轮 prev_stats 与当前图相同 → 可触发 stagnation gap）",
        "",
        "## ③ 产出（生成了什么）",
        f"- 候选池 +{result.pool_size} 条（prior={result.prior_count} · rule_gap={result.gap_count} · 去重后={result.pool_size}）",
        f"- 来源分布：{result.sources}",
        probe_lines,
        "",
        "## ④ 怎么算的",
        "- prior：frontier technique → L2 technique_neighbors(incoming优先+outgoing补位, ≤2) → Probe",
        "- rule_gap：单节点 bootstrap → stagnation 补 unseen kill-chain tactics",
        "- CandidatePool.add 按 dedup_key 去重；本拍不调用 voi()",
        "",
        "## ⑤ 维护了什么",
        "【图】只读",
        "【决策账】只读（供 leading / explanation_ids）",
        "【Beta/义务】未写",
        "",
        "## Ground truth 校验",
    ]
    for c in result.checks:
        mark = {"pass": "OK", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[c.status]
        lines.append(f"- [{mark}] {c.id}: {c.message}")
        if c.status in ("fail", "warn") and c.expected is not None:
            lines.append(f"    expected={c.expected!r} actual={c.actual!r}")
    return "\n".join(lines)


def save_result(result: LPhaseStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step2_{result.scenario_id}.json"
    payload = {
        "step": 2,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "pool_size": result.pool_size,
        "prior_count": result.prior_count,
        "gap_count": result.gap_count,
        "sources": result.sources,
        "probes": [asdict(p) for p in result.probes],
        "prev_stats": result.prev_stats,
        "ledger_leading": result.ledger_leading,
        "ledger_margin": result.ledger_margin,
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 2 L-phase 测试（本地 MCP 场景）")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_l_phase_step(sid)
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
