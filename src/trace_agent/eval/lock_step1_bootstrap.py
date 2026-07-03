"""LOCK Step 1 — triage_entry + bootstrap_chain + 薄播种决策账.

泛化本地 MCP（soar_mcp_env）场景测试：用 ground_truth 校验每一步结构不变量，
并输出与 RFC-004-02 / 前端 stepExplains 对齐的可读报告。

Usage:
    python -m trace_agent.eval.lock_step1_bootstrap
    python -m trace_agent.eval.lock_step1_bootstrap --scenario pipeline_18
    python -m trace_agent.eval.lock_step1_bootstrap --all
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from trace_agent.agents.orchestrator import DecisionOrchestrator, BudgetState
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent, SeedPayload
from trace_agent.eval.metrics import collect_metrics
from trace_agent.eval.quality_gates import run_quality_gates
from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_agent.loop.scenario_executor import ScenarioExecutor
from trace_agent.prior_v2 import PriorManager

SOAR_ENV_DIR = Path(__file__).resolve().parent.parent.parent.parent / "soar_mcp_env"
RESULTS_DIR = SOAR_ENV_DIR / "results"
REGISTRY_PATH = SOAR_ENV_DIR / "registry.json"


def list_scenario_ids() -> list[str]:
    if not REGISTRY_PATH.is_file():
        return ["pipeline_18"]
    reg = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    return list(reg.get("scenarios", {}).keys())

CheckStatus = Literal["pass", "fail", "warn", "skip"]


@dataclass
class StepCheck:
    id: str
    status: CheckStatus
    message: str
    expected: Any = None
    actual: Any = None


@dataclass
class TriageEntryResult:
    scenario_id: str
    entry_ref: str
    alert: AlertEvent
    triage_malicious: bool
    triage_critical_asset: bool | None
    asset_criticality: float | None
    checks: list[StepCheck] = field(default_factory=list)


@dataclass
class BootstrapStepResult:
    scenario_id: str
    triage: TriageEntryResult
    seed: SeedPayload
    graph_stats: dict[str, Any]
    graph_nodes: list[dict[str, Any]]
    ledger_snapshot: dict[str, Any]
    beta_snapshot: dict[str, Any]
    obligation_count: int
    mcp_toolbox_ok: bool
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _host_uid(event: dict) -> str:
    src = event.get("src_entity") or {}
    dst = event.get("dst_entity") or {}
    return (
        (src.get("attrs") or {}).get("host_uid")
        or (dst.get("attrs") or {}).get("host_uid")
        or ""
    )


def _cmdb_lookup(cmdb: dict, host_uid: str) -> dict | None:
    if not host_uid:
        return None
    for key, val in cmdb.items():
        if key.lower() == host_uid.lower():
            return val
    return None


def triage_entry(scenario_id: str) -> TriageEntryResult:
    """初诊门控 + 从场景 entry 构建 AlertEvent（对应 RFC triage_entry）。"""
    scenario_data, registry_spec = load_scenario(scenario_id)
    entry_event = find_entry_event(scenario_data, registry_spec)
    alert = build_alert_event(entry_event)
    meta = scenario_data.get("meta") or {}
    cmdb = meta.get("cmdb") or {}
    host = _host_uid(entry_event)
    cmdb_row = _cmdb_lookup(cmdb, host or alert.asset_id or "")
    criticality = float(cmdb_row["criticality"]) if cmdb_row and "criticality" in cmdb_row else None

    technique = entry_event.get("technique")
    anomaly = float(entry_event.get("anomaly_score") or 0)
    triage_malicious = bool(technique) or anomaly >= 0.5
    triage_critical = criticality is not None and criticality >= 0.7

    checks: list[StepCheck] = []
    checks.append(
        StepCheck(
            id="triage_entry_found",
            status="pass" if entry_event else "fail",
            message="entry_alert_ref 对应事件存在",
            actual=entry_event.get("raw_log_ref"),
        )
    )
    checks.append(
        StepCheck(
            id="triage_malicious",
            status="pass" if triage_malicious else "fail",
            message="初诊恶意：technique 非空或 anomaly_score ≥ 0.5",
            expected=True,
            actual={"technique": technique, "anomaly_score": anomaly},
        )
    )
    checks.append(
        StepCheck(
            id="triage_asset_present",
            status="pass" if alert.asset_id else "fail",
            message="告警锚定资产 host_uid",
            actual=alert.asset_id,
        )
    )
    if criticality is not None:
        checks.append(
            StepCheck(
                id="triage_critical_asset",
                status="pass" if triage_critical else "warn",
                message="CMDB 核心资产（criticality ≥ 0.7）",
                expected="≥0.7",
                actual=criticality,
            )
        )
    else:
        checks.append(
            StepCheck(
                id="triage_critical_asset",
                status="skip",
                message="CMDB 无此资产记录",
                actual=alert.asset_id,
            )
        )

    gt = scenario_data.get("ground_truth") or {}
    entry_ref = entry_event.get("raw_log_ref", "")
    attack_refs = gt.get("attack_edge_refs") or []
    if entry_ref.startswith("attack:"):
        checks.append(
            StepCheck(
                id="gt_entry_in_attack_refs",
                status="pass" if entry_ref in attack_refs else "fail",
                message="入口告警在 ground_truth.attack_edge_refs",
                expected=entry_ref,
                actual=entry_ref in attack_refs,
            )
        )

    return TriageEntryResult(
        scenario_id=scenario_id,
        entry_ref=entry_ref,
        alert=alert,
        triage_malicious=triage_malicious,
        triage_critical_asset=triage_critical if criticality is not None else None,
        asset_criticality=criticality,
        checks=checks,
    )


def bootstrap_chain(
    triage: TriageEntryResult,
    *,
    prior_manager: PriorManager | None = None,
) -> BootstrapStepResult:
    """bootstrap_chain：seed 四本账 + SessionGraph 告警锚点（不进入 LOCK 主循环）。"""
    scenario_data, _ = load_scenario(triage.scenario_id)
    prior = prior_manager or PriorManager(load_prior_bundle())
    executor = ScenarioExecutor(scenario_data, seed=42)
    seed = DecisionLedger(prior).seed(triage.alert)

    orch = DecisionOrchestrator(
        alert=triage.alert,
        executor=executor,
        prior_manager=prior,
        seed=seed,
        budget=BudgetState(total_rounds=1, total_probes=1),
    )
    orch._bootstrap()

    if orch.ledger is None or orch.graph is None:
        raise RuntimeError("bootstrap 未初始化 ledger / graph")

    graph_stats = orch.graph.stats()
    graph_nodes = [
        {
            "id": n.id,
            "technique": n.technique,
            "tactic": n.tactic,
            "asset_id": (n.attributes or {}).get("asset_id"),
            "source": n.source,
        }
        for n in orch.graph._nodes.values()
    ]

    posteriors = orch.ledger._get_probabilities()
    ledger_snapshot = {
        "explanations": [
            {
                "id": e.id,
                "title": e.title,
                "technique": e.current_technique,
                "prior_p": round(e.prior_probability, 4),
                "posterior_p": round(posteriors.get(e.id, 0.0), 4),
            }
            for e in orch.ledger.explanations
        ],
        "null_anchor": {
            "benign": round(orch.ledger.null_anchor.benign, 4),
            "oos": round(orch.ledger.null_anchor.oos, 4),
        },
        "contested_edges": [
            {
                "edge_id": eid,
                "p_in_attack": round(b.p_in_attack, 4),
                "p_benign": round(b.p_benign, 4),
                "p_oos": round(b.p_oos, 4),
            }
            for eid, b in orch.ledger.contested.items()
        ],
        "entropy": round(collect_metrics(seed)["entropy"], 4),
        "max_prior": round(collect_metrics(seed)["max_prior"], 4),
    }

    beta_snapshot = orch.beta.to_dict()
    obligation_count = len(orch.obligations.obligations)

    mcp_ok = False
    try:
        from soar_mcp_env.setup import create_soar_toolbox

        create_soar_toolbox(triage.scenario_id)
        mcp_ok = True
    except Exception:
        pass

    checks = list(triage.checks)
    checks.extend(_validate_bootstrap(triage, seed, graph_stats, graph_nodes, beta_snapshot, obligation_count, scenario_data))
    qg = run_quality_gates(seed)
    checks.append(
        StepCheck(
            id="quality_gates",
            status="pass" if qg["gates"]["all_pass"] else "fail",
            message="Prior quality gates（高熵薄先验）",
            actual=qg["gates"],
        )
    )
    checks.append(
        StepCheck(
            id="mcp_toolbox_ready",
            status="pass" if mcp_ok else "warn",
            message="soar_mcp_env Toolbox 可装配（查询桥就绪）",
            actual=mcp_ok,
        )
    )

    return BootstrapStepResult(
        scenario_id=triage.scenario_id,
        triage=triage,
        seed=seed,
        graph_stats=graph_stats,
        graph_nodes=graph_nodes,
        ledger_snapshot=ledger_snapshot,
        beta_snapshot=beta_snapshot,
        obligation_count=obligation_count,
        mcp_toolbox_ok=mcp_ok,
        checks=checks,
    )


def _validate_bootstrap(
    triage: TriageEntryResult,
    seed: SeedPayload,
    graph_stats: dict,
    graph_nodes: list[dict],
    beta_snapshot: dict,
    obligation_count: int,
    scenario_data: dict,
) -> list[StepCheck]:
    alert = triage.alert
    metrics = collect_metrics(seed)
    checks: list[StepCheck] = []

    four_ok = graph_stats.get("node_count", 0) >= 1 and seed.explanations
    checks.append(
        StepCheck(
            id="four_ledgers_ready",
            status="pass" if four_ok else "fail",
            message="四本账就绪（图/决策/Beta/义务）",
        )
    )
    checks.append(
        StepCheck(
            id="graph_bootstrap_node",
            status="pass" if alert.technique_id in graph_stats.get("techniques_seen", []) else "fail",
            message="SessionGraph 写入告警 technique 节点",
            expected=alert.technique_id,
            actual=graph_stats.get("techniques_seen"),
        )
    )
    checks.append(
        StepCheck(
            id="graph_frontier_only",
            status="pass" if graph_stats.get("edge_count", 0) == 0 else "warn",
            message="bootstrap 阶段无边（frontier = 告警锚点）",
            actual={"nodes": graph_stats.get("node_count"), "edges": graph_stats.get("edge_count")},
        )
    )
    asset_match = any(n.get("asset_id", "").lower() == (alert.asset_id or "").lower() for n in graph_nodes)
    checks.append(
        StepCheck(
            id="graph_alert_asset",
            status="pass" if asset_match else "fail",
            message="图节点 asset_id 与告警一致",
            expected=alert.asset_id,
            actual=[n.get("asset_id") for n in graph_nodes],
        )
    )
    checks.append(
        StepCheck(
            id="seed_explanation_count",
            status="pass" if 1 <= metrics["explanation_count"] <= 6 else "fail",
            message="竞争解释 1–6 条",
            actual=metrics["explanation_count"],
        )
    )
    high_entropy = metrics["max_prior"] <= 0.55 and (
        metrics["entropy"] >= 0.45 or metrics["explanation_count"] <= 2
    )
    checks.append(
        StepCheck(
            id="seed_high_entropy",
            status="pass" if high_entropy else "fail",
            message="高熵薄先验（max_prior≤0.55）",
            actual={"max_prior": metrics["max_prior"], "entropy": metrics["entropy"]},
        )
    )
    null_ok = seed.branch_null_anchor.benign > 0 and seed.branch_null_anchor.oos > 0
    checks.append(
        StepCheck(
            id="seed_null_anchor",
            status="pass" if null_ok else "fail",
            message="null 锚 benign/oos 均 > 0（分支定界落点）",
            actual={"benign": seed.branch_null_anchor.benign, "oos": seed.branch_null_anchor.oos},
        )
    )
    tech_match = any(e.current_technique == alert.technique_id for e in seed.explanations)
    checks.append(
        StepCheck(
            id="seed_technique_in_explanations",
            status="pass" if tech_match else "warn",
            message="至少一条解释 current_technique 匹配告警",
            expected=alert.technique_id,
        )
    )
    beta_empty = len(beta_snapshot.get("params") or {}) == 0
    checks.append(
        StepCheck(
            id="beta_default_prior",
            status="pass" if beta_empty else "warn",
            message="BetaLedger 空账（α0=β0=1，无观测）",
            actual=beta_snapshot,
        )
    )
    checks.append(
        StepCheck(
            id="obligations_empty",
            status="pass" if obligation_count == 0 else "warn",
            message="ObligationLedger bootstrap 后无义务项",
            actual=obligation_count,
        )
    )

    gt = scenario_data.get("ground_truth") or {}
    kill_chain: list[str] = []
    events_by_ref = {e.get("raw_log_ref"): e for e in scenario_data.get("events", []) if e.get("raw_log_ref")}
    for ref in gt.get("attack_edge_refs") or []:
        ev = events_by_ref.get(ref)
        if ev and ev.get("technique") and ev["technique"] not in kill_chain:
            kill_chain.append(ev["technique"])
    expl_techniques = {e.current_technique for e in seed.explanations}
    overlap = expl_techniques & set(kill_chain)
    checks.append(
        StepCheck(
            id="gt_kill_chain_overlap",
            status="pass" if overlap else "warn",
            message="seed 解释 technique 与 ground_truth kill chain 有交集",
            expected=sorted(kill_chain)[:8],
            actual=sorted(overlap),
        )
    )
    return checks


def run_bootstrap_step(scenario_id: str, *, prior_manager: PriorManager | None = None) -> BootstrapStepResult:
    triage = triage_entry(scenario_id)
    return bootstrap_chain(triage, prior_manager=prior_manager)


def format_step_report(result: BootstrapStepResult) -> str:
    """生成与 demo stepExplains ①–⑤ 对齐的可读报告。"""
    t = result.triage
    a = t.alert
    ls = result.ledger_snapshot
    expl_lines = " · ".join(
        f"{e['id']} {e['prior_p']:.0%}" for e in ls["explanations"][:4]
    )
    null_b = ls["null_anchor"]["benign"]
    null_o = ls["null_anchor"]["oos"]
    null_line = f"null 锚 benign={null_b:.0%} oos={null_o:.0%}"
    contested_lines = ls["contested_edges"][:3]
    contested_txt = (
        "; ".join(
            f"{c['edge_id']} {{attack:{c['p_in_attack']:.0%}, benign:{c['p_benign']:.0%}, oos:{c['p_oos']:.0%}}}"
            for c in contested_lines
        )
        or "（无 L2 dual-use 边 → contested 为空）"
    )

    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"

    lines = [
        f"# Step 1 · bootstrap + 薄播种决策账 [{status}]",
        f"场景: {result.scenario_id} · 入口: {t.entry_ref}",
        "",
        "## ① 做了什么",
        "初诊门控通过后，执行 triage_entry、bootstrap_chain，初始化四本账中的决策账。",
        "",
        "## ② 输入（读了什么）",
        f"- 告警 E：{a.asset_id} · {a.technique_id} / {a.tactic}（anomaly={a.anomaly_score}）",
        f"- 初诊：恶意={'Y' if t.triage_malicious else 'N'}"
        + (f" · 核心资产={'Y' if t.triage_critical_asset else 'N'}" if t.triage_critical_asset is not None else ""),
        "- score_v3 七维先验 + LifecycleTemplate（PriorManager L1–L4）",
        "- 空 SessionGraph → 仅告警锚点",
        "",
        "## ③ 产出（生成了什么）",
        f"- SessionGraph：{result.graph_stats['node_count']} 节点 · frontier={result.graph_stats['frontier_count']}",
        f"- DecisionLedger.seed：{expl_lines} · {null_line}",
        f"- contested：{contested_txt}",
        f"- BetaLedger：{result.beta_snapshot['alpha0']}/{result.beta_snapshot['beta0']} 默认先验，keys={len(result.beta_snapshot.get('params', {}))}",
        f"- ObligationLedger：{result.obligation_count} 条",
        "",
        "## ④ 怎么算的",
        "- score_v3 → softmax(τ=2) → 各解释 P(H)；非探针 VOI 分",
        "- null 锚 = 分支定界落点（benign/oos），非整案误报主战场",
        f"- max_prior={ls['max_prior']} entropy={ls['entropy']}",
        "",
        "## ⑤ 维护了什么",
        "【图】bootstrap 告警节点",
        "【决策账】explanations + contested 初始化",
        "【Beta】α0,β0 默认",
        "【义务】空",
        "",
        "## Ground truth 校验",
    ]
    for c in result.checks:
        mark = {"pass": "OK", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[c.status]
        lines.append(f"- [{mark}] {c.id}: {c.message}")
        if c.status == "fail" and c.expected is not None:
            lines.append(f"    expected={c.expected!r} actual={c.actual!r}")
    return "\n".join(lines)


def save_result(result: BootstrapStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step1_{result.scenario_id}.json"

    def _serialize(obj: Any) -> Any:
        if hasattr(obj, "__dataclass_fields__"):
            return {k: _serialize(v) for k, v in asdict(obj).items()}
        if isinstance(obj, AlertEvent):
            return asdict(obj)
        if isinstance(obj, SeedPayload):
            return {
                "alert": asdict(obj.alert),
                "explanation_ids": [e.id for e in obj.explanations],
                "null_anchor": asdict(obj.branch_null_anchor),
                "contested_count": len(obj.contested_edges),
            }
        return obj

    payload = {
        "step": 1,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "graph_stats": result.graph_stats,
        "ledger_snapshot": result.ledger_snapshot,
        "beta_snapshot": result.beta_snapshot,
        "obligation_count": result.obligation_count,
        "mcp_toolbox_ok": result.mcp_toolbox_ok,
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 1 bootstrap 测试（本地 MCP 场景）")
    parser.add_argument("--scenario", default="pipeline_18", help="registry 场景 ID")
    parser.add_argument("--all", action="store_true", help="跑全部注册场景")
    parser.add_argument("--save", action="store_true", help="写入 soar_mcp_env/results/")
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_bootstrap_step(sid)
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
