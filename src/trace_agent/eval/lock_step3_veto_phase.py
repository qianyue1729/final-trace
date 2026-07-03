"""LOCK Step 3 — ② 拍 · VETO + MANDATE 检验.

Step 1 bootstrap → Step 2 L 拍 → ② 检验拍；含 gt_root_cause_reachability 前瞻检查。

Usage:
    python -m trace_agent.eval.lock_step3_veto_phase
    python -m trace_agent.eval.lock_step3_veto_phase --scenario pipeline_18 --save
    python -m trace_agent.eval.lock_step3_veto_phase --all
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from trace_agent.data_loader import load_prior_bundle
from trace_agent.eval.lock_step1_bootstrap import RESULTS_DIR, StepCheck, list_scenario_ids
from trace_agent.eval.lock_step2_l_phase import (
    ProbeSnapshot,
    _probe_snapshot,
    _setup_orchestrator,
    _technique_to_tactic,
)
from trace_agent.eval.soar_integration_runner import load_scenario
from trace_agent.prior_v2 import PriorManager
from trace_agent.utils.config import DISCRIMINATIVE_MARGIN_THRESHOLD

# 可跨主机 / 追根因的 operator（前瞻 reachability，非 C 拍执行结果）
ROOT_CAUSE_REACH_OPERATORS = frozenset({
    "auth_log",
    "lateral_movement_check",
    "network_flow",
    "dns_query",
    "email_gateway",
    "script_execution",
})

ROOT_CAUSE_REACH_TACTICS = frozenset({
    "initial-access",
    "lateral-movement",
    "credential-access",
})

_TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


@dataclass
class ObligationSnapshot:
    id: str
    type: str
    anchor: str
    hard: bool
    discharged: bool
    tags: list[str]


@dataclass
class VetoPhaseStepResult:
    scenario_id: str
    entry_ref: str
    alert_asset: str
    pool_size_before: int
    pool_size_after: int
    probes_before: list[ProbeSnapshot]
    probes_after: list[ProbeSnapshot]
    obligations: list[ObligationSnapshot]
    mandated_count: int
    ledger_margin: float
    root_cause_entity: str
    root_cause_technique: str
    reachability_matches: list[dict[str, Any]]
    checks: list[StepCheck] = field(default_factory=list)

    @property
    def all_pass(self) -> bool:
        return all(c.status in ("pass", "warn", "skip") for c in self.checks)


def _parse_root_technique(raw: str | None) -> str:
    if not raw:
        return ""
    m = _TECHNIQUE_ID_RE.search(raw)
    return m.group(0) if m else raw.split()[0] if raw else ""


def _root_cause_info(scenario_data: dict) -> dict[str, str]:
    gt = scenario_data.get("ground_truth") or {}
    technique = _parse_root_technique(gt.get("root_cause_technique"))
    return {
        "entity_id": str(gt.get("root_cause_entity_id") or "").strip(),
        "technique": technique,
        "tactic": _technique_to_tactic(technique).lower() if technique else "",
    }


def _probe_reachability_match(
    probe: ProbeSnapshot,
    *,
    root_entity: str,
    root_tactic: str,
    alert_asset: str,
) -> bool:
    op = probe.operator.lower()
    tac = probe.tactic.lower().replace("_", "-")
    target = probe.target.lower()
    root = root_entity.lower()
    alert = alert_asset.lower()
    md = probe.metadata or {}

    if root and root in target:
        return True
    if op in ROOT_CAUSE_REACH_OPERATORS:
        return True
    if "email" in op or "mail" in op:
        return True
    if tac in ROOT_CAUSE_REACH_TACTICS:
        return True
    if md.get("missing_tactic") in ROOT_CAUSE_REACH_TACTICS:
        return True
    if root_tactic and tac == root_tactic:
        return True
    # 同主机根因：告警资产即根因主机时 process_tree 足够
    if root and alert and root == alert and op == "process_tree":
        return True
    return False


def _check_gt_root_cause_reachability(
    probes: list[ProbeSnapshot],
    alert_asset: str,
    root_info: dict[str, str],
) -> StepCheck:
    root_entity = root_info["entity_id"]
    root_technique = root_info["technique"]
    root_tactic = root_info["tactic"]

    if not root_technique and not root_entity:
        return StepCheck(
            id="gt_root_cause_reachability",
            status="skip",
            message="ground_truth 无 root_cause 字段",
        )

    alert = (alert_asset or "").lower()
    root = root_entity.lower()

    if root and alert and root == alert:
        return StepCheck(
            id="gt_root_cause_reachability",
            status="pass",
            message="告警资产即根因主机，本地 process_tree 可追根",
            expected=root_entity,
            actual=alert_asset,
        )

    matches = [
        p
        for p in probes
        if _probe_reachability_match(
            p,
            root_entity=root_entity,
            root_tactic=root_tactic,
            alert_asset=alert_asset,
        )
    ]
    detail = [
        {"operator": p.operator, "tactic": p.tactic, "target": p.target, "source": p.source}
        for p in matches[:8]
    ]

    # external 根因：强调 network/dns/IA
    if root == "external":
        ok = any(
            p.operator.lower() in {"network_flow", "dns_query", "auth_log"}
            or p.tactic.lower().replace("_", "-") == "initial-access"
            for p in probes
        )
    else:
        ok = len(matches) >= 1

    return StepCheck(
        id="gt_root_cause_reachability",
        status="pass" if ok else "fail",
        message="幸存候选含可追根 operator/tactic（auth_log/lateral/network/email/IA 等）",
        expected={
            "root_entity": root_entity or "(cross-host)",
            "root_technique": root_technique,
            "root_tactic": root_tactic,
            "reach_operators": sorted(ROOT_CAUSE_REACH_OPERATORS),
        },
        actual=detail,
    )


def run_veto_phase_step(
    scenario_id: str,
    *,
    prior_manager: PriorManager | None = None,
) -> VetoPhaseStepResult:
    orch, scenario_data, triage = _setup_orchestrator(scenario_id, prior_manager)
    root_info = _root_cause_info(scenario_data)

    prev_stats = orch.graph.stats()
    node_before = prev_stats.get("node_count", 0)
    margin_before = orch.ledger.margin()
    beta_before = len(orch.beta.all_keys())
    obligation_before = len(orch.obligations.obligations)

    pool_before = orch._l_phase(prev_stats)
    probes_before = [_probe_snapshot(p) for p in pool_before.peek()]
    size_before = pool_before.size()

    pool_after = orch._veto_phase(pool_before)
    probes_after = [_probe_snapshot(p) for p in pool_after.peek()]
    size_after = pool_after.size()

    graph_after = orch.graph.stats()
    obligations = [
        ObligationSnapshot(
            id=o.id,
            type=o.type.value if hasattr(o.type, "value") else str(o.type),
            anchor=o.anchor,
            hard=o.hard,
            discharged=o.discharged,
            tags=list(o.tags or []),
        )
        for o in orch.obligations.obligations
    ]
    mandated = orch.obligations.materialize_open(orch._graph_to_dict())

    reach_matches = [
        asdict(p)
        for p in probes_after
        if _probe_reachability_match(
            p,
            root_entity=root_info["entity_id"],
            root_tactic=root_info["tactic"],
            alert_asset=triage.alert.asset_id or "",
        )
    ]

    checks: list[StepCheck] = []

    checks.append(
        StepCheck(
            id="v_pool_survives",
            status="pass" if size_after >= 1 else "fail",
            message="② 拍后幸存候选池非空",
            actual=size_after,
        )
    )
    checks.append(
        StepCheck(
            id="v_pool_not_expanded",
            status="pass" if size_after <= size_before else "fail",
            message="VETO 不扩张候选池（仅过滤/义务物化）",
            expected=f"<={size_before}",
            actual=size_after,
        )
    )
    checks.append(
        StepCheck(
            id="v_graph_readonly",
            status="pass" if graph_after.get("node_count") == node_before else "fail",
            message="② 拍不写入 SessionGraph",
        )
    )
    checks.append(
        StepCheck(
            id="v_ledger_readonly",
            status="pass" if abs(orch.ledger.margin() - margin_before) < 1e-9 else "fail",
            message="② 拍不更新 DecisionLedger 后验",
        )
    )
    checks.append(
        StepCheck(
            id="v_beta_readonly",
            status="pass" if len(orch.beta.all_keys()) == beta_before == 0 else "fail",
            message="② 拍不写入 BetaLedger",
        )
    )

    new_ob = len(orch.obligations.obligations) - obligation_before
    if new_ob > 0:
        checks.append(
            StepCheck(
                id="v_obligations_scanned",
                status="pass",
                message="obligation.scan 产生新义务",
                actual=new_ob,
            )
        )
    else:
        checks.append(
            StepCheck(
                id="v_obligations_scanned",
                status="warn",
                message="bootstrap 单节点图常无结构/生命周期义务（scan 已执行）",
                actual=0,
            )
        )

    if margin_before < DISCRIMINATIVE_MARGIN_THRESHOLD:
        has_disc = any(o.type == "discriminative" for o in obligations if not o.discharged)
        checks.append(
            StepCheck(
                id="v_discriminative_when_low_margin",
                status="pass" if has_disc else "warn",
                message=f"margin<{DISCRIMINATIVE_MARGIN_THRESHOLD} 时应触发判别义务",
                actual=has_disc,
            )
        )

    if obligations:
        checks.append(
            StepCheck(
                id="v_mandated_materializable",
                status="pass" if mandated else "warn",
                message="开放义务可 materialize_open 为 mandated 探针",
                actual=len(mandated),
            )
        )

    checks.append(
        _check_gt_root_cause_reachability(
            probes_after,
            triage.alert.asset_id or "",
            root_info,
        )
    )

    return VetoPhaseStepResult(
        scenario_id=scenario_id,
        entry_ref=triage.entry_ref,
        alert_asset=triage.alert.asset_id or "",
        pool_size_before=size_before,
        pool_size_after=size_after,
        probes_before=probes_before,
        probes_after=probes_after,
        obligations=obligations,
        mandated_count=len(mandated),
        ledger_margin=round(margin_before, 4),
        root_cause_entity=root_info["entity_id"],
        root_cause_technique=root_info["technique"],
        reachability_matches=reach_matches,
        checks=checks,
    )


def format_step_report(result: VetoPhaseStepResult) -> str:
    fails = [c for c in result.checks if c.status == "fail"]
    status = "PASS" if not fails else "FAIL"

    before_ops = ", ".join(sorted({p.operator for p in result.probes_before}))
    after_ops = ", ".join(sorted({p.operator for p in result.probes_after}))
    ob_lines = "\n".join(
        f"  - [{o.type}] {o.anchor} hard={o.hard}"
        for o in result.obligations[:6]
    ) or "  - （无开放义务 — bootstrap 单节点常见）"

    reach = result.reachability_matches[:5]
    reach_txt = json.dumps(reach, ensure_ascii=False) if reach else "[]"

    lines = [
        f"# Step 3 · ② 拍 · 检验（VETO + MANDATE） [{status}]",
        f"场景: {result.scenario_id} · 入口: {result.entry_ref}",
        f"根因 GT: {result.root_cause_entity or '(未指定)'} · {result.root_cause_technique}",
        "",
        "## ① 做了什么",
        "证据信任闸门 + obligation.scan/discharge；当前 orchestrator 对池内 Probe 不做硬 VETO（C 拍验真时处理）。",
        "",
        "## ② 输入（读了什么）",
        f"- L 拍候选池 {result.pool_size_before} 条 · operators: {before_ops}",
        f"- SessionGraph 不变 · margin={result.ledger_margin:.2%}",
        "- EvidenceTrust / 图不变量（scan 输入）",
        "",
        "## ③ 产出（生成了什么）",
        f"- 幸存池 {result.pool_size_after} 条 · operators: {after_ops}",
        f"- 义务 {len(result.obligations)} 条 · mandated 物化 {result.mandated_count}",
        ob_lines,
        f"- gt_root_cause_reachability 匹配: {reach_txt}",
        "",
        "## ④ 怎么算的",
        "- scan_structural / lifecycle / anti_forensics / discriminative",
        "- discharge 关闭已满足义务",
        "- reachability：operator ∈ auth_log|lateral|network|dns|email 或 tactic=IA/lateral/credential",
        "",
        "## ⑤ 维护了什么",
        "【图/决策/Beta】只读",
        "【义务】scan + discharge（本场景常仍为 0）",
        "【候选池】当前实现透传（size 不变）",
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


def save_result(result: VetoPhaseStepResult, path: Path | None = None) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = path or RESULTS_DIR / f"lock_step3_{result.scenario_id}.json"
    payload = {
        "step": 3,
        "scenario_id": result.scenario_id,
        "all_pass": result.all_pass,
        "pool_size_before": result.pool_size_before,
        "pool_size_after": result.pool_size_after,
        "obligations": [asdict(o) for o in result.obligations],
        "mandated_count": result.mandated_count,
        "root_cause_entity": result.root_cause_entity,
        "root_cause_technique": result.root_cause_technique,
        "reachability_matches": result.reachability_matches,
        "probes_after": [asdict(p) for p in result.probes_after],
        "checks": [asdict(c) for c in result.checks],
        "report_md": format_step_report(result),
    }
    out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return out


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="LOCK Step 3 ②-phase 测试（本地 MCP 场景）")
    parser.add_argument("--scenario", default="pipeline_18")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--save", action="store_true")
    args = parser.parse_args()

    ids = list_scenario_ids() if args.all else [args.scenario]
    exit_code = 0
    for sid in ids:
        result = run_veto_phase_step(sid)
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
