"""Run traced LOCK sessions against soar_mcp_env scenarios for the demo frontend."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, urlparse

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))

from trace_agent.agents.orchestrator import (
    BudgetState,
    DecisionOrchestrator,
    InvestigationResult,
)
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.types import AlertEvent
from trace_agent.eval.lock_step5_c_phase import _align_executor_to_alert
from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.loop.probe import Probe
from trace_agent.loop.scenario_executor import ScenarioExecutor
from trace_agent.prior_v2 import PriorManager
from trace_agent.probe.voi_engine import EPS_VOI, decision_robust, voi

SOAR_ENV_DIR = _PROJECT_ROOT / "soar_mcp_env"
REGISTRY_PATH = SOAR_ENV_DIR / "registry.json"

TECHNIQUE_KIND = {
    "T1566": "email", "T1566.001": "email",
    "T1059": "process", "T1059.001": "process",
    "T1053": "process", "T1053.005": "process",
    "T1486": "file", "T1021": "host", "T1021.001": "host",
    "T1071": "host", "T1071.001": "host", "T1048": "host",
    "T1003": "user", "T1005": "file",
}

TACTIC_CN = {
    "initial-access": "初始访问",
    "execution": "执行",
    "persistence": "持久化",
    "lateral-movement": "横向移动",
    "credential-access": "凭据访问",
    "collection": "收集",
    "exfiltration": "外泄",
    "discovery": "发现",
    "defense-evasion": "防御规避",
    "privilege-escalation": "权限提升",
    "impact": "影响",
}


def list_soar_scenarios() -> list[dict]:
    registry = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    out: list[dict] = []
    for sid, spec in registry.get("scenarios", {}).items():
        gt_total = {"pipeline_18": 18, "apt_5host": 25, "multipath_12host": 31}.get(sid, 0)
        out.append({
            "id": sid,
            "name": spec.get("name", sid),
            "description": spec.get("description", ""),
            "tags": spec.get("tags", []),
            "gtTotal": gt_total,
        })
    return out


def parse_scenario_id(path: str, default: str = "pipeline_18") -> str:
    parsed = urlparse(path)
    qs = parse_qs(parsed.query)
    scenario = (qs.get("scenario") or [default])[0]
    return scenario


def _gt_refs(scenario_data: dict) -> set[str]:
    return set(scenario_data.get("ground_truth", {}).get("attack_edge_refs", []))


def _graph_gt_hits(orch: DecisionOrchestrator, gt_refs: set[str]) -> set[str]:
    hits: set[str] = set()
    for node in orch.graph._nodes.values():
        attrs = node.attributes or {}
        ref = str(attrs.get("raw_log_ref") or node.id or "")
        if ref in gt_refs:
            hits.add(ref)
        elif str(node.id) in gt_refs:
            hits.add(str(node.id))
    return hits


def _node_host(attrs: dict) -> str:
    for key in ("host_uid", "asset_id", "host", "target"):
        val = attrs.get(key)
        if val:
            return str(val)
    return ""


def _is_attack_node(node) -> bool:
    attrs = node.attributes or {}
    if attrs.get("is_attack"):
        return True
    ref = str(attrs.get("raw_log_ref") or node.id or "")
    return ref.startswith("attack:")


def extract_graph(orch: DecisionOrchestrator) -> dict:
    nodes = []
    edges = []
    for nid, node in orch.graph._nodes.items():
        attrs = node.attributes or {}
        host = _node_host(attrs)
        tech = node.technique or ""
        kind = TECHNIQUE_KIND.get(tech) or TECHNIQUE_KIND.get(tech.split(".")[0], "host")
        label_parts = [host, tech] if host else [tech or nid[:12]]
        nodes.append({
            "id": nid,
            "label": " · ".join(p for p in label_parts if p),
            "kind": kind,
            "x": 0,
            "y": 0,
            "malicious": _is_attack_node(node),
            "host": host or "unknown",
            "tactic": node.tactic or "unknown",
            "technique": tech,
            "timestamp": float(node.timestamp or 0),
        })

    for eid, edge in orch.graph._edges.items():
        edges.append({
            "id": str(eid),
            "source": str(edge.src),
            "target": str(edge.dst),
            "label": edge.relation,
            "confirmed": True,
        })

    attack_count = sum(1 for n in nodes if n["malicious"])
    total = len(nodes)
    return {
        "nodes": nodes,
        "edges": edges,
        "meta": {
            "totalNodes": total,
            "attackNodes": attack_count,
            "defaultFilter": "attack" if total > 18 and attack_count >= 3 else "all",
        },
    }


def extract_decision_ledger(orch: DecisionOrchestrator) -> dict:
    probs = orch.ledger._get_probabilities()
    leading_id = orch.ledger.leading()
    explanations = []
    for eid, p in sorted(probs.items(), key=lambda x: x[1], reverse=True):
        if eid == "__null__":
            explanations.append({
                "eid": "null",
                "label": "分支定界 (null 锚)",
                "posterior": round(p, 4),
                "isNull": True,
            })
            continue
        expl_obj = next((e for e in orch.ledger.explanations if e.id == eid), None)
        explanations.append({
            "eid": eid,
            "label": getattr(expl_obj, "title", eid) if expl_obj else eid,
            "posterior": round(p, 4),
            "leading": eid == leading_id,
            "lifecycleStage": getattr(expl_obj, "stage", "") if expl_obj else "",
        })
    contested = [{
        "edgeId": edge_id,
        "edgeLabel": edge_id,
        "pInAttack": round(belief.p_in_attack, 4),
        "pBenign": round(belief.p_benign, 4),
        "pOos": round(belief.p_oos, 4),
    } for edge_id, belief in orch.ledger.contested.items()]
    return {
        "explanations": explanations,
        "contested": contested,
        "margin": round(orch.ledger.margin(), 4),
    }


def extract_beta_entries(orch: DecisionOrchestrator) -> list:
    entries = []
    for key in orch.beta.all_keys():
        alpha, beta_val = orch.beta.get_params(key)
        entries.append({
            "key": key,
            "hits": int(alpha - 1),
            "total": int((alpha - 1) + (beta_val - 1)),
        })
    return entries


def extract_obligations(orch: DecisionOrchestrator) -> list:
    result = []
    for ob in orch.obligations.obligations:
        result.append({
            "id": ob.id,
            "type": ob.type.value if hasattr(ob.type, "value") else str(ob.type),
            "anchor": ob.anchor,
            "hard": ob.hard,
            "voi": round(ob.voi_estimate, 4),
            "deadline": f"R+{max(0, ob.deadline_round - orch.budget.rounds_used)}",
            "discharged": ob.discharged,
        })
    return result


def extract_probe_pool(
    orch: DecisionOrchestrator,
    pool: Optional[CandidatePool] = None,
    chosen: Optional[list[Probe]] = None,
    pre_probes: Optional[list[Probe]] = None,
) -> list:
    if pre_probes is not None:
        probes = pre_probes
    elif pool is not None:
        probes = pool.peek()
    elif chosen is not None:
        probes = chosen
    else:
        return []

    chosen_ids = {p.id for p in (chosen or [])}
    result = []
    for probe in probes[:12]:
        try:
            voi_result = voi(
                orch._probe_to_dict(probe),
                orch.ledger,
                orch._beta_to_dict(),
                orch._calib_to_dict(),
                orch.loss,
                orch.trust,
                graph_stats=orch._compute_graph_stats(),
            )
            voi_score = voi_result.voi_score
            session_risk = voi_result.risk_now - voi_result.expected_risk_after
            cost = voi_result.cost
        except Exception:
            voi_score = probe.priority_hint
            session_risk = voi_score * 0.7
            cost = 0.04
        result.append({
            "probe": f"{probe.operator} → {probe.target}",
            "voi": round(voi_score, 4),
            "hitRate": round(orch.beta.sensitivity(probe.learning_key()), 4),
            "breakdown": {
                "session": round(max(0, session_risk), 4),
                "boundary": 0.0,
                "cost": round(cost, 4),
            },
            "selected": probe.id in chosen_ids,
        })
    result.sort(key=lambda x: x["voi"], reverse=True)
    return result


def extract_stop_signals(orch: DecisionOrchestrator) -> dict:
    entropy_val = orch.ledger.entropy()
    margin_val = orch.ledger.margin()
    max_voi_est = entropy_val * (1.0 - margin_val) * orch.loss.lambda_miss * 0.1
    for ob in orch.obligations.open_voi_gated():
        max_voi_est = max(max_voi_est, ob.voi_estimate)
    robust = False
    try:
        robust = decision_robust(orch.ledger, orch.loss)
    except Exception:
        pass
    return {
        "budget": orch.budget.exhausted(),
        "hardObligations": not orch.obligations.open_hard(),
        "voiFloor": max_voi_est < EPS_VOI,
        "robust": robust,
    }


def _probe_detail(p: Probe) -> dict:
    """Extract human-readable probe details for display."""
    return {
        "id": p.id,
        "operator": p.operator,
        "target": p.target,
        "source": p.source,
        "tactic": p.tactic,
        "label": f"{p.operator} → {p.target}",
    }


def _event_detail(ev: dict) -> dict:
    """Extract human-readable event details for display."""
    attrs = ev.get("attributes", {}) or {}
    return {
        "technique": ev.get("technique", ""),
        "tactic": ev.get("tactic", ""),
        "host": attrs.get("host_uid") or attrs.get("asset_id") or attrs.get("target") or ev.get("target", ""),
        "isAttack": bool(attrs.get("is_attack", False)),
        "isOos": bool(attrs.get("oos", False)),
        "source": ev.get("source", ""),
        "routeBucket": ev.get("_route_bucket", ""),
        "id": str(ev.get("id", "")),
    }


def capture_phase(
    phase: str,
    orch: DecisionOrchestrator,
    pool: Optional[CandidatePool] = None,
    chosen: Optional[list[Probe]] = None,
    pre_probes: Optional[list[Probe]] = None,
    summary: str = "",
    narration: str = "",
    phase_details: Optional[dict] = None,
) -> dict:
    return {
        "phase": phase,
        "summary": summary,
        "narration": narration,
        "graph": extract_graph(orch),
        "decisionLedger": extract_decision_ledger(orch),
        "probePool": extract_probe_pool(orch, pool, chosen, pre_probes),
        "obligations": extract_obligations(orch),
        "betaEntries": extract_beta_entries(orch),
        "stopSignals": extract_stop_signals(orch),
        "budgetUsed": orch.budget.probes_used,
        "phaseDetails": phase_details or {},
    }


def _build_narrative(
    scenario_id: str,
    scenario_name: str,
    alert: AlertEvent,
    entry_ref: str,
    rounds_data: list[dict],
    result: InvestigationResult,
    gt_hits: set[str],
    gt_total: int,
    posterior_history: list[dict],
) -> dict:
    kill_chain: list[dict] = []
    seen_tactics: set[str] = set()
    for rd in rounds_data:
        for phase in rd.get("phases", []):
            if phase.get("phase") not in ("K", "STOP"):
                continue
            for node in phase.get("graph", {}).get("nodes", []):
                if not node.get("malicious"):
                    continue
                label = node.get("label", "")
                parts = label.split(" · ")
                tech = parts[-1] if len(parts) > 1 else label
                tactic = ""
                for t_cn, t_en in TACTIC_CN.items():
                    if t_cn in label:
                        tactic = t_en
                        break
                if tactic and tactic not in seen_tactics:
                    seen_tactics.add(tactic)
                    kill_chain.append({
                        "stage": TACTIC_CN.get(tactic, tactic),
                        "technique": tech,
                        "evidence": f"LOCK 图内节点 · {label}",
                        "confidence": "调查确认",
                    })

    round_narratives = []
    for rd in rounds_data:
        meta = rd.get("_meta", {})
        round_narratives.append({
            "round": rd["round"],
            "title": rd["title"],
            "discovery": meta.get("discovery", rd["title"]),
            "techniques": meta.get("new_refs", []),
            "tactics": [],
            "posteriorAfter": meta.get("h1", 0),
            "nodesAdded": meta.get("nodes_added", 0),
            "edgesAdded": meta.get("edges_added", 0),
        })

    coverage_pct = round(100.0 * len(gt_hits) / gt_total, 1) if gt_total else 0.0
    scene_name = scenario_name or scenario_id
    conf_str = f"{result.confidence:.1%}" if result.confidence is not None else "N/A"
    conclusion = (
        f"场景 {scene_name}：经 {len(rounds_data)} 轮 LOCK 循环，"
        f"GT 攻击边命中 {len(gt_hits)}/{gt_total}（{coverage_pct}%），"
        f"决策 {result.decision}，置信度 {conf_str}，"
        f"停止原因 {result.stop_reason or 'budget'}。"
    )
    return {
        "caseId": f"SOAR-{scenario_id.upper()}",
        "analyst": "LOCK 溯源引擎 · soar_mcp_env 真实场景回放",
        "generatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "alertSummary": (
            f"入口告警 {entry_ref} · {alert.technique_id} @ {alert.asset_id or '未知主机'}"
        ),
        "investigationGoal": "在 SOAR MCP 多源场景上还原完整 LOCK 单环溯源过程",
        "killChainStages": kill_chain[:12],
        "roundNarratives": round_narratives,
        "posteriorEvolution": posterior_history,
        "attackPath": " → ".join(
            s["technique"] for s in kill_chain[:8]
        ) or "（调查进行中）",
        "conclusion": conclusion,
        "recommendation": (
            "contain/escalate" if result.decision == "contain_escalate"
            else "继续监控并补查高 VOI 主机/算子缺口"
        ),
    }


def run_soar_traced_session(scenario_id: str) -> dict:
    """Run full traced LOCK loop on a soar_mcp_env scenario."""
    scenario_data, registry_spec = load_scenario(scenario_id)
    spec_name = registry_spec.get("name", scenario_id)
    entry_event = find_entry_event(scenario_data, registry_spec)
    entry_ref = entry_event.get("raw_log_ref", "")
    alert = build_alert_event(entry_event)

    gt_refs = _gt_refs(scenario_data)
    gt_total = len(gt_refs)
    bundle = load_prior_bundle()
    prior_manager = PriorManager(bundle)
    dl = DecisionLedger(prior_manager)
    seed = dl.seed(alert)

    executor = ScenarioExecutor(scenario_data, seed=42)
    budget = BudgetState(
        total_rounds=50,
        total_probes=400,
        fanout_per_round=8,
        min_rounds_before_robust=4,
        min_rounds_after_root=8,
    )
    orch = DecisionOrchestrator(
        alert=alert,
        executor=executor,
        prior_manager=prior_manager,
        budget=budget,
        seed=seed,
    )
    orch._bootstrap()
    _align_executor_to_alert(orch, scenario_data, registry_spec)

    rounds_data: list[dict] = []
    posterior_history: list[dict] = []
    prev_stats = orch.graph.stats()
    prev_hits = _graph_gt_hits(orch, gt_refs)
    prev_nodes = orch.graph.stats().get("node_count", 0)
    prev_edges = len(orch.graph._edges)
    final_stop_reason = "budget"

    # Track previous probabilities for K-phase delta
    prev_probs = orch.ledger._get_probabilities()

    while not orch.budget.exhausted():
        orch.budget.rounds_used += 1
        round_num = orch.budget.rounds_used
        phases: list[dict] = []

        # ── L 拍 ──
        pool = orch._l_phase(prev_stats)
        pool_size = pool.size()
        l_probes = pool.peek()
        l_details = {
            "probeCount": pool_size,
            "probes": [_probe_detail(p) for p in l_probes[:12]],
            "targets": sorted({p.target for p in l_probes if p.target}),
            "sources": sorted({p.source for p in l_probes if p.source}),
            "operators": sorted({p.operator for p in l_probes if p.operator}),
        }
        phases.append(capture_phase(
            "L", orch, pool=pool,
            summary=f"生成 {pool_size} 条候选探针",
            narration=f"来源: {', '.join(l_details['sources'])} · 目标主机: {', '.join(l_details['targets'][:5])}",
            phase_details=l_details,
        ))

        # ── VETO 拍 ──
        pool_after_veto = orch._veto_phase(pool)
        veto_count = pool_size - pool_after_veto.size()
        surviving_probes = pool_after_veto.peek()
        vetoed_targets = sorted(
            {p.target for p in l_probes if p not in surviving_probes}
        )
        veto_details = {
            "vetoedCount": veto_count,
            "survivingCount": pool_after_veto.size(),
            "survivingProbes": [_probe_detail(p) for p in surviving_probes[:10]],
            "survivingTargets": sorted({p.target for p in surviving_probes if p.target}),
        }
        phases.append(capture_phase(
            "VETO", orch, pool=pool_after_veto,
            summary=f"VETO 过滤 {veto_count} 条 · 义务扫描",
            narration=f"幸存 {pool_after_veto.size()} 条 · 目标: {', '.join(veto_details['survivingTargets'][:5])}",
            phase_details=veto_details,
        ))

        # ── O 拍 ──
        pre_o_probes = pool_after_veto.peek()
        chosen = orch._o_phase(pool_after_veto)
        if not chosen:
            final_stop_reason = "no_probes"
            break
        chosen_targets = sorted({p.target for p in chosen if p.target})
        chosen_operators = sorted({p.operator for p in chosen if p.operator})
        o_details = {
            "chosenCount": len(chosen),
            "chosenProbes": [_probe_detail(p) for p in chosen],
            "targets": chosen_targets,
            "operators": chosen_operators,
            "budgetRemaining": orch.budget.total_probes - orch.budget.probes_used - len(chosen),
        }
        phases.append(capture_phase(
            "O", orch, chosen=chosen, pre_probes=pre_o_probes,
            summary=f"VOI 排序 · 选中 {len(chosen)} 条探针",
            narration=f"目标: {', '.join(chosen_targets)} · 算子: {', '.join(chosen_operators)}",
            phase_details=o_details,
        ))

        # ── C 拍 ──
        ingest_result = orch._c_phase(chosen)
        confirmed = len(getattr(ingest_result, "confirmed", []))
        graph_eligible = len(getattr(ingest_result, "graph_eligible", []))
        # Extract event details from routed buckets
        routed = getattr(ingest_result, "routed", {})
        all_events = getattr(ingest_result, "all_events", [])
        # Build per-bucket summary
        bucket_summary = {}
        attack_events = []
        for bucket_name, bucket_events in routed.items():
            bucket_summary[bucket_name] = len(bucket_events)
            for ev in bucket_events:
                detail = _event_detail(ev)
                if detail["isAttack"]:
                    attack_events.append(detail)
        c_details = {
            "totalEvents": len(all_events),
            "confirmedCount": confirmed,
            "graphEligibleCount": graph_eligible,
            "bucketSummary": bucket_summary,
            "attackEvents": attack_events[:10],
            "allEventDetails": [_event_detail(ev) for ev in all_events[:12]],
            "hostsTouched": sorted({
                _event_detail(ev)["host"] for ev in all_events if _event_detail(ev)["host"]
            }),
        }
        phases.append(capture_phase(
            "C", orch, chosen=chosen,
            summary=f"扇出取证 · {confirmed} 确认 · {graph_eligible} 入图",
            narration=f"事件: {len(all_events)} 条 · 桶: {bucket_summary} · 主机: {', '.join(c_details['hostsTouched'][:5])}",
            phase_details=c_details,
        ))

        # ── K 拍 ──
        stop_decision = orch._k_phase(chosen, ingest_result)
        cur_probs = orch.ledger._get_probabilities()
        prob_changes = {}
        for eid, p in cur_probs.items():
            prev_p = prev_probs.get(eid, 0)
            prob_changes[eid] = {
                "before": round(prev_p, 4),
                "after": round(p, 4),
                "delta": round(p - prev_p, 4),
            }
        cur_hits = _graph_gt_hits(orch, gt_refs)
        new_refs = sorted(cur_hits - prev_hits)
        cur_nodes = orch.graph.stats().get("node_count", 0)
        cur_edges = len(orch.graph._edges)
        k_details = {
            "stopReason": stop_decision.reason,
            "shouldStop": stop_decision.should_stop,
            "probChanges": prob_changes,
            "leading": orch.ledger.leading(),
            "margin": round(orch.ledger.margin(), 4),
            "newGtHits": new_refs[:6],
            "newGtCount": len(new_refs),
            "gtTotal": gt_total,
            "gtCumulative": len(cur_hits),
            "nodesBefore": prev_nodes,
            "nodesAfter": cur_nodes,
            "nodesAdded": max(0, cur_nodes - prev_nodes),
            "edgesBefore": prev_edges,
            "edgesAfter": cur_edges,
            "edgesAdded": max(0, cur_edges - prev_edges),
        }
        phases.append(capture_phase(
            "K", orch, chosen=chosen,
            summary=(
                f"后验更新 · leading={orch.ledger.leading()} · "
                f"margin={orch.ledger.margin():.2%} · stop={stop_decision.reason}"
            ),
            narration=f"GT {len(cur_hits)}/{gt_total} (+{len(new_refs)}) · 图 {prev_nodes}→{cur_nodes} 节点",
            phase_details=k_details,
        ))

        probs = cur_probs
        h1 = round(probs.get("H1", 0), 4)
        posterior_history.append({
            "round": round_num,
            "h1": h1,
            "h2": round(probs.get("H2", 0), 4),
            "hNull": round(probs.get("__null__", 0), 4),
        })

        discovery = (
            f"GT 累计 {len(cur_hits)}/{gt_total}（+{len(new_refs)}）"
            if new_refs
            else f"GT 累计 {len(cur_hits)}/{gt_total} · 图节点 {cur_nodes}"
        )
        rounds_data.append({
            "round": round_num,
            "title": f"R{round_num} · {discovery}",
            "phases": phases,
            "_meta": {
                "discovery": discovery,
                "new_refs": new_refs[:6],
                "h1": h1,
                "nodes_added": max(0, cur_nodes - prev_nodes),
                "edges_added": max(0, cur_edges - prev_edges),
            },
        })

        prev_probs = cur_probs

        prev_stats = orch.graph.stats()
        prev_hits = cur_hits
        prev_nodes = cur_nodes
        prev_edges = cur_edges

        if stop_decision.should_stop:
            final_stop_reason = stop_decision.reason
            phases.append(capture_phase(
                "STOP", orch,
                summary=f"会话结束 ({final_stop_reason})",
                narration="价值导向停止 · 生成决策报告",
            ))
            break

    result = orch._build_result(final_stop_reason)
    final_hits = _graph_gt_hits(orch, gt_refs)
    trace_narrative = _build_narrative(
        scenario_id, spec_name, alert, entry_ref,
        rounds_data, result, final_hits, gt_total, posterior_history,
    )

    alert_title = f"{alert.technique_id} @ {alert.asset_id or '未知主机'}"
    coverage_pct = round(100.0 * len(final_hits) / gt_total, 1) if gt_total else 0.0

    return {
        "id": scenario_id,
        "scenarioId": scenario_id,
        "scenarioName": spec_name,
        "entryRef": entry_ref,
        "alert": {
            "title": alert_title,
            "asset": alert.asset_id or "未知主机",
            "triage": {"malicious": True, "critical": True},
        },
        "budgetTotal": orch.budget.total_probes,
        "gtCoverage": {
            "hits": len(final_hits),
            "total": gt_total,
            "pct": coverage_pct,
        },
        "rounds": rounds_data,
        "report": {
            "action": result.decision.upper().replace("_", " / "),
            "confidence": round(result.confidence, 4),
            "stopReason": final_stop_reason,
            "leadingExplanation": result.leading_explanation,
            "suboptimalExplanation": {
                "label": result.alternatives[0]["id"] if result.alternatives else "",
                "posterior": round(result.alternatives[0]["posterior"], 4) if result.alternatives else 0,
                "reason": "次优解释后验不足以翻转处置决策",
            },
            "counterfactual": result.counterfactuals[0] if result.counterfactuals else "",
            "prunedEdges": [k for k, v in result.boundary_decisions.items() if v == "prune"],
            "oosItems": [],
            "traceNarrative": trace_narrative,
        },
    }
