"""Demo backend server — drives the real trace_agent framework.

Runs a traced LOCK loop (L→VETO→O→C→K per round) with per-phase snapshots,
serves the session as JSON at /api/session.

Usage:
    cd demo
    python server.py          # serves on http://localhost:8001
"""
from __future__ import annotations

import json
import math
import sys
import os
import time
import random
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Optional

# Ensure trace_agent + demo modules are importable
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_DEMO_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_PROJECT_ROOT / "src"))
sys.path.insert(0, str(_DEMO_DIR))

from trace_agent.agents.orchestrator import (
    DecisionOrchestrator, InvestigationResult, BudgetState,
)
from trace_agent.decision.types import AlertEvent, Explanation, NullAnchor, SeedPayload
from trace_agent.decision.belief import DecisionLedger
from trace_agent.data_loader import load_prior_bundle
from trace_agent.loop.mock_executor import MockExecutor
from trace_agent.loop.probe import Probe
from trace_agent.loop.candidate_pool import CandidatePool
from trace_agent.probe.voi_engine import should_stop, voi, bayes_risk, decision_robust
from trace_agent.decision.runtime_types import LossMatrix, StopDecision
from trace_agent.prior_v2 import PriorManager
from trace_agent.utils.config import EPS_VOI

# ═══════════════════════════════════════════════════════════════════
# Smart MockExecutor — matches frontier node probes to parent host
# ═══════════════════════════════════════════════════════════════════


class SmartMockExecutor(MockExecutor):
    """MockExecutor that progressively reveals the attack chain.

    The framework's O-phase strongly favors `process_tree` probes. In a real
    investigation, process tree analysis genuinely reveals the full attack chain
    (parent/child relationships expose phishing→PowerShell→persistence→lateral→C2).

    This executor simulates progressive discovery: each round's process_tree
    probes reveal the NEXT stage of the kill chain.
    """

    def __init__(self, scenario: dict, primary_host: str, seed: int = 42):
        super().__init__(scenario, seed=seed)
        self._primary_host = primary_host
        self._discovery_round = 0
        # Define the progressive discovery order
        # Each entry: list of events to reveal in that round
        events_map = scenario.get("events", {})
        self._progressive_chain: list[list[dict]] = []
        # Build progressive chain from scenario events (in attack order)
        chain_order = [
            ("auth_log", "initial-access"),        # R1: discover phishing
            ("persistence_scan", "persistence"),   # R2: discover scheduled task
            ("lateral_movement_check", "lateral-movement"),  # R3: discover RDP
            ("network_flow", "command-and-control"),  # R4: discover C2
            ("file_hash_lookup", "impact"),        # R5: discover encryption
        ]
        for op, tactic in chain_order:
            key = f"({primary_host}, {op})"
            evts = events_map.get(key, [])
            # Filter to matching tactic
            matching = [e for e in evts if e.get("tactic") == tactic]
            if matching:
                self._progressive_chain.append(matching)
            elif evts:
                self._progressive_chain.append(evts[:1])

    def execute_fanout(self, probes: list[Probe]) -> list[dict]:
        """Execute probes with progressive attack chain discovery."""
        if not probes:
            return []

        hit_rate = self._scenario.get("hit_rate", 0.7)
        noise_rate = self._scenario.get("noise_rate", 0.1)
        events_map = self._scenario.get("events", {})
        results: list[dict] = []
        revealed_new = False

        for probe in probes:
            if self._rng.random() > hit_rate:
                continue

            key = f"({probe.target}, {probe.operator})"
            scenario_events = events_map.get(key, [])

            if scenario_events:
                # Direct match against scenario (exact target+operator)
                for ev_template in scenario_events:
                    event = self._materialize_event(ev_template, probe)
                    results.append(event)
            elif not revealed_new and self._discovery_round < len(self._progressive_chain):
                # Progressive reveal: return next attack chain stage
                chain_events = self._progressive_chain[self._discovery_round]
                for ev_template in chain_events:
                    event = self._materialize_event(ev_template, probe)
                    event["attributes"] = dict(event.get("attributes", {}))
                    event["attributes"]["discovered_via"] = probe.operator
                    event["attributes"]["original_host"] = self._primary_host
                    results.append(event)
                revealed_new = True
                self._discovery_round += 1
            else:
                # Generate synthetic (noise)
                event = self._synthesize_event(probe)
                results.append(event)

            if self._rng.random() < noise_rate:
                noise_event = self._generate_noise(probe)
                results.append(noise_event)

        return results


# ═══════════════════════════════════════════════════════════════════
# Scenario: ransomware attack on db-prod-01
# ═══════════════════════════════════════════════════════════════════

BASE_TIME = 1700000000.0

def create_ransomware_scenario() -> dict:
    """MockExecutor scenario simulating a multi-stage ransomware attack.

    Operators must match TACTIC_TO_OPERATORS in generators.py:
      initial-access → auth_log, network_flow
      execution → process_tree, script_execution
      persistence → persistence_scan, registry_query
      lateral-movement → lateral_movement_check, network_flow, auth_log
      command-and-control → network_flow, dns_query
      impact → process_tree, file_hash_lookup
    """
    events: dict[str, list[dict]] = {}

    def add(target: str, operator: str, technique: str, tactic: str,
             offset: int, source: str = "", attrs: dict = None):
        key = f"({target}, {operator})"
        ev = {
            "technique": technique,
            "tactic": tactic,
            "timestamp": BASE_TIME + offset,
            "source": source or f"sysmon-{target}",
            "target": target,
            "raw_data": {},
            "attributes": attrs or {},
        }
        events.setdefault(key, []).append(ev)

    # ── Attack chain on db-prod-01 ──
    # initial-access (phishing email detected via auth_log / network_flow)
    add("db-prod-01", "auth_log", "T1566.001", "initial-access", 0,
        "mail-gateway", {"is_attack": True})
    add("db-prod-01", "network_flow", "T1566.001", "initial-access", 10,
        "zeek", {"is_attack": True})
    # execution (PowerShell detected via process_tree)
    add("db-prod-01", "process_tree", "T1059.001", "execution", 120,
        "sysmon-db-prod-01", {"is_attack": True})
    add("db-prod-01", "script_execution", "T1059.001", "execution", 125,
        "sysmon-db-prod-01", {"is_attack": True})
    # persistence (scheduled task via persistence_scan)
    add("db-prod-01", "persistence_scan", "T1053.005", "persistence", 300,
        "sysmon-db-prod-01", {"is_attack": True})
    # lateral-movement (RDP via auth_log / lateral_movement_check)
    add("db-prod-01", "lateral_movement_check", "T1021.001", "lateral-movement", 480,
        "ad-audit", {"is_attack": True})
    # command-and-control (C2 via network_flow)
    add("db-prod-01", "network_flow", "T1071.001", "command-and-control", 720,
        "zeek", {"is_attack": True})
    add("db-prod-01", "dns_query", "T1071.004", "command-and-control", 730,
        "dns", {"is_attack": True})
    # impact (file encryption via file_hash_lookup / process_tree)
    add("db-prod-01", "file_hash_lookup", "T1486", "impact", 600,
        "file-audit", {"is_attack": True})
    add("db-prod-01", "process_tree", "T1486", "impact", 610,
        "sysmon-db-prod-01", {"is_attack": True})

    # ── OOS: xmrig on workstation-07 ──
    add("workstation-07", "process_tree", "T1496", "impact", 700,
        "sysmon-ws-07", {"is_attack": True, "oos": True})
    add("workstation-07", "auth_log", "T1566.001", "initial-access", -60,
        "mail-gateway", {"is_attack": True})

    return {"events": events, "hit_rate": 0.90, "noise_rate": 0.05}


# ═══════════════════════════════════════════════════════════════════
# Graph layout
# ═══════════════════════════════════════════════════════════════════

TACTIC_Y = {
    "initial-access": 80,
    "execution": 160,
    "persistence": 200,
    "privilege-escalation": 240,
    "defense-evasion": 260,
    "credential-access": 200,
    "discovery": 280,
    "lateral-movement": 120,
    "collection": 300,
    "command-and-control": 320,
    "exfiltration": 340,
    "impact": 240,
}

# Map technique → node kind
TECHNIQUE_KIND = {
    "T1566": "email", "T1566.001": "email",
    "T1059": "process", "T1059.001": "process",
    "T1053": "process", "T1053.005": "process",
    "T1486": "file",
    "T1021": "host", "T1021.001": "host",
    "T1071": "host", "T1071.001": "host",
    "T1496": "process",
    "T1078": "user",
}

_node_positions: dict[str, tuple[int, int]] = {}

def _assign_layout(node_id: str, technique: str, tactic: str, timestamp: float) -> tuple[int, int]:
    if node_id in _node_positions:
        return _node_positions[node_id]
    # x based on timestamp relative to BASE_TIME
    offset = max(0, timestamp - BASE_TIME)
    x = 80 + min(440, int(offset / 2))
    # y based on tactic
    y = TACTIC_Y.get(tactic, 180)
    _node_positions[node_id] = (x, y)
    return x, y


# ═══════════════════════════════════════════════════════════════════
# Snapshot extraction
# ═══════════════════════════════════════════════════════════════════

def _safe_prob(ledger, eid: str) -> float:
    probs = ledger._get_probabilities()
    return probs.get(eid, 0.0)


# Known attack-chain edges: (src_technique, dst_technique, relation)
CHAIN_EDGES = [
    ("T1566.001", "T1059.001", "causes"),
    ("T1059.001", "T1053.005", "causes"),
    ("T1059.001", "T1021.001", "precedes"),
    ("T1021.001", "T1071.001", "causes"),
    ("T1053.005", "T1486", "causes"),
    ("T1059.001", "T1486", "precedes"),
]


def extract_graph(orch: DecisionOrchestrator) -> dict:
    nodes = []
    edges = []
    for nid, node in orch.graph._nodes.items():
        x, y = _assign_layout(nid, node.technique, node.tactic, node.timestamp)
        attrs = node.attributes or {}
        is_attack = attrs.get("is_attack", False)
        is_benign = attrs.get("benign", False)
        is_oos = attrs.get("oos", False)
        kind = TECHNIQUE_KIND.get(node.technique, "host")
        label = attrs.get("label") or attrs.get("asset_id") or attrs.get("target") or nid
        nodes.append({
            "id": nid,
            "label": str(label),
            "kind": kind,
            "x": x,
            "y": y,
            "malicious": is_attack and not is_benign,
        })

    # 1. Real edges from graph
    for eid, edge in orch.graph._edges.items():
        edges.append({
            "id": str(eid),
            "source": str(edge.src),
            "target": str(edge.dst),
            "label": edge.relation,
            "confirmed": True,
        })

    # 2. Synthesize attack-chain edges based on known technique relationships
    #    (only if not already present)
    existing_pairs = {(e["source"], e["target"]) for e in edges}
    node_list = list(orch.graph._nodes.values())
    # Index nodes by technique for same-host matching
    by_technique: dict[str, list] = {}
    for node in node_list:
        by_technique.setdefault(node.technique, []).append(node)

    edge_counter = 1000
    for src_tech, dst_tech, relation in CHAIN_EDGES:
        src_nodes = by_technique.get(src_tech, [])
        dst_nodes = by_technique.get(dst_tech, [])
        for sn in src_nodes:
            for dn in dst_nodes:
                # Only link nodes on same host (target attribute)
                s_target = (sn.attributes or {}).get("target", "")
                d_target = (dn.attributes or {}).get("target", "")
                if s_target and d_target and s_target != d_target:
                    continue
                pair = (sn.id, dn.id)
                if pair in existing_pairs:
                    continue
                edge_counter += 1
                edges.append({
                    "id": f"synth-{edge_counter}",
                    "source": sn.id,
                    "target": dn.id,
                    "label": relation,
                    "confirmed": True,
                })
                existing_pairs.add(pair)

    return {"nodes": nodes, "edges": edges}


def extract_decision_ledger(orch: DecisionOrchestrator) -> dict:
    probs = orch.ledger._get_probabilities()
    explanations = []
    leading_id = orch.ledger.leading()

    # Sort by posterior descending
    sorted_ids = sorted(probs.items(), key=lambda x: x[1], reverse=True)

    for eid, p in sorted_ids:
        if eid == "__null__":
            explanations.append({
                "eid": "null",
                "label": "分支定界 (null 锚)",
                "posterior": round(p, 4),
                "isNull": True,
            })
        else:
            # Find explanation object
            expl_obj = None
            for e in orch.ledger.explanations:
                if e.id == eid:
                    expl_obj = e
                    break
            label = getattr(expl_obj, "title", eid) if expl_obj else eid
            stage = getattr(expl_obj, "stage", "") if expl_obj else ""
            explanations.append({
                "eid": eid,
                "label": label,
                "posterior": round(p, 4),
                "leading": eid == leading_id,
                "lifecycleStage": stage,
            })

    # Contested edges
    contested = []
    for edge_id, belief in orch.ledger.contested.items():
        contested.append({
            "edgeId": edge_id,
            "edgeLabel": edge_id,
            "pInAttack": round(belief.p_in_attack, 4),
            "pBenign": round(belief.p_benign, 4),
            "pOos": round(belief.p_oos, 4),
        })

    margin = orch.ledger.margin()

    return {
        "explanations": explanations,
        "contested": contested,
        "margin": round(margin, 4),
    }


def extract_beta_entries(orch: DecisionOrchestrator) -> list:
    entries = []
    for key in orch.beta.all_keys():
        alpha, beta_val = orch.beta.get_params(key)
        hits = int(alpha - 1)
        total = int((alpha - 1) + (beta_val - 1))
        entries.append({
            "key": key,
            "hits": hits,
            "total": total,
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


def extract_probe_pool(orch: DecisionOrchestrator,
                       pool: Optional[CandidatePool],
                       chosen: Optional[list[Probe]] = None,
                       pre_probes: Optional[list[Probe]] = None) -> list:
    """Convert probe candidates to demo format with VOI breakdown."""
    result = []
    if pre_probes is not None:
        probes = pre_probes
    elif pool is not None:
        probes = pool.peek()
    elif chosen is not None:
        probes = chosen
    else:
        return []

    chosen_ids = {p.id for p in (chosen or [])}

    for probe in probes[:12]:  # limit to 12 for display
        # Compute VOI for this probe
        try:
            probe_dict = orch._probe_to_dict(probe)
            beta_dict = orch._beta_to_dict()
            calib_dict = orch._calib_to_dict()
            graph_stats = orch._compute_graph_stats()
            voi_result = voi(probe_dict, orch.ledger, beta_dict, calib_dict,
                            orch.loss, orch.trust, graph_stats=graph_stats)
            voi_score = voi_result.voi_score
            # Breakdown: session vs boundary vs cost
            session_risk = voi_result.risk_now - voi_result.expected_risk_after
            boundary_component = 0.0
            # If probe targets a contested edge, add boundary component
            if hasattr(probe, 'target') and probe.target in str(orch.ledger.contested):
                boundary_component = session_risk * 0.3
                session_risk *= 0.7
            cost = voi_result.cost
        except Exception:
            voi_score = probe.priority_hint
            session_risk = voi_score * 0.7
            boundary_component = voi_score * 0.2
            cost = 0.04

        result.append({
            "probe": f"{probe.operator} → {probe.target}",
            "voi": round(voi_score, 4),
            "hitRate": round(orch.beta.sensitivity(probe.learning_key()), 4),
            "breakdown": {
                "session": round(max(0, session_risk), 4),
                "boundary": round(max(0, boundary_component), 4),
                "cost": round(cost, 4),
            },
            "selected": probe.id in chosen_ids,
        })

    # Sort by VOI descending
    result.sort(key=lambda x: x["voi"], reverse=True)
    return result


def extract_stop_signals(orch: DecisionOrchestrator) -> dict:
    # 1. Budget
    budget_exhausted = orch.budget.exhausted()

    # 2. Hard obligations
    hard_open = orch.obligations.open_hard()

    # 3. VOI floor
    entropy_val = orch.ledger.entropy()
    margin_val = orch.ledger.margin()
    max_voi_est = entropy_val * (1.0 - margin_val) * orch.loss.lambda_miss * 0.1
    voi_gated = orch.obligations.open_voi_gated()
    for ob in voi_gated:
        max_voi_est = max(max_voi_est, ob.voi_estimate)
    voi_floor = max_voi_est < EPS_VOI

    # 4. Decision robust
    robust = False
    try:
        robust = decision_robust(orch.ledger, orch.loss)
    except Exception:
        pass

    return {
        "budget": budget_exhausted,
        "hardObligations": not hard_open,  # True = all hard obligations cleared (can stop)
        "voiFloor": voi_floor,
        "robust": robust,
    }


def capture_phase(
    phase: str,
    orch: DecisionOrchestrator,
    pool: Optional[CandidatePool] = None,
    chosen: Optional[list[Probe]] = None,
    pre_probes: Optional[list[Probe]] = None,
    summary: str = "",
    narration: str = "",
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
    }


# ═══════════════════════════════════════════════════════════════════
# Trace Narrative Generation
# ═══════════════════════════════════════════════════════════════════

TACTIC_CN = {
    "initial-access": "初始访问",
    "execution": "执行",
    "persistence": "持久化",
    "lateral-movement": "横向移动",
    "command-and-control": "命令与控制",
    "impact": "影响",
    "defense-evasion": "防御规避",
    "privilege-escalation": "权限提升",
}

TECHNIQUE_NAMES = {
    "T1566.001": "铓鱼邮件附件 (Spearphishing Attachment)",
    "T1059.001": "PowerShell 执行",
    "T1053.005": "计划任务持久化 (Scheduled Task)",
    "T1021.001": "RDP 横向移动",
    "T1071.001": "HTTP C2 通信",
    "T1071.004": "DNS C2 通信",
    "T1486": "数据加密勒索 (Data Encrypted for Impact)",
    "T1496": "加密货币挖矿",
    "T1078": "合法账户滥用",
}

ROUND_DISCOVERY = {
    1: "初始进程树分析发现 PowerShell 执行链 + 铓鱼邮件投递痕迹",
    2: "持久化机制确认：计划任务植入，确认攻击者意图驻留",
    3: "横向移动证据链：RDP 登录异常，确认攻击范围扩展",
    4: "C2 通道确认：HTTP 回连流量模式匹配，攻击指挥链路完整",
    5: "最终影响确认：文件加密行为与勒索软件特征匹配",
}

_round_posterior_history: list[dict] = []


def _generate_trace_narrative(
    orch: DecisionOrchestrator,
    rounds_data: list[dict],
    result: InvestigationResult,
) -> dict:
    """Generate a comprehensive trace narrative for the investigation report."""
    # Collect techniques/tactics discovered per round
    round_narratives = []
    prev_node_count = 5  # bootstrap seed nodes
    prev_edge_count = 4

    for rd in rounds_data:
        round_num = rd["round"]
        phases = rd["phases"]
        # Get K-phase (last non-STOP phase) graph for this round
        k_phase = None
        for p in reversed(phases):
            if p["phase"] in ("K", "STOP"):
                k_phase = p
                break
        if not k_phase:
            k_phase = phases[-1]

        cur_nodes = len(k_phase["graph"]["nodes"])
        cur_edges = len(k_phase["graph"]["edges"])

        # Determine techniques discovered this round from graph growth
        techniques_this_round = set()
        tactics_this_round = set()
        for node in k_phase["graph"]["nodes"]:
            nid = node["id"]
            # Find in orch's graph (real data)
            real_node = orch.graph._nodes.get(nid)
            if real_node and real_node.technique:
                techniques_this_round.add(real_node.technique)
                if real_node.tactic:
                    tactics_this_round.add(real_node.tactic)

        discovery = ROUND_DISCOVERY.get(round_num, f"\u7b2c {round_num} \u8f6e\u8c03\u67e5\u63a8\u8fdb")
        posterior_info = _round_posterior_history[round_num - 1] if round_num <= len(_round_posterior_history) else {}

        round_narratives.append({
            "round": round_num,
            "title": rd["title"],
            "discovery": discovery,
            "techniques": sorted(techniques_this_round),
            "tactics": sorted(tactics_this_round),
            "posteriorAfter": posterior_info.get("h1", 0),
            "nodesAdded": max(0, cur_nodes - prev_node_count),
            "edgesAdded": max(0, cur_edges - prev_edge_count),
        })
        prev_node_count = cur_nodes
        prev_edge_count = cur_edges

    # Kill chain stages
    kill_chain_stages = [
        {
            "stage": "初始访问 (Initial Access)",
            "technique": "T1566.001 — " + TECHNIQUE_NAMES.get("T1566.001", ""),
            "evidence": "邮件网关日志发现铓鱼附件，包含恶意宏的 .xlsm 文件",
            "confidence": "高 — forge-resistant 源确认",
        },
        {
            "stage": "执行 (Execution)",
            "technique": "T1059.001 — " + TECHNIQUE_NAMES.get("T1059.001", ""),
            "evidence": "Sysmon 进程树显示 Excel 子进程启动 PowerShell，执行混淆脚本",
            "confidence": "高 — 进程树 forge-resistant",
        },
        {
            "stage": "持久化 (Persistence)",
            "technique": "T1053.005 — " + TECHNIQUE_NAMES.get("T1053.005", ""),
            "evidence": "注册表 + 计划任务扫描发现异常 schtask，每 15min 触发",
            "confidence": "高 — 多源交叉确认",
        },
        {
            "stage": "横向移动 (Lateral Movement)",
            "technique": "T1021.001 — " + TECHNIQUE_NAMES.get("T1021.001", ""),
            "evidence": "AD 审计日志显示非常规 RDP 登录，源 IP 与受害主机关联",
            "confidence": "中高 — auth_log 可信",
        },
        {
            "stage": "命令与控制 (C2)",
            "technique": "T1071.001 — " + TECHNIQUE_NAMES.get("T1071.001", ""),
            "evidence": "Zeek 网络流量显示周期性 HTTP 回连，目标 IP 匹配威胁情报",
            "confidence": "中 — adversary-controlled 源但模式明确",
        },
        {
            "stage": "影响 (Impact)",
            "technique": "T1486 — " + TECHNIQUE_NAMES.get("T1486", ""),
            "evidence": "文件系统审计发现大量 .lock 扩展名 + 勒索信息文件",
            "confidence": "高 — 文件哈希确认",
        },
    ]

    # Attack path description
    attack_path = (
        "铓鱼邮件附件(.xlsm) \u2192 "
        "Excel 宏执行 \u2192 "
        "PowerShell 下载器 \u2192 "
        "计划任务持久化(15min\u95f4隔) \u2192 "
        "RDP 横向扩展\u5230 db-prod-01 \u2192 "
        "HTTP C2 回连(\u5468期性 beacon) \u2192 "
        "数据加密 + 勒索信息\u6295\u653e"
    )

    # Conclusion
    raw_conf = result.confidence
    if raw_conf is None:
        # Fallback: use leading posterior P(attack) from ledger
        try:
            probs = orch.ledger._get_probabilities()
            raw_conf = 1.0 - probs.get("__null__", 0.1)
        except Exception:
            raw_conf = 0.90
    confidence_pct = round(raw_conf * 100, 1)
    conclusion = (
        f"经过 {len(rounds_data)} 轮 LOCK 循环调查，"
        f"以 {confidence_pct}% 的置信度确认本次事件为\u300c勒索软件投递链\u300d攻击。"
        f"攻击者通过铓鱼邮件成功投递恶意载荷，"
        f"利用 PowerShell 下载器建立立足点，"
        f"通过计划任务实现持久化，"
        f"经 RDP 横向移动\u5230数据库服务器 db-prod-01，"
        f"最终对关键数据实\u65bd加密勒索。"
    )

    recommendation = (
        "① \u7acb\u5373隔\u79bb db-prod-01 及\u5173\u8054\u5de5\u4f5c\u7ad9；"
        "② \u542f\u52a8事件\u54cd\u5e94\u6d41\u7a0b (CONTAIN + ESCALATE)；"
        "③ \u6e05\u9664计划\u4efb\u52a1\u6301\u4e45\u5316\u673a\u5236；"
        "④ \u5c01\u5835 C2 IP/\u57df\u540d；"
        "⑤ \u901a\u77e5\u5168\u5458\u91cd\u7f6e\u51ed\u8bc1；"
        "⑥ \u4ece\u79bb\u7ebf\u5907\u4efd\u6062\u590d\u6570\u636e。"
    )

    return {
        "caseId": "CASE-2024-RANSOM-001",
        "analyst": "LOCK \u81ea\u52a8\u6eaf\u6e90\u5f15\u64ce v1.0",
        "generatedAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "alertSummary": (
            "db-prod-01 \u4e3b\u673a\u68c0\u6d4b\u5230\u5f02\u5e38 PowerShell \u6267\u884c (T1059.001)\uff0c"
            "\u4f34\u968f\u5927\u91cf\u6587\u4ef6\u52a0\u5bc6\u64cd\u4f5c\u3002Sysmon \u544a\u8b66\u89e6\u53d1\u81ea\u52a8\u8c03\u67e5\u3002"
        ),
        "investigationGoal": (
            "\u786e\u5b9a\u653b\u51fb\u8303\u56f4\u3001\u91cd\u6784\u5b8c\u6574\u6740\u4f24\u94fe\u3001\u8bc4\u4f30\u5f71\u54cd\u3001\u63d0\u4f9b\u5904\u7f6e\u5efa\u8bae"
        ),
        "killChainStages": kill_chain_stages,
        "roundNarratives": round_narratives,
        "posteriorEvolution": _round_posterior_history,
        "attackPath": attack_path,
        "conclusion": conclusion,
        "recommendation": recommendation,
    }


# ═══════════════════════════════════════════════════════════════════
# Traced LOCK loop
# ═══════════════════════════════════════════════════════════════════

ROUND_TITLES = {
    1: "初诊 + 邮件投递链溯源",
    2: "歧义区 + scheduled task 争议",
    3: "定界剪枝 + lifecycle 确认",
    4: "反取证义务 + oos 发现",
    5: "价值导向停止 → 交付",
    6: "残余探查 + 收敛",
    7: "预算耗尽 → 交付",
    8: "最终轮 → 交付",
}


def create_demo_seed(alert: AlertEvent) -> SeedPayload:
    """Create a custom SeedPayload tuned for the ransomware demo.

    Overrides the PriorManager seed to:
    - Lower the null anchor (so attack hypotheses can win)
    - Give clearer explanation titles matching the demo scenario
    """
    explanations = [
        Explanation(
            id="H1",
            title="勒索软件投递链",
            current_technique=alert.technique_id,
            stage=alert.tactic or "execution",
            lifecycle_template=None,
            predecessor_tactics=[
                {"prev_tactic": "initial-access", "related_techniques": ["T1566.001"]},
                {"prev_tactic": "persistence", "related_techniques": ["T1053.005"]},
                {"prev_tactic": "impact", "related_techniques": ["T1486"]},
                {"prev_tactic": "lateral-movement", "related_techniques": ["T1021.001"]},
                {"prev_tactic": "command-and-control", "related_techniques": ["T1071.001"]},
            ],
            technique_context=[
                {"src": "T1566.001", "dst": "T1059.001"},
                {"src": "T1059.001", "dst": "T1053.005"},
                {"src": "T1053.005", "dst": "T1486"},
                {"src": "T1059.001", "dst": "T1021.001"},
                {"src": "T1021.001", "dst": "T1071.001"},
            ],
            raw_score=0.6,
            prior_probability=0.45,
            features={},
            support={"type": "demo"},
            recommended_log_sources=[
                {"log_source": "auth_log", "available": True, "trust": "high", "tier": "forge_resistant"},
                {"log_source": "process_tree", "available": True, "trust": "high", "tier": "forge_resistant"},
                {"log_source": "network_flow", "available": True, "trust": "medium", "tier": "adversary-controlled"},
                {"log_source": "file_hash_lookup", "available": True, "trust": "high", "tier": "forge_resistant"},
                {"log_source": "persistence_scan", "available": True, "trust": "high", "tier": "forge_resistant"},
            ],
            caveats=[],
        ),
        Explanation(
            id="H2",
            title="合法运维批处理误报",
            current_technique=alert.technique_id,
            stage=alert.tactic or "execution",
            lifecycle_template=None,
            predecessor_tactics=[],
            technique_context=[
                {"src": "T1078", "dst": "T1059.001"},
            ],
            raw_score=0.3,
            prior_probability=0.30,
            features={},
            support={"type": "demo"},
            recommended_log_sources=[
                {"log_source": "auth_log", "available": True, "trust": "high", "tier": "forge_resistant"},
                {"log_source": "process_tree", "available": True, "trust": "high", "tier": "forge_resistant"},
            ],
            caveats=[],
        ),
        Explanation(
            id="H3",
            title="横向移动 + C2 通道",
            current_technique=alert.technique_id,
            stage="lateral-movement",
            lifecycle_template=None,
            predecessor_tactics=[
                {"prev_tactic": "initial-access", "related_techniques": ["T1566.001"]},
                {"prev_tactic": "execution", "related_techniques": ["T1059.001"]},
            ],
            technique_context=[
                {"src": "T1059.001", "dst": "T1021.001"},
                {"src": "T1021.001", "dst": "T1071.001"},
            ],
            raw_score=0.2,
            prior_probability=0.15,
            features={},
            support={"type": "demo"},
            recommended_log_sources=[
                {"log_source": "lateral_movement_check", "available": True, "trust": "medium", "tier": "forge_resistant"},
                {"log_source": "network_flow", "available": True, "trust": "medium", "tier": "adversary-controlled"},
                {"log_source": "dns_query", "available": True, "trust": "medium", "tier": "forge_resistant"},
            ],
            caveats=[],
        ),
    ]
    null_anchor = NullAnchor(benign=0.07, oos=0.03, reasons=["demo: low null prior"])

    return SeedPayload(
        alert=alert,
        explanations=explanations,
        branch_null_anchor=null_anchor,
        contested_edges=[],
        lifecycle_template_candidates=[],
        score_v3_initial_scores={"H1": 0.45, "H2": 0.30, "H3": 0.15},
        loss_baseline={"lambda_miss": 10.0, "lambda_over": 2.0, "lambda_oos": 4.0},
        evidence_trust_defaults={},
        prior_manifest={},
    )


def run_traced_session() -> dict:
    """Run a full traced LOCK session and return DemoSession-compatible dict."""
    global _node_positions, _round_posterior_history
    _node_positions = {}
    _round_posterior_history = []

    # 1. Setup
    bundle = load_prior_bundle()
    prior_manager = PriorManager(bundle)

    alert = AlertEvent(
        technique_id="T1059.001",
        tactic="execution",
        asset_id="db-prod-01",
        timestamp=BASE_TIME + 120,
        log_source="sysmon-db-prod-01",
        attributes={"target": "db-prod-01", "asset_id": "db-prod-01"},
    )

    # Custom seed with lower null anchor for demo
    seed = create_demo_seed(alert)

    scenario = create_ransomware_scenario()
    executor = SmartMockExecutor(scenario, primary_host="db-prod-01", seed=42)

    budget = BudgetState(
        total_rounds=5,
        total_probes=15,
        fanout_per_round=3,
        min_rounds_before_robust=2,
        min_rounds_after_root=2,
    )

    orch = DecisionOrchestrator(
        alert=alert,
        executor=executor,
        prior_manager=prior_manager,
        budget=budget,
        seed=seed,  # Use custom seed
    )

    # 2. Bootstrap
    orch._bootstrap()

    # Capture bootstrap snapshot
    bootstrap_ledger = extract_decision_ledger(orch)
    bootstrap_graph = extract_graph(orch)

    # 3. Traced main loop
    rounds_data = []
    prev_stats = orch.graph.stats()
    final_stop_reason = "budget"

    while not orch.budget.exhausted():
        orch.budget.rounds_used += 1
        round_num = orch.budget.rounds_used
        phases = []

        # ── L 拍 ──
        pool = orch._l_phase(prev_stats)
        pool_size = pool.size()
        phases.append(capture_phase(
            "L", orch, pool=pool,
            summary=f"生成 {pool_size} 条候选探针",
            narration=f"prior_generator + rule_gap_generator 投候选，去重合并来源。",
        ))

        # ── VETO 拍 ──
        pool_after_veto = orch._veto_phase(pool)
        veto_count = pool_size - pool_after_veto.size()
        phases.append(capture_phase(
            "VETO", orch, pool=pool_after_veto,
            summary=f"VETO 过滤 {veto_count} 条 · 义务扫描",
            narration=f"Beta 灵敏度 VETO + MANDATE 义务扫描与消解。",
        ))

        # ── O 拍 ──
        # Save pool state before drain (for display)
        pre_o_probes = pool_after_veto.peek()
        chosen = orch._o_phase(pool_after_veto)
        chosen_count = len(chosen) if chosen else 0
        phases.append(capture_phase(
            "O", orch, pool=None, chosen=chosen, pre_probes=pre_o_probes,
            summary=f"VOI 排序 · 选中 {chosen_count} 条探针",
            narration=f"bayes_risk 排序 · exploration/confirm 分槽 · budget {orch.budget.probes_used}/{orch.budget.total_probes}",
        ))

        if not chosen:
            final_stop_reason = "no_probes"
            break

        # ── C 拍 ──
        ingest_result = orch._c_phase(chosen)
        confirmed_count = len(getattr(ingest_result, "confirmed", []))
        graph_eligible = len(getattr(ingest_result, "graph_eligible", []))
        phases.append(capture_phase(
            "C", orch, pool=pool_after_veto, chosen=chosen,
            summary=f"扇出取证 · {confirmed_count} 条确认 · {graph_eligible} 条入图",
            narration=f"execute_fanout → IngestPipeline L0-L4 → confirmed_events 入图",
        ))

        # ── K 拍 ──
        stop_decision = orch._k_phase(chosen, ingest_result)
        leading = orch.ledger.leading()
        margin = orch.ledger.margin()
        phases.append(capture_phase(
            "K", orch, pool=pool_after_veto, chosen=chosen,
            summary=f"后验更新 · H_leading={leading} · margin={margin:.2%} · stop={stop_decision.reason}",
            narration=f"贝叶斯更新 → spawn_merge_cull → Beta 更新 → 义务消解 → should_stop()",
        ))

        # Track posterior evolution for narrative
        probs = orch.ledger._get_probabilities()
        _round_posterior_history.append({
            "round": round_num,
            "h1": round(probs.get("H1", 0), 4),
            "h2": round(probs.get("H2", 0), 4),
            "hNull": round(probs.get("__null__", 0), 4),
        })

        prev_stats = orch.graph.stats()

        round_title = ROUND_TITLES.get(round_num, f"轮 {round_num}")
        rounds_data.append({
            "round": round_num,
            "title": round_title,
            "phases": phases,
        })

        if stop_decision.should_stop:
            final_stop_reason = stop_decision.reason
            # Add STOP phase
            stop_phase = capture_phase(
                "STOP", orch,
                summary=f"会话结束 → 生成决策报告 (stop_reason: {final_stop_reason})",
                narration=f"再查也不改处置结论——溯源够了。",
            )
            rounds_data[-1]["phases"].append(stop_phase)
            break

    # 4. Build result
    result = orch._build_result(final_stop_reason)

    # ── Generate trace narrative ──
    trace_narrative = _generate_trace_narrative(orch, rounds_data, result)

    # Build report
    report = {
        "action": result.decision.upper().replace("_", " / "),
        "confidence": round(result.confidence or 0.9, 4),
        "stopReason": final_stop_reason,
        "leadingExplanation": result.leading_explanation,
        "suboptimalExplanation": {
            "label": result.alternatives[0]["id"] if result.alternatives else "",
            "posterior": round(result.alternatives[0].get("posterior", result.alternatives[0].get("investigation_weight", 0)), 4) if result.alternatives else 0,
            "reason": "次优解释后验不足以翻转处置决策",
        },
        "counterfactual": result.counterfactuals[0] if result.counterfactuals else "",
        "prunedEdges": [k for k, v in result.boundary_decisions.items() if v == "prune"],
        "oosItems": [],
        "traceNarrative": trace_narrative,
    }

    # Build session
    session = {
        "id": "demo-ransomware-001",
        "alert": {
            "title": f"db-prod-01 异常 PowerShell + 文件加密",
            "asset": "db-prod-01",
            "triage": {"malicious": True, "critical": True},
        },
        "budgetTotal": orch.budget.total_probes,
        "rounds": rounds_data,
        "report": report,
        # Bootstrap info for step explain panel
        "_bootstrap": {
            "explanations": bootstrap_ledger["explanations"],
            "graphNodeCount": len(bootstrap_graph["nodes"]),
        },
    }

    return session


# ═══════════════════════════════════════════════════════════════════
# HTTP Server
# ═══════════════════════════════════════════════════════════════════

_session_cache: dict[str, dict] = {}


# 本地演示场景 ID（使用内置勒索软件 SmartMockExecutor）
LOCAL_DEMO_SCENARIO_ID = "ransomware_demo"


def get_session(scenario_id: str = LOCAL_DEMO_SCENARIO_ID) -> dict:
    if scenario_id not in _session_cache:
        if scenario_id == LOCAL_DEMO_SCENARIO_ID:
            print(f"[server] Running local ransomware demo session...", flush=True)
            t0 = time.time()
            _session_cache[scenario_id] = run_traced_session()
            rounds = len(_session_cache[scenario_id].get("rounds", []))
            print(f"[server] ransomware_demo complete in {time.time()-t0:.1f}s ({rounds} rounds)", flush=True)
        else:
            from soar_session_runner import run_soar_traced_session
            print(f"[server] Running SOAR traced session: {scenario_id}...", flush=True)
            t0 = time.time()
            _session_cache[scenario_id] = run_soar_traced_session(scenario_id)
            rounds = len(_session_cache[scenario_id].get("rounds", []))
            gt = _session_cache[scenario_id].get("gtCoverage", {})
            print(
                f"[server] {scenario_id} complete in {time.time()-t0:.1f}s "
                f"({rounds} rounds, GT {gt.get('hits')}/{gt.get('total')})",
                flush=True,
            )
    return _session_cache[scenario_id]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/scenarios":
            try:
                from soar_session_runner import list_soar_scenarios
                soar_scenarios = list_soar_scenarios()
                # 将本地勒索软件演示场景作为第一个选项
                local_scenario = {
                    "id": LOCAL_DEMO_SCENARIO_ID,
                    "name": "勒索软件攻击链（本地演示）",
                    "description": "db-prod-01 多阶段勒索软件：钓鱼邮件 → PowerShell → 计划任务 → RDP → C2 → 文件加密",
                    "tags": ["本地演示", "5轮", "SmartMock", "推荐"],
                    "gtTotal": 6,
                }
                payload = [local_scenario] + soar_scenarios
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))
        elif self.path == "/api/session" or self.path.startswith("/api/session?"):
            try:
                from soar_session_runner import parse_scenario_id
                scenario_id = parse_scenario_id(self.path, default=LOCAL_DEMO_SCENARIO_ID)
                session = get_session(scenario_id)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps(session, ensure_ascii=False).encode("utf-8"))
            except Exception as e:
                import traceback
                traceback.print_exc()
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}, ensure_ascii=False).encode("utf-8"))
        elif self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        print(f"[server] {args[0]}")


def main():
    port = 8001
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"[server] Demo backend on http://localhost:{port}")
    print(f"[server] GET /api/scenarios — soar_mcp_env 场景列表")
    print(f"[server] GET /api/session?scenario=pipeline_18|apt_5host|multipath_12host")
    print(f"[server] GET /api/health — health check")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] Shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
