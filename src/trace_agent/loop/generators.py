"""L 拍生成器 — RFC-004-02 §3.1 候选投放"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from trace_agent.prior_v2 import TACTIC_ID_TO_SHORT

from .probe import Probe
from .session_graph import SessionGraph

# Late-stage entry alerts need backward trace before robust stop
LATE_STAGE_TACTICS = frozenset({
    "exfiltration",
    "impact",
    "command-and-control",
    "collection",
})

CROSS_HOST_REACH_OPERATORS = frozenset({
    "auth_log",
    "lateral_movement_check",
    "network_flow",
    "email_gateway",
})


def normalize_tactic(raw: str | None, fallback: str = "execution") -> str:
    """Map MITRE TA#### IDs to semantic kill-chain tactic names."""
    if not raw:
        return fallback
    text = str(raw).strip()
    lowered = text.lower().replace("_", "-")
    upper = text.upper()
    if upper in TACTIC_ID_TO_SHORT:
        return TACTIC_ID_TO_SHORT[upper]
    if lowered.startswith("ta") and len(lowered) >= 5:
        ta_key = lowered[:6].upper() if lowered[2:3].isdigit() else upper
        if ta_key in TACTIC_ID_TO_SHORT:
            return TACTIC_ID_TO_SHORT[ta_key]
    return lowered


# Helper: map tactic to best operators
TACTIC_TO_OPERATORS: dict[str, list[str]] = {
    "initial-access": ["auth_log", "network_flow"],
    "execution": ["process_tree", "script_execution"],
    "persistence": ["persistence_scan", "registry_query"],
    "privilege-escalation": ["process_tree", "auth_log"],
    "defense-evasion": ["process_tree", "file_hash_lookup"],
    "credential-access": ["credential_access_check", "auth_log"],
    "discovery": ["process_tree", "dns_query"],
    "lateral-movement": ["lateral_movement_check", "network_flow", "auth_log"],
    "collection": ["file_hash_lookup", "process_tree"],
    "command-and-control": ["network_flow", "dns_query"],
    "exfiltration": ["network_flow", "dns_query"],
    "impact": ["process_tree", "file_hash_lookup"],
}

# Default target types for tactics
TACTIC_TO_TARGET_TYPE: dict[str, str] = {
    "initial-access": "host",
    "execution": "process",
    "persistence": "host",
    "privilege-escalation": "process",
    "defense-evasion": "process",
    "credential-access": "user",
    "discovery": "host",
    "lateral-movement": "network",
    "collection": "file",
    "command-and-control": "network",
    "exfiltration": "network",
    "impact": "host",
}

# MITRE tactic kill-chain ordering for gap detection
TACTIC_KILL_CHAIN: list[str] = [
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

# Predecessor / Successor mappings for structural debt & chain follow
TACTIC_PREDECESSOR: dict[str, list[str]] = {}
TACTIC_SUCCESSOR: dict[str, list[str]] = {}
for _i, _t in enumerate(TACTIC_KILL_CHAIN):
    TACTIC_PREDECESSOR[_t] = [TACTIC_KILL_CHAIN[_i - 1]] if _i > 0 else []
    TACTIC_SUCCESSOR[_t] = [TACTIC_KILL_CHAIN[_i + 1]] if _i < len(TACTIC_KILL_CHAIN) - 1 else []


# =========================================================================
# Helper utilities
# =========================================================================

def _tactic_to_operator(tactic: str) -> str:
    """Map tactic to its primary operator."""
    operators = TACTIC_TO_OPERATORS.get(tactic, ["process_tree"])
    return operators[0]


def _make_probe(
    target: str,
    tactic: str,
    operator: str,
    source: str,
    priority_hint: float = 0.5,
    *,
    explanation_ids: list[str] | None = None,
    metadata: dict[str, Any] | None = None,
    target_type: str | None = None,
) -> Probe:
    """Unified probe construction helper."""
    if target_type is None:
        target_type = TACTIC_TO_TARGET_TYPE.get(tactic, "host")
    probe_id = Probe.generate_id(target, operator, tactic)
    return Probe(
        id=probe_id,
        target=target,
        target_type=target_type,
        operator=operator,
        tactic=tactic,
        source=source,
        explanation_ids=list(explanation_ids or []),
        metadata=dict(metadata or {}),
        priority_hint=priority_hint,
    )


def _find_orphan_nodes(graph: SessionGraph) -> list[dict]:
    """获取无incoming边的节点（非唯一根）- 返回dict列表方便生成器使用。"""
    orphans: list[dict] = []
    for nid, in_edges in graph._adj_in.items():
        if not in_edges:
            node = graph.get_node(nid)
            if node is None:
                continue
            attrs = node.attributes or {}
            host = attrs.get("asset_id") or attrs.get("host") or attrs.get("target") or ""
            orphans.append({
                "id": nid,
                "tactic": normalize_tactic(node.tactic),
                "host": host,
                "technique": node.technique,
            })
    return orphans


def _find_leaf_nodes(graph: SessionGraph) -> list[dict]:
    """获取无outgoing边的节点 - 返回dict列表方便生成器使用。"""
    leaves: list[dict] = []
    for nid, out_edges in graph._adj_out.items():
        if not out_edges:
            node = graph.get_node(nid)
            if node is None:
                continue
            attrs = node.attributes or {}
            host = attrs.get("asset_id") or attrs.get("host") or attrs.get("target") or ""
            leaves.append({
                "id": nid,
                "tactic": normalize_tactic(node.tactic),
                "host": host,
                "technique": node.technique,
            })
    return leaves


def _load_lifecycle_templates() -> list[dict] | None:
    """Load lifecycle_templates.json from prior_knowledge/templates/."""
    # Try multiple paths for robustness
    candidates = [
        Path(__file__).resolve().parent.parent.parent.parent / "prior_knowledge" / "templates" / "lifecycle_templates.json",
    ]
    try:
        from prior_knowledge.paths import LIFECYCLE_TEMPLATES_TEMPLATE_PATH
        candidates.insert(0, LIFECYCLE_TEMPLATES_TEMPLATE_PATH)
    except ImportError:
        pass

    for p in candidates:
        if p.exists():
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return data.get("templates", [])
            except Exception:
                continue
    return None


def _match_best_template(tactics_seen: set[str], templates: list[dict]) -> dict | None:
    """Find the template with the largest overlap with seen tactics."""
    best: dict | None = None
    best_overlap = 0
    for tmpl in templates:
        stages = tmpl.get("stages", [])
        # Collect all expected_tactics from stages
        template_tactics: set[str] = set()
        for stage in stages:
            for t in stage.get("expected_tactics", []):
                template_tactics.add(t)
        overlap = len(tactics_seen & template_tactics)
        if overlap > best_overlap:
            best_overlap = overlap
            best = tmpl
    return best


# =========================================================================
# 2.1 Prior Generator — 解除cap，同时查 incoming + outgoing
# =========================================================================

def prior_generator(graph: SessionGraph, ledger: Any, prior_manager: Any) -> list[Probe]:
    """基于图 frontier + 先验知识生成候选。

    Strategy:
    1. For each frontier node, look up its technique in prior_manager
    2. Get neighbor techniques (likely next steps in attack chain)
    3. For each neighbor, generate a probe with appropriate operator
    4. Also generate probes for the leading explanation's expected next stage

    Args:
        graph: Current SessionGraph (read frontier + node info)
        ledger: RuntimeDecisionLedger (read leading explanation + explanations)
        prior_manager: PriorManager (L1/L2 lookup)

    Returns:
        List of Probe candidates (typically 3-10 per round)
    """
    probes: list[Probe] = []

    frontier_ids = graph.frontier()
    if not frontier_ids:
        return probes

    # Determine leading explanation for explanation_ids linkage
    leading_id = ""
    leading_expl = None
    if ledger and hasattr(ledger, "leading"):
        leading_id = ledger.leading()
        if leading_id and leading_id != "__null__" and hasattr(ledger, "explanations"):
            for expl in ledger.explanations:
                if expl.id == leading_id:
                    leading_expl = expl
                    break

    # 1. Frontier-based probes via technique neighbors
    for nid in frontier_ids:
        node = graph.get_node(nid)
        if node is None:
            continue

        technique = node.technique
        tactic = node.tactic
        # Derive target from node attributes or use a default
        target = node.attributes.get("asset_id", node.attributes.get("host", f"frontier-{nid}"))

        # Look up technique neighbors: query BOTH incoming and outgoing simultaneously
        if prior_manager and technique:
            neighbor_specs: list[tuple[dict, str]] = []
            # Incoming neighbors (溯源) — limit 5
            try:
                for nb in prior_manager.technique_neighbors(technique, direction="incoming", top_k=5):
                    neighbor_specs.append((nb, "incoming"))
            except Exception:
                pass
            # Outgoing neighbors (前进) — limit 4
            try:
                for nb in prior_manager.technique_neighbors(technique, direction="outgoing", top_k=4):
                    neighbor_specs.append((nb, "outgoing"))
            except Exception:
                pass

            for neighbor, edge_dir in neighbor_specs:
                if edge_dir == "incoming":
                    dst_id = neighbor.get("src", "")
                    dst_node_info = neighbor.get("src_node") or {}
                else:
                    dst_id = neighbor.get("dst", "")
                    dst_node_info = neighbor.get("dst_node") or {}
                neighbor_tactic = dst_node_info.get("tactic", tactic) if dst_node_info else tactic
                # Normalize tactic
                if isinstance(neighbor_tactic, list):
                    neighbor_tactic = neighbor_tactic[0] if neighbor_tactic else tactic
                neighbor_tactic_lower = normalize_tactic(str(neighbor_tactic), fallback=tactic)

                operators = TACTIC_TO_OPERATORS.get(neighbor_tactic_lower, ["process_tree"])
                operator = operators[0]
                target_type = TACTIC_TO_TARGET_TYPE.get(neighbor_tactic_lower, "host")

                probe_id = Probe.generate_id(target, operator, neighbor_tactic_lower)
                expl_ids = [leading_id] if leading_id and leading_id != "__null__" else []

                prob = neighbor.get("probability", 0.0)
                priority = float(prob) if prob else 0.3

                probe = Probe(
                    id=probe_id,
                    target=target,
                    target_type=target_type,
                    operator=operator,
                    tactic=neighbor_tactic_lower,
                    source="prior",
                    explanation_ids=expl_ids,
                    metadata={
                        "origin_technique": technique,
                        "neighbor_technique": dst_id,
                        "edge_direction": edge_dir,
                    },
                    priority_hint=priority,
                )
                probes.append(probe)

    # 2. Leading explanation stage-based probes
    if leading_expl and prior_manager:
        stage = leading_expl.stage
        if stage:
            # Use predecessor_tactics to find what commonly precedes the current stage
            # and generate probes for successor stages
            try:
                predecessors = prior_manager.predecessor_tactics(stage, top_k=3)
            except Exception:
                predecessors = []

            # Generate probes for the current stage's expected techniques
            stage_lower = normalize_tactic(stage, fallback="execution")
            operators = TACTIC_TO_OPERATORS.get(stage_lower, ["process_tree"])
            target_type = TACTIC_TO_TARGET_TYPE.get(stage_lower, "host")

            # If current technique has recommended log sources, use them
            try:
                recommended = prior_manager.recommended_log_sources(leading_expl.current_technique)
            except Exception:
                recommended = []

            if recommended:
                for rec in recommended[:2]:
                    log_src = rec.get("log_source", operators[0])
                    target = f"stage-{stage_lower}"
                    probe_id = Probe.generate_id(target, log_src, stage_lower)
                    probe = Probe(
                        id=probe_id,
                        target=target,
                        target_type=target_type,
                        operator=log_src,
                        tactic=stage_lower,
                        source="prior",
                        explanation_ids=[leading_id],
                        metadata={"reason": "leading_explanation_stage", "technique": leading_expl.current_technique},
                        priority_hint=0.5,
                    )
                    probes.append(probe)

    return probes


def rule_gap_generator(graph: SessionGraph, prev_stats: dict) -> list[Probe]:
    """基于结构缺口生成候选。

    Structural gaps (RFC-004-02 §8 structural debt):
    1. Orphan nodes: nodes with no incoming edges AND not root (missing causal parent)
    2. Tactic gaps: expected tactics in kill chain not yet seen
    3. Bridge hosts: nodes connecting disconnected subgraphs (lateral movement indicators)

    Args:
        graph: Current SessionGraph
        prev_stats: Previous round's graph.stats() (detect changes)

    Returns:
        List of Probe candidates addressing structural gaps
    """
    probes: list[Probe] = []
    stats = graph.stats()

    # 1. Orphan detection: nodes with no incoming edges that aren't roots
    roots = set(graph.roots())
    frontier = graph.frontier()

    for nid in frontier:
        node = graph.get_node(nid)
        if node is None:
            continue
        # A node is "orphan" if it's a root but not the first root (i.e., disconnected)
        # We look for leaf nodes that have no in-edges and are not the primary root
        if nid in roots and len(roots) > 1:
            # This root is potentially a disconnected component — probe for its parent
            tactic = node.tactic.lower().replace("_", "-")
            target = node.attributes.get("asset_id", f"orphan-{nid}")
            operators = TACTIC_TO_OPERATORS.get(tactic, ["process_tree"])
            operator = operators[0]
            target_type = TACTIC_TO_TARGET_TYPE.get(tactic, "host")

            probe_id = Probe.generate_id(target, operator, f"gap-orphan-{tactic}")
            probe = Probe(
                id=probe_id,
                target=target,
                target_type=target_type,
                operator=operator,
                tactic=tactic,
                source="rule_gap",
                explanation_ids=[],
                metadata={"gap_type": "orphan", "orphan_node": nid},
                priority_hint=0.4,
            )
            probes.append(probe)

    # 2. Tactic gap detection: find missing tactics between first and last seen
    tactics_seen = set(stats.get("tactics_seen", []))
    # Derive known targets from graph for better probe targeting
    _known_targets: list[str] = []
    for _nid in list(graph._nodes.keys()):
        _node = graph.get_node(_nid)
        if _node and _node.attributes:
            _host = _node.attributes.get("asset_id") or _node.attributes.get("host") or _node.attributes.get("target")
            if _host and _host not in _known_targets:
                _known_targets.append(_host)

    if tactics_seen:
        # Find the range in kill chain
        first_idx = len(TACTIC_KILL_CHAIN)
        last_idx = -1
        for i, t in enumerate(TACTIC_KILL_CHAIN):
            if t in tactics_seen:
                first_idx = min(first_idx, i)
                last_idx = max(last_idx, i)

        # Any tactic between first and last that's missing is a gap
        if first_idx < last_idx:
            for i in range(first_idx + 1, last_idx):
                gap_tactic = TACTIC_KILL_CHAIN[i]
                if gap_tactic not in tactics_seen:
                    operators = TACTIC_TO_OPERATORS.get(gap_tactic, ["process_tree"])
                    operator = operators[0]
                    target_type = TACTIC_TO_TARGET_TYPE.get(gap_tactic, "host")
                    target = _known_targets[0] if _known_targets else f"gap-{gap_tactic}"

                    probe_id = Probe.generate_id(target, operator, f"gap-tactic-{gap_tactic}")
                    probe = Probe(
                        id=probe_id,
                        target=target,
                        target_type=target_type,
                        operator=operator,
                        tactic=gap_tactic,
                        source="rule_gap",
                        explanation_ids=[],
                        metadata={"gap_type": "tactic_gap", "missing_tactic": gap_tactic},
                        priority_hint=0.35,
                    )
                    probes.append(probe)

    # 3. Stagnation detection: if no new nodes since last round, broaden search
    prev_node_count = prev_stats.get("node_count", 0) if prev_stats else 0
    current_node_count = stats.get("node_count", 0)
    if prev_stats and current_node_count == prev_node_count and current_node_count > 0:
        # Derive targets from existing graph nodes (use real host names)
        known_targets: list[str] = []
        for nid in list(graph._nodes.keys()):
            node = graph.get_node(nid)
            if node and node.attributes:
                host = node.attributes.get("asset_id") or node.attributes.get("host") or node.attributes.get("target")
                if host and host not in known_targets:
                    known_targets.append(host)

        # Graph didn't grow — probe for unseen tactics to break stagnation
        unseen = [t for t in TACTIC_KILL_CHAIN if t not in tactics_seen]
        for gap_tactic in unseen[:3]:  # limit to 3 stagnation probes
            operators = TACTIC_TO_OPERATORS.get(gap_tactic, ["process_tree"])
            operator = operators[0]
            target_type = TACTIC_TO_TARGET_TYPE.get(gap_tactic, "host")
            # Use real target from graph if available, otherwise synthetic
            target = known_targets[0] if known_targets else f"stagnation-{gap_tactic}"

            probe_id = Probe.generate_id(target, operator, f"stagnation-{gap_tactic}")
            probe = Probe(
                id=probe_id,
                target=target,
                target_type=target_type,
                operator=operator,
                tactic=gap_tactic,
                source="rule_gap",
                explanation_ids=[],
                metadata={"gap_type": "stagnation", "missing_tactic": gap_tactic},
                priority_hint=0.25,
            )
            probes.append(probe)

    return probes


def _hosts_with_labels(graph: SessionGraph) -> list[tuple[str, str]]:
    """Return (canonical_host_label, lower) for each distinct host in graph."""
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for node in graph._nodes.values():
        attrs = node.attributes or {}
        label = ""
        for key in ("host_uid", "asset_id", "host", "target"):
            val = attrs.get(key)
            if val:
                label = str(val)
                break
        if not label:
            continue
        low = label.lower()
        if low not in seen:
            seen.add(low)
            out.append((label, low))
    return out


def _graph_hosts(graph: SessionGraph) -> set[str]:
    return {low for _, low in _hosts_with_labels(graph)}


def _tactics_on_host(graph: SessionGraph, host_lower: str) -> set[str]:
    tactics: set[str] = set()
    for node in graph._nodes.values():
        attrs = node.attributes or {}
        label = ""
        for key in ("host_uid", "asset_id", "host", "target"):
            val = attrs.get(key)
            if val:
                label = str(val).lower()
                break
        if label == host_lower:
            tactics.add(normalize_tactic(node.tactic))
    return tactics


# =========================================================================
# 2.3 Chain Follow Generator — 增强：全missing + reverse chain follow
# =========================================================================

def chain_follow_generator(graph: SessionGraph) -> list[Probe]:
    """沿杀伤链在已入图主机上补查缺失阶段（同一主机上的下一跳）。

    增强逻辑：
    - 找出该主机kill-chain中所有缺失的tactic，每个都生成探针
    - 新增reverse chain follow：对有outgoing但无incoming的节点生成反向探针
    """
    probes: list[Probe] = []
    for host_label, host_lower in _hosts_with_labels(graph):
        host_tactics = _tactics_on_host(graph, host_lower)
        if not host_tactics:
            continue

        indices = [TACTIC_KILL_CHAIN.index(t) for t in host_tactics if t in TACTIC_KILL_CHAIN]
        if not indices:
            continue
        lo, hi = min(indices), max(indices)

        # 找出该主机kill-chain中所有缺失的tactic
        target_indices: set[int] = set()
        # 链内缺口：lo到hi之间所有缺失的
        for i in range(lo, hi + 1):
            if TACTIC_KILL_CHAIN[i] not in host_tactics:
                target_indices.add(i)
        # 向前追所有后续阶段
        for i in range(hi + 1, len(TACTIC_KILL_CHAIN)):
            if TACTIC_KILL_CHAIN[i] not in host_tactics:
                target_indices.add(i)

        # 不再限制数量，为每个缺失tactic生成探针
        for i in sorted(target_indices):
            tactic = TACTIC_KILL_CHAIN[i]
            operators = TACTIC_TO_OPERATORS.get(tactic, ["process_tree"])
            operator = operators[0]
            target_type = TACTIC_TO_TARGET_TYPE.get(tactic, "host")
            probe_id = Probe.generate_id(host_label, operator, f"chain-{tactic}")
            probes.append(
                Probe(
                    id=probe_id,
                    target=host_label,
                    target_type=target_type,
                    operator=operator,
                    tactic=tactic,
                    source="chain_follow",
                    explanation_ids=[],
                    metadata={"gap_type": "chain_follow", "host": host_label, "tactic": tactic},
                    priority_hint=0.78,
                )
            )

        # 横向扩展：已见主机上查 network / lateral
        for operator, tactic in (("network_flow", "lateral-movement"), ("lateral_movement_check", "lateral-movement")):
            probe_id = Probe.generate_id(host_label, operator, f"chain-lat-{tactic}")
            probes.append(
                Probe(
                    id=probe_id,
                    target=host_label,
                    target_type="network",
                    operator=operator,
                    tactic=tactic,
                    source="chain_follow",
                    explanation_ids=[],
                    metadata={"gap_type": "chain_lateral", "host": host_label},
                    priority_hint=0.62,
                )
            )

    # Reverse chain follow: 对每个有outgoing边但无incoming边的节点生成反向探针
    for nid in list(graph._nodes.keys()):
        out_edges = graph._adj_out.get(nid, [])
        in_edges = graph._adj_in.get(nid, [])
        if out_edges and not in_edges:
            node = graph.get_node(nid)
            if node is None:
                continue
            tactic = normalize_tactic(node.tactic)
            attrs = node.attributes or {}
            host = attrs.get("asset_id") or attrs.get("host") or attrs.get("target") or f"node-{nid}"
            # 生成反向探针：查找该节点tactic的predecessor tactic
            predecessors = TACTIC_PREDECESSOR.get(tactic, [])
            for pred_tactic in predecessors:
                operator = _tactic_to_operator(pred_tactic)
                target_type = TACTIC_TO_TARGET_TYPE.get(pred_tactic, "host")
                probe_id = Probe.generate_id(host, operator, f"reverse-chain-{pred_tactic}")
                probes.append(
                    Probe(
                        id=probe_id,
                        target=host,
                        target_type=target_type,
                        operator=operator,
                        tactic=pred_tactic,
                        source="chain_follow",
                        explanation_ids=[],
                        metadata={"gap_type": "reverse_chain_follow", "origin_node": nid, "origin_tactic": tactic},
                        priority_hint=0.70,
                    )
                )

    return probes


def _cross_host_priority(host: str) -> tuple[int, str]:
    upper = host.upper()
    if upper.startswith("WS-"):
        return (0, host)
    if upper.startswith("SRV-"):
        return (1, host)
    return (2, host)


# =========================================================================
# 2.2 Cross-Host Generator — 全场景激活
# =========================================================================

def cross_host_probe_generator(
    graph: SessionGraph,
    known_hosts: list[str],
    *,
    alert_asset: str = "",
) -> list[Probe]:
    """跨主机追根：满足任一激活条件时，对场景内其他主机投放 auth_log + network_flow 探针。

    激活条件（满足任一即可）：
    1. graph中存在 >1 个host
    2. graph中有lateral-movement相关tactic的节点
    3. 场景的known_hosts > 1
    """
    probes: list[Probe] = []
    if not known_hosts:
        return probes

    stats = graph.stats()
    tactics_seen = {normalize_tactic(t) for t in stats.get("tactics_seen", [])}
    graph_hosts = _graph_hosts(graph)

    # 激活条件检查
    has_multiple_graph_hosts = len(graph_hosts) > 1
    has_lateral_movement = "lateral-movement" in tactics_seen
    has_multiple_known_hosts = len(known_hosts) > 1

    if not (has_multiple_graph_hosts or has_lateral_movement or has_multiple_known_hosts):
        return probes

    alert_lower = (alert_asset or "").lower()
    # 对所有已知但未入图的主机生成探针
    # 告警主机例外：即使已在图中，也需要 auth_log + network_flow 探针
    # 因为告警主机有最多攻击事件，但可能缺少多种算子覆盖
    candidates = sorted(
        (
            h for h in known_hosts
            if h.lower() not in graph_hosts or h.lower() == alert_lower
        ),
        key=_cross_host_priority,
    )

    # 主机上限: 8（含告警主机）
    for host in candidates[:8]:
        is_workstation = host.upper().startswith("WS-")
        is_alert_host = host.lower() == alert_lower
        # auth_log 探针
        probe_id = Probe.generate_id(host, "auth_log", "initial-access")
        probes.append(
            Probe(
                id=probe_id,
                target=host,
                target_type="host",
                operator="auth_log",
                tactic="initial-access",
                source="cross_host",
                explanation_ids=[],
                metadata={"gap_type": "cross_host", "target_host": host},
                priority_hint=0.96 if (is_workstation or is_alert_host) else 0.58,
            )
        )
        # network_flow 探针
        probe_id_nf = Probe.generate_id(host, "network_flow", "lateral-movement")
        probes.append(
            Probe(
                id=probe_id_nf,
                target=host,
                target_type="network",
                operator="network_flow",
                tactic="lateral-movement",
                source="cross_host",
                explanation_ids=[],
                metadata={"gap_type": "cross_host", "target_host": host},
                priority_hint=0.90 if (is_workstation or is_alert_host) else 0.52,
            )
        )
    return probes


# =========================================================================
# 2.4 Structural Debt Generator
# =========================================================================

def structural_debt_generator(graph: SessionGraph, ledger: Any = None) -> list[Probe]:
    """Pro-active: 对图中每个断裂点生成桥接探针。

    1. 孤儿节点(无incoming): 生成parent-finding探针
    2. 末端节点(无outgoing): 生成child-finding探针
    3. 断连组件桥接: 不同host间lateral movement
    """
    probes: list[Probe] = []

    # Collect known hosts from graph for fallback when nodes lack host info
    known_hosts_list = list(_graph_hosts(graph))

    # 1. 孤儿节点(无incoming): 生成parent-finding探针
    orphan_nodes = _find_orphan_nodes(graph)
    for node in orphan_nodes:
        tactic = node.get("tactic", "")
        host = node.get("host", "")
        if not host:
            # Fallback to first known host from graph (never use node ID as target)
            host = known_hosts_list[0] if known_hosts_list else ""
        if not host:
            continue  # Skip if no valid host available
        predecessors = TACTIC_PREDECESSOR.get(tactic, [])
        for pred_tactic in predecessors:
            probes.append(_make_probe(
                target=host,
                tactic=pred_tactic,
                operator=_tactic_to_operator(pred_tactic),
                source="structural_debt",
                priority_hint=0.72,
                metadata={"debt_type": "orphan_parent", "origin_node": node.get("id", ""), "origin_tactic": tactic},
            ))

    # 2. 末端节点(无outgoing): 生成child-finding探针
    leaf_nodes = _find_leaf_nodes(graph)
    for node in leaf_nodes:
        tactic = node.get("tactic", "")
        host = node.get("host", "")
        if not host:
            # Fallback to first known host from graph (never use node ID as target)
            host = known_hosts_list[0] if known_hosts_list else ""
        if not host:
            continue  # Skip if no valid host available
        successors = TACTIC_SUCCESSOR.get(tactic, [])
        for succ_tactic in successors:
            probes.append(_make_probe(
                target=host,
                tactic=succ_tactic,
                operator=_tactic_to_operator(succ_tactic),
                source="structural_debt",
                priority_hint=0.68,
                metadata={"debt_type": "leaf_child", "origin_node": node.get("id", ""), "origin_tactic": tactic},
            ))

    # 3. 断连组件桥接: 不同host间lateral movement
    hosts_in_graph = list(_graph_hosts(graph))
    if len(hosts_in_graph) >= 2:
        for i, h1 in enumerate(hosts_in_graph):
            for h2 in hosts_in_graph[i + 1:]:
                probes.append(_make_probe(
                    target=h2,
                    tactic="lateral-movement",
                    operator="lateral_movement_check",
                    source="structural_debt",
                    priority_hint=0.82,
                    metadata={"debt_type": "bridge", "from_host": h1, "to_host": h2},
                ))

    return probes


# =========================================================================
# 2.5 Lifecycle Template Generator
# =========================================================================

def lifecycle_template_generator(graph: SessionGraph, templates: list[dict] | None = None) -> list[Probe]:
    """基于lifecycle_templates.json预测缺失阶段。

    匹配最佳模板，找出缺失阶段，对每个缺失阶段在所有已知主机上生成探针。
    """
    probes: list[Probe] = []
    stats = graph.stats()
    tactics_seen = set(stats.get("tactics_seen", []))
    hosts = list(_graph_hosts(graph))

    if not templates:
        templates = _load_lifecycle_templates()
    if not templates:
        return probes

    # 匹配最佳模板
    best_template = _match_best_template(tactics_seen, templates)
    if not best_template:
        return probes

    # 找出缺失阶段: 收集模板中所有expected_tactics
    template_tactics: set[str] = set()
    for stage in best_template.get("stages", []):
        for t in stage.get("expected_tactics", []):
            template_tactics.add(t)

    missing = template_tactics - tactics_seen

    # 对每个缺失阶段，在所有已知主机上生成探针
    for stage_tactic in missing:
        for host in hosts:
            probes.append(_make_probe(
                target=host,
                tactic=stage_tactic,
                operator=_tactic_to_operator(stage_tactic),
                source="lifecycle_template",
                priority_hint=0.65,
                metadata={
                    "template_id": best_template.get("template_id", ""),
                    "missing_tactic": stage_tactic,
                },
            ))

    return probes


# =========================================================================
# 2.6 Clue Pivot Generator (real_trace_01 v2 — backward pivot chain)
# =========================================================================

def clue_pivot_probe_generator(
    graph: SessionGraph,
    clue_pivot_rules: list[dict] | None = None,
    cached_events: list[dict] | None = None,
) -> list[Probe]:
    """真实模式回溯：从已确认事件的属性提取下一跳 pivot，逐字段回溯攻击链。

    每条规则 = {attr, field, technique[, tactic, operator]}：
      从事件的 ``attributes[attr]`` 取值 val，生成携带显式 Lucene
      ``{field}:"{val}" AND rule.mitre.id:{technique}`` 的探针。

    证据来源同时含图节点与 executor 取证缓存（seed_only 时种子仅在缓存里）。
    rules 为空（如 pipeline_18）时直接返回 []，不影响既有路径。
    """
    rules = list(clue_pivot_rules or [])
    if not rules:
        return []

    # 统一成 (attrs, technique) 视图：图节点 + 缓存事件
    views: list[tuple[dict, str]] = []
    for node in graph.all_nodes():
        views.append((
            getattr(node, "attributes", {}) or {},
            str(getattr(node, "technique", "") or ""),
        ))
    for ev in (cached_events or []):
        attrs = dict(ev.get("attributes") or {})
        tech = str(ev.get("technique") or attrs.get("mitre_technique") or "")
        views.append((attrs, tech))

    if not views:
        return []

    # 已发现的技术 → 该回溯步骤已完成，避免重复发探针。
    seen_techniques = {
        tech.strip().upper() for _attrs, tech in views if tech.strip()
    }

    probes: list[Probe] = []
    emitted: set[str] = set()
    for attrs, _tech in views:
        for rule in rules:
            attr = str(rule.get("attr") or "").strip()
            field = str(rule.get("field") or "").strip()
            technique = str(rule.get("technique") or "").strip()
            if not attr or not field or not technique:
                continue
            if technique.upper() in seen_techniques:
                continue
            value = attrs.get(attr)
            if value in (None, "", [], {}):
                continue
            value = str(value)
            query = f'{field}:"{value}" AND rule.mitre.id:{technique}'
            if query in emitted:
                continue
            emitted.add(query)
            tactic = str(rule.get("tactic") or "") or normalize_tactic(technique)
            operator = str(rule.get("operator") or "clue_pivot")
            probes.append(Probe(
                id=Probe.generate_id(value, operator, technique),
                target=value,
                target_type="clue",
                operator=operator,
                tactic=tactic,
                source="clue_pivot",
                priority_hint=0.9,
                metadata={
                    "mcp_query": query,
                    "expected_technique": technique,
                    "pivot_field": field,
                    "pivot_attr": attr,
                },
            ))

    return probes
