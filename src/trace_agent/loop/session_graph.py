"""SessionGraph — RFC-004-02 §3.2 运行时因果图（第一本账）"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class GraphNode:
    id: str
    technique: str           # MITRE technique ID (e.g., "T1059.001")
    tactic: str              # MITRE tactic (e.g., "execution")
    timestamp: float         # unix epoch
    source: str              # log source that produced this event
    trust_tier: str          # "forge_resistant" / "high" / "medium" / "low"
    explanation_ids: list[str] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    fact_confirmed: bool = False
    attribution_status: str = "UNSET"
    malicious_status: str = "unknown"
    host_id: str = ""
    entity_id: str = ""
    provenance: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    src: str                 # source node id
    dst: str                 # destination node id
    relation: str            # "causes" / "precedes" / "lateral_to" / "elevates_to"
    confidence: float = 1.0
    explanation_ids: list[str] = field(default_factory=list)


class SessionGraph:
    """RFC-004-02 §3.2 — 运行时因果图，LOCK 第一本账。

    邻接表 + 时间索引设计，不引外部依赖。
    K 拍写入确认事件，L 拍读 frontier，证据修订级联可删边。
    """

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._adj_out: dict[str, list[str]] = {}  # node_id → [edge_ids outgoing]
        self._adj_in: dict[str, list[str]] = {}   # node_id → [edge_ids incoming]
        self._node_counter: int = 0
        self._edge_counter: int = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_events(self, events: list[dict]) -> list[str]:
        """入图（K 拍调用），返回新增 node ids。

        Each event dict should have:
        - technique: str (required)
        - tactic: str (required)
        - timestamp: float (required)
        - source: str (required)
        - trust_tier: str (default "medium")
        - explanation_ids: list[str] (default [])
        - attributes: dict (optional)
        - parent_id: str | None (if linked to existing node, creates edge)
        - relation: str (default "causes")
        """
        new_ids: list[str] = []
        for ev in events:
            node_id = ev.get("id") or self._next_node_id()
            node = GraphNode(
                id=node_id,
                technique=ev["technique"],
                tactic=ev["tactic"],
                timestamp=ev["timestamp"],
                source=ev["source"],
                trust_tier=ev.get("trust_tier", "medium"),
                explanation_ids=list(ev.get("explanation_ids", [])),
                attributes=dict(ev.get("attributes", {})),
                fact_confirmed=bool(ev.get("_fact_confirmed", False)),
                attribution_status=str(
                    ev.get("_attribution_status", "UNSET")
                ),
                malicious_status=str(
                    ev.get("malicious_status", "suspected")
                    if ev.get("_attribution_confirmed")
                    else "unknown"
                ),
                host_id=str(
                    (ev.get("attributes") or {}).get("host_uid")
                    or (ev.get("attributes") or {}).get("asset_id")
                    or (ev.get("attributes") or {}).get("target")
                    or ev.get("target")
                    or ""
                ),
                entity_id=str(
                    (ev.get("attributes") or {}).get("entity_id")
                    or ev.get("id")
                    or ""
                ),
                provenance=dict(
                    (ev.get("attributes") or {}).get("provenance") or {}
                ),
            )
            self._nodes[node_id] = node
            self._adj_out.setdefault(node_id, [])
            self._adj_in.setdefault(node_id, [])

            # If parent specified, create edge parent → this node
            parent_id = ev.get("parent_id")
            if parent_id and parent_id in self._nodes:
                relation = ev.get("relation", "causes")
                edge_id = self._next_edge_id()
                edge = GraphEdge(
                    id=edge_id,
                    src=parent_id,
                    dst=node_id,
                    relation=relation,
                    explanation_ids=list(ev.get("explanation_ids", [])),
                )
                self._edges[edge_id] = edge
                self._adj_out[parent_id].append(edge_id)
                self._adj_in[node_id].append(edge_id)

            new_ids.append(node_id)
        return new_ids

    def stats(self) -> dict:
        """当前图统计。"""
        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "frontier_count": len(self.frontier()),
            "max_depth": self._compute_max_depth(),
            "tactics_seen": sorted(set(n.tactic for n in self._nodes.values())),
            "techniques_seen": sorted(set(n.technique for n in self._nodes.values())),
        }

    def frontier(self) -> list[str]:
        """叶节点 ids（没有出边的节点），供 L 拍生成候选。"""
        return [
            nid for nid, edges in self._adj_out.items()
            if not edges
        ]

    def subgraph_for(self, explanation_id: str) -> dict:
        """提取属于某解释的子图。Returns {"nodes": [...], "edges": [...]}"""
        nodes = [
            n for n in self._nodes.values()
            if explanation_id in n.explanation_ids
        ]
        edges = [
            e for e in self._edges.values()
            if explanation_id in e.explanation_ids
        ]
        return {
            "nodes": [n.id for n in nodes],
            "edges": [e.id for e in edges],
        }

    def compressed_context(
        self,
        event: dict,
        explanation_ids: list[str] | None = None,
        *,
        max_nodes: int = 40,
        hops: int = 2,
    ) -> dict:
        """Build a bounded, evidence-preserving graph view for L3 judgement."""
        explanation_ids = explanation_ids or []
        parent_ids = [
            node_id
            for node_id in event.get("_l1_parent_candidates", [])
            if node_id in self._nodes
        ]
        frontier_ids = set(self.frontier())
        scores: dict[str, float] = {}

        def mark(node_id: str, score: float) -> None:
            if node_id in self._nodes:
                scores[node_id] = max(scores.get(node_id, 0.0), score)

        for node_id in parent_ids:
            mark(node_id, 1000.0)

        # Preserve one evidence-linked ancestor backbone per candidate parent.
        backbone_paths: list[list[str]] = []
        for parent_id in parent_ids:
            path = [parent_id]
            current = parent_id
            path_seen = {parent_id}
            while self._adj_in.get(current):
                incoming = [
                    self._edges[edge_id]
                    for edge_id in self._adj_in[current]
                    if edge_id in self._edges
                ]
                if not incoming:
                    break
                edge = max(
                    incoming,
                    key=lambda item: (
                        item.confidence,
                        self._nodes.get(item.src).timestamp
                        if self._nodes.get(item.src)
                        else 0.0,
                    ),
                )
                if edge.src in path_seen:
                    break
                path_seen.add(edge.src)
                path.append(edge.src)
                current = edge.src
            ordered_path = list(reversed(path))
            backbone_paths.append(ordered_path)
            for depth, node_id in enumerate(path):
                mark(node_id, max(700.0, 950.0 - depth * 5.0))

        wave = set(parent_ids)
        visited = set(parent_ids)
        for depth in range(max(0, hops)):
            next_wave: set[str] = set()
            for node_id in wave:
                edge_ids = self._adj_out.get(node_id, []) + self._adj_in.get(node_id, [])
                for edge_id in edge_ids:
                    edge = self._edges.get(edge_id)
                    if edge is None:
                        continue
                    neighbor = edge.dst if edge.src == node_id else edge.src
                    mark(neighbor, 800.0 - depth * 100.0)
                    if neighbor not in visited:
                        visited.add(neighbor)
                        next_wave.add(neighbor)
            wave = next_wave

        event_attrs = event.get("attributes") or {}
        event_entities = {
            str(value).lower()
            for value in (
                event.get("target"),
                event.get("source_host"),
                event_attrs.get("host_uid"),
                event_attrs.get("asset_id"),
                event_attrs.get("user"),
                event_attrs.get("principal"),
                event_attrs.get("process_name"),
                event_attrs.get("src_ip"),
                event_attrs.get("dst_ip"),
            )
            if value not in (None, "")
        }
        event_ts = float(event.get("timestamp") or 0.0)

        for node_id, node in self._nodes.items():
            attrs = node.attributes or {}
            node_entities = {
                str(value).lower()
                for value in (
                    attrs.get("target"),
                    attrs.get("host"),
                    attrs.get("host_uid"),
                    attrs.get("asset_id"),
                    attrs.get("user"),
                    attrs.get("principal"),
                    attrs.get("process_name"),
                    attrs.get("src_ip"),
                    attrs.get("dst_ip"),
                )
                if value not in (None, "")
            }
            if event_entities.intersection(node_entities):
                mark(node_id, 650.0)
            if explanation_ids and set(node.explanation_ids).intersection(explanation_ids):
                mark(node_id, 500.0)
            if node_id in frontier_ids:
                mark(node_id, 350.0)
            if event_ts:
                mark(node_id, max(0.0, 100.0 - abs(node.timestamp - event_ts) / 60.0))

        ranked = sorted(
            self._nodes,
            key=lambda node_id: (
                scores.get(node_id, 0.0),
                self._nodes[node_id].timestamp,
                node_id,
            ),
            reverse=True,
        )
        selected_ids = set(ranked[:max(1, max_nodes)])
        nodes = [
            self._node_context(self._nodes[node_id])
            for node_id in ranked
            if node_id in selected_ids
        ]
        edges = [
            {
                "id": edge.id,
                "src": edge.src,
                "dst": edge.dst,
                "relation": edge.relation,
                "confidence": edge.confidence,
                "explanation_ids": list(edge.explanation_ids),
            }
            for edge in self._edges.values()
            if edge.src in selected_ids and edge.dst in selected_ids
        ]

        omitted_groups: dict[tuple[str, str, str, str], dict] = {}
        for node_id, node in self._nodes.items():
            if node_id in selected_ids:
                continue
            attrs = node.attributes or {}
            host = str(
                attrs.get("host_uid")
                or attrs.get("asset_id")
                or attrs.get("host")
                or attrs.get("target")
                or ""
            )
            key = (host, node.tactic, node.technique, node.source)
            group = omitted_groups.setdefault(
                key,
                {
                    "host": host,
                    "tactic": node.tactic,
                    "technique": node.technique,
                    "source": node.source,
                    "count": 0,
                    "first_timestamp": node.timestamp,
                    "last_timestamp": node.timestamp,
                },
            )
            group["count"] += 1
            group["first_timestamp"] = min(group["first_timestamp"], node.timestamp)
            group["last_timestamp"] = max(group["last_timestamp"], node.timestamp)

        return {
            "stats": self.stats(),
            "candidate_parent_ids": parent_ids,
            "backbone_paths": [
                [node_id for node_id in path if node_id in selected_ids]
                for path in backbone_paths
            ],
            "roots": [node_id for node_id in self.roots() if node_id in selected_ids],
            "frontiers": [node_id for node_id in self.frontier() if node_id in selected_ids],
            "nodes": nodes,
            "edges": edges,
            "omitted_summary": sorted(
                omitted_groups.values(),
                key=lambda item: item["count"],
                reverse=True,
            )[:12],
            "compression": {
                "max_nodes": max_nodes,
                "hops": hops,
                "selected_nodes": len(nodes),
                "omitted_nodes": max(0, len(self._nodes) - len(nodes)),
            },
        }

    def has_edge(self, src: str, dst: str) -> bool:
        """检查两节点间是否存在边"""
        out_edges = self._adj_out.get(src, [])
        for eid in out_edges:
            edge = self._edges.get(eid)
            if edge and edge.dst == dst:
                return True
        return False

    def link_parent(
        self,
        child_id: str,
        parent_id: str,
        relation: str = "causes",
        *,
        explanation_ids: list[str] | None = None,
    ) -> str | None:
        """Add parent → child edge when child already exists (upstream backfill)."""
        if child_id not in self._nodes or parent_id not in self._nodes:
            return None
        if self.has_edge(parent_id, child_id):
            return None
        edge_id = self._next_edge_id()
        edge = GraphEdge(
            id=edge_id,
            src=parent_id,
            dst=child_id,
            relation=relation,
            explanation_ids=list(explanation_ids or []),
        )
        self._edges[edge_id] = edge
        self._adj_out.setdefault(parent_id, []).append(edge_id)
        self._adj_in.setdefault(child_id, []).append(edge_id)
        return edge_id

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """获取节点，不存在返回 None"""
        return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[GraphEdge]:
        """获取边"""
        return self._edges.get(edge_id)

    def temporal_neighbors(self, node_id: str, window_sec: int = 300) -> list[str]:
        """获取时间窗口内的临近节点 ids"""
        target = self._nodes.get(node_id)
        if target is None:
            return []
        t = target.timestamp
        return [
            nid for nid, node in self._nodes.items()
            if nid != node_id and abs(node.timestamp - t) <= window_sec
        ]

    def remove_edges(self, edge_ids: list[str]) -> None:
        """证据修订级联时删除边（不删节点，仅断开连接）"""
        for eid in edge_ids:
            edge = self._edges.pop(eid, None)
            if edge is None:
                continue
            # Remove from adjacency lists
            out_list = self._adj_out.get(edge.src, [])
            if eid in out_list:
                out_list.remove(eid)
            in_list = self._adj_in.get(edge.dst, [])
            if eid in in_list:
                in_list.remove(eid)

    def depth_of(self, node_id: str) -> int:
        """节点的图深度（从根到该节点的最长路径）"""
        if node_id not in self._nodes:
            return -1
        # BFS/DFS from roots, compute longest path to node_id
        # Use dynamic programming with topological approach
        depths: dict[str, int] = {}
        # Process via BFS from all roots
        roots = self.roots()
        if not roots:
            # Graph may have cycles or be empty
            return 0
        # If node is a root, depth is 0
        if node_id in roots:
            return 0
        # Compute longest path using BFS with level tracking
        return self._longest_path_to(node_id)

    def roots(self) -> list[str]:
        """根节点 ids（没有入边的节点）"""
        return [
            nid for nid, edges in self._adj_in.items()
            if not edges
        ]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _node_context(node: GraphNode) -> dict:
        keep = {
            "target",
            "host",
            "host_uid",
            "asset_id",
            "user",
            "principal",
            "process_name",
            "parent_process",
            "src_ip",
            "dst_ip",
            "action",
        }
        attrs = {
            key: value
            for key, value in (node.attributes or {}).items()
            if key in keep and isinstance(value, (str, int, float, bool))
        }
        return {
            "id": node.id,
            "technique": node.technique,
            "tactic": node.tactic,
            "timestamp": node.timestamp,
            "source": node.source,
            "trust_tier": node.trust_tier,
            "explanation_ids": list(node.explanation_ids),
            "attributes": attrs,
        }

    def _next_node_id(self) -> str:
        self._node_counter += 1
        return f"N{self._node_counter}"

    def _next_edge_id(self) -> str:
        self._edge_counter += 1
        return f"E{self._edge_counter}"

    def _compute_max_depth(self) -> int:
        """Compute maximum depth in graph via BFS from roots."""
        roots = self.roots()
        if not roots:
            return 0
        max_d = 0
        # Longest path BFS from each root
        depth_map: dict[str, int] = {r: 0 for r in roots}
        queue: deque[str] = deque(roots)
        while queue:
            nid = queue.popleft()
            current_depth = depth_map[nid]
            for eid in self._adj_out.get(nid, []):
                edge = self._edges.get(eid)
                if edge is None:
                    continue
                child = edge.dst
                new_depth = current_depth + 1
                if child not in depth_map or depth_map[child] < new_depth:
                    depth_map[child] = new_depth
                    queue.append(child)
                    if new_depth > max_d:
                        max_d = new_depth
        return max_d

    def _longest_path_to(self, node_id: str) -> int:
        """Compute longest path from any root to given node."""
        roots = self.roots()
        if not roots:
            return 0
        depth_map: dict[str, int] = {r: 0 for r in roots}
        queue: deque[str] = deque(roots)
        while queue:
            nid = queue.popleft()
            current_depth = depth_map[nid]
            for eid in self._adj_out.get(nid, []):
                edge = self._edges.get(eid)
                if edge is None:
                    continue
                child = edge.dst
                new_depth = current_depth + 1
                if child not in depth_map or depth_map[child] < new_depth:
                    depth_map[child] = new_depth
                    queue.append(child)
        return depth_map.get(node_id, 0)
