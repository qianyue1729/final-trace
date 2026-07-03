"""Deterministic probe executor driven by graph replay fixtures."""
from __future__ import annotations

from typing import Any, Optional

from trace_agent.loop.executor import ProbeExecutor
from trace_agent.loop.probe import Probe
from trace_agent.loop.session_graph import SessionGraph


class GraphFixtureExecutor(ProbeExecutor):
    """Reveal hidden world_graph nodes in fixture-controlled order.

    B0 driver: no DARPA ingest. Uses reveal_queue + optional probe_bindings
    so LOCK loop replay is deterministic.
    """

    def __init__(self, fixture: dict[str, Any], graph: Optional[SessionGraph] = None):
        self._fixture = fixture
        world = fixture.get("world_graph") or {}
        self._nodes = {n["id"]: n for n in world.get("nodes", [])}
        self._edges = world.get("edges", [])
        driver = fixture.get("replay_driver") or {}
        self._reveal_queue: list[str] = list(driver.get("reveal_queue", []))
        self._pollute_queue: list[str] = list(driver.get("pollute_queue", []))
        self._probe_bindings = driver.get("probe_bindings") or []
        self._revealed: set[str] = set()
        self._graph = graph

    def attach_graph(self, graph: SessionGraph) -> None:
        self._graph = graph

    def execute_fanout(self, probes: list[Probe]) -> list[dict]:
        if not probes:
            return []

        events: list[dict] = []
        used_probes: set[int] = set()

        for binding in self._probe_bindings:
            match = binding.get("match") or {}
            reveals = binding.get("reveals") or []
            for idx, probe in enumerate(probes):
                if idx in used_probes:
                    continue
                if not self._probe_matches(probe, match):
                    continue
                for node_id in reveals:
                    ev = self._materialize_node(node_id, probe)
                    if ev is not None:
                        events.append(ev)
                used_probes.add(idx)

        for idx, probe in enumerate(probes):
            if idx in used_probes:
                continue
            if not self._reveal_queue:
                break
            node_id = self._reveal_queue.pop(0)
            ev = self._materialize_node(node_id, probe)
            if ev is not None:
                events.append(ev)

        if self._pollute_queue and probes:
            node_id = self._pollute_queue.pop(0)
            ev = self._materialize_node(node_id, probes[0])
            if ev is not None:
                events.append(ev)

        return events

    def available(self) -> bool:
        return True

    def revealed_nodes(self) -> set[str]:
        return set(self._revealed)

    def _probe_matches(self, probe: Probe, match: dict[str, Any]) -> bool:
        if not match:
            return False
        if "operator" in match and probe.operator != match["operator"]:
            return False
        if "operator_contains" in match and match["operator_contains"] not in probe.operator:
            return False
        if "tactic" in match and probe.tactic != match["tactic"]:
            return False
        if "tactics" in match and probe.tactic not in match["tactics"]:
            return False
        if "operators" in match and probe.operator not in match["operators"]:
            return False
        return True

    def _materialize_node(self, world_node_id: str, probe: Probe) -> dict | None:
        if world_node_id in self._revealed:
            return None
        node = self._nodes.get(world_node_id)
        if node is None:
            return None

        parent_id = self._resolve_parent(world_node_id)
        event = {
            "id": world_node_id,
            "technique": node["technique"],
            "tactic": node["tactic"],
            "timestamp": float(node["timestamp"]),
            "source": node.get("source", "fixture-replay"),
            "trust_tier": node.get("trust_tier", "high"),
            "target": probe.target,
            "probe_id": probe.id,
            "attributes": dict(node.get("attributes") or {}),
        }
        event["attributes"]["graph_replay_attach"] = True
        if parent_id:
            event["parent_id"] = parent_id
        self._revealed.add(world_node_id)
        return event

    def _resolve_parent(self, world_node_id: str) -> str | None:
        src_world: str | None = None
        for edge in self._edges:
            if edge.get("dst") == world_node_id and edge.get("role", "attack") == "attack":
                src_world = edge.get("src")
                break
        if not src_world:
            return None

        src_node = self._nodes.get(src_world)
        if src_node is None:
            return None

        if self._graph is None:
            return None

        src_technique = src_node["technique"]
        src_timestamp = float(src_node["timestamp"])
        best_id: str | None = None
        best_delta = float("inf")
        for nid, runtime in self._graph._nodes.items():
            if runtime.technique != src_technique:
                continue
            delta = abs(runtime.timestamp - src_timestamp)
            if delta < best_delta:
                best_delta = delta
                best_id = nid
        return best_id
