"""ProvSec provenance → graph replay logic (B2.0).

Reads ProvSec syscall-level JSON, aggregates into security super-events
compatible with the DARPA TC event model, then delegates to shared
normalization in ``darpa_tc_common``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from trace_agent.eval.adapters.base import ProvenanceAdapterConfig
from trace_agent.eval.adapters.darpa_tc_common import (
    assemble_graph_fixture,
    build_ground_truth_subgraph,
    merged_ground_truth,
    normalize_darpa_tc_world_graph,
    parse_timestamp,
    read_provenance_events,
    repo_root,
)
from trace_agent.eval.adapters.normalization_stats import (
    audit_raw_events,
    collect_normalization_stats,
)

# ---------------------------------------------------------------------------
# Module-level CVE map cache
# ---------------------------------------------------------------------------
_CVE_MAP_CACHE: dict[str, Any] | None = None

# Syscall → relation mapping (ProvSec evt.type → world_graph edge relation)
_SYSCALL_RELATION_MAP: dict[str, str] = {
    "execve": "execve",
    "clone": "process_spawn",
    "fork": "process_spawn",
    "vfork": "process_spawn",
    "connect": "network_connect",
    "accept": "network_connect",
    "accept4": "network_connect",
    "sendto": "network_connect",
    "recvfrom": "network_connect",
    "open": "file_read",
    "openat": "file_read",
    "write": "file_write",
    "read": "file_read",
    "close": "file_read",
    "dup2": "file_read",
    "mmap": "file_read",
    "mprotect": "process_spawn",
}

# Relation → tactic_technique_map key for benign events
_RELATION_TO_TTM_KEY: dict[str, str] = {
    "process_spawn": "process_creation",
    "execve": "process_creation",
    "file_read": "file_access",
    "file_write": "file_creation",
    "network_connect": "network_connection",
}


# ---------------------------------------------------------------------------
# 1. CVE map loader
# ---------------------------------------------------------------------------

# Default fallback maps when cve_mitre_map.json is missing keys
_DEFAULT_SYSCALL_ACTION_MAP: dict[str, str] = {
    "execve": "EXEC",
    "clone": "FORK",
    "fork": "FORK",
    "vfork": "FORK",
    "connect": "CONNECT",
    "accept": "CONNECT",
    "open": "OPEN_FILE",
    "openat": "OPEN_FILE",
    "read": "READ",
    "write": "WRITE",
}

_DEFAULT_TACTIC_TECHNIQUE_MAP: dict[str, dict[str, str]] = {
    "process_creation": {"technique_id": "T1059", "tactic": "execution"},
    "file_creation": {"technique_id": "T1105", "tactic": "command-and-control"},
    "file_access": {"technique_id": "T1005", "tactic": "collection"},
    "network_connection": {"technique_id": "T1071.001", "tactic": "command-and-control"},
    "unknown": {"technique_id": "T0000", "tactic": "unknown"},
}


def load_cve_map() -> dict[str, Any]:
    """Load ``data/provsec/cve_mitre_map.json`` (cached after first call).

    Tolerates missing ``syscall_action_map`` / ``tactic_technique_map`` keys
    by injecting sensible defaults so ``aggregate_syscalls`` never crashes.
    """
    global _CVE_MAP_CACHE  # noqa: PLW0603
    if _CVE_MAP_CACHE is not None:
        return _CVE_MAP_CACHE
    map_path = repo_root() / "data" / "provsec" / "cve_mitre_map.json"
    if not map_path.is_file():
        _CVE_MAP_CACHE = {
            "mappings": {},
            "syscall_action_map": dict(_DEFAULT_SYSCALL_ACTION_MAP),
            "tactic_technique_map": dict(_DEFAULT_TACTIC_TECHNIQUE_MAP),
        }
        return _CVE_MAP_CACHE
    raw = json.loads(map_path.read_text(encoding="utf-8"))
    # Handle both flat and nested (per-dataset) layouts
    if "syscall_action_map" not in raw:
        raw["syscall_action_map"] = _DEFAULT_SYSCALL_ACTION_MAP
    if "tactic_technique_map" not in raw:
        raw["tactic_technique_map"] = _DEFAULT_TACTIC_TECHNIQUE_MAP
    if "mappings" not in raw:
        # Maybe nested under a dataset key — try to find first dict with "mappings"
        for v in raw.values():
            if isinstance(v, dict) and "mappings" in v:
                raw["mappings"] = v["mappings"]
                break
        else:
            raw["mappings"] = {}
    _CVE_MAP_CACHE = raw
    return _CVE_MAP_CACHE


# ---------------------------------------------------------------------------
# 2. Event reader
# ---------------------------------------------------------------------------

def read_provsec_events(input_path: Path, *, max_events: int = 5000) -> dict[str, Any]:
    """Read ProvSec JSON and return normalized event payload.

    The JSON has top-level metadata fields + ``events`` + ``ground_truth``.
    """
    payload = json.loads(input_path.read_text(encoding="utf-8"))
    all_events = list(payload.get("events") or [])[:max_events]

    # ProvSec events lack pre-normalized relation/subject/object, so we
    # cannot reuse ``audit_raw_events`` directly.  Keep everything that has
    # an ``event_id`` and drop the rest.
    kept: list[dict[str, Any]] = []
    dropped: dict[str, int] = {}
    for evt in all_events:
        if not evt.get("event_id"):
            dropped["missing_event_id"] = dropped.get("missing_event_id", 0) + 1
            continue
        kept.append(evt)

    # Extract metadata from top-level keys (everything except events/ground_truth)
    meta_keys = {"events", "ground_truth"}
    metadata = {k: v for k, v in payload.items() if k not in meta_keys}

    return {
        "metadata": metadata,
        "events": kept,
        "events_raw_count": len(all_events),
        "dropped_events": dropped,
        "ground_truth": payload.get("ground_truth") or {},
    }


# ---------------------------------------------------------------------------
# 3. Syscall aggregation
# ---------------------------------------------------------------------------

def _parse_net_addr(addr: str) -> dict[str, Any]:
    """Parse ``src:port->dst:port`` into a network object dict."""
    if not addr or "->" not in addr:
        return {"type": "network", "ip": "0.0.0.0", "port": 0}
    dst_part = addr.split("->", 1)[1]
    # Handle host:port or just host
    if ":" in dst_part:
        ip, _, port_str = dst_part.rpartition(":")
        try:
            port = int(port_str)
        except ValueError:
            port = 0
    else:
        ip = dst_part
        port = 0
    return {"type": "network", "ip": ip, "port": port}


def _resolve_relation(evt_type: str, evt_args: str) -> str:
    """Map ProvSec ``evt.type`` to a LOCK-compatible relation."""
    # open/openat: check args for write intent
    if evt_type in ("open", "openat"):
        args_lower = (evt_args or "").lower()
        if any(flag in args_lower for flag in ("o_wronly", "o_rdwr", "o_creat", "o_append", "write")):
            return "file_write"
        return "file_read"
    return _SYSCALL_RELATION_MAP.get(evt_type, "process_spawn")


def _attack_stage_technique(
    relation: str,
    event_index: int,
    attack_stages: dict[str, dict[str, str]],
) -> tuple[str, str]:
    """Pick technique/tactic for an attack event based on position in chain."""
    stages = attack_stages or {}
    if event_index == 0 and "initial" in stages:
        s = stages["initial"]
        return s["tactic"], s["technique_id"]
    if relation == "network_connect" and "execution" in stages:
        # C2 / network exploitation stage
        s = stages.get("execution", stages.get("initial", {}))
        return s.get("tactic", "command-and-control"), s.get("technique_id", "T1071.001")
    if relation in ("execve", "process_spawn"):
        if "execution" in stages:
            s = stages["execution"]
            return s["tactic"], s["technique_id"]
    if relation in ("file_write", "file_read") and "exfiltration" in stages:
        s = stages["exfiltration"]
        return s["tactic"], s["technique_id"]
    # Fallback: use initial stage
    if "initial" in stages:
        s = stages["initial"]
        return s["tactic"], s["technique_id"]
    return "execution", "T1059"


def _get_technique_for_attack_event(
    evt: dict,
    attack_stages: dict[str, dict[str, str]],
    attack_indices: dict[str, int],
) -> tuple[str, str]:
    """Resolve technique/tactic for an attack event.

    Convenience wrapper around ``_attack_stage_technique`` that extracts
    ``relation`` and ``event_index`` from the event dict.
    """
    relation = evt.get("relation", "process_spawn")
    idx = attack_indices.get(evt["event_id"], 0)
    return _attack_stage_technique(relation, idx, attack_stages)


def _benign_technique(relation: str, ttm: dict[str, dict[str, str]]) -> tuple[str, str]:
    """Pick technique/tactic for a benign event from tactic_technique_map."""
    key = _RELATION_TO_TTM_KEY.get(relation, "unknown")
    entry = ttm.get(key, ttm.get("unknown", {}))
    return entry.get("tactic", "unknown"), entry.get("technique_id", "T0000")


def aggregate_syscalls(events: list[dict], *, cve_map: dict) -> list[dict]:
    """Transform ProvSec syscall events into security-level super-events.

    Performs two phases:
    1. Map every raw syscall to a DARPA-TC-compatible intermediate event.
    2. Deduplicate by ``(proc.pid, relation, fd.name|net.addr)`` — collapsing
       repeated reads/writes to the same file (or same network destination)
       from the same process into a single super-event.

    Process lifecycle events (execve/clone/fork) are never merged; instead
    the latest execve/clone per PID is tracked and injected as
    ``parent_event_id`` on subsequent file/network super-events.

    Output events are compatible with DARPA TC event format consumed by
    ``normalize_darpa_tc_world_graph()``.
    """
    syscall_action_map = cve_map.get("syscall_action_map") or {}
    ttm = cve_map.get("tactic_technique_map") or {}
    mappings = cve_map.get("mappings") or {}

    # Detect which CVE case from the first event or metadata — use all
    # attack_stages across mappings as a union (best-effort).
    # Build a merged attack_stages lookup.
    merged_stages: dict[str, dict[str, str]] = {}
    for case_info in mappings.values():
        for stage_name, stage_info in (case_info.get("attack_stages") or {}).items():
            if stage_name not in merged_stages:
                merged_stages[stage_name] = stage_info

    # Count attack events for positional heuristic
    attack_indices: dict[str, int] = {}
    attack_counter = 0
    for evt in events:
        if evt.get("role") == "attack":
            attack_indices[evt["event_id"]] = attack_counter
            attack_counter += 1

    # ------------------------------------------------------------------
    # Phase 1: 1-to-1 syscall → intermediate event transformation
    # ------------------------------------------------------------------
    intermediate: list[dict[str, Any]] = []
    for evt in events:
        evt_type = str(evt.get("evt.type") or "")
        evt_args = str(evt.get("evt.args") or "")
        role = str(evt.get("role") or "benign")
        host = str(evt.get("host") or evt.get("default_host") or "provsec-host")
        proc_name = str(evt.get("proc.name") or "unknown")
        proc_pid = evt.get("proc.pid", 0)
        fd_name = str(evt.get("fd.name") or "")
        net_addr = str(evt.get("net.addr") or "")

        relation = _resolve_relation(evt_type, evt_args)
        action = syscall_action_map.get(evt_type, "UNKNOWN")

        # Subject
        subject: dict[str, Any] = {
            "type": "process",
            "name": proc_name,
            "pid": proc_pid,
            "host_id": host,
        }

        # Object based on relation
        if relation in ("process_spawn", "execve"):
            obj: dict[str, Any] = {"type": "process", "name": proc_name, "pid": proc_pid}
        elif relation == "network_connect":
            obj = _parse_net_addr(net_addr)
        elif relation in ("file_read", "file_write"):
            obj = {"type": "file", "path": fd_name}
        else:
            obj = {"type": "process", "name": proc_name, "pid": proc_pid}

        # Technique / tactic
        if role == "attack":
            tactic, technique = _get_technique_for_attack_event(
                {"relation": relation, "event_id": evt["event_id"]},
                merged_stages, attack_indices,
            )
        else:
            tactic, technique = _benign_technique(relation, ttm)

        timestamp = parse_timestamp(evt.get("evt.time"))

        intermediate.append({
            "event_id": evt["event_id"],
            "timestamp": timestamp,
            "relation": relation,
            "role": role,
            "technique": technique,
            "tactic": tactic,
            "subject": subject,
            "object": obj,
            "host_id": host,
            "parent_event_id": evt.get("parent_event_id"),
            "_action": action,
            # Internal bookkeeping stripped before return
            "_pid": proc_pid,
            "_fd_name": fd_name,
            "_net_addr": net_addr,
            "_evt_nums": [evt.get("evt.num")],
        })

    # ------------------------------------------------------------------
    # Phase 2: deduplication-based aggregation
    # ------------------------------------------------------------------
    # Lifecycle relations that must be kept 1:1 (never merged).
    _LIFECYCLE = frozenset({"execve", "process_spawn"})

    lifecycle_events: list[dict[str, Any]] = []
    # latest_lifecycle[pid] = event_id of most recent execve/clone
    latest_lifecycle: dict[int, str] = {}
    # dedup key → first intermediate event dict
    dedup: dict[tuple, dict[str, Any]] = {}
    key_order: list[tuple] = []

    for ie in intermediate:
        rel = ie["relation"]
        pid = ie["_pid"]

        if rel in _LIFECYCLE:
            lifecycle_events.append(ie)
            latest_lifecycle[pid] = ie["event_id"]
            continue

        # Build dedup key: (pid, relation, target)
        if rel == "network_connect":
            target = ie["_net_addr"]
        elif rel in ("file_read", "file_write"):
            target = ie["_fd_name"]
        else:
            # Unknown category — keep 1:1 (use event_id as unique key)
            target = ie["event_id"]

        key = (pid, rel, target)
        if key in dedup:
            # Merge into existing: upgrade role to attack, accumulate evt.nums
            existing = dedup[key]
            if ie["role"] == "attack":
                existing["role"] = "attack"
            existing["_evt_nums"].extend(ie["_evt_nums"])
        else:
            dedup[key] = ie
            key_order.append(key)

    # Build aggregated list: lifecycle events + deduplicated super-events
    aggregated: list[dict[str, Any]] = []

    for ie in lifecycle_events:
        ie.pop("_pid", None)
        ie.pop("_fd_name", None)
        ie.pop("_net_addr", None)
        ie.pop("_evt_nums", None)
        aggregated.append(ie)

    for key in key_order:
        ie = dedup[key]
        pid = key[0]
        # Inject parent_event_id from latest lifecycle event for this PID
        if not ie.get("parent_event_id") and pid in latest_lifecycle:
            ie["parent_event_id"] = latest_lifecycle[pid]
        ie.pop("_pid", None)
        ie.pop("_fd_name", None)
        ie.pop("_net_addr", None)
        ie.pop("_evt_nums", None)
        aggregated.append(ie)

    # Return in timestamp order
    aggregated.sort(key=lambda e: e["timestamp"])
    return aggregated


# ---------------------------------------------------------------------------
# 4. World graph normalization
# ---------------------------------------------------------------------------

def normalize_provsec_world_graph(
    raw: dict[str, Any],
    *,
    case_id: str = "provsec_case_05",
    cve_map: dict | None = None,
) -> dict[str, Any]:
    """Aggregate ProvSec syscalls then build world_graph via DARPA TC normalizer."""
    if cve_map is None:
        cve_map = load_cve_map()

    aggregated = aggregate_syscalls(raw.get("events") or [], cve_map=cve_map)
    # Build a pseudo-raw payload compatible with normalize_darpa_tc_world_graph
    pseudo_raw: dict[str, Any] = {"events": aggregated}
    default_host = str(
        (raw.get("metadata") or {}).get("default_host")
        or (raw.get("metadata") or {}).get("host")
        or "provsec-host"
    )
    return normalize_darpa_tc_world_graph(
        pseudo_raw,
        performer="provsec",
        default_host=default_host,
    )


# ---------------------------------------------------------------------------
# 5. Ground truth builder
# ---------------------------------------------------------------------------

def build_provsec_ground_truth(
    raw: dict[str, Any],
    world_graph: dict[str, Any],
) -> dict[str, Any]:
    """Extract ProvSec ground_truth and build the subgraph via shared helper."""
    gt_raw = raw.get("ground_truth") or {}
    # Ensure required keys exist for build_ground_truth_subgraph
    gt_normalized: dict[str, Any] = {
        "entry_event_id": gt_raw.get("entry_event_id"),
        "attack_event_ids": gt_raw.get("attack_event_ids") or [],
        "root_causes": gt_raw.get("root_causes") or [],
        "attack_technique_pairs": gt_raw.get("attack_technique_pairs") or [],
        "category": gt_raw.get("category") or (raw.get("metadata") or {}).get("category"),
    }
    # Pass through optional B2.5-lite keys
    for key in (
        "benign_technique_pairs",
        "oos_technique_pairs",
        "attack_node_ids",
        "attack_edge_ids",
        "attack_hosts",
        "oos_hosts",
        "cross_host_attack_edges",
        "lateral_movement_pairs",
        "network_pivot_pairs",
        "benign_cross_host_pairs",
        "anomaly_score",
    ):
        if gt_raw.get(key) is not None:
            gt_normalized[key] = gt_raw[key]

    return build_ground_truth_subgraph(world_graph, gt_normalized)


# ---------------------------------------------------------------------------
# 6. Main entry point
# ---------------------------------------------------------------------------

def load_provsec_graph_fixture(config: ProvenanceAdapterConfig) -> dict[str, Any]:
    """Load ProvSec data → normalize → assemble complete graph fixture."""
    raw = read_provsec_events(config.input_path, max_events=config.max_events)
    cve_map = load_cve_map()
    gt_raw = merged_ground_truth(raw, config.ground_truth_path)

    # Aggregate syscalls once and reuse for both normalization and stats.
    aggregated = aggregate_syscalls(raw.get("events") or [], cve_map=cve_map)

    # Build pseudo_raw directly from aggregated events — bypass
    # normalize_provsec_world_graph (which would aggregate again).
    default_host = str(
        (raw.get("metadata") or {}).get("default_host")
        or (raw.get("metadata") or {}).get("host")
        or "provsec-host"
    )
    world_graph = normalize_darpa_tc_world_graph(
        {"events": aggregated}, performer="provsec", default_host=default_host,
    )

    # Pass aggregated events (which carry `relation`) so stats are accurate.
    norm_stats = collect_normalization_stats(
        {"events": aggregated, "metadata": raw.get("metadata")},
        world_graph,
        dropped=raw.get("dropped_events"),
        source="provsec",
    )

    return assemble_graph_fixture(
        config=config,
        raw=raw,
        gt_raw=gt_raw,
        world_graph=world_graph,
        norm_stats=norm_stats,
        source="provsec",
        performer="provsec",
        title_prefix="ProvSec",
    )
