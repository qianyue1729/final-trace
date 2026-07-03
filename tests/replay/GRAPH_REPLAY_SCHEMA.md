# Graph Replay Case Schema (B0)

L1 graph replay fixtures live under `tests/replay/graph/`. They extend the labeled replay schema with three **required** blocks for end-to-end LOCK evaluation.

## Required fields (graph replay)

```json
{
  "case_id": "graph_toy_powershell_chain",
  "schema_version": "graph_replay_v1",
  "entry_alert": {
    "event_id": "e_execution",
    "technique_id": "T1059.001",
    "tactic": "execution",
    "platform": "windows",
    "log_source": "process_creation",
    "timestamp": 1735689660.0,
    "anomaly_score": 0.85,
    "attributes": { "host_id": "host-1" }
  },
  "ground_truth_subgraph": {
    "root_causes": ["e_initial", "T1566.001"],
    "attack_nodes": ["e_initial", "e_execution", "e_persist"],
    "attack_edges": [
      ["T1566.001", "T1059.001"],
      "edge_exec_persist"
    ],
    "benign_edges": [["T1059.001", "T1082"]],
    "oos_edges": [["T1105", "T1496"]],
    "attack_event_ids": ["e_initial", "e_execution"],
    "attack_node_ids": ["e_initial", "e_execution"],
    "attack_edge_ids": ["edge_ia_exec"]
  },
  "expected_decision": {
    "action": "contain",
    "allowed_actions": ["contain", "contain_escalate", "escalate", "monitor"],
    "must_include_boundaries": ["edge_ia_exec"],
    "must_exclude_boundaries": ["edge_benign_admin"],
    "counterfactuals": []
  }
}
```

## Supporting fields

| Field | Purpose |
| --- | --- |
| `alert` | Legacy L0 alias; if omitted, copied from `entry_alert` |
| `world_graph` | Hidden ground-truth world: nodes + edges with stable ids |
| `replay_driver` | Deterministic offline executor: `reveal_queue`, `pollute_queue`, `probe_bindings` |
| `replay_config` | `max_rounds`, `fanout_per_round`, `seed`, `root_cause_k` |

### `world_graph`

Coarse GT is acceptable in B0 — technique-level or edge-level ids, not full DARPA event objects.

```json
{
  "nodes": [
    {
      "id": "e_initial",
      "technique": "T1566.001",
      "tactic": "initial-access",
      "timestamp": 1735689600.0,
      "source": "email_log",
      "attributes": { "host_id": "host-1" }
    }
  ],
  "edges": [
    {
      "id": "edge_ia_exec",
      "src": "e_initial",
      "dst": "e_execution",
      "relation": "causes",
      "role": "attack"
    }
  ]
}
```

Edge `role`: `attack` | `benign` | `oos`.

### `replay_driver`

Drives `GraphFixtureExecutor` without DARPA TC ingest:

- **`reveal_queue`**: world node ids revealed in order (one per probe slot per round)
- **`pollute_queue`**: benign/oos distractors revealed after main queue (optional)
- **`probe_bindings`**: optional explicit `(operator, tactic) → reveals[]` overrides

## L1 metrics (B0)

| Metric | Definition |
| --- | --- |
| `root_cause_hit@k` | GT root node recovered in graph OR root technique in top-k explanations |
| `attack_subgraph_recall` | \|recovered ∩ GT attack edge pairs\| / \|GT attack edge pairs\| |
| `boundary_precision` | \|recovered attack edges\| / \|all recovered edges\| |
| `benign_pollution_rate` | \|recovered ∩ GT benign edge pairs\| (count + ratio) |
| `probe_cost_to_decision` | `{probes, rounds}` at stop |
| `decision_accuracy` | normalized decision ∈ `allowed_actions` |

### Optional event-level GT (B2.5-lite)

Technique-pair GT remains the default comparison. Fixtures may also include (report-only):

| Field | Purpose |
| --- | --- |
| `attack_event_ids` | World event ids in attack story |
| `attack_node_ids` | Alias for attack world nodes |
| `attack_edge_ids` | Stable world edge ids |

### C-level multi-host GT (OpTC)

| Field | Purpose |
| --- | --- |
| `attack_hosts` | Hosts legitimately in attack scope |
| `oos_hosts` | Hosts that must not merge into attack story |
| `cross_host_attack_edges` | Cross-host attack technique-pairs |
| `lateral_movement_pairs` | Lateral movement GT pairs |
| `network_pivot_pairs` | Host↔network pivot pairs |
| `benign_cross_host_pairs` | Normal cross-host activity (must not attach) |

C metrics live under `metrics.multihost` (see `optc_multihost_metrics.py`).

## Rules

- Graph fixtures MUST NOT be mixed into L0-only `tests/replay/fixtures/` counts without `schema_version`.
- `label_quality=synthetic` → `evaluation.calibration_eligible` MUST be `false`.
- B0 does **not** claim DARPA TC fidelity — only contract + metric plumbing.
- `_sync_world_edges` backfills **attack-role** edges only; benign/oos distractors must not be auto-wired (pollution metric stays honest).
- GT `attack_edges` / `benign_edges` / `oos_edges` accept **technique-pair arrays** `["T1","T2"]` or world **edge ids** (mixed OK).
- `expected_decision.must_include_technique_pairs` / `must_exclude_technique_pairs` mirror GT pair format.
- Mordor graph cases: `tests/replay/graph/mordor_*.json`; builder at `src/trace_agent/eval/graph_fixture_builder.py`.
- CADETS (B1/B1.5): raw subsets in `tests/replay/data/cadets/cadets_sample_001.json` … `006.json`; adapter `darpa_tc_cadets.py`.
- THEIA (B2.1): raw subsets in `tests/replay/data/theia/theia_sample_*.json`; adapter `darpa_tc_theia.py`.
- TRACE (B2.2): raw subsets in `tests/replay/data/trace/trace_sample_*.json`; adapter `darpa_tc_trace.py`.
- Common (B2.0): `base.py` (`ProvenanceAdapterConfig`, `ProvenanceGraphAdapter`), `darpa_tc_common.py`; normalization stats in `normalization_stats.py`; committed fixtures `tests/replay/graph/darpa_*_sample_*.json`.
- OpTC (C): `optc_corrected.py`; toy `optc_multihost_lateral_toy_001.json`; subset `tests/replay/data/optc/`; C metrics in `optc_multihost_metrics.py`.
