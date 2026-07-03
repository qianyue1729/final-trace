# Labeled Replay Case Schema (T18)

Each fixture under `tests/replay/fixtures/` SHOULD include:

```json
{
  "case_id": "mordor_powershell_download_001",
  "title": "...",
  "category": "attack-like|benign|ambiguous|telemetry-gap|adversarial",
  "source": "mordor|optc|darpa|synthetic|manual",
  "label_quality": "ground_truth|analyst_labeled|weak_label|synthetic",
  "alert": { "technique_id": "...", "attributes": { "tenant_profile": {} } },
  "ground_truth": {
    "expected_explanation_family": [],
    "true_boundary": "in_attack|benign|oos|uncertain",
    "benign": false,
    "oos": false,
    "expected_techniques": [],
    "expected_log_sources": []
  },
  "expected_behavior": {},
  "evaluation": {
    "calibration_eligible": false,
    "top_k_should_include": []
  }
}
```

## Graph replay extensions (B0 / L1)

Graph replay cases (`tests/replay/graph/`, see `GRAPH_REPLAY_SCHEMA.md`) add three fields on top of the labeled schema:

```json
{
  "schema_version": "graph_replay_v1",
  "entry_alert": {
    "event_id": "e_terminal_alert",
    "technique_id": "T1059.001",
    "tactic": "execution",
    "platform": "windows",
    "log_source": "process_creation",
    "timestamp": 1735689660.0,
    "attributes": { "host_id": "host-1" }
  },
  "ground_truth_subgraph": {
    "root_causes": ["e_initial_access"],
    "attack_nodes": ["e_initial_access", "e_execution"],
    "attack_edges": ["edge_ia_to_exec"],
    "benign_edges": ["edge_benign_admin"],
    "oos_edges": []
  },
  "expected_decision": {
    "action": "contain",
    "allowed_actions": ["contain", "contain_escalate", "monitor"],
    "must_include_boundaries": ["edge_ia_to_exec"],
    "must_exclude_boundaries": ["edge_benign_admin"],
    "counterfactuals": []
  }
}
```

- `entry_alert` — LOCK session entry (may duplicate `alert` for L0 compatibility).
- `ground_truth_subgraph` — coarse GT for subgraph/boundary metrics; event-level perfection not required in B0.
- `expected_decision` — disposition contract; `action` is the preferred label, `allowed_actions` defines pass set.

Rules:
- `label_quality=synthetic` → `evaluation.calibration_eligible` MUST be `false`
- Brier/ECE only runs when `calibration_eligible=true` AND `label_quality != synthetic` AND count ≥ 30
- Legacy `expect` key remains supported as alias of `expected_behavior`
- `evaluation.visibility_annotation_source`: `manual_gap_design` | `derived_from_prior_recommendation` | `manual_expected` — documents how visibility expectations were set (derived ≠ independent SOC ground truth)
