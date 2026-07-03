# Corrected OpTC Multi-Host Adapter (C1)

Small-subset adapter for **Corrected OpTC** provenance → L1 graph replay. Focus: multi-host lateral movement, host↔network pivot, benign enterprise noise, OOS host split.

## Scope (C1)

- **Not** full OpTC dump or multi-day enterprise replay
- **Not** event-level GT hard gate (technique-pair GT remains default)
- **Not** `decision_accuracy` hard gate

## Files

| Path | Role |
| --- | --- |
| `src/trace_agent/eval/adapters/optc_corrected.py` | Adapter (`source=optc_corrected`) |
| `tests/replay/data/optc/optc_sample_001.json` | Raw small subset |
| `tests/replay/graph/optc_sample_001.json` | Committed graph fixture |
| `tests/replay/graph/optc_multihost_lateral_toy_001.json` | C0 OpTC-like toy (no raw adapter) |
| `src/trace_agent/eval/optc_multihost_metrics.py` | C-specific metrics |

## Event extensions (multi-host)

OpTC events extend the common DARPA TC subset with:

- `src_host`, `dst_host`, `edge_scope`, `network_flow_id`
- Relations: `lateral_movement`, `remote_service_create`, `file_share`
- Object type `service` for remote service creation

## Ground truth extensions

`ground_truth_subgraph` may include (optional, report-only unless noted):

```json
{
  "attack_event_ids": [],
  "attack_node_ids": [],
  "attack_edge_ids": [],
  "attack_hosts": ["host-a", "host-b"],
  "oos_hosts": ["host-c"],
  "cross_host_attack_edges": [["T1059.001", "T1021.002"]],
  "lateral_movement_pairs": [["T1021.002", "T1021.002"]],
  "network_pivot_pairs": [["T1059.001", "T1021.002"]],
  "benign_cross_host_pairs": [["T1039", "T1059.001"]]
}
```

## C-specific metrics (`metrics.multihost`)

| Metric | Meaning |
| --- | --- |
| `cross_host_attack_recall` | Cross-host attack technique-pairs recovered / GT |
| `host_pivot_precision` | Recovered cross-host pivots that are true attack |
| `network_pivot_recall` | Network pivot pairs recovered |
| `lateral_movement_recall` | Lateral movement pairs recovered |
| `benign_cross_host_pollution_rate` | Benign cross-host pairs wrongly attached |
| `oos_host_split_accuracy` | OOS hosts kept out of attack scope |
| `hosts_over_attributed` | Hosts in recovered scope but not in GT attack_hosts |

## Hard gates (C0 / C1)

1. Multi-host fixture runs `run_graph_case()` without error
2. Cross-host attack edges representable (`edge_scope`, `network_flow_id`)
3. `benign_cross_host_pollution_rate.count == 0`
4. `hosts_over_attributed.count == 0` (C0 toy)
5. `normalization_stats` present on adapter fixtures
6. `report_markdown` includes OpTC multi-host section

Report-only: recall thresholds, `decision_accuracy`, event-level GT coverage.

## Run tests

```bash
PYTHONPATH=src python -m pytest tests/replay/test_optc_multihost_graph_replay.py tests/replay/test_optc_corrected_adapter.py tests/replay/test_b25_lite_normalization.py -q
```
