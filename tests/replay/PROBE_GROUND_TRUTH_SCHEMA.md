# Probe Ground Truth Schema (P3)

Probe metrics evaluate **recommended probe plans**, not causal prior scores. They do **not** claim SOC probe accuracy until expectations are independently labeled.

## Fixture block

```json
{
  "probe_ground_truth": {
    "expected_probe_sources": ["process_creation", "script_execution"],
    "must_not_probe": ["bash_history", "full_disk_scan"],
    "probe_cost_profile": {
      "process_creation": 1,
      "script_execution": 2,
      "network_connection": 2,
      "powershell_log": 2,
      "full_disk_scan": 10
    },
    "expected_probe_outcome": {
      "process_creation": "confirm_parent_lineage",
      "script_execution": "confirm_script_content"
    },
    "label_quality": "synthetic|manual|weak_label|analyst_labeled",
    "annotation_source": "derived_from_visibility_expectation|manual_expected|analyst_labeled"
  }
}
```

## Rules

- `expected_probe_sources` — should appear in top-k recommended probes (default k=3).
- `must_not_probe` — must **not** appear in any recommended probe (low-trust / expensive noise).
- `probe_cost_profile` — optional; enables cost-weighted hit rate (lower cost = higher utility weight).
- `expected_probe_outcome` — documents investigative intent; **not** scored until probe execution exists (P4).
- `annotation_source=derived_from_visibility_expectation` — suite consistency only, not independent SOC ground truth.

## Metrics (replay / ablation)

| Metric | Meaning |
|--------|---------|
| `probe_source_hit_rate` | all `expected_probe_sources` present in top-k |
| `probe_must_not_violation_rate` | any forbidden source recommended |
| `probe_cost_weighted_hit_rate` | weighted recall using `1/cost` |
| `probe_coverage_at_k` | \|expected ∩ top-k\| / \|expected\| |
| `probe_noise_rate` | top-k probes outside expected set |

## What we do **not** claim

```text
Sigma improves probe accuracy          ❌
log_source_hit = SOC recommendation    ❌
derived expectation = independent label  ❌
```

Allowed:

```text
Sigma improves visibility coverage and expected-source recovery in the behavioral suite.
Probe metrics validate internal consistency until analyst_labeled ground truth exists.
```
