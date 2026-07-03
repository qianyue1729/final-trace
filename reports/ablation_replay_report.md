# Prior Ablation Sanity Report

Fixtures: 80

## Prior / explanation metrics

| variant | expl_count | entropy | norm_entropy | max_prior | top_k | log_src |
|---------|------------|---------|--------------|-----------|-------|---------|
| full | 3.85 | 1.3369 | 0.9997 | 0.2777 | 1.0 | 1.0 |
| no_flow | 1.95 | 0.658 | 0.9492 | 0.5401 | 0.4 | 1.0 |
| no_sigma | 3.85 | 1.3369 | 0.9997 | 0.2777 | 1.0 | 0.75 |
| no_dual_use | 2.8875 | 1.049 | 0.9871 | 0.3684 | 1.0 | 1.0 |
| no_lifecycle | 2.8625 | 1.032 | 0.9624 | 0.3731 | 0.9 | 1.0 |

## Sigma-specific Visibility / Probe Metrics

| variant | log_source_hit | probe_hit | visibility_gap | evidence_debt | sigma_trace | mean_rec_count |
|---------|---------------:|----------:|---------------:|--------------:|------------:|---------------:|
| full | 1.0 | 1.0 | 0.833 | 1.0 | 0.875 | 2.388 |
| no_sigma | 0.738 | 0.7 | 0.4 | 0.375 | 0.0 | 1.087 |

no_sigma 对 max_prior / entropy 影响弱是**预期行为**（Sigma 不进入因果主权重）；no_sigma 显著削弱 visibility / probe / passport 层能力。

> 消融验证了语义防火墙：移除 Sigma 不会显著改变因果先验分布，但会明显降低 log source 命中、可见性缺口识别和 Sigma trace 覆盖率——Sigma 的价值在可观测性与探针规划，不在因果主权重。

**Formal principle:** Sigma contribution is evaluated only on visibility/probe/passport metrics, not on causal prior metrics (`sigma_visibility_delta_gate`: 2/3 meaningful deltas).

**sigma_visibility_delta_gate:** PASS (3/3 deltas meaningful; details: {'log_source_hit_rate': 0.262, 'visibility_gap_detection_rate': 0.433, 'sigma_trace_presence_rate': 0.875})

**mean_rec_count note:** mean_recommended_log_source_count reflects increased visibility coverage, not precision; probe precision deferred until labeled probe ground truth

**log_source_hit note:** log_source_hit_rate on synthetic fixtures is visibility behavior suite pass rate, not real SOC log-source recommendation accuracy, when expectations are derived_from_prior_recommendation

### By visibility_annotation_source (full mode)

- `derived_from_prior_recommendation` (n=72): log_source_hit=1.0, probe_hit=1.0
- `manual_gap_design` (n=8): log_source_hit=1.0, probe_hit=1.0

## Probe Ground Truth Metrics (P3)

| variant | source_hit | must_not_ok | cost_weighted | coverage@k | noise |
|---------|----------:|------------:|--------------:|---------:|------:|
| full | 1.0 | 1.0 | 1.0 | 1.0 | 0.142 |
| no_sigma | 0.125 | 0.938 | 0.476 | 0.412 | 0.3 |

**Probe note:** probe metrics on derived_from_visibility_expectation validate behavioral-suite consistency; they do not claim SOC probe accuracy or optimal probe selection

### By probe annotation_source (full mode)

- `derived_from_visibility_expectation` (n=72): probe_source_hit=1.0, must_not_ok=1.0
- `manual_expected` (n=8): probe_source_hit=1.0, must_not_ok=1.0

## Sanity notes

- no_flow: candidate collapse — fewer explanations; check normalized_entropy not raw entropy