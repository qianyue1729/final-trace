# Silver-Solid Release Gate: **BLOCKED**

## Passed

- ✅ build provenance production_eligible
- ✅ flow raw trace index present
- ✅ stix weak support index present
- ✅ 80 synthetic replay fixtures (80)
- ✅ labeled calibration-eligible cases (30)
- ✅ synthetic replay PASS
- ✅ calibration experimental
- ✅ ablation framework (full/no_flow/no_sigma/no_dual_use/no_lifecycle)
- ✅ sigma_visibility_delta_gate PASS
- ✅ ablation sanity warnings (2)

## Blockers

- ❌ calibration_eligible labeled cases 30 < 80 (stable threshold)
- ❌ labeled set entirely weak_label — insufficient for stable calibration claims
- ❌ calibration not stable (experimental)

## Warnings (expected ablation behavior)

- ⚠️ no_flow: candidate collapse (expl_count down) — check normalized_entropy, not raw entropy
- ⚠️ no_flow: max_prior rose — softmax on fewer H; investigate over-concentration
- ⚠️ Sigma visibility metrics use synthetic derived expected_log_sources — suite pass rate, not SOC accuracy; probe precision awaits labeled probe ground truth
- ⚠️ family_level_hit_rate=1.0 on weak-label set — coarse family labels; not a generalization claim
- ⚠️ ECE=0.2982 above informal stable threshold — calibration not production-ready