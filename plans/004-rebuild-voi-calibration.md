# Plan 004: Rebuild VOI around calibrated outcome and cost models

> **Executor instructions**: Characterize the existing behavior before
> replacing it. Keep Beta responsible only for no-data sensitivity; do not
> count the same sensitivity twice. Update the plan index when done.
>
> **Drift check**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_agent\probe\voi_engine.py,`
>   src\trace_agent\decision\runtime_ledger.py,`
>   src\trace_agent\loop\gen_calibration.py,`
>   src\trace_agent\agents\orchestrator.py
> ```
>
> Expected:
> `3665A5A9A6DC5F3AD0C682BC9671B025AC5CC0AC1D7E64CFCE4D7038BF4D159E`,
> `CF6E8BEF43F04872006789FE138624D3D83FDF33672CB9FC77973C3B3EBD0DE1`,
> `7C5F59BB383792AA26E55B5ECCF0B0D9E3D8EEFFB7FFD52BB19C4EF3128DA3D9`,
> `E2E82C69A097440E0CD7277FFCBC7F674DE2BE958531612AD6A5270CDC062D86`.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH — changes probe ranking and stop behavior
- **Depends on**: Plans 002 and 003
- **Category**: architecture / bug
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

Current VOI appears adaptive but consumes a constant calibration multiplier,
uses sensitivity twice, and applies fixed hypothetical posterior shifts that
ignore the probe, target, explanation, and evidence likelihood. Probe ordering
and stopping therefore lack the stated probabilistic semantics.

## Current state

- `_calib_to_dict()` always returns `{"cost_multiplier": 1.0}` at
  `orchestrator.py:1226-1228`.
- `predict_outcomes()` uses sensitivity for `P(no_data)` and again in
  attributable mass at `voi_engine.py:155-180`.
- `RuntimeDecisionLedger.hypothetical_update()` applies the same
  `+0.5/-0.3/...` shifts to every probe and explanation.
- `GenCalibration.cost()` exists but is not used by O phase.
- Beta and calibration state start fresh per investigation; no tenant/source
  hierarchy exists.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| VOI tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_voi_engine.py src\trace_agent\tests\test_beta_ledger.py src\trace_agent\tests\test_gen_calibration.py -q` | all pass |
| Integration | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py tests\engine -q` | all pass |

## Scope

**In scope**

- `src/trace_agent/probe/voi_engine.py`
- `src/trace_agent/decision/runtime_ledger.py`
- `src/trace_agent/loop/beta_ledger.py`
- `src/trace_agent/loop/gen_calibration.py`
- `src/trace_agent/agents/orchestrator.py`
- a new `src/trace_agent/probe/outcome_model.py`
- persistence/config needed for versioned aggregate priors
- VOI/calibration tests

**Out of scope**

- LLM-generated numeric probabilities.
- Multi-step planning beyond one-step VOI.
- Optimizing thresholds against leaked scenario labels.

## Steps

### Step 1: Add characterization and invariant tests

Test probability normalization, monotonicity with cost, no-data sensitivity,
edge-risk reduction, and probe-specific outcome changes. Add a failing test
showing two materially different probes currently receive identical
hypothetical belief movement.

### Step 2: Define a typed OutcomeModel contract

Input must include probe operator/target type/tactic, tenant/environment slice,
current explanation posterior, structural fit, visibility, and Beta no-data
prior. Output must be `{attributable_by_H, benign, oos, no_data}` with version
and status. Provide a deterministic conservative baseline.

### Step 3: Give Beta one job

Use Beta only to estimate `P(no_data | learning_key, context)` with hierarchical
shrinkage from global → tenant → target type. Conditional outcome mass must come
from the same explanation likelihood family used by ledger updates.

**Verify**: sensitivity appears exactly once in the probability derivation.

### Step 4: Replace fixed hypothetical shifts

`hypothetical_update()` must receive the probe and modeled outcome likelihoods,
then update each explanation and the targeted contested edge. It must not move
every contested edge globally.

### Step 5: Connect measured costs

Feed latency, query count, records scanned, provider cost, and failure rate from
Plan 002 into `GenCalibration`. Use a bounded, versioned cost model in VOI.
Unseen probes shrink to a reasonable global prior rather than a punitive
epsilon floor.

### Step 6: Persist and audit learning state

Store aggregate calibration separately from case evidence, keyed by tenant and
schema/model versions. Add minimum-sample gates and reset/migration behavior.

### Step 7: Revalidate stop decisions

Run leakage-free replay and report probe ranking, cost, risk reduction, and stop
changes. Do not tune to recover old results; investigate deviations.

## Test plan

- Outcome probabilities sum to one.
- Beta affects no-data once.
- Different probes move different explanations/edges.
- Higher measured cost lowers VOI.
- Missing calibration falls back conservatively.
- Version/slice mismatch does not reuse stale statistics.

## Done criteria

- [x] Constant `_calib_to_dict()` is removed.
- [x] Fixed universal hypothetical shifts are removed.
- [x] No sensitivity double counting.
- [x] Probe-specific cost/outcome audit is present.
- [x] Stop tests and full suite pass.
- [x] Plan index updated.

Implementation result (2026-07-03): VOI/Beta/cost suite `74 passed`;
integration `59 passed`; full engine/core `309 passed`. The outcome model is a
deterministic conservative baseline because leakage-free fitting labels are
not yet available.

## STOP conditions

- Leakage-free labels are insufficient to fit a contextual model: ship the
  deterministic baseline and data collection only.
- OutcomeModel and actual ledger update cannot share likelihood semantics.
- Persisted calibration would mix tenants without an explicit policy.

## Maintenance notes

The outcome model is statistical infrastructure, not an LLM prompt. Any new
probe operator requires cost, no-data, and conditional-outcome coverage.
