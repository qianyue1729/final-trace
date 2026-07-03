# Plan 003: Introduce a calibrated decision and confidence contract

> **Executor instructions**: Do not rename an uncalibrated score to
> `confidence`. Automatic-action gates must fail closed when calibration is
> unavailable. Update the plan index when done.
>
> **Drift check**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_agent\decision\types.py,`
>   src\trace_agent\agents\orchestrator.py,`
>   src\trace_engine\runner.py
> ```
>
> Expected:
> `7DE2D467FBA64D56911D50729DDC2E65785956FC452FB9675A60123C6FF39DBC`,
> `E2E82C69A097440E0CD7277FFCBC7F674DE2BE958531612AD6A5270CDC062D86`,
> `5FD076638163E8AC6407FA49B02F25FA6C96E09040F02AB9887CCB5F565679E7`.

## Status

- **Priority**: P0
- **Effort**: L
- **Risk**: HIGH — changes public decision semantics and automation gates
- **Depends on**: Plan 001
- **Category**: architecture / tests
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

The code correctly labels priors as uncalibrated but later treats normalized
ledger scores as probabilities, applies fixed 0.7 action thresholds, and emits
`margin + 0.5` as confidence. Production consumers may interpret that value as
a validated probability and automate containment incorrectly.

## Current state

- `Explanation.probability_status` defaults to `uncalibrated` in
  `src/trace_agent/decision/types.py:40`.
- `_build_result()` selects contain/dismiss at fixed 0.7 posterior mass and
  derives confidence from margin at
  `src/trace_agent/agents/orchestrator.py:987-999`.
- Boundary include/prune also uses fixed 0.7.
- Engine reports expose that value as `decision.confidence`.
- Deployment documentation already admits that ECE calibration is absent.

The required vocabulary is:

- `investigation_score`: relative ranking quantity, never a probability.
- `calibrated_probability`: nullable probability from a versioned calibrator.
- `confidence_status`: `unavailable | experimental | stable | stale`.
- `automation_eligible`: explicit boolean with reason codes.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| Decision tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_runtime_ledger.py src\trace_agent\tests\test_full_loop.py tests\engine\test_api_e2e.py -q` | all pass |
| Full baseline | `$env:PYTHONPATH='src'; python -m pytest tests\engine src\trace_agent\tests -q` | all pass |

## Scope

**In scope**

- `src/trace_agent/decision/types.py`
- `src/trace_agent/decision/runtime_types.py`
- `src/trace_agent/agents/orchestrator.py`
- `src/trace_agent/eval/calibration.py`
- `src/trace_agent/eval/silver_gate.py`
- `src/trace_engine/runner.py`
- `src/trace_engine/service/app.py`
- `src/trace_engine/config.py`
- associated tests and deployment response documentation

**Out of scope**

- Training a production calibrator without independent labels.
- Using LLM self-confidence.
- Changing loss policy by tenant before the contract exists.

## Steps

### Step 1: Split score, probability, and decision policy

Replace scalar `confidence` internals with a typed object carrying
investigation score, nullable calibrated probability, status, calibrator
version, sample count/slice, and automation eligibility. Keep a temporary
response compatibility field only if it is explicitly nullable and documented.

**Verify**: schema tests reject a numeric calibrated probability when status is
`unavailable`.

### Step 2: Add a calibrator interface and artifact contract

Define a read-only calibrator that consumes leakage-free features and returns a
probability plus metadata. Artifacts must include training cutoff, label source,
sample counts, per-slice metrics, and checksum. Loading an absent/stale/invalid
artifact yields `confidence_status=unavailable|stale`, never a fallback number.

**Verify**: unit tests cover valid, missing, corrupt, stale, and wrong-feature
artifacts.

### Step 3: Gate automatic decisions

Make contain/dismiss automation require:

- stable calibrator;
- minimum slice support;
- configured precision/recall target;
- no unresolved hard obligation;
- decision robust under calibrated interval;
- no telemetry truncation from Plan 002.

Otherwise return the recommended action as advisory with
`automation_eligible=false`.

**Verify**: no-calibrator runs cannot produce an automation-eligible action.

### Step 4: Calibrate boundary decisions separately

Do not reuse session calibration for edge include/prune. Add separate boundary
calibration or keep boundary state `contested`. Preserve benign and OOS as
distinct outcomes.

**Verify**: tests demonstrate a stable session decision can coexist with an
uncalibrated edge.

### Step 5: Update reports and compatibility documentation

Expose score/probability/status/interval/reasons. Update examples and clients so
they do not display investigation scores as percentages.

**Verify**: API E2E snapshots contain no misleading numeric confidence.

## Test plan

- Missing/stale/stable calibrator.
- Slice below minimum support.
- Stable session but contested boundary.
- Decision robustness across confidence interval.
- Backward-compatible consumer behavior.

## Done criteria

- [x] No `margin + 0.5` confidence remains.
- [x] Fixed posterior thresholds cannot authorize automated action without a
  stable calibrator.
- [x] Reports distinguish score from probability.
- [x] Calibration metadata is versioned and auditable.
- [x] Full tests pass.
- [x] Plan index updated.

Implementation result (2026-07-03): decision/calibration target suite
`63 passed`; full engine/core `304 passed`. No production artifact was
fabricated, so the default status is `unavailable` and automation fails closed.

## STOP conditions

- No independent labeled data exists for the intended slice: implement the
contract and leave status unavailable; do not fabricate a model.
- A downstream client requires numeric confidence unconditionally: STOP and
  negotiate a versioned API transition.
- Evaluation labels can still enter runtime features.

## Maintenance notes

Recalibration must be triggered by source schema, model, prior bundle, or
tenant-policy changes. Reviewers should reject any future code that equates
normalized posterior mass with calibrated probability.
