# Plan 001: Remove evaluation-label leakage from runtime

> **Executor instructions**: Follow each step and run its verification before
> continuing. Do not preserve scenario pass rates by introducing a differently
> named label shortcut. When done, update `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_agent\loop\scenario_executor.py,`
>   src\trace_agent\loop\ingest.py,`
>   src\trace_engine\runner.py
> ```
>
> Expected hashes respectively:
> `5D5C4ECCA4A0E4317C44EA3DE12B12C1493D5E5E11C38A821FA955DCE9D1FD11`,
> `6EADE548AEF1A448575A6054F01CAF008E6C57FD363B9C5F246079CF9CCD801B`,
> `5FD076638163E8AC6407FA49B02F25FA6C96E09040F02AB9887CCB5F565679E7`.
> If they differ, compare the current-state facts below and STOP on semantic
> drift.

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: MED — truthful metrics may fall and tests will need separation
- **Depends on**: none
- **Category**: bug / tests
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

Runtime currently receives the answer key through event IDs and an
`is_attack` attribute. Those labels widen attachment windows, promote parked
events into the graph, and can filter production Wazuh queries to known attack
events. No recall or model comparison is meaningful until runtime and
evaluation labels are physically separated.

## Current state

- `src/trace_agent/loop/scenario_executor.py:389` writes:
  `is_attack = raw_log_ref.startswith("attack:")`.
- `src/trace_agent/loop/ingest.py:28-33` treats the attribute or ID prefix as
  attack truth.
- `src/trace_agent/loop/ingest.py:323-324` grants attack-like events a seven-day
  attachment window.
- `src/trace_agent/loop/ingest.py:650-691` promotes attack-like WEAK/PARK/SPAWN
  events into graph-eligible facts.
- `src/trace_engine/runner.py:111-117` sets `wazuh_attacks_only=True` when a
  production request contains `scenario_id`.
- Evaluation already has an appropriate out-of-band location:
  `InvestigationRunner._eval_ground_truth()` reads scenario ground truth after
  the run.

Design constraint: ground truth may be consumed only by code under
`src/trace_agent/eval/`, engine post-run evaluation, or tests. It must never be
present in events passed to L/O/C/K.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Targeted tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_c_phase.py tests\engine\test_runner_backend.py -q` | all pass |
| Full tests | `$env:PYTHONPATH='src'; python -m pytest tests\engine src\trace_agent\tests -q` | all pass |
| Leakage scan | `rg -n "is_attack_like|startswith\\(\"attack:\"\\)|wazuh_attacks_only=True" src\trace_agent\loop src\trace_engine` | no runtime classification use |

## Scope

**In scope**

- `src/trace_agent/loop/scenario_executor.py`
- `src/trace_agent/loop/ingest.py`
- `src/trace_engine/runner.py`
- `src/trace_engine/normalizer.py` if needed to strip evaluation-only fields
- `src/trace_agent/tests/`
- `tests/engine/`
- scenario/eval tests that must receive GT separately

**Out of scope**

- Changing scenario ground-truth files.
- Tuning thresholds to recover lost recall.
- Enabling an LLM.
- Deleting post-run GT metrics.

## Steps

### Step 1: Establish a no-label runtime contract

Add a test helper that deep-copies scenario events and strips evaluation-only
fields before executor ingestion. Assert that runtime events contain neither
`attributes.is_attack` nor any equivalent answer-key field. IDs may remain for
joinability, but ID prefixes must be opaque to runtime code.

**Verify**: add tests proving identical non-ID evidence with `attack:` and
`noise:` IDs receives identical L0–L4 treatment.

### Step 2: Remove attack-prefix behavior from ScenarioExecutor and Ingest

Delete `is_attack_like()` and every routing, temporal-window, backward-trace,
and promotion branch that consumes GT-like labels. Replace each use with
observable features already computed by the pipeline:

- structural attachment;
- evidence trust;
- rule/model attribution;
- explicit corroboration;
- boundary belief.

Do not add a replacement boolean named `malicious`, `known_attack`, or similar.

**Verify**: `rg` leakage scan returns no runtime classification use.

### Step 3: Stop filtering production queries to labeled attacks

In `_build_executor()`, keep a production `scenario_id` only as incident/case
scope. Never set `wazuh_attacks_only=True` from a request. If the configuration
field remains for controlled fixture debugging, reject it when
`backend=soar_mcp` unless an explicitly named evaluation-only mode is active.

**Verify**: extend `tests/engine/test_runner_backend.py` to assert production
incident scoping leaves `attacks_only=False`.

### Step 4: Keep GT exclusively post-run

Ensure `_eval_ground_truth()` and eval modules join runtime node IDs to GT only
after investigation completion. Add a test that mutating GT labels does not
change graph construction, chosen probes, stop reason, or decision; it may
change only the post-run metrics object.

**Verify**: run full tests and one acceptance scenario twice with alternate GT;
runtime report excluding `ground_truth_eval` must be identical.

## Test plan

- ID-prefix invariance at C phase.
- No `is_attack` field in converted runtime events.
- Production `scenario_id` scopes incident but does not filter attacks.
- GT mutation changes metrics only.
- Existing benign, OOS, backward-provenance, and SPAWN tests remain meaningful
  without answer keys.

## Done criteria

- [x] Runtime code does not branch on ID prefixes or GT labels.
- [x] Production cannot set `attacks_only` through normal investigation input.
- [x] GT mutation invariance test passes.
- [x] Full core/engine tests pass.
- [x] New leakage-free scenario metrics are recorded without tuning.
- [x] `plans/README.md` row 001 is updated.

Implementation result (2026-07-03): core/engine `287 passed`; evidence
lifecycle `3 passed`. Leakage-free `pipeline_18` single-round baseline:
decision `monitor`, GT recall `0.0556`. No thresholds were retuned.

## STOP conditions

- Runtime cannot distinguish required behavior without a label and no
  observable rule/model feature exists; report the missing feature instead of
  recreating GT leakage.
- A third-party production contract truly returns analyst verdict labels mixed
  with telemetry; STOP and design a typed `analyst_verdict` channel with
  provenance rather than treating it as raw evidence.
- In-scope hashes drift semantically.

## Maintenance notes

Reviewers should search future code for attack/noise ID conventions. Evaluation
adapters must keep labels in sidecar structures, never event attributes.
