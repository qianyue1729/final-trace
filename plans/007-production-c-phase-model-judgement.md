# Plan 007: Wire model-assisted C-phase judgement into production safely

> **Executor instructions**: Preserve rule-only operation and make model modes
> explicit (`off`, `shadow`, `assist`). Do not linearly treat raw model scores
> as calibrated log likelihoods. Update the plan index when done.
>
> **Drift check**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_agent\loop\llm_ingest.py,`
>   src\trace_agent\llm\client.py,`
>   src\trace_agent\agents\orchestrator.py,`
>   src\trace_engine\runner.py,`
>   src\trace_engine\config.py
> ```
>
> Expected:
> `A9EF805D377CDBB735D8F2A43B552B99D60468BF6F7423861C8EF9C95C5D9D22`,
> `F113BDCC222FF9A9CCA1882798DEA0DEF67F7AE67AB0C069AD2220B62B301BA7`,
> `E2E82C69A097440E0CD7277FFCBC7F674DE2BE958531612AD6A5270CDC062D86`,
> `5FD076638163E8AC6407FA49B02F25FA6C96E09040F02AB9887CCB5F565679E7`,
> `557AADEE51902A023096450517EFD3E8B7105AD07DE39272610A4115CBD4D2DF`.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH — model output can affect graph attribution
- **Depends on**: Plans 001 and 003
- **Category**: direction / architecture / security
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

The repository now has bounded graph context, prior hits, three-way boundary
belief, evidence-reference validation, and strict L4 gates. Production still
always constructs rule-only `IngestPipeline`; model ingestion is injected only
by an evaluation monkey patch. The current client also disables TLS
verification, and raw rule/model scores are combined with a fixed 0.6 weight.

## Current state

- Rule-only construction:
  `src/trace_agent/agents/orchestrator.py:210`.
- Evaluation-only monkey patch:
  `src/trace_agent/eval/soar_integration_runner.py:334-344`.
- Fixed model parameters:
  `src/trace_agent/loop/llm_ingest.py:19-33`.
- Linear cross-scale merge:
  `llm_ingest.py:468-475`.
- TLS verification disabled:
  `src/trace_agent/llm/client.py:59`.
- Existing tests use a fake model and cover graph/prior/boundary context:
  `src/trace_agent/tests/test_llm_judgement_context.py`.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| C/model tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_c_phase.py src\trace_agent\tests\test_llm_judgement_context.py -q` | all pass |
| Engine tests | `$env:PYTHONPATH='src'; python -m pytest tests\engine -q` | all pass |
| Full suite | `$env:PYTHONPATH='src'; python -m pytest tests\engine src\trace_agent\tests -q` | all pass |

## Scope

**In scope**

- `src/trace_agent/loop/llm_ingest.py`
- `src/trace_agent/llm/client.py`
- `src/trace_agent/agents/orchestrator.py`
- `src/trace_engine/config.py`
- `src/trace_engine/runner.py`
- service audit/usage reporting
- model judgement tests and example configuration

**Out of scope**

- Model-assisted L planning (Plan 006).
- Alert enrichment (Plan 008).
- Automatic graph writes outside K phase.
- Accepting model probabilities as calibrated confidence.

## Steps

### Step 1: Add production model configuration

Define typed settings for mode, provider/model, endpoint, credential env-var
name, CA bundle, connect/read timeout, retries, per-round/case call and token
budgets, context-node cap, and fallback. Secrets must remain environment or
secret-manager references.

### Step 2: Fix transport security and resource lifecycle

Enable TLS verification by default. Support a configured CA bundle; never use
`verify=False`. Close HTTP clients when investigations/service shut down.
Redact provider errors from user reports while retaining structured internal
audit codes.

### Step 3: Replace monkey patching with dependency injection

Let `InvestigationRunner` construct an ingest strategy through a factory and
pass it into `DecisionOrchestrator`. Modes:

- `off`: existing rules only;
- `shadow`: call model and record result, routing remains rule-only;
- `assist`: validated model judgement may affect L3, L4 remains deterministic.

### Step 4: Stop linearly mixing incompatible scores

Store rule likelihood, model judgement, and prior separately. In shadow mode,
collect labels for a fusion calibrator. Until Plan 003 reports a stable
fusion slice, assist mode may only:

- break explicitly ambiguous rule ties;
- raise PARK/WEAK uncertainty;
- propose benign/OOS review;
- never elevate to automatic ATTACH solely from model output.

### Step 5: Make model allocation risk-based

Batch/share context where safe. Select calls by expected boundary/decision
risk, not event arrival order. Preserve per-case budgets and reserve capacity
for high-impact contested edges.

### Step 6: Add operational telemetry

Record provider/model/prompt schema versions, latency, token/cost, timeout,
parse/rejection, rule/model disagreement, routing delta, and supporting refs.
Never log raw sensitive attributes by default.

### Step 7: Define rollout gates

Require shadow non-inferiority on independent attack/benign/OOS cases,
calibration by slice, prompt-injection tests, deterministic fallback, and
latency/cost SLOs before assist mode.

## Test plan

- Off/shadow/assist behavior.
- TLS default and custom CA.
- Timeout, malformed JSON, unknown refs, provider errors.
- Shadow cannot alter route/graph.
- Assist remains behind deterministic L4 and calibration gates.
- Prompt injection in event strings.
- Token/call budget exhaustion.

## Done criteria

- [x] Production runner can configure all three modes.
- [x] No monkey patch is required.
- [x] TLS verification is enabled.
- [x] Raw cross-scale weighted averaging is removed.
- [x] Shadow audit and deterministic fallback pass.
- [x] Full suite passes.
- [x] Plan index updated.

Implementation result (2026-07-03): C/model/runner target suite `34 passed`;
engine `34 passed`; full engine/core `323 passed`. Production defaults to
`off`; shadow is route-invariant, and assist is limited to evidence-backed
ambiguous-rule tie breaking.

## STOP conditions

- Plan 003 calibrated contract is missing for any proposed probability use.
- Provider data-retention/residency terms are unacceptable for telemetry.
- PII/secret redaction cannot be guaranteed.
- Assist changes routes without valid evidence references.

## Maintenance notes

Model, prompt, context schema, and prior-bundle changes all invalidate shadow
comparisons and fusion calibration. Keep rule-only mode permanently supported.
