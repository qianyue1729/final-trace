# Plan 009: Establish a LOCK runtime parity gate

> **Executor instructions**: Follow this plan step by step. Do not refactor
> runtime code in this plan. This plan creates the characterization boundary
> required by Plans 010-012. Run every verification command and stop on a
> mismatch instead of changing expected values until the mismatch is explained.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88 -- src/trace_agent/agents src/trace_agent/phases `
>   src/trace_engine/runner.py tests
> ```
>
> The plan was written against a dirty worktree. Also compare current SHA-256
> hashes with:
>
> - `src/trace_agent/agents/orchestrator.py`:
>   `8A73685CCF81BDEC912F3348E7A1C2D79026B42527DE51032381A2B7DDF02F21`
> - `src/trace_agent/agents/modular_orchestrator.py`:
>   `2B3583D892DAACD568FCE390D4E257B67FC09EF11CC0CA2EA2678B1EE2840880`
> - `src/trace_engine/runner.py`:
>   `C709594994FED5C32B3A5C6A278FD9E9C0F159EB0B25C281F3F64E1F9D2E3E5E`

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: LOW
- **Depends on**: none
- **Category**: tests / migration
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

Production now runs `ModularOrchestrator`, while most full-loop, replay,
step-by-step, and ablation tests still execute `DecisionOrchestrator`. Without
an explicit parity gate, the project can report good evaluation metrics for a
runtime that production no longer uses.

## Current state

- `src/trace_engine/runner.py:392-417` constructs `LOCKSession` and
  `ModularOrchestrator`.
- `src/trace_agent/tests/test_full_loop.py:1-90` exercises the deprecated
  `DecisionOrchestrator`.
- `src/trace_agent/eval/graph_replay.py:8` and
  `src/trace_agent/eval/lock_step7_full_loop.py:18` import the deprecated path.
- `src/trace_agent/eval/ablation_experiment.py:150` subclasses the deprecated
  orchestrator and overrides phase internals.
- `tests/engine` currently has one known failure:
  `test_full_investigation_pipeline_18` receives the guardrailed action
  `inconclusive`, while the assertion excludes that valid action. Classify this
  mismatch before declaring a clean baseline.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Core tests | `$env:PYTHONPATH='src'; python -m pytest tests\engine src\trace_agent\tests -q` | all pass after the known action contract is resolved |
| Deep Agent tests | `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |
| Replay tests | `$env:PYTHONPATH='src'; python -m pytest tests\replay tests\soar_mcp -q` | all pass |

## Scope

**In scope**

- New characterization tests under `tests/convergence/`
- Test fixtures/helpers required to run old and new runtimes from identical
  alert, scenario, budget, prior, and executor inputs
- The incorrect API assertion if investigation confirms that `inconclusive`
  is the intended guardrail result

**Out of scope**

- Runtime implementation changes
- Deleting or renaming either orchestrator
- Changing thresholds, priors, VOI, obligations, or model prompts

## Steps

### Step 1: Establish a clean test baseline

Run all three commands above. Investigate the `inconclusive` mismatch using the
report's `original_action` and `guardrail_flags`. Either update the assertion
to include the documented guardrail action or fix the guardrail input if the
action is genuinely wrong. Do not weaken guardrails merely to satisfy a test.

**Verify**: all engine/core tests pass with no xfail added.

### Step 2: Build a shared deterministic runtime fixture

Create `tests/convergence/runtime_fixture.py`. It must:

- load one scenario through existing scenario loaders;
- create one alert, prior manager, deterministic executor, and identical
  `BudgetState` values;
- construct the deprecated runtime and modular runtime independently;
- normalize only representation differences, never decision values.

Use the fixture for `pipeline_18`, `apt_5host`, and `multipath_12host`.

**Verify**:

```powershell
$env:PYTHONPATH='src'
python -m pytest tests\convergence -q
```

Expected: fixture smoke tests pass for all three scenarios.

### Step 3: Record semantic parity, not object-shape parity

For both runtimes compare:

- stop reason and rounds/probes used;
- action before and after guardrails;
- leading explanation ID, posterior ordering, margin, and entropy;
- graph node/edge identities and routing bucket counts;
- open/discharged obligations;
- planner and LLM call/audit counts.

If a difference is intentional, encode it in a named allowlist entry with a
reason and removal issue. Unnamed differences fail the test.

**Verify**: `python -m pytest tests\convergence -q` passes with zero unnamed
differences.

### Step 4: Add failure-path characterization

Inject one failing executor and one failing phase executor. Record the intended
contract: a phase failure must surface as an error result and must not become a
successful `no_probes` investigation.

**Verify**: failure-path tests fail against the current masking behavior and
are marked as the explicit prerequisite for Plan 011, not silently skipped.

## Test plan

- Three scenario parity cases.
- Budget exhaustion, no probes, robust stop, and incomplete obligations.
- LLM off and fake-model shadow modes.
- Phase exception and executor exception.
- No real network or production Wazuh calls.

## Done criteria

- [ ] Full engine/core, replay/SOAR, and Deep Agent suites have a recorded clean baseline.
- [ ] `tests/convergence/` compares both runtimes on three scenarios.
- [ ] Every semantic difference is either fixed or named with rationale.
- [ ] Failure masking is captured by a regression test for Plan 011.
- [ ] No runtime source file changed.

## STOP conditions

- Either runtime needs production credentials or real network access.
- The same fixture cannot construct both runtimes without changing domain data.
- More than five unexplained semantic differences appear; report them before
  broadening the allowlist.

## Maintenance notes

Keep this parity suite until Plan 012 deletes the deprecated implementation.
After deletion, convert it into golden contract tests for the modular runtime.
