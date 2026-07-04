# Plan 010: Create one investigation lifecycle and report path

> **Executor instructions**: Make `trace_engine` the application layer that
> prepares investigations and builds reports. Deep Agent tools must adapt this
> API, not copy it. Preserve all public report fields.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88 -- src/trace_engine/runner.py `
>   deep-agent-backend/src/trace_deep_agent/phase_tools.py
> ```

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: MED
- **Depends on**: Plan 009
- **Category**: bug / tech-debt
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

`InvestigationRunner._run_inner` and Deep Agent
`_init_session_from_runner` independently implement enrichment, executor
creation, availability checks, time alignment, bootstrap, prior/seed creation,
budget creation, session construction, and orchestrator construction. Their
report builders have already diverged: the Deep Agent discards the actual
`InvestigationResult` and rebuilds it with `stop_reason="completed"`.

## Current state

- Canonical-looking path: `src/trace_engine/runner.py:334-445`.
- Duplicated path: `deep-agent-backend/src/trace_deep_agent/phase_tools.py:169-285`.
- Deep Agent calls `ctx.orch.run(...)` at `phase_tools.py:775`, stores the
  result, but `_build_report_from_session` reconstructs another result with
  `orch._build_result(stop_reason="completed")` at `phase_tools.py:305-306`.
- Runner report assembly is `src/trace_engine/runner.py:448-548`; a second copy
  is `phase_tools.py:292-384`.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Engine tests | `$env:PYTHONPATH='src'; python -m pytest tests\engine -q` | all pass |
| Deep Agent tests | `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |
| Convergence tests | `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest tests\convergence -q` | all pass |

## Scope

**In scope**

- `src/trace_engine/runner.py`
- New application DTO/module under `src/trace_engine/`, if needed
- `deep-agent-backend/src/trace_deep_agent/phase_tools.py`
- Focused tests in `tests/engine/`, `tests/convergence/`, and
  `deep-agent-backend/tests/`

**Out of scope**

- Phase algorithms and decision thresholds
- Progress-event schema changes
- Deprecated orchestrator deletion
- Frontend changes

## Steps

### Step 1: Introduce a prepared-investigation DTO

Add a typed application DTO, for example `PreparedInvestigation`, containing
the alert, executor, scenario data, enrichment, bootstrap stats, `LOCKSession`,
and `ModularOrchestrator`. Add a public `InvestigationRunner.prepare(...)`
method that owns the current `_run_inner` setup sequence.

`InvestigationRunner.run()` must call `prepare()` and then run the returned
orchestrator. Do not leave a second setup implementation in `_run_inner`.

**Verify**: existing runner tests pass unchanged.

### Step 2: Make report construction a public application service

Move report assembly behind one method accepting:

- the prepared investigation;
- the exact `InvestigationResult` returned by `run()`;
- elapsed time.

The method must preserve enrichment, trace coverage, GT evaluation for scenario
mode, demo profile, decision ledger, usage, model audit, and guardrails.

**Verify**: report snapshots from the pre-refactor runner and new builder are
equal after removing elapsed time.

### Step 3: Replace Deep Agent setup and report copies

Change `init_investigation` to call `runner.prepare(...)`. Store the prepared
object or its fields in `SessionContext`. Delete
`_init_session_from_runner` setup logic and `_build_report_from_session`
assembly logic; thin wrappers are acceptable only if they delegate.

Change `run_full_loop` to pass the actual result returned at `phase_tools.py:775`
to the canonical report builder. Stop reason must be `budget`, `no_probes`,
`robust`, etc., never the synthetic value `completed`.

**Verify**: a budget-exhausted Deep Agent test reports `stop_reason="budget"`
and `incomplete` matches the direct runner.

### Step 4: Centralize cleanup

Give the prepared DTO/context one idempotent `close()` path that closes
orchestrator, planner, ingest client, executor/transport where owned, and any
future resources. Use `finally` in runner and every Deep Agent terminal path.

**Verify**: fake resources record exactly one close call on success, provider
failure, force stop, and explicit close.

## Test plan

- Direct runner and Deep Agent full-loop reports are equivalent.
- Actual stop reason is retained.
- Scenario GT exists only in scenario mode.
- Bootstrap/enrichment metadata survives.
- Cleanup executes once on every exit path.

## Done criteria

- [ ] One setup implementation remains.
- [ ] One report implementation remains.
- [ ] `_build_result(stop_reason="completed")` has no Deep Agent call site.
- [ ] Direct and Deep Agent reports are contract-equivalent.
- [ ] All verification commands pass.

## STOP conditions

- A public report field must be removed or renamed.
- Deep Agent requires setup behavior that cannot be represented in the
  application DTO without importing Deep Agent packages into `trace_engine`.
- Plan 009 reports unexplained semantic differences in setup behavior.

## Maintenance notes

Dependency direction must remain:
`deep-agent-backend -> trace_engine -> trace_agent`. Never import Deep Agent
types into engine/core.
