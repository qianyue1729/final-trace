# Plan 012: Retire the deprecated monolithic orchestrator

> **Executor instructions**: Migrate every internal consumer to the modular
> runtime, preserve evaluation semantics through Plan 009's parity gate, then
> delete the second implementation. Do not keep copied algorithms in a
> compatibility class.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88 -- src/trace_agent/agents/orchestrator.py `
>   src/trace_agent/eval src/trace_agent/tests tests
> ```

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Depends on**: Plans 009, 010, 011
- **Category**: migration / tech-debt
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

The deprecated orchestrator remains roughly two thousand lines and is still
the runtime for full-loop tests, graph replay, step evaluations, integration
evaluation, demo-specific tests, and ablation. Every phase algorithm therefore
exists twice and can drift independently from production.

## Current state

- Deprecated implementation:
  `src/trace_agent/agents/orchestrator.py:106` (`DecisionOrchestrator`).
- New implementation:
  `src/trace_agent/agents/modular_orchestrator.py:41`.
- Public package root still exports the deprecated API:
  `src/trace_agent/__init__.py:21,168-170`.
- Internal deprecated imports remain in:
  - `src/trace_agent/eval/graph_replay.py`
  - `src/trace_agent/eval/lock_step1_bootstrap.py`
  - `src/trace_agent/eval/lock_step2_l_phase.py`
  - `src/trace_agent/eval/lock_step7_full_loop.py`
  - `src/trace_agent/eval/soar_integration_runner.py`
  - `src/trace_agent/eval/ablation_experiment.py`
  - `src/trace_agent/tests/test_full_loop.py`
  - `src/trace_agent/tests/test_model_probe_planner.py`
  - `tests/engine/test_orchestrator_demo.py`
- `AblationOrchestrator` subclasses and overrides old private phase methods at
  `src/trace_agent/eval/ablation_experiment.py:150-447`.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| All Python | `$env:PYTHONPATH='src'; python -m pytest tests src\trace_agent\tests -q` | all pass |
| Deep Agent | `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |
| Import scan | `rg -n "DecisionOrchestrator|agents\\.orchestrator" src tests deep-agent-backend scripts` | no runtime/test imports; only migration note if retained |

## Scope

**In scope**

- Shared result/budget contracts under `src/trace_agent/agents/`
- All internal imports and tests listed above
- Modular equivalents for replay, step evaluation, and ablation
- Deletion or replacement of `agents/orchestrator.py`
- Package exports and architecture docs

**Out of scope**

- Changing evaluation formulas or GT labels
- Changing phase algorithms
- Model prompt/config changes
- Reintroducing the deleted standalone `demo/` backend or UI

## Steps

### Step 1: Extract neutral contracts

Move `InvestigationResult` and any still-shared DTOs out of the deprecated
module into a small neutral module. Keep only one `BudgetState`, the one used
by `LOCKSession`. Update modular runtime and callers.

**Verify**: importing modular runtime does not import the deprecated module.

### Step 2: Migrate tests and evaluation entry points

Convert full-loop tests, graph replay, step evaluators, and integration runner
to construct `LOCKSession` plus `ModularOrchestrator`, preferably through the
canonical application lifecycle from Plan 010.

Preserve Plan 009 normalized outputs. Any changed metric requires a named,
reviewed parity exception.

**Verify**: all non-ablation tests pass and deprecated import count decreases
to the ablation module only.

### Step 3: Replace inheritance-based ablation

Do not subclass `ModularOrchestrator` and override private methods. Represent
ablations as explicit injected components/config:

- null planner / rule ingest;
- minimal trust model;
- disabled obligation/cascade policy;
- alternate O-phase selection policy;
- disabled exploration/adaptive strategy.

Each ablation must use the same state machine and serializers as production.

**Verify**: ablation matrix runs through `ModularOrchestrator` and records
active flags in audit output.

### Step 4: Remove the second implementation

Delete monolithic phase algorithms. If external compatibility is required,
retain a thin deprecated constructor adapter in a clearly named
`legacy_orchestrator.py`; it must delegate to the canonical lifecycle and
contain no L/Veto/O/C/K algorithm.

Update root exports and docs to name `ModularOrchestrator`/application runner.

**Verify**: import scan has no internal consumer and source line count no
longer includes a second phase implementation.

## Test plan

- Plan 009 parity suite becomes modular golden tests.
- All existing full-loop and replay scenarios run modular.
- Every ablation flag changes only its intended component.
- Deprecated import emits warning only if an external adapter is retained.

## Done criteria

- [ ] One implementation exists for each LOCK phase.
- [ ] Production, evaluation, replay, ablation, and tests use modular runtime.
- [ ] `trace_agent` root no longer exports a second algorithm implementation.
- [ ] Deleted standalone demo files remain deleted.
- [ ] All Python and Deep Agent suites pass.

## STOP conditions

- Plan 009 shows an unexplained metric regression.
- An external consumer of the old constructor is identified without a
  deprecation window decision.
- Ablation cannot be expressed without adding a production-facing extension
  point; report the required interface before adding it.

## Maintenance notes

After this plan, prohibit phase logic in eval modules. Evaluations may inject
policies and inspect outputs, but may not fork orchestration code.
