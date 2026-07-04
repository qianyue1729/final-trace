# Plan 011: Make the modular state machine and progress contract authoritative

> **Executor instructions**: Move round transitions, inter-phase data flow,
> and failure semantics into `ModularOrchestrator`. Make progress serialization
> consume the real `PhaseResult` contract and generate frontend types from one
> versioned schema.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88 -- src/trace_agent/agents/modular_orchestrator.py `
>   src/trace_agent/agents/progress_protocol.py src/trace_agent/phases `
>   deep-agent-backend/src/trace_deep_agent/phase_tools.py `
>   deep-agents-ui/src/app/types/types.ts
> ```

## Status

- **Priority**: P0
- **Effort**: L
- **Risk**: MED
- **Depends on**: Plans 009, 010
- **Category**: bug / architecture
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

The full-loop and phase-by-phase modes currently have two state machines:
`ModularOrchestrator.run_one_round` and Deep Agent `_run_single_phase`.
Exceptions are converted into unsuccessful `PhaseResult`s, but callers continue
and can turn a failed L/O phase into a successful `no_probes` conclusion.
Progress DTOs also expect fields that phase executors do not consistently emit.

## Current state

- Full-loop transitions: `modular_orchestrator.py:190-317`.
- Adapter transitions and round increment:
  `phase_tools.py:550-594`.
- Failure masking: `modular_orchestrator.py:348-367` catches every exception,
  while `run_one_round` does not check `result.success`.
- `VetoPhaseExecutor` returns `veto_reasons: list[str]` and
  `surviving_pool` at `src/trace_agent/phases/veto_phase.py:89-95`.
- `build_phase_event` converts `veto_reasons` with `dict(...)` and expects
  `surviving_count`, `mandated_count`, and `obligation_types` in
  `progress_protocol.py:274-279`; the rich event therefore falls back or emits
  empty values.
- `KPhaseExecutor` returns only `stop_decision`, `ledger_snapshot`, and
  `round_diagnostic` at `k_phase.py:246-259`, while `KPhaseEvent` expects full
  explanations, boundary beliefs, beta updates, obligation counts, and graph
  deltas.
- TypeScript duplicates the Python contract manually at
  `deep-agents-ui/src/app/types/types.ts:76-242`.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Core | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests tests\convergence -q` | all pass |
| Backend | `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |
| UI lint | `cd deep-agents-ui; yarn lint` | exit 0 |
| UI build | `cd deep-agents-ui; yarn build` | exit 0 |

## Scope

**In scope**

- `src/trace_agent/agents/modular_orchestrator.py`
- `src/trace_agent/agents/progress_protocol.py`
- `src/trace_agent/phases/*.py`
- `deep-agent-backend/src/trace_deep_agent/phase_tools.py`
- One versioned progress schema and generated TypeScript output
- `deep-agents-ui/src/app/types/types.ts` or a generated replacement

**Out of scope**

- Phase decision algorithms
- Report construction
- Old orchestrator migration
- UI visual redesign

## Steps

### Step 1: Make `run_phase` own all transitions

`ModularOrchestrator.run_phase("L")` must start a new round and increment the
budget exactly once. After every successful phase it must transfer pool,
chosen probes, ingest result, and previous stats itself. The adapter must stop
mutating `session.data`, `session.round`, and `_executed_phases`.

Represent the legal sequence explicitly: `L -> Veto -> O -> C -> K`, then a
new `L`. Reject repeats, skips, and calls after stop.

**Verify**: full-loop and five manual phase calls produce identical snapshots.

### Step 2: Fail closed on phase errors

Introduce one typed phase execution error/result contract. A failed phase must:

- emit an error progress event;
- preserve the failing phase and structured reason code;
- stop the round/investigation;
- never become `no_probes`, `completed`, or a normal K decision.

Do not expose raw provider exceptions in user-facing output.

**Verify**: the failure tests from Plan 009 pass without xfail.

### Step 3: Align every `PhaseResult.data` contract

For each phase, define the exact serialized fields once. Either emit the
current progress fields from the executor or derive them from session in one
serializer. Remove fallback serialization that silently drops rich data.

At minimum fix Veto reason/count shapes and K ledger/graph/obligation fields.

**Verify**: contract tests instantiate each phase event and assert all required
keys and JSON-serializable values.

### Step 4: Generate the frontend contract

Create a versioned schema under a neutral `contracts/` directory. Generate the
TypeScript discriminated union consumed by `useChat`/`useLOCKState`; do not
maintain a second handwritten field list. Add a check command that fails when
generated output is stale.

**Verify**: generation followed by `git diff --exit-code` produces no diff;
UI lint and build pass.

## Test plan

- Legal and illegal phase orders.
- Exactly one round increment per L phase.
- Full-loop/manual equivalence.
- Failure in every phase.
- JSON contract fixtures for L/Veto/O/C/K/stop/round summary.
- Frontend reducer consumes each generated fixture without undefined required
  fields.

## Done criteria

- [ ] One state-transition implementation remains.
- [ ] No adapter writes `session.data` or `_executed_phases`.
- [ ] Failed phases cannot return normal investigation outcomes.
- [ ] Python and TypeScript consume one versioned schema.
- [ ] No progress serialization fallback is triggered in tests.
- [ ] All verification commands pass.

## STOP conditions

- A required UI field cannot be derived without changing a phase algorithm.
- LangGraph custom streaming cannot carry the chosen schema.
- Plan 010 has not removed duplicate session/report construction.

## Maintenance notes

Any future phase field change must update the schema first, regenerate types,
and add/adjust a contract fixture in the same change.
