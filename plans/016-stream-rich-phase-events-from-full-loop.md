# Plan 016: Emit rich lock_phase events from run_full_loop so the fast path also drives the frontend

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/agents/modular_orchestrator.py `
>   deep-agent-backend/src/trace_deep_agent/phase_tools.py `
>   src/trace_agent/agents/progress_protocol.py
> ```
> If any file changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as
> a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/015 (rich events must carry real data first)
- **Category**: bug
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

The Deep Agent exposes two ways to run LOCK: per-phase tools (`run_l_phase` …
`run_k_phase`) and the one-shot `run_full_loop`. `graph.py` documents
`run_full_loop` as the "快速模式". Only the per-phase path emits the rich
`kind:"lock_phase"` events that the frontend `LOCKPhaseStream` and
`DashboardPanel` consume; `run_full_loop` streams only the legacy flat
`kind:"lock_progress"` events. So whenever the agent takes the fast path, the
entire phase stream and all dashboard panels stay empty — the framework's
capabilities are invisible. This plan makes `run_full_loop` emit the same rich
per-phase events the manual path does, so both demo paths light up the UI.

## Current state

- `deep-agent-backend/src/trace_deep_agent/phase_tools.py:780-832`
  (`run_full_loop`) wires a progress callback and calls `ctx.orch.run(max_rounds)`:

```python
progress = _phase_progress_cb(runtime, "run_full_loop")
ctx.lock_session.progress_cb = progress
...
result = ctx.orch.run(max_rounds=max_rounds)
```

- `_phase_progress_cb` (`phase_tools.py:112-130`) emits **only** the legacy
  event: `writer({"kind": "lock_progress", ...})`.
- `ModularOrchestrator.run` → `run_one_round`
  (`src/trace_agent/agents/modular_orchestrator.py:190-321`) calls
  `self._emit_progress({...})` after each phase. `_emit_progress`
  (`modular_orchestrator.py:384-392`) just forwards the dict to
  `session.progress_cb` — i.e. the legacy `lock_progress` writer. It never
  calls `build_phase_event`.
- The rich path exists only in the adapter's `_run_single_phase`
  (`phase_tools.py:626-641`), which builds `build_phase_event(...)` and streams
  it with `kind:"lock_phase"` via `_stream_progress`.
- The frontend only accumulates `lockPhaseStream` from `kind === "lock_phase"`:
  `deep-agents-ui/src/app/hooks/useChat.ts:86-101`. Legacy `lock_progress`
  goes into a separate flat `lockProgress` list
  (`useChat.ts:78-83`).
- `PhaseResult` objects for each phase are already produced inside
  `run_one_round` (`l_result`, `veto_result`, `o_result`, `c_result`,
  `k_result`), so the data needed for `build_phase_event` is in hand — it is
  simply not converted to rich events.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Core tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass |
| Backend adapter tests | `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |
| UI build | `cd deep-agents-ui; npm run build` | exit 0 |

Use system Python 3.11.5. Do NOT use `deep-agent-backend/.venv`.

## Scope

**In scope**:
- `deep-agent-backend/src/trace_deep_agent/phase_tools.py` — make
  `run_full_loop` emit rich `lock_phase` events per phase and per round.
- Optionally a small helper in the same file (or reuse `_stream_progress` +
  `build_phase_event`) — do not duplicate the serialization logic already in
  `_run_single_phase`; factor a shared helper if it reduces duplication.

**Out of scope** (do NOT touch):
- `src/trace_agent/agents/modular_orchestrator.py` phase execution / stop
  logic. (You may read `run_one_round`, but the preferred implementation drives
  rich events from the adapter using a per-phase hook, not by rewriting the
  orchestrator's loop — see Step 1.)
- `progress_protocol.build_phase_event` — reuse as-is.
- `deep-agents-ui/**` — the consumer already handles `lock_phase`.
- The Plan 011 state-machine unification.

## Git workflow

- Branch: `advisor/016-full-loop-rich-stream`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Route rich events through the full-loop run

Choose the lower-risk of these two approaches (prefer A):

**Approach A — per-phase hook (preferred, no orchestrator change):**
`ModularOrchestrator` exposes `run_phase(name)` and the adapter already knows
how to convert a `PhaseResult` into a rich event (`_run_single_phase`,
`phase_tools.py:626-641`). Reimplement `run_full_loop` to drive the loop from
the adapter: repeatedly call `ctx.orch.run_phase("L"/"Veto"/"O"/"C"/"K")`,
after each call build+stream the rich `lock_phase` event exactly as
`_run_single_phase` does, honor `should_stop`, and stop on budget/stop
decision. Factor the "run one phase + stream rich event" body of
`_run_single_phase` into a shared helper both entry points call, so there is a
single serialization site. This keeps `ModularOrchestrator` untouched.

**Approach B — orchestrator progress upgrade (only if A is infeasible):**
Give `ModularOrchestrator.run_one_round` an optional `rich_emit(phase, result)`
callback invoked after each phase with the real `PhaseResult`, and have the
adapter pass one that builds+streams `build_phase_event`. Do not remove the
existing `_emit_progress` legacy events (backward compatible).

Either way: after each phase emit `kind:"lock_phase"` with
`event_kind:"phase_end"`; on K stop emit the `stop_decision` event (reuse the
block at `phase_tools.py:662-680`).

**Verify**: `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` → all pass.

### Step 2: Keep the final compact report behavior

`run_full_loop` must still return the same compact report it does today
(`_build_report_from_session` + `_get_compact_report()`), and still clean up
the session (`_remove_session` + `ctx.orch.close()`). Only the streaming is
added; the return value is unchanged.

**Verify**: `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass.

### Step 3: Add an adapter test asserting rich events are emitted

Add a test (in `deep-agent-backend/tests/`, matching the existing test style
there) that runs `run_full_loop` against the scenario backend with a fake
`runtime` capturing `stream_writer` calls, and asserts at least one captured
event has `kind == "lock_phase"` and `event_kind == "phase_end"` for phases
`O`, `C`, and `K`.

**Verify**: `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass, including the new test.

### Step 4: Confirm the UI still builds

No frontend change is expected; confirm nothing broke.

**Verify**: `cd deep-agents-ui; npm run build` → exit 0.

## Test plan

- New adapter test `deep-agent-backend/tests/test_full_loop_streaming.py`
  (or add to an existing adapter test file):
  - `test_full_loop_emits_rich_phase_events` — captured events include
    `kind=="lock_phase"` phase_end for O/C/K.
  - `test_full_loop_still_returns_compact_report` — return value has the
    compact-report keys (`status`, `lock_loop`).
- Structural pattern: existing tests under `deep-agent-backend/tests/`.
- Verification: all commands in "Commands you will need" pass.

## Done criteria

- [ ] Running `run_full_loop` streams `kind:"lock_phase"` events with real
      per-phase data (verified by the new adapter test capturing O/C/K
      phase_end events).
- [ ] `run_full_loop` return value is unchanged (compact report) and session
      cleanup still runs.
- [ ] `src\trace_agent\tests\test_full_loop.py` and
      `deep-agent-backend\tests` pass.
- [ ] `cd deep-agents-ui; npm run build` exits 0.
- [ ] `git status` shows only in-scope files modified.
- [ ] `plans/README.md` status row for 016 updated.

## STOP conditions

- `run_full_loop` or `_run_single_phase` code does not match the "Current
  state" excerpts (drift) — stop and report.
- Approach A cannot reproduce the exact inter-phase data passing that
  `run_one_round` does (pool → chosen → ingest_result), causing different
  results between full-loop and per-phase — fall back to Approach B; if both
  diverge, STOP and report (this is the Plan 011 unification territory).
- The new streaming causes `test_full_loop.py` result values (rounds,
  stop_reason, graph size) to change — you altered execution, not just
  streaming; revert and report.

## Maintenance notes

- Plan 011 will unify the two state machines; when it lands, the full-loop and
  per-phase paths should share one transition + serialization implementation.
  This plan intentionally keeps `ModularOrchestrator` untouched (Approach A) so
  it does not conflict with 011 — the shared helper it introduces is the seam
  011 can build on.
- Depends on Plan 015: without the K/Veto rich fields populated, the events
  this plan streams for those phases would still be empty. Land 015 first.
- A reviewer should confirm full-loop and five manual phase calls on the same
  scenario produce the same final graph/decision (only streaming differs).
