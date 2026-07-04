# Plan 015: Populate K-phase and Veto-phase rich stream events so the dashboard panels show data

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/phases/k_phase.py `
>   src/trace_agent/phases/veto_phase.py `
>   src/trace_agent/agents/progress_protocol.py
> ```
> If any file changed since this plan was written, compare the "Current state"
> excerpts against the live code before proceeding; on a mismatch, treat it as
> a STOP condition.

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: MED
- **Depends on**: none (can land before the Plan 009→010→011 convergence)
- **Category**: bug
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot
- **Relationship to Plan 011**: Plan 011 Step 3 will formalize this contract
  with a versioned schema + codegen and depends on 009+010. This plan is the
  **scoped, dependency-free subset** that makes the demo panels work now. When
  011 lands it supersedes the hand-wired fields here; keep the field names
  identical so 011 can absorb them.

## Why this matters

The frontend dashboard has four panels — Decision Ledger, Beta Ledger, Graph,
Obligations — plus the LOCK phase stream. In `useLOCKState.ts` every one of
these is populated **only** from the K-phase `phase_end` event (with obligation
types from Veto and `delta_p_atk` from C). But `KPhaseExecutor` returns a
`PhaseResult` whose `data` has only `stop_decision`, `ledger_snapshot`, and
`round_diagnostic` — none of the keys `build_phase_event` reads. So the K event
ships all zeros/empty, and all four panels render blank during a real
investigation. Veto has the same shape mismatch. This is the core reason "每个
模块都有数据" fails on the recommended per-phase demo path.

## Current state

### The consumer expects these fields

`src/trace_agent/agents/progress_protocol.py`, K branch of `build_phase_event`
(the `elif phase == Phase.K:` block, PHASE_END path) reads from `result.data`:

```python
evt.explanations = _r4_list(expl_list)          # data["explanations"]: [{eid,label,posterior,is_null,null_kind}]
evt.contested_edges = _r4_list(raw_edges)        # data["contested_edges"]: [{edge_id,p_in,p_benign,p_oos}]
evt.leading_explanation = data.get("leading_explanation", "")
evt.margin = _r4(data.get("margin", 0.0))
evt.entropy = _r4(data.get("entropy", 0.0))
evt.beta_updates = _r4_list(list(data.get("beta_updates", [])))   # [{probe_key,hit,new_alpha,new_beta}]
evt.obligations_open = data.get("obligations_open", 0)
evt.obligations_discharged = data.get("obligations_discharged", 0)
evt.obligations_overdue = data.get("obligations_overdue", 0)
evt.new_nodes = data.get("new_nodes", 0)
evt.new_edges = data.get("new_edges", 0)
evt.graph_node_count = data.get("graph_node_count", 0)
evt.graph_edge_count = data.get("graph_edge_count", 0)
```

The Veto branch (`elif phase == Phase.VETO:`) reads:

```python
evt.vetoed_count = data.get("vetoed_count", 0)
evt.veto_reasons = dict(data.get("veto_reasons", {}))   # expects a dict/mapping
evt.mandated_count = data.get("mandated_count", 0)
evt.obligation_types = dict(data.get("obligation_types", {}))
evt.surviving_count = data.get("surviving_count", 0)
evt.trust_revisions = data.get("trust_revisions", 0)
```

### The producer today

`src/trace_agent/phases/k_phase.py:242-261` returns only:

```python
return PhaseResult(
    phase="K", success=True, should_stop=stop.should_stop,
    data={
        "stop_decision": stop,
        "ledger_snapshot": {"leading": ..., "margin": ..., "entropy": ...},
        "round_diagnostic": self.round_diagnostics[-1] if self.round_diagnostics else {},
    },
    ...
)
```

Note `k_phase.py` already computes most needed values just above (lines
~193-218): `graph_stats = session.graph.stats()`, `prev_node_count`,
`prev_edge_count`, `probs_after`, `session.ledger.margin()`,
`session.ledger.entropy()`. And `round_diagnostics[-1]` already holds
`new_graph_nodes`, `new_graph_edges`, `graph_nodes`, `graph_edges`.

`src/trace_agent/phases/veto_phase.py:83-95` returns `veto_reasons` as a
**list** (`veto_reasons: list[str]`) and does not emit `surviving_count`,
`mandated_count`, `obligation_types`, or `trust_revisions`.

### The exact data already available live (reference implementation)

`deep-agent-backend/src/trace_deep_agent/query_tools.py` already builds every
one of these shapes from the same `session` objects — use it as the source of
truth for field construction:

- explanations + null anchor + contested_edges: `query_tools.py:122-172`
  (`get_decision_ledger`)
- obligation open/discharged/overdue counts: `query_tools.py:301-347`
  (`get_obligation_status`)
- Beta per-key stats via `session.beta`: `query_tools.py:208-217`

The K event field names (`eid`, `label`, `posterior`, `is_null`, `null_kind`
for explanations; `edge_id`, `p_in`, `p_benign`, `p_oos` for contested edges;
`probe_key`, `hit`, `new_alpha`, `new_beta` for beta) are defined in
`progress_protocol.py` KPhaseEvent docstrings and consumed in
`deep-agents-ui/src/app/hooks/useLOCKState.ts:77-131`. Match them exactly.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Core tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass |
| Engine tests | `$env:PYTHONPATH='src'; python -m pytest tests\engine\test_soar_executor.py -q` | all pass |
| New contract test | `$env:PYTHONPATH='src'; python -m pytest tests\engine\test_phase_event_contract.py -q` | all pass (created in this plan) |

Use system Python 3.11.5 (has pytest 9.0.3). Do NOT use
`deep-agent-backend/.venv`.

## Scope

**In scope**:
- `src/trace_agent/phases/k_phase.py` — add the missing keys to the returned
  `PhaseResult.data`.
- `src/trace_agent/phases/veto_phase.py` — return `surviving_count`,
  `mandated_count`, `obligation_types` (dict), and keep `veto_reasons` as a
  count map (see Step 2).
- `src/trace_agent/agents/progress_protocol.py` — **only** if Veto
  `veto_reasons` must stay a list for other consumers; otherwise leave the
  consumer as-is and produce the mapping in the executor (preferred).
- `tests/engine/test_phase_event_contract.py` (create).

**Out of scope** (do NOT touch):
- Phase decision algorithms (stop logic, VOI, Bayesian update). You are only
  surfacing already-computed values into `PhaseResult.data`.
- `deep-agents-ui/**` — the consumer already reads the right field names.
- `k_phase.py` stop-decision logic and `round_diagnostics` schema.
- The full state-machine unification (that is Plan 011).

## Git workflow

- Branch: `advisor/015-k-veto-rich-events`
- Commit per phase file + one for the test; short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Enrich K-phase `PhaseResult.data`

In `k_phase.py`, before the `return PhaseResult(...)` at line ~242, build the
fields from values already in scope and the session ledger/beta/obligations.
Add these keys to the `data=` dict (do not remove existing keys):

- `explanations`: list of `{eid, label, posterior, is_null, null_kind}` from
  `session.ledger` — replicate `get_decision_ledger` logic
  (`query_tools.py:122-147`), including the `__null__` anchor entry.
- `contested_edges`: list of `{edge_id, p_in, p_benign, p_oos}` from
  `session.ledger.contested` (note the consumer key is `p_in`, not
  `p_in_attack` — map `belief.p_in_attack` → `p_in`).
- `leading_explanation`: `session.ledger.leading()`.
- `margin`: `session.ledger.margin()`; `entropy`: `session.ledger.entropy()`.
- `beta_updates`: list of `{probe_key, hit, new_alpha, new_beta}`. Derive from
  `session.beta` for the probe keys touched this round. If per-round hit/miss
  deltas are not readily available, emit one entry per known key with the
  current `alpha`/`beta` and `hit` set from the round's confirmed probes; if
  even that is not derivable without new algorithm code, emit `[]` and record
  this in the PR summary (do NOT invent values).
- `obligations_open` / `obligations_discharged` / `obligations_overdue`:
  integer counts from `session.obligations` — replicate
  `get_obligation_status` counting (`query_tools.py:301-347`) using
  `session.round` as the current round.
- `new_nodes` / `new_edges` / `graph_node_count` / `graph_edge_count`: reuse
  the values already computed for `round_diagnostics[-1]`
  (`new_graph_nodes`, `new_graph_edges`, `graph_nodes`, `graph_edges`).

**Verify**: `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` → all pass (no regression).

### Step 2: Fix Veto-phase event fields

In `veto_phase.py`, change the returned `data` so that:

- `veto_reasons` is a **count mapping** `{reason: count}` (the consumer does
  `dict(veto_reasons)` and `Object.entries` over it). Convert the current
  `list[str]` into a `Counter`-style dict keyed by the reason prefix (e.g.
  `beta_veto`, `unknown_host`).
- add `vetoed_count` (already present), `surviving_count` (size of the
  surviving pool), `mandated_count` (number of obligations materialized this
  phase), and `obligation_types` (`{type: count}` over materialized
  obligations). If the Veto executor does not currently materialize
  obligations (that happens in O per `o_phase.py`), set `mandated_count: 0` and
  `obligation_types: {}` and note it — do NOT fabricate.

**Verify**: `$env:PYTHONPATH='src'; python -m pytest tests\engine\test_soar_executor.py -q` → all pass.

### Step 3: Add a phase-event contract test

Create `tests/engine/test_phase_event_contract.py` that:

1. Builds a minimal in-memory `LOCKSession` via the same path
   `tests/soar_mcp` / `test_full_loop.py` use (model after
   `src/trace_agent/tests/test_full_loop.py` bootstrap), runs one full round,
   then calls `build_phase_event(Phase.K, EventKind.PHASE_END, k_result, session)`
   and asserts the resulting `to_stream_dict()` has non-empty `explanations`,
   numeric `margin`/`entropy`, and integer `graph_node_count`.
2. Does the same for `Phase.VETO`, asserting `veto_reasons` is a dict and
   `surviving_count` is an int.

Model the harness after `src/trace_agent/tests/test_full_loop.py`.

**Verify**: `$env:PYTHONPATH='src'; python -m pytest tests\engine\test_phase_event_contract.py -q` → all pass.

## Test plan

- New file `tests/engine/test_phase_event_contract.py`:
  - `test_k_phase_event_has_decision_fields` — explanations non-empty, margin
    numeric, graph counts present.
  - `test_k_phase_event_has_obligation_and_graph_counts`.
  - `test_veto_phase_event_reasons_is_mapping` — `veto_reasons` is a dict,
    `surviving_count` int.
- Structural pattern: `src/trace_agent/tests/test_full_loop.py`.
- Verification: the three commands in "Commands you will need" all pass,
  including the new contract test.

## Done criteria

- [ ] `k_phase.py` `PhaseResult.data` includes: `explanations`,
      `contested_edges`, `leading_explanation`, `margin`, `entropy`,
      `beta_updates`, `obligations_open`, `obligations_discharged`,
      `obligations_overdue`, `new_nodes`, `new_edges`, `graph_node_count`,
      `graph_edge_count`.
- [ ] `veto_phase.py` returns `veto_reasons` as a dict plus `surviving_count`,
      `mandated_count`, `obligation_types`.
- [ ] `tests/engine/test_phase_event_contract.py` exists and passes.
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py tests\engine\test_soar_executor.py -q` passes.
- [ ] `git status` shows only in-scope files modified.
- [ ] `plans/README.md` status row for 015 updated.

## STOP conditions

- The K or Veto executor code does not match the "Current state" excerpts
  (drift) — stop and report.
- Producing `beta_updates` or `mandated_count` would require changing the
  Bayesian/obligation algorithm rather than reading existing state — emit `[]`
  / `0`, note it in the summary, and continue; do NOT invent values.
- Any existing test regresses and the cause is a decision-algorithm change
  (you were only supposed to surface data) — revert and report.
- `contested` belief attribute names differ from `p_in_attack`/`p_benign`/
  `p_oos` — inspect `DecisionLedger`/belief type and report before guessing.

## Maintenance notes

- Keep field names byte-identical to `useLOCKState.ts` and the KPhaseEvent
  docstrings, so Plan 011's schema codegen can adopt them without a frontend
  change.
- When Plan 011 introduces the versioned contract, this hand-wired
  serialization should be replaced by the single serializer 011 defines — do
  not maintain both.
- A reviewer should confirm no stop-decision or posterior value changed
  (diff `round_diagnostics` and stop reasons before/after on a fixed scenario).
