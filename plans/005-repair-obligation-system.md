# Plan 005: Repair obligation creation, scheduling, and materialization

> **Executor instructions**: Do not weaken hard obligations merely to make
> loops stop. Correct their facts, host binding, executability, and discharge
> semantics. Update the plan index when done.
>
> **Drift check**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_agent\obligation_integration\obligation_ledger.py,`
>   src\trace_agent\agents\orchestrator.py
> ```
>
> Expected:
> `1DDFE79FDA100113711BB0AFE5BD4F180B3660D7418462AE047102479247F8A0`,
> `E2E82C69A097440E0CD7277FFCBC7F674DE2BE958531612AD6A5270CDC062D86`.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH — affects hard-stop invariants and investigation budgets
- **Depends on**: Plans 001 and 002
- **Category**: bug / architecture
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

All graph nodes are exported as confirmed, structural scanning treats confirmed
as malicious, and ordinary leaves become hard obligations. Several obligation
types then materialize template IDs, evidence IDs, or explanation IDs as host
targets and are filtered as non-executable. This can both block stopping and
fail to run the probe that would discharge the block.

## Current state

- `_graph_to_dict()` sets every node `"confirmed": True` at
  `orchestrator.py:1180-1188`.
- `scan_structural()` computes malicious as `malicious or confirmed` and makes
  an incoming-edge leaf a hard “orphan” at
  `obligation_ledger.py:99-113`.
- `_current_round()` derives time from maximum obligation creation round, so
  time does not advance reliably.
- `_obligation_dicts_to_probes()` maps:
  lifecycle → template ID, anti-forensics → evidence ID, discriminative →
  explanation ID, at `orchestrator.py:1126-1142`.
- Hard obligations unconditionally block `should_stop()`.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| Obligation tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_obligation_ledger.py src\trace_agent\tests\test_full_loop.py -q` | all pass |
| Full suite | `$env:PYTHONPATH='src'; python -m pytest tests\engine src\trace_agent\tests -q` | all pass |

## Scope

**In scope**

- `src/trace_agent/decision/runtime_types.py`
- `src/trace_agent/loop/session_graph.py`
- `src/trace_agent/obligation_integration/obligation_ledger.py`
- `src/trace_agent/obligation_integration/mandate_from_trust.py`
- `src/trace_agent/agents/orchestrator.py`
- obligation/full-loop tests

**Out of scope**

- Model planner implementation (Plan 006).
- Removing hard structural/anti-forensics invariants.
- Treating high-trust evidence as automatically malicious.

## Steps

### Step 1: Make graph fact and attribution state explicit

Add typed fields for fact confirmation, attribution status, malicious status,
host/entity IDs, and provenance. Stop deriving maliciousness from trust tier,
ID prefix, or generic confirmation.

### Step 2: Correct structural obligation semantics

Define separately:

- orphan fact: no supported parent where a parent is required;
- unresolved leaf: normal frontier, not automatically debt;
- bridge ambiguity: cross-host relation with unresolved provenance;
- dangling credential: credential entity without source.

Only explicit structural invariants may be hard. Add reason codes and supporting
node/edge IDs.

### Step 3: Pass the actual round into the ledger

`scan`, `prioritize`, and deadline checks must accept the orchestrator round.
Remove `_current_round()` inference from creation history.

### Step 4: Introduce a typed ObligationIntent

Each obligation must carry:

- affected entity/host IDs;
- question to resolve;
- allowed operator families;
- evidence acceptance criterion;
- hard/VOI-gated state;
- deadline and creation round.

Do not parse behavior from colon-delimited anchor strings.

### Step 5: Materialize executable deterministic probes

Resolve hosts through graph/asset inventory, map operator families through the
configured capability registry, and emit no probe if the obligation cannot be
executed. An unexecutable hard obligation must become an explicit blocked state
requiring operator intervention, not an infinite loop.

### Step 6: Make discharge evidence-specific

Discharge only when the acceptance criterion is met by named evidence/edges.
Anti-forensics absence requires restored visibility or an explicit unavailable
source decision.

### Step 7: Add budget and escalation behavior

Track attempts, failures, deadlines, and blocked reasons. Hard obligations still
block a normal “robust” stop, but budget exhaustion must yield an escalated,
incomplete result with the unresolved obligations listed.

## Test plan

- Ordinary graph leaf creates no hard orphan.
- True orphan/bridge/credential obligations.
- Round and deadline progression.
- Every materialized probe has a real host and allowed operator.
- Unexecutable hard obligation escalates rather than loops.
- Evidence-specific discharge and revision cascade.

## Done criteria

- [x] No node is malicious merely because it is confirmed/high-trust.
- [x] No anchor-string parsing is required for execution.
- [x] Deadlines advance with orchestrator round.
- [x] Hard obligations are executable or explicitly blocked/escalated.
- [x] Full tests pass.
- [x] Plan index updated.

Implementation result (2026-07-03): obligation/full-loop `51 passed`; full
engine/core `312 passed`. Budget exhaustion with unresolved hard obligations
now returns `escalate_incomplete` plus typed unresolved-obligation details.

## STOP conditions

- The graph lacks an entity needed to bind an obligation: report the missing
  entity-model change.
- A required operator has no production transport capability.
- Correctness would require making all structural debts soft.

## Maintenance notes

Plan 006 will consume `ObligationIntent`; keep it provider-neutral and fully
validatable without a model.
