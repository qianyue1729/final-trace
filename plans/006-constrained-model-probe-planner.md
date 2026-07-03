# Plan 006: Add a constrained model-assisted probe planner

> **Executor instructions**: The model proposes typed probe intents; it never
> executes tools, writes the graph, or bypasses the validator. Launch in shadow
> mode only. Update the plan index when done.
>
> **Drift check**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_agent\loop\generators.py,`
>   src\trace_agent\agents\orchestrator.py,`
>   src\trace_agent\loop\llm_ingest.py
> ```
>
> Expected:
> `4F4F499078D77B1CD9A6628C7EE2F71B5C28A3A3BD9A9AA35271754F77CFFA77`,
> `E2E82C69A097440E0CD7277FFCBC7F674DE2BE958531612AD6A5270CDC062D86`,
> `A9EF805D377CDBB735D8F2A43B552B99D60468BF6F7423861C8EF9C95C5D9D22`.

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH — changes investigation coverage and external query cost
- **Depends on**: Plans 002, 004, 005
- **Category**: direction / architecture
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

L phase currently assumes a linear tactic order, fixed tactic/operator mapping,
`WS-`/`SRV-` host naming, a hard eight-host cap, and synthetic targets such as
`stage-execution`. A model can improve semantic probe planning, but only inside
a strict capability, entity, budget, and evidence contract.

## Current state

- Static maps and linear chain are in `generators.py:46-99`.
- Cross-host selection relies on host prefixes and `candidates[:8]` at
  `generators.py:643-713`.
- Chain-follow generates every later missing tactic.
- Prior stage probes use log-source names as operators and synthetic targets at
  `generators.py:344-354`.
- O phase already has a CandidatePool and deterministic selection point; reuse
  it rather than creating a separate execution path.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| L/O tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_l_phase.py src\trace_agent\tests\test_voi_engine.py -q` | all pass |
| New planner tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_model_probe_planner.py -q` | all pass |
| Full suite | `$env:PYTHONPATH='src'; python -m pytest tests\engine src\trace_agent\tests -q` | all pass |

## Scope

**In scope**

- new `src/trace_agent/loop/model_probe_planner.py`
- new typed planner DTOs under `src/trace_agent/loop/`
- `src/trace_agent/loop/generators.py`
- `src/trace_agent/agents/orchestrator.py`
- `src/trace_engine/config.py`
- model provider protocol/client extensions
- planner tests, metrics, and example configuration

**Out of scope**

- Letting the planner call SOAR directly.
- Model-generated operators or hosts outside allowlists.
- Replacing VOI with model ranking.
- Enforce mode before shadow acceptance.

## Target contracts

Planner input:

- compressed graph with IDs;
- competing explanations and calibrated status;
- unresolved `ObligationIntent`s;
- known entities/assets and roles;
- available operator capabilities and data sources;
- allowed time-window bounds;
- current budget/cost and recent probe outcomes.

Planner output:

```json
{
  "intents": [{
    "target_entity_id": "asset:123",
    "operator": "auth_log",
    "tactic": "initial-access",
    "time_window": {"from": 0, "to": 0},
    "distinguishes": ["H1", "H2"],
    "expected_outcomes": ["attributable", "benign", "oos", "no_data"],
    "evidence_refs": ["N12", "obligation_4"],
    "reason_codes": ["DISCRIMINATES_CREDENTIAL_ORIGIN"]
  }]
}
```

## Steps

### Step 1: Build a provider-neutral planner protocol

Define `ProbePlanner.plan(context) -> PlannerResult`. Implement a null planner
and fake planner first. Reuse bounded graph/context sanitization patterns from
`LLMIngestPipeline`.

### Step 2: Implement the deterministic validator

Reject intents unless:

- target resolves to a known entity and allowed scope;
- operator exists in the capability registry;
- datasource and transport support it;
- time window respects Plan 002 bounds;
- evidence references exist;
- budget/cost constraints pass;
- intent is not a duplicate or recent proven-dead query.

Return rejection reason codes for every invalid intent.

### Step 3: Add a narrowly scoped model prompt

Treat all case strings as untrusted data. Ask only for the typed contract.
Require abstention when no useful discriminating probe exists. Do not request
probabilities or free-form tool commands.

### Step 4: Integrate in shadow mode

Generate model intents beside rule candidates, validate them, but do not add
them to CandidatePool. Log proposal validity, overlap, projected VOI, latency,
token cost, and missed opportunities.

### Step 5: Define graduation gates

On independent cases/tenant pilot, require:

- zero scope/operator violations after validation;
- bounded p95 latency and cost;
- non-inferior attack/boundary recall;
- lower or equal pollution/query cost;
- deterministic fallback success.

Only then add `assist` mode, where validated model candidates join the same
CandidatePool and VOI ranking. No direct priority override.

### Step 6: Retire only proven-bad heuristics

Keep rule generators as fallback. Remove host-prefix/synthetic-target behavior
only after shadow evidence demonstrates replacement coverage.

## Test plan

- Valid intent, abstention, hallucinated host/operator, stale refs.
- Prompt injection inside process/host strings.
- Excessive time window and budget.
- Shadow mode executes no model probe.
- Assist mode joins CandidatePool but remains subject to VOI/veto.
- Provider timeout/failure falls back to rules.

## Done criteria

- [x] Model has no tool or graph-write capability.
- [x] Every intent is validated with reason codes.
- [x] Shadow metrics and audit records exist.
- [x] Assist mode is default-off.
- [x] Full suite passes.
- [x] Plan index updated.

Implementation result (2026-07-03): planner/L/VOI `44 passed`; full
engine/core `317 passed`. Default mode is `shadow`; the default null provider
abstains, and no model probe is executed.

## STOP conditions

- Plans 002/004/005 contracts are not available.
- Operator capability registry cannot validate model output.
- Evaluation still contains runtime GT leakage.
- Model provider cannot guarantee structured output and timeout control.

## Maintenance notes

Review every new operator against transport capabilities and cost calibration.
Prompt changes are model-versioned behavior changes and require shadow replay.
