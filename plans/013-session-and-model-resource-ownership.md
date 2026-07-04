# Plan 013: Enforce session isolation and model resource ownership

> **Executor instructions**: Replace module-global active-session behavior
> with an explicit manager bound to the calling thread/session. Consolidate
> model provider construction and ensure every owned client is closed.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88 -- deep-agent-backend/src/trace_deep_agent `
>   src/trace_engine/config.py src/trace_engine/runner.py `
>   src/trace_engine/alert_enricher.py src/trace_agent/llm/client.py
> ```

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: Plans 010, 011
- **Category**: correctness / security / tech-debt
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

Deep Agent sessions live in a process-global dictionary. Query tools with no
`session_id` select the most recently created session across the process,
which can expose or mutate the wrong investigation under concurrent threads.
Abandoned sessions have no TTL cleanup. Model clients are also constructed in
several places with divergent TLS/config/lifecycle behavior.

## Current state

- Global registry: `phase_tools.py:72-88`.
- Cross-session fallback: `query_tools.py:27-38` returns the most recently
  created global session when no ID is supplied.
- `SessionContext.created_at` exists, but no expiry scan uses it.
- Model settings are repeated in `AlertEnricherConfig`,
  `ModelPlannerConfig`, and `ModelJudgementConfig` in
  `src/trace_engine/config.py:177-253`.
- Outer agent model construction is separate in
  `deep-agent-backend/src/trace_deep_agent/model.py:13-75`.
- `_DeepSeekModelEnricher.enrich_alert` creates a new `DeepSeekClient` at
  `src/trace_engine/alert_enricher.py:574-583` and does not close it.

## Commands you will need

| Purpose | Command | Expected |
|---|---|---|
| Backend tests | `$env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |
| Model tests | `$env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_llm_client_security.py tests\engine\test_alert_enricher.py tests\engine\test_runner_backend.py -q` | all pass |
| Full engine | `$env:PYTHONPATH='src'; python -m pytest tests\engine -q` | all pass |

## Scope

**In scope**

- Deep Agent session manager and all query/control/phase tool access
- Thread/session binding and TTL cleanup
- Shared model provider settings/factory in the engine application layer
- Alert enricher client lifecycle
- Concurrency and cleanup tests

**Out of scope**

- Authentication product design
- Model prompts and decision authority
- Replacing LangChain's `ChatOpenAI`
- Persisting full mutable LOCK sessions across process restarts

## Steps

### Step 1: Introduce an explicit `InvestigationSessionManager`

Encapsulate create/get/remove/close/expire operations. Bind entries to the
LangGraph thread identity available in `ToolRuntime` plus `session_id`.
Remove direct imports of `_sessions` and `_sessions_lock`.

No query or control tool may resolve a global "latest session". Optional
`session_id` is allowed only when the current thread has exactly one active
session; otherwise return a structured ambiguity error.

**Verify**: two concurrent fake threads cannot read or mutate each other's
sessions.

### Step 2: Add bounded lifecycle cleanup

Add configurable max active sessions and idle TTL. Expiry/removal must call the
canonical idempotent close path from Plan 010. Trigger bounded cleanup during
create/get operations; a background scheduler is not required.

**Verify**: expiry and capacity tests close fake resources exactly once.

### Step 3: Consolidate provider settings and construction

Extract common endpoint/model/credential/TLS/timeout/retry settings. Keep
feature-specific mode and budgets in enricher/planner/judgement configs.
Provide one engine-level factory for structured DeepSeek clients.

The outer Deep Agent may continue using `ChatOpenAI`, but it must consume the
same resolved credential, endpoint, model, timeout, and TLS policy instead of a
parallel environment interpretation.

**Verify**: one configuration test demonstrates identical resolved provider
settings for outer agent, planner, judgement, and enrichment.

### Step 4: Define and test ownership

Choose one of:

- one client per prepared investigation, shared only where thread-safe, closed
  by the prepared investigation; or
- one client per component, each closed by its component.

Document the choice in code. Wrap alert enrichment client use in `try/finally`
or retain and close it with runner ownership. Test exceptions and retries.

**Verify**: no `DeepSeekClient` construction site lacks an explicit owner and
close test.

## Test plan

- Two concurrent thread identities and same/different session IDs.
- Ambiguous omitted session ID.
- TTL expiry and max-capacity eviction.
- Success/error/force-stop cleanup.
- TLS true, custom CA, and explicit dev-only TLS override.
- Missing credentials deterministic fallback.

## Done criteria

- [ ] No module-global latest-session fallback remains.
- [ ] Active sessions are thread-bound and bounded by TTL/capacity.
- [ ] All resources close exactly once.
- [ ] Common provider configuration is resolved once.
- [ ] All verification commands pass.

## STOP conditions

- `ToolRuntime` provides no stable thread identity; report the available
  metadata and require explicit `session_id` instead.
- Sharing a model client is not documented thread-safe.
- A TLS policy change would weaken production verification by default.

## Maintenance notes

Keep secrets as environment/secret-manager references. Tests may use fake
credential values only and must never read or print the real `.env`.
