# Plan 014: Enable the model-processing layers on the real_trace_01 demo path

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- configs/engine.real_trace.yaml `
>   src/trace_engine/config.py
> ```
> If either file changed since this plan was written, compare the "Current
> state" excerpts against the live code before proceeding; on a mismatch,
> treat it as a STOP condition.

## Status

- **Priority**: P0
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug / dx
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

The user's demo goal is that the LOCK loop's **model-processing** parts show
real data in the frontend. On the `real_trace_01` demo path this is impossible
today because `configs/engine.real_trace.yaml` contains no `model_*` sections,
so the engine falls back to dataclass defaults: `model_judgement.mode="off"`
and `model_mcp_compiler.mode="off"`. As a result the C-phase stream ships an
empty `llm_judgements` list and a null `mcp_compiler_audit`, and the "LLM 研判
(L4)" / MCP-compiler panels stay blank even though a `DEEPSEEK_API_KEY` is
present in `.env`. Enabling these layers (mirroring the already-working
`engine_demo_wazuh.yaml`) makes the model-processing data appear.

## Current state

- `configs/engine.real_trace.yaml` — the demo config the user runs. Its
  `soar_mcp` / `normalizer` / `budget` sections exist, but there is **no**
  `model_planner`, `model_judgement`, or `model_mcp_compiler` section. Full
  current content is 60 lines ending at the `budget:` block plus trailing
  comments.
- `src/trace_engine/config.py` defines the defaults that apply when a section
  is absent:
  - `ModelPlannerConfig.mode = "shadow"` (config.py, `class ModelPlannerConfig`)
  - `ModelJudgementConfig.mode = "off"` (config.py, `class ModelJudgementConfig`)
  - `ModelMcpCompilerConfig.mode = "off"` (config.py, `class ModelMcpCompilerConfig`)
- The **working reference** is `configs/engine_demo_wazuh.yaml:70-108`, which
  enables the layers like this:

```yaml
model_planner:
  mode: "shadow"
  provider: "deepseek"
  model: "deepseek-v4-flash"
  endpoint: "https://api.deepseek.com/v1"
  credential_env: "DEEPSEEK_API_KEY"
  verify_tls: true
  max_intents_per_round: 4
  cost_budget_per_round: 1.0
  max_graph_nodes: 40

model_judgement:
  mode: "assist"
  provider: "deepseek"
  model: "deepseek-v4-flash"
  endpoint: "https://api.deepseek.com/v1"
  credential_env: "DEEPSEEK_API_KEY"
  verify_tls: true
  max_calls_per_round: 3
  max_calls_per_case: 20
  max_tokens_per_case: 20000
  max_context_nodes: 40
  ambiguity_margin: 0.35

model_mcp_compiler:
  mode: "shadow"
  provider: "deepseek"
  model: "deepseek-v4-flash"
  endpoint: "https://api.deepseek.com/v1"
  credential_env: "DEEPSEEK_API_KEY"
  verify_tls: true
  max_plans_per_round: 4
  max_calls_per_round: 3
  max_calls_per_case: 30
  max_tokens_per_case: 20000
  max_context_nodes: 40
  max_time_range_days: 30
  max_filters: 4
  fallback_to_template: true
```

- Credentials: `.env` at repo root contains `DEEPSEEK_API_KEY` and
  `LLM_PROVIDER`. The backend launcher `scripts/start_deep_agent_backend.ps1`
  injects `DEEPSEEK_API_KEY` into the process. No secret value is reproduced
  here — reference the env var name only.
- The model layers degrade gracefully when the key is missing (planner falls
  back to `NullProbePlanner`; judgement/compiler report `provider_status`
  disabled), so enabling the sections is safe even without a live key.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Config loads | `$env:PYTHONPATH='src'; python -c "from trace_engine.config import EngineConfig; c=EngineConfig.load('configs/engine.real_trace.yaml'); print(c.model_judgement.mode, c.model_mcp_compiler.mode, c.model_planner.mode)"` | prints `assist shadow shadow` |
| Engine tests | `$env:PYTHONPATH='src'; python -m pytest tests/engine/test_soar_executor.py tests/engine/test_normalizer.py tests/engine/test_scenario_registry.py -q` | all pass |

Note: use the system Python (3.11.5, ships pytest 9.0.3). Do **not** use
`deep-agent-backend/.venv` (its cp311 binaries are incompatible with a 3.12
runtime).

## Scope

**In scope** (the only file you should modify):
- `configs/engine.real_trace.yaml`

**Out of scope** (do NOT touch):
- `src/trace_engine/config.py` — defaults are correct; only the demo config
  needs the explicit sections.
- `configs/engine_demo_wazuh.yaml` — reference only.
- Any Python source. This is a config-only change.

## Git workflow

- Branch: `advisor/014-real-trace-model-layers`
- One commit; message style matches repo (short imperative, e.g.
  `enable model layers in real_trace demo config`).
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Append the three model sections to the real_trace config

Add `model_planner`, `model_judgement`, and `model_mcp_compiler` sections to
`configs/engine.real_trace.yaml`, copying the field values verbatim from the
`engine_demo_wazuh.yaml` block quoted in "Current state". Place them after the
`budget:` block, before the trailing `# === 查询契约` comment lines (or at end
of file — YAML section order does not matter).

Keep `model_judgement.mode: "assist"` and `model_mcp_compiler.mode: "shadow"`
so the C-phase stream carries both `llm_judgements` (assist executes) and
`mcp_compiler_audit` (shadow records without changing execution).

**Verify**: `$env:PYTHONPATH='src'; python -c "from trace_engine.config import EngineConfig; c=EngineConfig.load('configs/engine.real_trace.yaml'); print(c.model_judgement.mode, c.model_mcp_compiler.mode, c.model_planner.mode)"`
→ prints `assist shadow shadow`

### Step 2: Confirm engine tests still pass

The change is config-only; no test should regress.

**Verify**: `$env:PYTHONPATH='src'; python -m pytest tests/engine/test_soar_executor.py tests/engine/test_normalizer.py tests/engine/test_scenario_registry.py -q`
→ all pass

## Test plan

- No new automated test required (config-only, and there is no existing config
  fixture test for real_trace beyond `test_soar_executor.py::test_real_trace_config_enables_seed_only_pivots`,
  which must still pass).
- Manual demo verification (record result in the PR/summary, not automated):
  with `DEEPSEEK_API_KEY` set and `TRACE_AGENT_ALLOW_PRODUCTION=1`, run the
  real_trace seed through the per-phase tools and confirm a C-phase
  `lock_phase` event now contains a non-empty `llm_judgements` array and a
  non-null `mcp_compiler_audit`.

## Done criteria

- [ ] `EngineConfig.load('configs/engine.real_trace.yaml')` reports
      `model_judgement.mode == "assist"`, `model_mcp_compiler.mode == "shadow"`,
      `model_planner.mode == "shadow"`.
- [ ] `tests/engine` subset above passes.
- [ ] `git status` shows only `configs/engine.real_trace.yaml` modified.
- [ ] `plans/README.md` status row for 014 updated.

## STOP conditions

- The `engine.real_trace.yaml` current content does not match the "Current
  state" description (e.g. it already has model sections) — stop and report.
- Loading the config raises (YAML indentation error) after two fix attempts.
- `test_real_trace_config_enables_seed_only_pivots` starts failing — the
  section you added altered an unrelated assertion; stop and report.

## Maintenance notes

- This only makes the model layers *available*; whether the frontend renders
  the C-phase model data also depends on Plan 015 (K/Veto rich fields) and Plan
  016 (full_loop streaming). The C-phase `llm_judgements`/`mcp_compiler_audit`
  already flow on the per-phase path once these sections are enabled.
- If a live demo must run without network egress to DeepSeek, set
  `model_judgement.mode: "shadow"` to avoid blocking on provider calls; the
  audit still records model reasoning without executing edits.
- Reviewer should confirm no secret value was pasted into the YAML — only the
  `credential_env: "DEEPSEEK_API_KEY"` reference belongs there.
