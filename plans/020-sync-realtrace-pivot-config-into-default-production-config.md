# Plan 020: Sync real_trace_01 pivot/bootstrap/model settings into the default production engine config

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- configs/engine.yaml configs/engine.real_trace.yaml `
>   src/trace_engine/config.py tests/engine/test_config.py
> ```
> The worktree is dirty relative to `9dadd88` (plans 014–016 and earlier
> real_trace_01 work landed uncommitted). Compare the "Current state" excerpts
> below against the live files before proceeding; on a mismatch, treat it as a
> STOP condition.

## Status

- **Priority**: P0
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug (config drift)
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

Earlier work in this project redesigned the `real_trace_01` Wazuh scenario so
the LOCK engine discovers the attack chain **incrementally across many
rounds** — via `bootstrap_strategy: "seed_only"` (fetch only the seed event,
not the whole case) and `clue_pivot_rules` (backward-pivot one hop per round
from confirmed evidence). This redesign was applied only to
`configs/engine.real_trace.yaml`. But `deep-agent-backend`'s production
runner — the code path `init_investigation(backend="soar_mcp")` actually
uses — defaults to `configs/engine.yaml` unless the caller (or the process
environment) explicitly sets `TRACE_AGENT_ENGINE_CONFIG`. `configs/engine.yaml`
has **none** of the pivot/seed_only/model-layer settings; it falls back to
the class defaults (`bootstrap_strategy: "full_case"`, no `pivot_field_map`,
no `model_planner`/`model_judgement`/`model_mcp_compiler` sections, generic
`query_template: "host:{host}"`).

A real investigation run through this default path confirmed the effect: 5
of the 6 real_trace_01 attack-chain techniques were already fully confirmed
within **Round 1's** C-phase from just 4 generically-templated probes — the
incremental-discovery design was never exercised, because the config that
implements it was never loaded. The demo capability this project spent
significant effort building (multi-round pivot discovery, model layers
visible in the UI) is invisible on the path a caller reaches by simply
calling `init_investigation(backend="soar_mcp")` without extra configuration.
`configs/engine.yaml`'s own header comment already claims "real_trace_01 是
当前默认场景" — the intent was clearly for this file to carry the same
settings; they were only ever added to the "专用副本"
(`engine.real_trace.yaml`) and never synced back.

## Current state

- `deep-agent-backend/src/trace_deep_agent/tools.py:39-51` — the production
  runner path that `init_investigation(backend="soar_mcp")` uses when no
  scenario_id maps to a local scenario:

```python
def _production_runner() -> InvestigationRunner:
    """Fresh runner per call so demo-profile / strict config switches apply without restart."""
    default_config = (
        "configs/engine_demo_wazuh.yaml"
        if os.getenv("TRACE_ENGINE_DEMO_PROFILE", "0") == "1"
        else "configs/engine.yaml"
    )
    config_path = Path(
        os.getenv(
            "TRACE_AGENT_ENGINE_CONFIG",
            str(PROJECT_ROOT / default_config),
        )
    )
```

- `configs/engine.yaml` — the **full current content**, missing the pivot
  design entirely:

```yaml
# Windows trace-engine — 真实场景模式 (real_trace_01)
# 详见 REAL_TRACE_SCENARIO.md；专用副本: configs/engine.real_trace.yaml

backend: soar_mcp

soar_mcp:
  endpoint: "https://192.144.151.189/mcp"
  verify_tls: false
  ca_bundle: ""
  tool_name: "search_security_events"
  tool_profile: "wazuh"
  wazuh_time_range: "24h"
  wazuh_incident_prefix: ""
  wazuh_attacks_only: false
  wazuh_compact: false
  query_template: "host:{host}"

normalizer:
  field_map:
    ref: "id"
    timestamp: "timestamp"
    technique: "mitre_technique"
    tactic: "mitre_tactic"
    host: "hostname"
    host_fallback: "agent_name"

budget:
  total_rounds: 8
  total_probes: 30
  fanout_per_round: 4

# Bootstrap: rule.groups:real_trace AND data.srcip:203.0.113.50 → 6 条
# 种子: ... AND rule.mitre.id:T1048 → 1 条
```

- `configs/engine.real_trace.yaml` — the **full current content**, which has
  the complete pivot/model design (copy this into `engine.yaml`, do not
  re-derive it):

```yaml
# real_trace_01 v2 — 真实 Wazuh 形态 + 分步 pivot 回溯
# 对应服务端 real_trace_01 v2 / REAL_TRACE_HOST_ADAPTATION.md
# 用法: python scripts/validate_wazuh_runtime.py --config configs/engine.real_trace.yaml

backend: soar_mcp

soar_mcp:
  endpoint: "https://192.144.151.189/mcp"
  verify_tls: false
  ca_bundle: ""
  tool_name: "search_security_events"
  tool_profile: "wazuh"
  wazuh_time_range: "24h"
  wazuh_incident_prefix: ""
  wazuh_attacks_only: false
  wazuh_compact: false
  query_template: "host:{host}"

  # 种子只锁 1 条（T1048 + dst_ip），其余靠多轮 clue_pivot 回溯
  bootstrap_strategy: "seed_only"

  # pivot 探针查询模板（备用；clue_pivot 走 metadata.mcp_query 显式查询）
  pivot_field_map:
    clue_pivot: "srcip"
  query_template_by_pivot:
    host: "host:{value}"
    srcip: "data.srcip:{value}"
    dstuser: "data.dstuser:{value}"
    dst_ip: "data.dst_ip:{value}"

  # backward pivot 回溯链：从已确认事件属性回溯上一跳
  # attr = normalizer 归一后的 attributes 键；field = Wazuh Lucene 字段
  # 实测链: 种子(collected_file) → T1005(script_name) → T1059.004(src_ip)
  #        → T1078 / T1110.001（均用 src_ip；dstuser 会混入噪声登录）
  clue_pivot_rules:
    - attr: "collected_file"
      field: "data.collected_file"
      technique: "T1005"
      tactic: "collection"
    - attr: "script_name"
      field: "data.script_name"
      technique: "T1059.004"
      tactic: "execution"
    - attr: "src_ip"
      field: "data.srcip"
      technique: "T1078"
      tactic: "initial-access"
    - attr: "src_ip"
      field: "data.srcip"
      technique: "T1110.001"
      tactic: "credential-access"

normalizer:
  field_map:
    ref: "id"
    timestamp: "timestamp"
    technique: "mitre_technique"
    tactic: "mitre_tactic"
    host: "hostname"
    host_fallback: "agent_name"

budget:
  total_rounds: 10
  total_probes: 40
  fanout_per_round: 4

# === 查询契约（v2 backward pivot）===
# 种子:   rule.mitre.id:T1048 AND data.dst_ip:"198.51.100.77"        → 1
# 回溯1:  data.collected_file:"..." AND rule.mitre.id:T1005          → 1
# 回溯2:  data.script_name:"..."   AND rule.mitre.id:T1059.004       → 1
# 回溯3:  data.dstuser:...         AND rule.mitre.id:T1078           → 1
# 回溯4:  data.srcip:"..."         AND rule.mitre.id:T1110.001       → 2
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

- `src/trace_engine/config.py:105-112` — the class defaults these settings
  fall back to when absent from a loaded YAML (confirms `full_case` is what
  `engine.yaml` silently gets today):

```python
    query_template: str = "host:{host} source:{datasource}"
    bootstrap_strategy: str = "full_case"
    pivot_field_map: dict[str, str] = field(default_factory=dict)
    query_template_by_pivot: dict[str, str] = field(default_factory=lambda: {
        "host": "host:{value}",
        "srcip": "data.srcip:{value}",
```

## Design decision (do not redesign — implement exactly this)

Make `configs/engine.yaml` the **single source of truth** by copying the
missing sections from `configs/engine.real_trace.yaml` into it verbatim
(pivot config, model layers, and the wider budget). Do not invent new values,
do not merge/interpolate — copy exactly. Leave `configs/engine.real_trace.yaml`
in place unchanged (some scripts reference it explicitly by path, e.g.
`scripts/validate_wazuh_runtime.py --config configs/engine.real_trace.yaml`
and `scripts/verify_real_trace_windows.py`); do not delete it or redirect
those scripts. This plan only closes the gap for the *default* production
path.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Config loads without error | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -c "from trace_engine.config import EngineConfig; c = EngineConfig.load('configs/engine.yaml'); print(c.soar_mcp.bootstrap_strategy); print(c.model_judgement.mode)"` | prints `seed_only` then `assist`, exit 0 |
| Config regression tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_config_ca_bundle.py tests\engine\test_config_demo_profile.py tests\engine\test_config_production_flags.py -q` | all pass |
| Full loop tests (regression) | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass (this suite doesn't load `engine.yaml` directly, included as a general regression gate) |

Use system Python 3.11.5. Do NOT use `deep-agent-backend/.venv`. PowerShell on
this machine does not support `&&` — use `;` or run commands separately.

## Scope

**In scope** (the only file you should modify):
- `configs/engine.yaml`

**Out of scope** (do NOT touch, even though they look related):
- `configs/engine.real_trace.yaml` — leave byte-for-byte unchanged; scripts
  reference it by explicit path.
- `configs/engine_demo_wazuh.yaml` — a separate, intentionally broader
  production demo profile (50 rounds / 400 probes, opt-in via
  `TRACE_ENGINE_DEMO_PROFILE=1`) already has its own `model_*` sections but
  not the pivot design; syncing pivot config into it is a separate decision
  the maintainer hasn't asked for — do not add it here.
- `deep-agent-backend/src/trace_deep_agent/tools.py` — do not change which
  file is the default; this plan fixes the *contents* of the default file,
  not the selection logic.
- `src/trace_engine/config.py` — no schema changes needed; every field this
  plan adds already exists in the dataclass (proven by
  `engine.real_trace.yaml` already using them successfully).
- Anything under `soar_mcp_env/` (local scenario replay data) — unrelated,
  this plan only touches the production Wazuh-backed config.

## Git workflow

- Branch: `advisor/020-sync-realtrace-config-defaults`
- One commit, short imperative message (this is a config-only change).
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Copy the pivot/bootstrap block into `soar_mcp:`

In `configs/engine.yaml`, inside the `soar_mcp:` block, after the existing
`query_template: "host:{host}"` line, insert:

```yaml
  # 种子只锁 1 条（T1048 + dst_ip），其余靠多轮 clue_pivot 回溯
  bootstrap_strategy: "seed_only"

  # pivot 探针查询模板（备用；clue_pivot 走 metadata.mcp_query 显式查询）
  pivot_field_map:
    clue_pivot: "srcip"
  query_template_by_pivot:
    host: "host:{value}"
    srcip: "data.srcip:{value}"
    dstuser: "data.dstuser:{value}"
    dst_ip: "data.dst_ip:{value}"

  # backward pivot 回溯链：从已确认事件属性回溯上一跳
  # attr = normalizer 归一后的 attributes 键；field = Wazuh Lucene 字段
  # 实测链: 种子(collected_file) → T1005(script_name) → T1059.004(src_ip)
  #        → T1078 / T1110.001（均用 src_ip；dstuser 会混入噪声登录）
  clue_pivot_rules:
    - attr: "collected_file"
      field: "data.collected_file"
      technique: "T1005"
      tactic: "collection"
    - attr: "script_name"
      field: "data.script_name"
      technique: "T1059.004"
      tactic: "execution"
    - attr: "src_ip"
      field: "data.srcip"
      technique: "T1078"
      tactic: "initial-access"
    - attr: "src_ip"
      field: "data.srcip"
      technique: "T1110.001"
      tactic: "credential-access"
```

**Verify**: file still parses as valid YAML —
`Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -c "import yaml; yaml.safe_load(open('configs/engine.yaml', encoding='utf-8'))"` → exit 0, no exception.

### Step 2: Widen the budget to match the pivot design

Replace:

```yaml
budget:
  total_rounds: 8
  total_probes: 30
  fanout_per_round: 4
```

with:

```yaml
budget:
  total_rounds: 10
  total_probes: 40
  fanout_per_round: 4
```

(Matches `engine.real_trace.yaml` — the seed_only/pivot design needs the
extra rounds to walk the full backward chain.)

**Verify**: same YAML-parses check as Step 1.

### Step 3: Add the model layers

At the end of the file (after the existing bootstrap-comment lines), append:

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

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -c "from trace_engine.config import EngineConfig; c = EngineConfig.load('configs/engine.yaml'); print(c.soar_mcp.bootstrap_strategy); print(c.soar_mcp.clue_pivot_rules[0]); print(c.model_planner.mode); print(c.model_judgement.mode); print(c.model_mcp_compiler.mode); print(c.budget.total_rounds)"` → prints `seed_only`, the first pivot rule dict, `shadow`, `assist`, `shadow`, `10` — exit 0, no exception.

### Step 4: Update the file's header comment to stop claiming a sync that didn't exist

Replace:

```yaml
# Windows trace-engine — 真实场景模式 (real_trace_01)
# 详见 REAL_TRACE_SCENARIO.md；专用副本: configs/engine.real_trace.yaml
```

with:

```yaml
# Windows trace-engine — 真实场景模式 (real_trace_01 v2, seed_only + clue_pivot)
# 详见 REAL_TRACE_SCENARIO.md 和 REAL_TRACE_HOST_ADAPTATION.md。
# 此文件是 deep-agent-backend 生产路径的默认配置
# （见 deep-agent-backend/src/trace_deep_agent/tools.py:_production_runner）。
# 保持与 configs/engine.real_trace.yaml 同步 — 两者当前应内容一致；
# 如果只改了其中一个，另一个也要同步更新。
```

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` → all pass (regression gate; this suite doesn't load `engine.yaml`, confirms nothing else broke).

## Test plan

This is a config-only change; there is no new Python test to write. The
verification gate is the Python one-liners in Steps 1–3 (config loads and
exposes the expected values) plus the existing `test_full_loop.py` regression
suite and the existing config-focused tests
(`tests/engine/test_config_ca_bundle.py`,
`tests/engine/test_config_demo_profile.py`,
`tests/engine/test_config_production_flags.py`) — none of these should
reference `configs/engine.yaml`'s specific field values, so they should be
unaffected; run them as a regression gate anyway.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `python -c "import yaml; yaml.safe_load(open('configs/engine.yaml', encoding='utf-8'))"` exits 0
- [ ] `python -c "from trace_engine.config import EngineConfig; c = EngineConfig.load('configs/engine.yaml'); assert c.soar_mcp.bootstrap_strategy == 'seed_only'; assert c.model_judgement.mode == 'assist'; assert c.budget.total_rounds == 10; print('OK')"` prints `OK` and exits 0
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes unchanged
- [ ] `configs/engine.real_trace.yaml` is byte-for-byte unchanged (`git diff --stat -- configs/engine.real_trace.yaml` shows no output)
- [ ] No files outside `configs/engine.yaml` are modified (`git status`)
- [ ] `plans/README.md` status row for 020 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The live content of `configs/engine.yaml` or `configs/engine.real_trace.yaml`
  doesn't match the "Current state" excerpts (drift — someone already
  started reconciling these files).
- `EngineConfig.load` raises an exception after your edits — this means a
  YAML indentation or key-naming mistake; fix by re-comparing against the
  exact block copied from `engine.real_trace.yaml`, don't guess at the
  schema.
- `src/trace_engine/config.py`'s dataclasses don't actually define
  `bootstrap_strategy`, `pivot_field_map`, `query_template_by_pivot`,
  `model_planner`, `model_judgement`, or `model_mcp_compiler` as you'd expect
  from the "Current state" section — report the mismatch instead of adding
  new schema fields (that would be a much larger, riskier change than this
  plan scopes for).

## Maintenance notes

- `configs/engine.yaml` and `configs/engine.real_trace.yaml` are now
  intentionally duplicated. This is a deliberate, low-risk short-term fix —
  the "real" long-term fix (not in scope here) would be for
  `_production_runner()` to load `engine.real_trace.yaml` directly and retire
  `engine.yaml`, or for one file to `!include` the other. Flag this
  duplication to whoever next edits either file: **a change to one must be
  mirrored in the other until this consolidation happens.**
- `configs/engine_demo_wazuh.yaml` (the `TRACE_ENGINE_DEMO_PROFILE=1` path)
  still does not have the pivot design. If the maintainer wants the demo
  profile to also exercise incremental discovery, that's a follow-up plan —
  don't fold it into this one.
- A reviewer should scrutinize: that the YAML block was copied verbatim
  (matching indentation, no typos in Lucene field names like `data.srcip`
  vs `data.src_ip` — the existing file already has this exact inconsistency
  between `pivot_field_map`'s `srcip` key and `clue_pivot_rules`' `src_ip`
  attr name; this plan intentionally preserves that as-is since it's an
  existing, working part of `engine.real_trace.yaml` — do not "fix" it here).
