# Plan 002: Make SOAR query execution lossless and time-safe

> **Executor instructions**: Preserve the transport abstraction and add
> explicit capability handling; do not special-case the three fixture names.
> Update `plans/README.md` when complete.
>
> **Drift check**:
>
> ```powershell
> Get-FileHash -Algorithm SHA256 `
>   src\trace_engine\soar_executor.py,`
>   src\trace_engine\transports.py,`
>   src\trace_engine\config.py
> ```
>
> Expected:
> `C2103A38F2CFAB01EB1DA4F50695A898C3CCB2D3B3A229482AFB66C9FD3555E8`,
> `6F32B78B9EFBF7250A1C6DB3E59841FA1EBFE7E6CDA3D417521DF78FD3E4492C`,
> `557AADEE51902A023096450517EFD3E8B7105AD07DE39272610A4115CBD4D2DF`.

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: MED — changes remote query count and time coverage
- **Depends on**: Plan 001
- **Category**: bug / architecture
- **Planned at**: workspace snapshot without Git metadata, 2026-07-03

## Why this matters

Same-host probes are collapsed by target, so only the first operator's data
source is queried. The executor also advances a fixture-oriented 24-hour cursor
and assumes ascending, exact time-bound pagination even when Wazuh exposes only
coarse ranges. Real investigations can silently miss entire evidence families
or query future/unbounded data.

## Current state

- `SoarMcpProbeExecutor.execute_fanout()` deduplicates by target only at
  `src/trace_engine/soar_executor.py:187-194`.
- `_fetch_for_probe()` chooses a datasource from the operator at lines 177–185;
  therefore later operators on the same host never fetch their source.
- `_window_ms()` uses `TIME_WINDOW_STEP` from the scenario executor and returns
  `cursor + 24h` at lines 50–56.
- `ScenarioExecutor.execute_fanout()` advances that cursor by 24 hours at
  `src/trace_agent/loop/scenario_executor.py:222-227`.
- `_fetch_paginated()` assumes full pages are time-ascending and advances from
  maximum timestamp.
- `WazuhMcpTransport` converts arbitrary spans to `1d/7d/30d`; it does not
  honor exact `from_ms`.

## Commands

| Purpose | Command | Expected |
|---|---|---|
| Executor tests | `$env:PYTHONPATH='src'; python -m pytest tests\engine\test_soar_executor.py tests\engine\test_wazuh_transport.py -q` | all pass |
| Full engine | `$env:PYTHONPATH='src'; python -m pytest tests\engine -q` | all pass |

## Scope

**In scope**

- `src/trace_engine/soar_executor.py`
- `src/trace_engine/transports.py`
- `src/trace_engine/config.py`
- `src/trace_agent/loop/probe.py` if adding a typed query window
- `tests/engine/test_soar_executor.py`
- `tests/engine/test_wazuh_transport.py`
- `configs/engine.example.yaml`

**Out of scope**

- Model-based probe planning.
- Vendor-specific query syntax without a declared transport capability.
- Increasing page limits to hide pagination bugs.

## Steps

### Step 1: Introduce a transport capability contract

Add immutable capabilities describing exact time bounds, stable ascending sort,
cursor/search-after support, and supported query dimensions. Generic MCP and
Wazuh transports must declare their actual behavior.

**Verify**: unit tests assert each transport's capabilities.

### Step 2: Deduplicate equivalent queries, not targets

Build a canonical query key from target, datasource, operator-specific
dimensions, and time window. Fetch once only when two probes produce the same
canonical query. Keep a mapping from fetched records back to every originating
probe so Beta/calibration outcomes remain per probe.

**Verify**: a same-host batch containing `auth_log`, `network_flow`, and
`process_tree` issues three source-appropriate queries; two identical probes
issue one.

### Step 3: Separate fixture time progression from production windows

Keep progressive 24-hour replay only inside `ScenarioExecutor`. Production
windows must be anchored to alert time and current time with configured
lookback/lookahead bounds. Never query beyond `now + allowed_clock_skew`.

Add explicit configuration for lookahead and clock skew; default lookahead to
zero for live investigations.

**Verify**: tests with old, current, and future-dated alerts assert exact bounds.

### Step 4: Make pagination capability-aware

For exact cursor transports, enforce stable order and detect repeated cursors.
For coarse Wazuh ranges, use a supported search-after/page mechanism if
available. If unavailable and a full page is returned, report
`coverage_truncated=true` with the affected query instead of pretending the
window is complete.

**Verify**: duplicate pages terminate deterministically and surface truncation;
out-of-order pages are sorted or rejected per capability.

### Step 5: Expose coverage diagnostics

Report queries by operator/datasource, requested and observed time bounds,
pages, deduplicated query count, truncations, and errors. Preserve these fields
through `InvestigationRunner._build_report()`.

**Verify**: engine E2E report contains the diagnostics with no raw credentials.

## Test plan

- Same host, different datasource.
- Identical query deduplication.
- Exact and coarse pagination.
- Repeated cursor/full-page truncation.
- Future-time exclusion and clock skew.
- Probe-to-query attribution.

## Done criteria

- [x] No target-only fetch deduplication remains.
- [x] Production does not use scenario time advancement.
- [x] Pagination incompleteness is explicit.
- [x] Full engine/core tests pass.
- [x] Query diagnostics are present in reports.
- [x] Plan index updated.

Implementation result (2026-07-03): executor/transport `18 passed`;
engine `33 passed`; full engine/core `296 passed`.

## STOP conditions

- The production MCP tool offers neither exact time filtering nor pagination:
  STOP and document the upstream API requirement.
- Record ordering cannot be established from a stable field.
- A change would require embedding vendor credentials or query secrets.

## Maintenance notes

Every new transport must declare capabilities and pass the shared pagination
contract tests. Model planners in Plan 006 may propose windows only within the
executor's validated bounds.
