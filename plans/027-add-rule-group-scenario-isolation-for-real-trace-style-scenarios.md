# Plan 027: Add a rule-group-based isolation option for scenarios without incident_id (real_trace_01-style)

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_engine/scenario_registry.py `
>   src/trace_engine/transports.py soar_mcp_env/registry.json
> ```
> `scenario_registry.py` and `transports.py` are tracked at `9dadd88` and
> unmodified relative to it as of this plan's writing (should print
> nothing).

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none (complements Plan 025, which filters noise
  post-fetch; this plan reduces noise pre-fetch at the query level for
  scenarios that opt in)
- **Category**: dx / data quality (test-environment isolation)
- **Planned at**: commit `9dadd88`, 2026-07-04

## Why this matters

A reviewer suggested that mock scenarios sharing one Wazuh Indexer
(`pipeline_18`, `apt_5host`, `multipath_12host`, `real_trace_01`) should
have query-level isolation to reduce cross-scenario data pollution slowing
down investigations. Reading the code shows three of those four scenarios
already have this: `resolve_wazuh_scope()`
(`src/trace_engine/scenario_registry.py:32-58`) maps a `scenario_id` to a
`data.incident_id:"INC-..."` (or `data.scenario:"..."`) tag that
`WazuhMcpTransport._compose_wazuh_query` (`src/trace_engine/transports.py:635-657`)
prepends to every query for that scenario. `real_trace_01` is the outlier —
it's documented (`REAL_TRACE_SCENARIO.md` §1, `REAL_TRACE_HOST_ADAPTATION.md`
§1) as deliberately having **no** `incident_id`/`is_attack` fields, because
it's meant to look like genuine unmodified Wazuh telemetry. That's the right
design choice for realism, but it means `real_trace_01` currently has *no*
isolation mechanism at all — every query against it (and every wide
host-scoped query from *other* scenarios sharing the same Indexer) can
return `real_trace_01`'s injected events, and vice versa.

`REAL_TRACE_SCENARIO.md` §8 documents that the scenario's custom Wazuh rules
(rule IDs `100101`–`100105`, in
`config/custom_rules/local_real_trace_rules.xml`) already tag matching
events with `rule.groups: real_trace` — a debug-only isolation signal the
adaptation doc explicitly floats as an option
(`REAL_TRACE_HOST_ADAPTATION.md` §4.2: "或在本场景调试阶段加
`rule.groups:real_trace` 作隔离") but the engine has no code path to apply
it automatically. This plan wires that existing tag into the same
`WazuhScenarioScope`/`_compose_wazuh_query` mechanism the other three
scenarios already use, as an **additional scope-field option**, not a
replacement for the existing incident/scenario tagging.

## Current state

- `src/trace_engine/scenario_registry.py:14-58` — the full current
  `WazuhScenarioScope` dataclass and its resolver:

```python
@dataclass(frozen=True)
class WazuhScenarioScope:
    """Wazuh MCP query partition for a known indexed scenario."""

    incident_prefix: str
    scope_field: str = "incident"
    attacks_only: bool = False
    indexed_attack_chain: bool = False
    scenario_slug: str = ""


def resolve_wazuh_scope(scenario_id: str | None) -> WazuhScenarioScope | None:
    """Map scenario_id to Wazuh incident/is_attack scope when registry defines it."""
    if not scenario_id:
        return None
    spec = (_load_registry().get("scenarios") or {}).get(scenario_id) or {}
    raw = spec.get("wazuh_scope") or spec.get("wazuh") or {}
    if not raw:
        return None
    incident_prefix = str(
        raw.get("incident_prefix")
        or raw.get("incident_id")
        or ""
    ).strip()
    if not incident_prefix:
        return None
    scope_field = str(raw.get("scope_field") or "incident").strip().lower()
    if scope_field not in ("auto", "scenario", "incident"):
        scope_field = "incident"
    attacks_only = bool(raw.get("attacks_only", False))
    indexed = bool(raw.get("indexed_attack_chain", attacks_only))
    return WazuhScenarioScope(
        incident_prefix=incident_prefix,
        scope_field=scope_field,
        attacks_only=attacks_only,
        indexed_attack_chain=indexed,
        scenario_slug=str(raw.get("scenario_slug") or scenario_id),
    )
```

  Note `resolve_wazuh_scope` returns `None` whenever `incident_prefix` is
  empty — this is exactly why `real_trace_01` (no incident_id by design) can
  never get a scope from this function today, even if it were added to
  `soar_mcp_env/registry.json`.

- `src/trace_engine/transports.py:635-657` (`_compose_wazuh_query`) — the
  query-composition logic that consumes `incident_prefix`/`scope_field`/
  `attacks_only` (read via whatever config object populates
  `self.incident_prefix`, `self.scope_field`, `self.attacks_only`,
  `self.scenario_slug` on the transport instance — trace this assignment
  before making changes, likely in `WazuhMcpTransport.__init__` or a
  `configure_scope`-style method):

```python
    def _compose_wazuh_query(self, query: str) -> str:
        wazuh_query = self._to_wazuh_query(query)
        if self.incident_prefix:
            prefix = self.incident_prefix.strip()
            prefix_term = self._quote_term(prefix)
            if self.scope_field == "incident" or (
                self.scope_field == "auto"
                and prefix.upper().startswith("INC-")
            ):
                tag = f"data.incident_id:{prefix_term}"
            else:
                tag = f"data.scenario:{prefix_term}"
            if self.attacks_only:
                tag = f"{tag} AND data.is_attack:true"
            wazuh_query = f"{tag} AND ({wazuh_query})" if wazuh_query != "*" else tag
        elif (
            self.scenario_slug
            and "data.raw_log_ref:" in wazuh_query
            and "data.scenario:" not in wazuh_query
        ):
            slug_term = self._quote_term(self.scenario_slug)
            wazuh_query = f'data.scenario:{slug_term} AND ({wazuh_query})'
        return wazuh_query
```

- `soar_mcp_env/registry.json` — read this file in full before editing; it
  currently has entries for `pipeline_18`, `apt_5host`, `multipath_12host`
  (per the earlier investigation), each with a `wazuh_scope` block using
  `incident_prefix`/`scope_field`/`attacks_only`. `real_trace_01` has no
  entry.

- `configs/engine.real_trace.yaml` — currently sets
  `wazuh_incident_prefix: ""` and `wazuh_attacks_only: false` explicitly
  (per Plan 020's documented config), with a comment noting these must stay
  empty because the scenario has no `incident_id`/`is_attack` fields.

- `REAL_TRACE_SCENARIO.md` §8 — confirms the rule-group tag already exists
  server-side: `config/custom_rules/local_real_trace_rules.xml` (rules
  `100101`–`100105`) tags matching events, and the doc's own query examples
  (§5 Step 2/3) already use `rule.groups:real_trace AND ...` manually.

## Design decision (do not redesign — implement exactly this)

1. **Add a new `scope_field` value, `"rule_group"`, and a new
   `WazuhScenarioScope` field, `rule_group: str = ""`**, alongside the
   existing `incident_prefix`-based fields — do not replace or repurpose
   `incident_prefix` for this, since `real_trace_01` has no incident concept
   at all; this is a parallel, independent tagging mechanism.
2. **`resolve_wazuh_scope` must return a scope even when `incident_prefix`
   is empty, if a `rule_group` is configured.** Change the early-return
   condition from "no incident prefix → None" to "neither incident prefix
   nor rule group configured → None".
3. **`_compose_wazuh_query` composes a `rule.groups:{value}` tag exactly
   like it composes `data.incident_id:{value}`**, applied independently (a
   scenario could in principle have both, though none currently do) — when
   `rule_group` is set, AND it into the query the same way, using the same
   quoting helper (`_quote_term`) already used for the other tags.
4. **Register `real_trace_01` in `soar_mcp_env/registry.json`** with
   `wazuh_scope: {rule_group: "real_trace", scope_field: "rule_group"}`, and
   leave `configs/engine.real_trace.yaml`'s `wazuh_incident_prefix`/
   `wazuh_attacks_only` exactly as they are (still empty/false — this plan
   adds an *additional* isolation channel, it does not touch the existing
   incident/attacks_only settings that are correctly empty for this
   scenario).
5. **This is opt-in and additive** — no existing scenario's queries change
   unless `soar_mcp_env/registry.json` explicitly adds a `rule_group` value
   for it.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Transport / query composition tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine -k "transport or query or scenario_registry" -q` (adjust the `-k` filter after checking actual test file/function names for this area) | all pass |
| Full engine test suite | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine -q` | no new failures versus baseline (this suite is large and may include network-dependent tests that hang/timeout in a sandboxed environment without live MCP access — if so, note which tests were skipped/excluded and why in your summary rather than blocking on them) |

Use system Python 3.11.5. PowerShell on this machine does not support `&&` —
use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_engine/scenario_registry.py`
- `src/trace_engine/transports.py`
- `soar_mcp_env/registry.json`
- Whichever existing test file covers `resolve_wazuh_scope`/
  `_compose_wazuh_query` (search for one before assuming none exists; add a
  new one only if truly none covers this area)

**Out of scope** (do NOT touch, even though they look related):
- `configs/engine.real_trace.yaml` / `configs/engine.yaml` — do not add a
  rule-group setting to either config file; the isolation tag is resolved
  server-side via `scenario_registry.py` keyed by `scenario_id`, matching
  how the other three scenarios already work, not via engine YAML.
- `config/custom_rules/local_real_trace_rules.xml` — this is the server-side
  Wazuh rule definition (lives on the remote Manager, not in this repo's
  runtime path); this plan only wires the host-side query composition to
  use the tag that already exists there.
- Plan 025's `scenario_technique_allowlist` — a different, complementary,
  post-fetch filtering mechanism; do not merge the two into one config key.

## Git workflow

- Branch: `advisor/027-rule-group-scenario-isolation`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Extend `WazuhScenarioScope` and `resolve_wazuh_scope`

In `src/trace_engine/scenario_registry.py`:

```python
@dataclass(frozen=True)
class WazuhScenarioScope:
    """Wazuh MCP query partition for a known indexed scenario."""

    incident_prefix: str
    scope_field: str = "incident"
    attacks_only: bool = False
    indexed_attack_chain: bool = False
    scenario_slug: str = ""
    rule_group: str = ""


def resolve_wazuh_scope(scenario_id: str | None) -> WazuhScenarioScope | None:
    """Map scenario_id to Wazuh incident/is_attack/rule-group scope when registry defines it."""
    if not scenario_id:
        return None
    spec = (_load_registry().get("scenarios") or {}).get(scenario_id) or {}
    raw = spec.get("wazuh_scope") or spec.get("wazuh") or {}
    if not raw:
        return None
    incident_prefix = str(
        raw.get("incident_prefix")
        or raw.get("incident_id")
        or ""
    ).strip()
    rule_group = str(raw.get("rule_group") or "").strip()
    if not incident_prefix and not rule_group:
        return None
    scope_field = str(raw.get("scope_field") or "incident").strip().lower()
    if scope_field not in ("auto", "scenario", "incident", "rule_group"):
        scope_field = "incident"
    attacks_only = bool(raw.get("attacks_only", False))
    indexed = bool(raw.get("indexed_attack_chain", attacks_only))
    return WazuhScenarioScope(
        incident_prefix=incident_prefix,
        scope_field=scope_field,
        attacks_only=attacks_only,
        indexed_attack_chain=indexed,
        scenario_slug=str(raw.get("scenario_slug") or scenario_id),
        rule_group=rule_group,
    )
```

**Verify**: `python -m pytest tests\engine -k "scenario_registry" -q` (or the equivalent test area you found) → all pass.

### Step 2: Thread `rule_group` through to the transport and compose it into queries

First, find where `WazuhScenarioScope`'s fields (`incident_prefix`,
`scope_field`, `attacks_only`, `scenario_slug`) get copied onto the
`WazuhMcpTransport` instance (grep for `scenario_slug =` or
`incident_prefix =` assignment in `transports.py` or wherever the transport
is constructed/configured) and add `self.rule_group = scope.rule_group` (or
equivalent) at the same place, matching the existing pattern exactly.

Then, in `_compose_wazuh_query`, add rule-group composition alongside the
existing incident-prefix branch:

```python
    def _compose_wazuh_query(self, query: str) -> str:
        wazuh_query = self._to_wazuh_query(query)
        if self.incident_prefix:
            prefix = self.incident_prefix.strip()
            prefix_term = self._quote_term(prefix)
            if self.scope_field == "incident" or (
                self.scope_field == "auto"
                and prefix.upper().startswith("INC-")
            ):
                tag = f"data.incident_id:{prefix_term}"
            else:
                tag = f"data.scenario:{prefix_term}"
            if self.attacks_only:
                tag = f"{tag} AND data.is_attack:true"
            wazuh_query = f"{tag} AND ({wazuh_query})" if wazuh_query != "*" else tag
        elif getattr(self, "rule_group", ""):
            group_term = self._quote_term(self.rule_group.strip())
            tag = f"rule.groups:{group_term}"
            wazuh_query = f"{tag} AND ({wazuh_query})" if wazuh_query != "*" else tag
        elif (
            self.scenario_slug
            and "data.raw_log_ref:" in wazuh_query
            and "data.scenario:" not in wazuh_query
        ):
            slug_term = self._quote_term(self.scenario_slug)
            wazuh_query = f'data.scenario:{slug_term} AND ({wazuh_query})'
        return wazuh_query
```

Note the `elif` ordering: `incident_prefix` takes priority when both happen
to be set (none of the current scenarios set both, but this keeps the
existing three scenarios' behavior byte-for-byte unchanged), and
`rule_group` is checked before the `scenario_slug` fallback so it doesn't
get shadowed by that pre-existing branch.

**Verify**: `python -m pytest tests\engine -k "transport" -q` (adjust filter per actual test names) → all pass.

### Step 3: Register `real_trace_01` in the scenario registry

In `soar_mcp_env/registry.json`, add an entry for `real_trace_01` (match the
existing indentation/structure used by `pipeline_18`/`apt_5host`/
`multipath_12host`):

```json
    "real_trace_01": {
      "wazuh_scope": {
        "rule_group": "real_trace",
        "scope_field": "rule_group"
      }
    }
```

If `real_trace_01` already has a registry entry for non-Wazuh-scope purposes
(check first — do not assume it's absent), add the `wazuh_scope` key to the
existing entry instead of creating a duplicate top-level key.

**Verify**: run a short Python snippet (not a persistent test file) to
confirm resolution works:

```powershell
Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -c "from trace_engine.scenario_registry import resolve_wazuh_scope; s = resolve_wazuh_scope('real_trace_01'); print(s)"
```

Expected: a `WazuhScenarioScope` with `rule_group='real_trace'`,
`scope_field='rule_group'`, `incident_prefix=''`.

## Test plan

Add to whichever existing test file covers `scenario_registry.py`/
`transports.py` query composition (search first; if genuinely no such file
exists, create `tests/engine/test_scenario_registry.py` following the
structure of a sibling test file in `tests/engine/`):

- `test_resolve_wazuh_scope_rule_group_only_scenario` — call
  `resolve_wazuh_scope("real_trace_01")` (after Step 3 lands) and assert
  `rule_group == "real_trace"`, `scope_field == "rule_group"`,
  `incident_prefix == ""`.
- `test_resolve_wazuh_scope_returns_none_when_neither_field_set` — a
  registry entry with an empty `wazuh_scope: {}` block still returns `None`
  (regression guard for the changed early-return condition).
- `test_compose_wazuh_query_applies_rule_group_tag` — construct/configure a
  transport instance with `rule_group="real_trace"` and no
  `incident_prefix`, call `_compose_wazuh_query("data.srcip:203.0.113.50")`,
  assert the result starts with `rule.groups:"real_trace" AND (...)` (or
  whatever exact quoting `_quote_term` produces — match its actual output
  format, don't guess the quote characters).
- `test_compose_wazuh_query_incident_prefix_takes_priority_over_rule_group`
  — construct a transport with both `incident_prefix` and `rule_group` set
  (even though no real scenario does this today); assert only the incident
  tag is applied, proving the existing three scenarios' behavior can never
  be affected by this plan even if a future registry entry sets both by
  mistake.

Verification: `python -m pytest tests\engine -k "scenario_registry or transport" -q` → all pass, including the new tests.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "rule_group" src/trace_engine/scenario_registry.py src/trace_engine/transports.py soar_mcp_env/registry.json` shows matches in all three files
- [ ] The verification `python -c` snippet in Step 3 prints a `WazuhScenarioScope` with `rule_group='real_trace'`
- [ ] New/updated tests for `scenario_registry`/`transports` pass
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 027 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `soar_mcp_env/registry.json` already has a `real_trace_01` entry with a
  different structure than expected, or the file's schema doesn't match the
  "Current state" description (drift) — read the actual current schema and
  adapt the new entry to match it, or report if the schema is incompatible
  with this plan's design.
- The transport class doesn't expose a clear single place where
  `WazuhScenarioScope` fields get copied onto instance attributes (e.g. if
  scope resolution happens per-call rather than once at construction) —
  report the actual wiring pattern instead of guessing where to add
  `self.rule_group`.
- Any of the three existing scenarios' (`pipeline_18`/`apt_5host`/
  `multipath_12host`) composed queries change after this plan — the `elif`
  ordering in Step 2 is specifically designed to prevent this; if it happens
  anyway, there is a wiring bug in how `rule_group` defaults for scenarios
  that don't set it (it must default to falsy/empty, never leak a stale
  value from a previous scope resolution).
- The real Wazuh Manager's custom rules (`100101`–`100105`) turn out not to
  reliably tag `rule.groups: real_trace` on every relevant event (e.g. if
  only some of the 6 attack-chain events get the tag) — this would mean the
  isolation tag would need to be combined with the existing pivot-based
  bootstrap query strategy (Plan 020) rather than applied universally; if
  you can't verify this against `config/custom_rules/local_real_trace_rules.xml`
  or the server-side deployment, report it as unverifiable rather than
  assuming full coverage.

## Maintenance notes

- `REAL_TRACE_HOST_ADAPTATION.md` §7's "禁止查询清单" explicitly lists
  `rule.groups:real_trace AND data.srcip:203.0.113.50` as a **anti-pattern
  for the v2 pivot design** (bundling it with a wide `srcip` query still
  mixes attack + noise, just within the scenario's own tag) — this plan
  applies the rule-group tag uniformly to *all* queries against this
  scenario (bootstrap, pivot, and any ad-hoc probe), which narrows the
  shared-Indexer cross-scenario pollution problem this plan targets, but
  does **not** by itself fix the separate v1-vs-v2 pivot-design noise
  problem that Plan 025 addresses. Both plans are complementary — land
  either independently, both together for the strongest effect.
- If a future real-world (non-lab) Wazuh deployment is added as a "scenario"
  for this engine, it will have no custom rule groups to tag with — the
  `rule_group` field's `""` default correctly falls through to no isolation
  for that case, matching the current `real_trace_01`-without-this-plan
  behavior, which is the appropriate (if imperfect) fallback for genuinely
  unmodified production Wazuh.
