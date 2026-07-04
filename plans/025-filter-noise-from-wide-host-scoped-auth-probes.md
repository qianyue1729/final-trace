# Plan 025: Filter non-MITRE noise out of wide host-scoped auth_log/probe queries before WEAK-bucket counting

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/loop/ingest.py src/trace_engine/normalizer.py
> ```
> Both files are tracked at `9dadd88` and unmodified relative to it as of
> this plan's writing (should print nothing).

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none (complements Plan 022, which also touches
  `IngestPipeline`, but is independently scoped — this plan filters noise
  *before* triage; Plan 022 fixes attribution scoring *during* triage)
- **Category**: bug (data quality / reporting accuracy)
- **Planned at**: commit `9dadd88`, 2026-07-04

## Why this matters

A reviewer compared a report's noise summary — "4 次失败登录
(`203.0.113.50` → `root`/`admin`/`ubuntu`)" — against the `real_trace_01` v2
scenario's documented design (`REAL_TRACE_HOST_ADAPTATION.md` §3.1, §5.3):
the scenario injects exactly **3** noise events, all same `srcip`, dest users
`opsadmin`/`root`/`admin` — **never** `ubuntu`. The `ubuntu` failed-login
events are the real attack chain's `T1110.001` step, not noise. Mixing them
into a "4 failed logins, noise" count means the report conflated genuine
attack-chain evidence with injected noise under one number.

The adaptation doc already documents the fix as a *query-time* contract:

> "宽查 `data.srcip:203.0.113.50` 会返回 7+ 条(含 3 噪声)。引擎应：禁止将宽查
> 结果直接并入攻击主图；仅接受带 `mitre_technique` 且 technique 属于
> `{T1110.001,T1078,T1059.004,T1005,T1048}` 的记录；可选:排除
> `event_type:*_benign`。"

Reading the code confirms this filter does not exist yet. The
`cross_host_probe_generator` (used for any known host, including the
scenario's own `wazuh.manager` when acting as "alert host" — see its
exception clause) emits `auth_log` probes with `target=host` only, which
`_to_wazuh_query`/the transport layer expands to a **bare hostname** Lucene
query (`data.hostname:X OR data.host:X OR agent.name:X`) with no MITRE
technique or rule-group restriction. Against a shared Wazuh Indexer (per
`REAL_TRACE_HOST_ADAPTATION.md` §5.3 and §7's "禁止查询清单"), this returns
every `sshd`/`pam` event for that host — synthetic attack-chain events,
synthetic noise events, and (per the reviewer's suspicion) potentially real
host `sshd` syslog the Manager itself generates, all indistinguishably mixed
into whatever bucket `IngestPipeline` routes them to. Once in the `WEAK`
bucket, nothing downstream separates "noise event with no MITRE mapping"
from "weak-but-real attack evidence" when producing the noise-count summary
consumed by the report.

## Current state

- `src/trace_agent/loop/generators.py:656-715` (`cross_host_probe_generator`)
  — emits bare host-scoped `auth_log` probes, no technique restriction:

```python
    for host in candidates[:8]:
        is_workstation = host.upper().startswith("WS-")
        is_alert_host = host.lower() == alert_lower
        # auth_log 探针
        probe_id = Probe.generate_id(host, "auth_log", "initial-access")
        probes.append(
            Probe(
                id=probe_id,
                target=host,
                target_type="host",
                operator="auth_log",
                tactic="initial-access",
                source="cross_host",
                explanation_ids=[],
                metadata={"gap_type": "cross_host", "target_host": host},
                priority_hint=0.96 if (is_workstation or is_alert_host) else 0.58,
            )
        )
```

- `src/trace_engine/transports.py:539-551` (`_to_wazuh_query`) — expands a
  bare `host:{name}` probe token into an unrestricted host-scope Lucene
  query:

```python
        clauses: list[str] = []
        for token in query.split():
            low = token.lower()
            if low in ("and", "or", "not"):
                continue
            if low.startswith("host:"):
                host = token.split(":", 1)[1].strip()
                if host:
                    host_term = WazuhMcpTransport._quote_term(host)
                    clauses.append(
                        f"(data.hostname:{host_term} OR data.host:{host_term} OR "
                        f"agent.name:{host_term})"
                    )
```

  This has no awareness of `operator="auth_log"` or `tactic="initial-access"`
  from the originating `Probe` — by the time the query string reaches this
  function, that context is gone; it only sees a `host:{name}` token.

- `src/trace_engine/transports.py:287-301` — Wazuh `authentication_failed` /
  `sshd` / `pam` rule groups are normalized to `action="AUTH"` regardless of
  whether the underlying event carries a MITRE mapping:

```python
        if not out.get("action"):
            if groups & {
                "authentication_failed",
                "authentication_failures",
                "authentication_success",
                "sshd",
                "pam",
            }:
                out["action"] = "AUTH"
                out.setdefault("ocsf_class_uid", 5002)
```

- `src/trace_agent/loop/ingest.py:1-26` — `_REQUIRED_FIELDS` does not
  include `technique` as a value-required field beyond "non-empty string";
  an event with `technique=None` fails L0 already (see
  `_l0_denoise`'s `any(not event.get(f) for f in _REQUIRED_FIELDS)` check),
  so purely technique-less noise is *already* dropped by L0 — but the
  reviewer's scenario shows `ubuntu` failed-login events (which DO have
  `technique=T1110.001`) mixed into "噪声" counting, meaning the conflation
  happens on events that all *have* a technique, and the actual gap is that
  nothing distinguishes "this technique belongs to the real_trace_01 attack
  set" from "this technique/event is unrelated noise picked up by the wide
  host query" once both pass L0.
- `REAL_TRACE_HOST_ADAPTATION.md` §2 documents the exact allow-list this
  scenario's engine-side filtering should use:
  `{T1110.001, T1078, T1059.004, T1005, T1048}`.
- No config or code currently expresses this allow-list — `configs/engine.yaml`'s
  `clue_pivot_rules` (see Plan 020) hard-codes specific techniques per pivot
  *step*, but nothing filters a wide `auth_log`/`host:` probe's *raw results*
  against a scenario-level technique allow-list before they reach
  `IngestPipeline.triage()`.

## Design decision (do not redesign — implement exactly this)

1. **Do not touch the query-generation or transport layer** — restricting
   Lucene queries per-scenario is out of scope and risks breaking other
   scenarios (`pipeline_18`, `apt_5host`, `multipath_12host`) that
   legitimately want wide host-scoped results. Filter at the point where
   raw probe results are about to enter `IngestPipeline.triage()`, using
   information already available in each event's normalized `attributes`.
2. **Add an opt-in, config-driven technique allow-list for wide
   host/srcip-scoped probes.** When a probe's `operator` is one of a small
   configurable set (`auth_log` to start, matching this bug report) **and**
   the resulting event has a `technique` that is present but does **not**
   match a scenario-supplied allow-list (when one is configured), route the
   event as before if no allow-list is configured (default: no behavior
   change for scenarios without one), but treat it as noise-for-reporting
   purposes when an allow-list *is* configured and the technique isn't on
   it.
3. **Do not conflate "noise" with "WEAK".** Add a distinct classification —
   `is_probe_scope_noise` — set on events whose technique fails the
   allow-list check, and thread it through to whatever produces the
   noise-count summary in the report, so "N failed logins (noise)" and "M
   WEAK-bucket weak-attribution attack evidence" are counted and reported
   separately, never combined into one number.
4. **This plan does not need to change which bucket (`WEAK`/`PARK`) the
   event lands in** — `_l4_route`'s existing routing logic is untouched. It
   only adds an additional annotation used for **counting/reporting**, so
   this plan's risk to existing attach/route behavior is minimal.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| C-phase / ingest tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_c_phase.py -q` | all pass |
| Full loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass, same pass count as before |
| Engine config tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_config.py -q` (if this file doesn't exist, search for wherever `NormalizerConfig`/scenario config parsing is tested and run that instead — note which in your summary) | all pass |

Use system Python 3.11.5. PowerShell on this machine does not support `&&` —
use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/loop/ingest.py`
- `src/trace_engine/config.py` (add the optional allow-list config field —
  read this file first to find where scenario-level engine config is
  defined and match its existing style)
- `configs/engine.real_trace.yaml` (populate the new allow-list field for
  this scenario specifically, using the 5 techniques from
  `REAL_TRACE_HOST_ADAPTATION.md` §2)
- `src/trace_agent/tests/test_c_phase.py`

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_engine/transports.py` — query construction stays as-is; this is
  a post-fetch classification filter, not a query restriction.
- `src/trace_agent/loop/generators.py` — probe generation is unchanged;
  wide host-scoped `auth_log` probes are still legitimate and necessary for
  scenarios that need them.
- `configs/engine.yaml` (the default production config) — do not add the
  `real_trace_01`-specific technique allow-list here; it is scenario-specific
  and belongs only in `configs/engine.real_trace.yaml`. (If Plan 020's
  config-sync work is applied to `engine.yaml` as well, coordinate rather
  than duplicating this plan's config key there — check for a
  `technique_allow_list`-shaped key already present from Plan 020 before
  adding a second one.)
- Plan 022's L0 informational-event filter (`_is_informational_event`) —
  unrelated: that filter targets Wazuh's own zero-MITRE housekeeping events;
  this plan targets events that **do** have a technique but aren't part of
  the active scenario's attack-chain technique set.

## Git workflow

- Branch: `advisor/025-scenario-noise-allowlist`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Add an optional scenario-level technique allow-list config field

In `src/trace_engine/config.py`, find the dataclass/structure that holds
per-scenario or per-engine-run configuration (read the file first to match
its existing field style and naming convention — likely near
`NormalizerConfig` or wherever `soar_mcp`/`normalizer` top-level YAML keys
are parsed). Add a new optional field, e.g.:

```python
    # Optional: when set, wide host/srcip-scoped probe results (e.g. auth_log
    # against a whole host) whose technique isn't in this list are marked as
    # scope-noise for reporting purposes, not silently mixed into the attack
    # evidence count. Scenarios without this configured see no behavior
    # change (opt-in only).
    scenario_technique_allowlist: list[str] = field(default_factory=list)
```

Wire it through wherever the engine config is loaded from YAML into this
structure (match the existing pattern for other optional list/scalar
fields in the same file).

**Verify**: `python -m pytest tests\engine\test_config.py -q` (or the
equivalent config-parsing test file you found) → all pass.

### Step 2: Add the allow-list to `configs/engine.real_trace.yaml`

Add, at the top level (matching the YAML structure already used for
`normalizer`/`budget` blocks):

```yaml
# Scenario-level technique allow-list (REAL_TRACE_HOST_ADAPTATION.md §2).
# Wide host/srcip-scoped probes (e.g. auth_log) legitimately return events
# outside this set from the shared Wazuh Indexer; mark those as scope-noise
# rather than mixing them into attack-evidence counts.
scenario_technique_allowlist:
  - "T1110.001"
  - "T1078"
  - "T1059.004"
  - "T1005"
  - "T1048"
```

### Step 3: Classify out-of-allowlist events during triage, without changing routing

In `src/trace_agent/loop/ingest.py`, add a constructor parameter to
`IngestPipeline` for the allow-list (default empty = no behavior change):

```python
    def __init__(self, trust_model, graph: SessionGraph, ledger=None,
                 scenario_technique_allowlist: Optional[list[str]] = None):
        """
        Args:
            trust_model: EvidenceTrustModel (for L2 trust assessment)
            graph: SessionGraph (for L1 structural check)
            ledger: RuntimeDecisionLedger (for L3 explanation attribution, optional)
            scenario_technique_allowlist: optional list of MITRE technique
                IDs considered part of this scenario's attack chain. When
                set, events whose technique is present but NOT in this list
                are annotated `_is_probe_scope_noise=True` for
                reporting/counting purposes (does not change ATTACH/WEAK/
                PARK routing).
        """
        self._trust = trust_model
        self._graph = graph
        self._ledger = ledger
        self._seen_ids: set[str] = set()  # L0 dedup
        self._scenario_technique_allowlist = set(scenario_technique_allowlist or [])
```

Then, in `triage()`, right after L4 routing assigns `event["_route_bucket"]`
(near `self._materialize_candidate_link(event, bucket)`), add the
annotation:

```python
            event["_is_probe_scope_noise"] = self._is_scope_noise(event)
```

and add the helper:

```python
    def _is_scope_noise(self, event: dict) -> bool:
        """True when this event's technique is outside the configured
        scenario allow-list — i.e. it's a wide-query artifact (real host
        syslog or a different scenario's injected data on a shared Indexer),
        not attack-chain evidence, even though it has *some* technique tag."""
        if not self._scenario_technique_allowlist:
            return False
        technique = event.get("technique") or (event.get("attributes") or {}).get(
            "mitre_technique"
        )
        if not technique:
            return False
        return technique not in self._scenario_technique_allowlist
```

Finally, add `is_probe_scope_noise` to the `trust_annotations` entry already
built in `triage()` (next to `trust_tier`/`integrity`), so downstream
reporting code has it without needing to re-derive it:

```python
            result.trust_annotations.append({
                "event_id": event.get("id"),
                "trust_tier": event.get("_l2_trust_tier", "unknown"),
                "integrity": event.get("_l2_integrity", 0.0),
                "adversary_controllable": event.get("_l2_adversary_controllable", False),
                "is_probe_scope_noise": event.get("_is_probe_scope_noise", False),
            })
```

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` → all pass (existing callers that don't pass `scenario_technique_allowlist` see identical behavior — the parameter defaults to `None`/empty).

### Step 4: Wire the allow-list from session/engine config into `IngestPipeline` construction

Find where `IngestPipeline(...)` is constructed for the live session
(`src/trace_agent/agents/lock_session.py:224`, per the earlier grep in this
plan's investigation) and pass the configured allow-list through from
`runner.config` (read `src/trace_engine/runner.py` to see how `config` is
threaded into session construction, and match the existing pattern for
other config values already passed down this path).

**Verify**: `python -m pytest src\trace_agent\tests\test_full_loop.py -q` → all pass, same pass count as before (no scenario in the existing fixture set configures `scenario_technique_allowlist`, so this step must be a no-op for all of them).

## Test plan

Add to `src/trace_agent/tests/test_c_phase.py`:

- `test_event_outside_allowlist_marked_scope_noise_not_attach_evidence` —
  construct an `IngestPipeline` with
  `scenario_technique_allowlist=["T1110.001", "T1078"]`, feed `triage()` an
  event with `technique="T1021"` (a real MITRE technique, but not in this
  scenario's list) that would otherwise route to `WEAK` or `ATTACH`. Assert
  `_is_probe_scope_noise` (via `result.trust_annotations`) is `True` for
  that event, and separately assert the event's `_route_bucket` is
  unaffected by the allow-list (still whatever `_l4_route` would have
  produced without this plan — prove routing logic wasn't touched).
- `test_event_inside_allowlist_not_marked_noise` — same setup, feed an event
  with `technique="T1110.001"` (in the list); assert
  `is_probe_scope_noise is False`.
- `test_no_allowlist_configured_marks_nothing_as_noise` —
  `IngestPipeline` constructed with no allow-list (default); assert every
  event's `is_probe_scope_noise` is `False` regardless of technique —
  proves zero behavior change for scenarios without this config.

Verification: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` → all pass, including the new tests.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "scenario_technique_allowlist" src/trace_engine/config.py configs/engine.real_trace.yaml src/trace_agent/loop/ingest.py` shows matches in all three files
- [ ] `grep -n "_is_probe_scope_noise\|is_probe_scope_noise" src/trace_agent/loop/ingest.py` shows the annotation and helper
- [ ] `python -m pytest src\trace_agent\tests\test_c_phase.py -q` passes, including 3 new tests
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes with the same pass count as before this plan
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 025 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `src/trace_engine/config.py`'s structure doesn't have an obvious place for
  a scenario-level allow-list field (e.g. config is entirely flat YAML with
  no dataclass layer) — report the actual structure instead of inventing a
  new config-loading mechanism.
- `IngestPipeline`'s construction site in `lock_session.py` doesn't have
  access to the scenario/engine config at that point — report exactly what
  is and isn't available there rather than threading the config through
  multiple unrelated layers to reach it.
- Any existing `test_full_loop.py` scenario fixture's counts change after
  Step 4 — this would mean some existing scenario's config accidentally
  matches the new field name or a default wasn't actually empty; investigate
  and report rather than adjusting the fixture.

## Maintenance notes

- This plan deliberately does not change what gets ATTACHed — only what gets
  *counted as noise* for reporting. If the real underlying complaint is that
  wide host-scoped queries pollute the *candidate pool* (wasted VOI/rounds
  evaluating noise), that is a separate, larger change (restricting query
  generation itself) not covered here.
- The allow-list is scenario-specific by design (Plan 020 already documents
  that `real_trace_01`'s config diverges from the default `engine.yaml`) —
  do not promote it to a global default; other scenarios
  (`pipeline_18`/`apt_5host`/`multipath_12host`) already have their own
  isolation via `wazuh_incident_prefix`/`wazuh_attacks_only` (see Plan 027)
  and don't need this mechanism.
- A reviewer should scrutinize whether `is_probe_scope_noise` needs to be
  surfaced further up the stack (into `presentation.py`'s noise-count
  summary) to fully close the loop on the reviewer's original complaint —
  this plan stops at making the signal available in `IngestResult`/
  `trust_annotations`; wiring it into the final report's noise-count text is
  a natural, low-risk follow-up once this lands and the field is proven
  correct in the engine's own tests.
