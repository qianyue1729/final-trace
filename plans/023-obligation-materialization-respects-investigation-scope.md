# Plan 023: Obligation materialization must check investigation scope, not graph-referenced hosts

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/obligation_integration/obligation_ledger.py `
>   src/trace_agent/phases/o_phase.py src/trace_agent/phases/veto_phase.py `
>   src/trace_agent/tests/test_obligation_ledger.py
> ```
> These files are tracked at `9dadd88`; as of this plan's writing they are
> **unmodified** relative to it (verify with the command above — it should
> print nothing except possibly `o_phase.py`/`veto_phase.py`, which are
> untracked new files under `src/trace_agent/phases/` and won't show in this
> diff at all — check them with `git status --porcelain` instead and compare
> against the "Current state" excerpts below). This plan builds on Plan 018
> (anti-forensics SLA de-escalation) but is independent and can land before
> or after it — it fixes a different, more general gap: obligations for
> **any** type, not just anti-forensics, can be materialized into probes
> targeting hosts that a VETO phase will always reject, wasting rounds before
> Plan 018's SLA countdown would even apply.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none (complements Plan 018; recommended to land together)
- **Category**: bug (wasted rounds / stop-condition correctness)
- **Planned at**: commit `9dadd88`, 2026-07-04

## Why this matters

A reviewer observed that after cross-host data (from an out-of-scope
`multipath_12host`-style host such as `DC01`/`SRV-JUMP-01`) was correctly
VETOed as `unknown_host`, the investigation still spent Rounds 2–4
regenerating and re-vetoing an **identical** probe pool with no forward
progress, before finally hitting `force_stop`. Plan 018 fixes the
`ANTI_FORENSICS` half of this (obligations that can never discharge because
their acceptance criterion has no automated setter) by de-escalating them
from hard to VOI-gated once their SLA expires. That bounds the damage to
`sla_rounds` (3 rounds) but does not address the **root cause**: obligations
are materialized into probes using the wrong host set.

`ObligationLedger.materialize_open` (the O-phase step that turns open
obligations into candidate probes) resolves a target host by checking
whether any of the obligation's `host_ids` appear in `graph_hosts` — the set
of hosts **already referenced by nodes in the attack graph** — not the set of
hosts the current investigation is actually allowed to query
(`session._scenario_hosts`, the same set `veto_phase.py` uses for its
`unknown_host` check). If an out-of-scope host was ever referenced by a graph
node (e.g. as a lateral-movement target mentioned in an event's attributes,
even one that was itself flagged/parked rather than fully attached), it is
present in `graph_hosts` and materialization proceeds to build a probe
targeting it — which the very next VETO step then discards as
`unknown_host`. This round-trip (materialize → veto → still-undischarged →
materialize again next round) is the actual mechanism behind "反复生成/否决
完全相同的探针池", and it affects `LIFECYCLE`, `STRUCTURAL`, and
`DISCRIMINATIVE` obligations too, not just `ANTI_FORENSICS` — none of them
check investigation scope before materializing.

## Current state

- `src/trace_agent/obligation_integration/obligation_ledger.py:644-687`
  (`materialize_open`) — builds its host-matching pool from graph-referenced
  hosts, not investigation scope:

```python
    def materialize_open(
        self,
        graph: dict,
        veto_filter: Optional[Callable] = None,
        current_round: int = 0,
    ) -> List[dict]:
        probes: List[dict] = []
        graph_hosts = {
            str(node.get("host_id"))
            for node in graph.get("nodes", [])
            if node.get("host_id")
        }
        graph_hosts.update(str(host) for host in graph.get("known_hosts", []))

        for ob in self.obligations:
            if ob.discharged:
                continue
            intent = ob.intent
            if intent is None:
                ob.blocked_reason = "missing_typed_intent"
                continue
            host = next(
                (host for host in intent.host_ids if host in graph_hosts),
                None,
            )
            if host is None:
                ob.blocked_reason = "affected_host_unresolved"
                continue
            ...
```

  Note the method has **no `known_hosts`/scope parameter at all** — the only
  scope-like input is `graph.get("known_hosts", [])`, which (per
  `src/trace_agent/phases/_helpers.py`'s `graph_to_dict`, used to build this
  `graph` dict) is populated from the **scenario's** known-host list, i.e. it
  should already be the correct scope — but it is *merged into*, not used
  *instead of*, `graph_hosts` built from node references. A host that
  appears as a node attribute but is NOT in `known_hosts` still ends up in
  the matching pool via the first `graph_hosts` comprehension.

- `src/trace_agent/phases/o_phase.py:44-62` — the only call site in the
  active modular-phase path, and it already has `known_hosts_lower`
  available but never passes it to `materialize_open`:

```python
        pool = session.data.get("pool", CandidatePool())
        known_hosts_lower = (
            {h.lower() for h in session._scenario_hosts}
            if session._scenario_hosts else set()
        )
        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])

        mandated_probes: list[Probe] = []
        try:
            mandated_raw = session.obligations.materialize_open(
                graph_dict, current_round=session.budget.rounds_used,
            ) or []
            mandated_probes = [
                p for p in obligation_dicts_to_probes(mandated_raw)
                if probe_is_executable(p, session.executor, known_hosts_lower, session.graph)
            ]
        except Exception:
            pass
```

  `probe_is_executable` (imported from `._helpers`) is applied **after**
  materialization, as a second filter — but by then the obligation itself
  already "succeeded" at materializing (its `blocked_reason` was cleared),
  so the ledger has no record that this was actually an out-of-scope
  target; the probe is silently dropped from `mandated_probes` and the
  obligation goes right back into `materialize_open`'s candidate set next
  round with the same outcome.

- `src/trace_agent/phases/_helpers.py` — read `probe_is_executable` and
  `graph_to_dict` in full before making changes; confirm their exact
  signatures match what's shown above (drift check).

- `src/trace_agent/veto_integration` has no host-scope logic at all (it only
  handles forge-resistance gating for hard VETOs — see
  `veto_gates.py:7-87`); the actual `unknown_host` scope check lives in
  `src/trace_agent/phases/veto_phase.py:77-83`:

```python
        # 4. Non-host filter: remove probes whose target doesn't match any known host
        if known_hosts_lower:
            for probe in pool.peek():
                target_lower = (getattr(probe, "target", "") or "").lower().strip()
                if target_lower and target_lower not in known_hosts_lower:
                    veto_ids.append(probe.id)
                    veto_reasons.append(f"unknown_host:{target_lower}")
```

  This is the check `materialize_open` should be consulted against
  **before** producing a probe, using the same `known_hosts_lower` set.

- `src/trace_agent/decision/runtime_types.py:169-196` — the `Obligation`
  dataclass already has `blocked_reason: str = ""` and a `blocked` property;
  no new state field is needed, only a new value for `blocked_reason` and a
  way to distinguish "temporarily blocked, try again" from "permanently
  unreachable, stop retrying."

## Design decision (do not redesign — implement exactly this)

1. **Pass investigation scope into `materialize_open`.** Add a
   `known_hosts: Optional[set[str]] = None` parameter. When provided, an
   obligation's host resolution must additionally require the matched host to
   be in `known_hosts` (case-insensitive) — not just in `graph_hosts`. Keep
   `graph_hosts` matching as a fallback only when `known_hosts` is not passed
   (preserves behavior for the legacy orchestrator and eval callers that
   don't pass it — see "Out of scope" below).
2. **When an obligation's *entire* `host_ids` list is confirmed out of
   scope** (every entry fails the `known_hosts` check, and `known_hosts` was
   provided and non-empty), set a distinct `blocked_reason` value —
   `"host_out_of_investigation_scope"` — instead of the generic
   `"affected_host_unresolved"`. This is a **permanent** condition (the host
   will never enter scope mid-investigation), unlike
   `"affected_host_unresolved"` (which can resolve once a relevant node with
   a matching host appears later).
3. **Do not immediately discharge or hard-block on this** — obligations
   still show up in `unresolved()`/`unresolved_obligations` for the final
   report (same reporting contract as Plan 018). But for `hard=True`
   obligations whose `blocked_reason == "host_out_of_investigation_scope"`,
   `open_hard()` must stop counting them as blocking — mirroring Plan 018's
   de-escalation semantics but triggered immediately (scope is knowable up
   front) rather than after an SLA countdown.
4. **Wire `o_phase.py`'s call site** to pass `known_hosts=known_hosts_lower`
   (already computed there) into `materialize_open`.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Obligation ledger tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` | all pass |
| Full loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass, same pass count as before |
| Deep-agent-backend tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |

Use system Python 3.11.5. PowerShell on this machine does not support `&&` —
use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/obligation_integration/obligation_ledger.py`
- `src/trace_agent/phases/o_phase.py`
- `src/trace_agent/tests/test_obligation_ledger.py`

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_agent/agents/orchestrator.py` — legacy monolithic orchestrator
  (scheduled for deletion by plan 012); its `materialize_open(...)` call site
  should keep using the 2-arg form (no `known_hosts`), which remains valid
  because the new parameter defaults to `None` and preserves the old
  `graph_hosts`-only behavior.
- `src/trace_agent/veto_integration/veto_gates.py` — unrelated (forge-resistance
  gating, not host scope).
- Plan 018's `ANTI_FORENSICS`-specific SLA de-escalation code in
  `_try_discharge_anti_forensics` — this plan's `open_hard()` change must
  compose with it (an obligation could in principle hit both conditions),
  not replace it.
- Plan 019's `o_phase.py` pool-drain fix — unrelated section of the same
  file; if both plans land close together, make sure your diff for this plan
  only touches the `materialize_open(...)` call, not the `pool.drain()`/
  `pool.peek()` line.

## Git workflow

- Branch: `advisor/023-obligation-scope-check`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Add `known_hosts` parameter to `materialize_open` and scope-check host resolution

In `src/trace_agent/obligation_integration/obligation_ledger.py`:

```python
    def materialize_open(
        self,
        graph: dict,
        veto_filter: Optional[Callable] = None,
        current_round: int = 0,
        known_hosts: Optional[set] = None,
    ) -> List[dict]:
        """
        将开放义务物化为可排序的探针候选。

        Args:
            graph: 当前攻击图
            veto_filter: 可选的否决过滤器（排除已知低价值/违反约束的探针）
            known_hosts: 当前调查 scope 内允许探测的主机（小写）。若提供，
                义务只能物化出 target 在此集合内的探针；若某义务的全部
                host_ids 都不在此集合内，标记为永久性
                "host_out_of_investigation_scope"，而非可能日后恢复的
                "affected_host_unresolved"。

        Returns:
            探针候选列表，按优先级降序
        """
        probes: List[dict] = []
        graph_hosts = {
            str(node.get("host_id"))
            for node in graph.get("nodes", [])
            if node.get("host_id")
        }
        graph_hosts.update(str(host) for host in graph.get("known_hosts", []))
        known_hosts_lower = (
            {str(h).lower() for h in known_hosts} if known_hosts else None
        )

        for ob in self.obligations:
            if ob.discharged:
                continue
            intent = ob.intent
            if intent is None:
                ob.blocked_reason = "missing_typed_intent"
                continue

            if known_hosts_lower is not None and intent.host_ids:
                if not any(
                    str(h).lower() in known_hosts_lower for h in intent.host_ids
                ):
                    ob.blocked_reason = "host_out_of_investigation_scope"
                    continue

            host = next(
                (host for host in intent.host_ids if host in graph_hosts),
                None,
            )
            if host is None:
                ob.blocked_reason = "affected_host_unresolved"
                continue
            operator = next(
                (value for value in intent.allowed_operators if value),
                None,
            )
            if operator is None:
                ob.blocked_reason = "no_allowed_operator"
                continue
            ob.blocked_reason = ""
            ...
```

Keep the rest of the method body (probe construction, `veto_filter`
application, sort) unchanged — only the host-resolution block above changes.
Note the `intent.host_ids` empty-list case (e.g. anti-forensics obligations
built with `host_ids=[]` when `et.host_id` isn't set) intentionally skips the
new scope check (`and intent.host_ids` guard) and falls through to the
existing `graph_hosts` resolution, preserving Plan 018's anti-forensics test
fixtures which use `host_ids=[]`.

**Verify**: `python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` → all pass (existing calls with no `known_hosts` argument are unaffected by the default).

### Step 2: Make `open_hard()` skip permanently out-of-scope hard obligations

In the same file, change:

```python
    def open_hard(self) -> bool:
        """是否有未清硬阻断义务 → 无条件续跑"""
        return any(
            ob.hard and not ob.discharged
            for ob in self.obligations
        )
```

to:

```python
    def open_hard(self) -> bool:
        """是否有未清硬阻断义务 → 无条件续跑。

        永久性域外（host_out_of_investigation_scope）的硬义务不计入——
        该证据在当前调查范围内确定不可获得，继续无条件续跑没有意义；
        它仍会出现在 unresolved()/unresolved_obligations 中供报告审查。
        """
        return any(
            ob.hard
            and not ob.discharged
            and ob.blocked_reason != "host_out_of_investigation_scope"
            for ob in self.obligations
        )
```

**Verify**: `python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` → all pass.

### Step 3: Wire `o_phase.py` to pass investigation scope into materialization

In `src/trace_agent/phases/o_phase.py`, change:

```python
        mandated_raw = session.obligations.materialize_open(
            graph_dict, current_round=session.budget.rounds_used,
        ) or []
```

to:

```python
        mandated_raw = session.obligations.materialize_open(
            graph_dict,
            current_round=session.budget.rounds_used,
            known_hosts=known_hosts_lower or None,
        ) or []
```

(`known_hosts_lower` is already computed a few lines above this call — see
"Current state".)

**Verify**: `python -m pytest src\trace_agent\tests\test_full_loop.py -q` → all pass, same pass count as before. If any scenario fixture's `rounds_used` or `stop_reason` changes, that scenario likely has an obligation whose host genuinely used to resolve via `graph_hosts` alone (in scope, just not literally in `known_hosts` due to a casing/naming mismatch) — read it and report per STOP conditions, do not loosen the scope check to make it pass.

## Test plan

Add to `src/trace_agent/tests/test_obligation_ledger.py` (model after
`test_unexecutable_hard_obligation_is_explicitly_blocked`):

- `test_materialize_open_marks_out_of_scope_host_permanently_blocked` — build
  a hard obligation with `intent.host_ids=["DC01"]`, a graph whose nodes
  reference `host_id="DC01"` (so it WOULD resolve via the old `graph_hosts`
  path), and call `materialize_open(graph, known_hosts={"wazuh.manager"})`.
  Assert the returned probe list is empty and
  `ob.blocked_reason == "host_out_of_investigation_scope"`.
- `test_materialize_open_without_known_hosts_preserves_legacy_behavior` — same
  setup, call `materialize_open(graph)` (no `known_hosts` arg) and assert a
  probe **is** produced targeting `DC01` (unchanged legacy behavior for
  callers that don't pass scope).
- `test_open_hard_ignores_permanently_out_of_scope_obligation` — construct a
  hard obligation, set `ob.blocked_reason = "host_out_of_investigation_scope"`
  directly, assert `ledger.open_hard() is False`; then construct a second
  hard obligation with `blocked_reason = ""` (or any other value) in the same
  ledger and assert `open_hard() is True` again (proves the exclusion is
  reason-specific, not "any blocked hard obligation is ignored").
- `test_materialize_open_in_scope_host_still_resolves` — sanity check: an
  obligation whose host **is** in `known_hosts` still materializes a probe
  normally (guards against an overly-broad scope check that blocks
  everything).

Verification: `python -m pytest src\trace_agent\tests\test_obligation_ledger.py src\trace_agent\tests\test_full_loop.py -q` → all pass, including the new tests.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "known_hosts: Optional\[set\] = None" src/trace_agent/obligation_integration/obligation_ledger.py` shows the updated signature
- [ ] `grep -n "host_out_of_investigation_scope" src/trace_agent/obligation_integration/obligation_ledger.py` shows at least 2 matches (the assignment in `materialize_open` and the exclusion in `open_hard`)
- [ ] `grep -n "known_hosts=known_hosts_lower" src/trace_agent/phases/o_phase.py` shows the updated call
- [ ] `python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` passes, including 4 new tests
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes with the same pass count as before this plan
- [ ] `python -m pytest deep-agent-backend\tests -q` passes
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 023 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The code at `obligation_ledger.py` or `o_phase.py` does not match the
  "Current state" excerpts (drift).
- `test_full_loop.py` changes `rounds_used`, `stop_reason`, or graph size for
  any *existing* scenario fixture — read exactly which obligation's host
  changed classification and report it; do not adjust the scope check to
  force the old numbers back.
- You find a legacy orchestrator call site
  (`src/trace_agent/agents/orchestrator.py`) that would break if
  `materialize_open`'s signature changed — the new parameter must stay
  optional with a `None` default specifically to avoid this; if a positional
  (not keyword) call site would be broken by inserting the parameter in the
  wrong position, put `known_hosts` last, not before existing positional
  parameters.
- The interaction between this plan's `open_hard()` change and Plan 018's
  SLA-based de-escalation looks like it could produce a case where an
  obligation is excluded from `open_hard()` by this plan's check yet still
  reported as `hard=True` in `unresolved()` in a way that would mislead a
  human reviewer into thinking the loop is still blocked on it — report the
  exact field mismatch rather than silently changing `unresolved()`'s output
  shape (that would be a breaking change for Plan 021's/existing consumers).

## Maintenance notes

- This plan and Plan 018 both add new `blocked_reason` string values
  (`"host_out_of_investigation_scope"` here, `"sla_expired_no_recovery_path"`
  there). If Plan 021 (expose `blocked_reason` in `get_obligation_status`) is
  applied, both values will surface there for free — no additional wiring
  needed in that tool.
- If a future obligation type needs partial-scope semantics (e.g. "in scope
  for 2 of 3 required hosts"), the current "any host in scope" check
  (`any(...)`) will need revisiting — this plan intentionally keeps the
  simplest correct behavior for the reported bug (fully out-of-scope
  obligations), not a general partial-coverage model.
- A reviewer should scrutinize case-sensitivity handling: `known_hosts_lower`
  is already lower-cased by the caller, and this plan lower-cases
  `intent.host_ids` again inside `materialize_open` for the comparison —
  confirm no double-lowering issue and that `host_ids` stored on the
  `Obligation`/`ObligationIntent` itself remains in its original casing (only
  the comparison is case-insensitive).
