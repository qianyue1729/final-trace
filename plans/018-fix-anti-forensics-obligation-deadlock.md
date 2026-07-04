# Plan 018: Fix the permanent hard-obligation deadlock for anti-forensics/absence obligations

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
>   src/trace_agent/phases/veto_phase.py src/trace_agent/phases/k_phase.py `
>   src/trace_agent/agents/modular_orchestrator.py src/trace_engine/decision_guardrails.py `
>   src/trace_agent/tests/test_obligation_ledger.py tests/engine/test_decision_guardrails.py
> ```
> The worktree is dirty relative to `9dadd88` (plans 014–016 landed uncommitted,
> unrelated to this plan's files). Compare the "Current state" excerpts below
> against the live code before proceeding; on a mismatch, treat it as a STOP
> condition.

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

A real Wazuh investigation (`T1048` on `wazuh.manager`, session
`6cf3d31b-e78`) ran 4 rounds and never stopped naturally — the operator had to
call `force_stop` even though the decision ledger was fully confident (H1
posterior = 1.0, margin = 1.0, entropy ≈ 0). Root cause: once any
`ANTI_FORENSICS`-type obligation is created (triggered by low-trust /
adversary-controllable evidence — very common on real telemetry), it can
**never be discharged automatically**. Its only discharge path checks two node
attributes, `visibility_restored` and `source_unavailable_decision`, but
**nothing in the codebase ever sets either attribute to `True`** — grep
confirms zero writers, only readers. Since `open_hard()` unconditionally
blocks stopping while any hard obligation is open
(`src/trace_agent/phases/k_phase.py:556-558`), every investigation that
triggers even one anti-forensics obligation is now guaranteed to run to
budget exhaustion or `force_stop`, regardless of how confident the decision
is. This wastes rounds/probes and forces manual intervention on what should
be an unattended demo path.

## Current state

- `src/trace_agent/decision/runtime_types.py:169-195` — `Obligation` dataclass:

```python
@dataclass
class Obligation:
    """RFC-004-02 §8 统一义务"""
    id: str
    type: ObligationType
    anchor: str                  # 触发条件/锚定描述
    sla_rounds: int              # SLA 时限（轮数）
    hard: bool                   # True = 硬阻断（结构/反取证）; False = VOI 门控
    created_round: int
    deadline_round: int
    discharged: bool = False
    discharged_by: str = ""
    voi_estimate: float = 0.0
    tags: list[str] = field(default_factory=list)
    explanation_id: Optional[str] = None  # 关联解释 ID（生命周期/判别债务）
    intent: Optional[ObligationIntent] = None
    attempts: int = 0
    failures: int = 0
    blocked_reason: str = ""
    last_attempt_round: Optional[int] = None

    def is_overdue(self, current_round: int) -> bool:
        return not self.discharged and current_round > self.deadline_round

    @property
    def blocked(self) -> bool:
        return bool(self.blocked_reason) and not self.discharged
```

- `ObligationType` enum (`runtime_types.py:151-156`): values are the literal
  strings `"structural"`, `"lifecycle"`, `"anti_forensics"`,
  `"discriminative"`.

- `src/trace_agent/obligation_integration/obligation_ledger.py:330-378`
  (`scan_anti_forensics`) creates the obligation with `hard=True`,
  `sla_rounds=3`, `deadline_round=current_round + 3`:

```python
                if is_anti_forensics or is_absence:
                    ob_type_tag = "anti_forensics" if is_anti_forensics else "absence"
                    ob = Obligation(
                        id=self._next_id("anti_forensics"),
                        type=ObligationType.ANTI_FORENSICS,
                        anchor=f"anti_forensics:{eid}",
                        sla_rounds=3,
                        hard=True,
                        created_round=current_round,
                        deadline_round=current_round + 3,
                        tags=["anti_forensics", ob_type_tag],
                        intent=ObligationIntent(
                            affected_entity_ids=[str(eid)],
                            host_ids=[
                                str(getattr(et, "host_id", ""))
                            ] if getattr(et, "host_id", "") else [],
                            question="Restore visibility or record an explicit unavailable-source decision.",
                            allowed_operators=[
                                "process_tree",
                                "auth_log",
                                "network_flow",
                            ],
                            acceptance_criterion={
                                "type": "visibility_restored_or_unavailable",
                                "evidence_id": str(eid),
                            },
                            reason_code=(
                                "anti_forensics_indicator"
                                if is_anti_forensics
                                else "telemetry_absence"
                            ),
                        ),
                    )
                    new_obs.append(ob)
```

- `obligation_ledger.py:436-471` (`discharge`) dispatches by type; **no
  `current_round` parameter today**:

```python
    def discharge(self, graph: dict, ledger) -> List[str]:
        """
        关闭已满足/不再适用的义务。

        Returns:
            已关闭义务 ID 列表
        """
        discharged_ids: List[str] = []

        # 收集图中已确认的 tactics
        confirmed_tactics: set = set()
        for node in graph.get("nodes", []):
            tactic = node.get("tactic", "")
            if tactic and node.get("fact_confirmed", False):
                confirmed_tactics.add(tactic)

        # 收集图中已有出边的节点
        edge_sources = {e.get("src") for e in graph.get("edges", [])}

        for ob in self.obligations:
            if ob.discharged:
                continue

            if ob.type == ObligationType.LIFECYCLE:
                self._try_discharge_lifecycle(ob, confirmed_tactics, ledger, discharged_ids)

            elif ob.type == ObligationType.DISCRIMINATIVE:
                self._try_discharge_discriminative(ob, ledger, discharged_ids)

            elif ob.type == ObligationType.STRUCTURAL:
                self._try_discharge_structural(ob, graph, edge_sources, discharged_ids)

            elif ob.type == ObligationType.ANTI_FORENSICS:
                self._try_discharge_anti_forensics(ob, graph, discharged_ids)

        return discharged_ids
```

- `obligation_ledger.py:520-532` — the broken discharge path (only path that
  exists today):

```python
    def _try_discharge_anti_forensics(self, ob: Obligation, graph: dict,
                                      discharged_ids: List[str]) -> None:
        """尝试关闭反取证义务：对应证据已被补全或确认"""
        criterion = ob.intent.acceptance_criterion if ob.intent else {}
        evidence_id = str(criterion.get("evidence_id") or "")
        for node in graph.get("nodes", []):
            if node.get("id") == evidence_id and (
                node.get("visibility_restored", False)
                or node.get("source_unavailable_decision", False)
            ):
                ob.discharge(f"evidence_recovered:{evidence_id}")
                discharged_ids.append(ob.id)
                return
```

- `obligation_ledger.py:538-543` — `open_hard()` (unconditional block):

```python
    def open_hard(self) -> bool:
        """是否有未清硬阻断义务 → 无条件续跑"""
        return any(
            ob.hard and not ob.discharged
            for ob in self.obligations
        )
```

- `obligation_ledger.py:568-588` — `unresolved(current_round)` — **this is
  what feeds the final report's `unresolved_obligations` and, transitively,
  `decision_guardrails.py`**. Note it already exposes `type`, `overdue`,
  `attempts`, `blocked_reason` per item:

```python
    def unresolved(self, current_round: int) -> list[dict[str, Any]]:
        return [
            {
                "id": obligation.id,
                "type": obligation.type.value,
                "hard": obligation.hard,
                "reason_code": (
                    obligation.intent.reason_code
                    if obligation.intent else "missing_typed_intent"
                ),
                "question": obligation.intent.question if obligation.intent else "",
                "host_ids": list(obligation.intent.host_ids)
                if obligation.intent else [],
                "deadline_round": obligation.deadline_round,
                "overdue": obligation.is_overdue(current_round),
                "attempts": obligation.attempts,
                "failures": obligation.failures,
                "blocked_reason": obligation.blocked_reason,
            }
            for obligation in self.obligations
            if not obligation.discharged
        ]
```

- Call sites of `discharge(graph, ledger)` **that must be updated** (both are
  in the active modular-phase path used by the Deep Agent):
  - `src/trace_agent/phases/veto_phase.py:60-64`:
    ```python
        # 2. Discharge met obligations
        try:
            session.obligations.discharge(graph_dict, session.ledger)
        except (TypeError, AttributeError):
            pass
    ```
  - `src/trace_agent/phases/k_phase.py:273-278`:
    ```python
        # 6. Obligation discharge
        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])
        try:
            session.obligations.discharge(graph_dict, session.ledger)
        except (TypeError, AttributeError):
            pass
    ```
  - **Do NOT touch** these other call sites — they belong to the legacy
    monolithic orchestrator (scheduled for deletion by plan 012) and an eval
    script, neither used by the Deep Agent's modular phase path:
    `src/trace_agent/agents/orchestrator.py:802,1172`,
    `src/trace_agent/eval/ablation_experiment.py:288`.

- `src/trace_engine/decision_guardrails.py:52-63` — existing pattern for a
  guardrail that inspects `unresolved_obligations` items by `type`/`overdue`,
  independent of the `hard` flag (model your new function on this):

```python
def _lifecycle_obligation_unresolved(
    obligations: list[dict[str, Any]],
) -> bool:
    for item in obligations:
        oid = str(item.get("id") or "")
        otype = str(item.get("type") or "")
        if oid == "lifecycle_1" or otype in ("initial_access", "lifecycle"):
            if item.get("overdue") or int(item.get("attempts") or 0) > 0:
                return True
            if not item.get("resolved", False):
                return True
    return False
```

  and where it's wired into `collect_guardrail_flags`
  (`decision_guardrails.py:86-87`):

```python
    if _lifecycle_obligation_unresolved(obligations):
        flags.append("obligation_lifecycle_1_unresolved")
```

  and the `critical` flag set inside `should_force_inconclusive`
  (`decision_guardrails.py:148-157`):

```python
    critical = {
        "data_collection_critical_failure",
        "attack_chain_unresolved",
        "obligation_lifecycle_1_unresolved",
        "planner_non_functional",
        "telemetry_coverage_insufficient",
        "score_action_mismatch",
        "confidence_unavailable",
        "investigation_budget_exhausted",
    }
```

- Existing unit tests to keep green, in `src/trace_agent/tests/test_obligation_ledger.py`:
  the file uses `MockLedger`, `MockTrustForObligation`, `MockEvidenceTrustEntry`
  helpers (lines 31-67) and calls `ledger.discharge(graph, mock_ledger)` with
  exactly **2 positional args** (e.g. lines 394, 410, 440) — your signature
  change must keep this call form valid (add the new parameter with a default
  value, do not make it positional-required).

## Design decision (do not redesign — implement exactly this)

Do **not** auto-discharge (`ob.discharge(...)`) an expired anti-forensics
obligation — that would silently drop it out of `unresolved()` (which filters
`if not obligation.discharged`), hiding the real coverage gap from
`decision_guardrails.py` and from the final report's `unresolved_obligations`
list.

Instead, **de-escalate** it after its SLA deadline passes:
- Flip `ob.hard = False` (stops blocking `open_hard()`, i.e. unblocks the
  loop).
- Set `ob.blocked_reason = "sla_expired_no_recovery_path"`.
- Leave `ob.discharged = False` — it stays open, so it still shows up in
  `unresolved()`/`unresolved_obligations`, still carries `overdue=True`, and
  can still be picked up as a (now VOI-gated, not hard) probe candidate via
  `materialize_open`.
- Add a new guardrail check so the final report still flags this as an
  unresolved coverage gap even though it no longer force-blocks the loop.

This bounds the deadlock to `sla_rounds` (3 rounds) instead of infinity,
while preserving the "there is an unresolved telemetry gap, a human should
review this" signal all the way to the final decision.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Obligation ledger tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` | all pass |
| Full loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass |
| Decision guardrail tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_decision_guardrails.py tests\engine\test_decision_guardrails_demo.py -q` | all pass |
| Phase event contract tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_phase_event_contract.py -q` | all pass |

Use system Python 3.11.5. Do NOT use `deep-agent-backend/.venv`. PowerShell on
this machine does not support `&&` — use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/obligation_integration/obligation_ledger.py`
- `src/trace_agent/phases/veto_phase.py`
- `src/trace_agent/phases/k_phase.py`
- `src/trace_engine/decision_guardrails.py`
- `src/trace_agent/tests/test_obligation_ledger.py`
- `tests/engine/test_decision_guardrails.py`

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_agent/agents/orchestrator.py` — legacy monolithic orchestrator,
  scheduled for deletion (plan 012); its two `discharge(...)` call sites keep
  using the default `current_round=0` (see Step 1) and are unaffected.
- `src/trace_agent/eval/ablation_experiment.py` — eval tooling, same reason.
- `src/trace_agent/agents/modular_orchestrator.py` — the `incomplete`
  computation there reads `unresolved_obligations`, which already reflects
  the de-escalated-but-open obligation correctly once Step 3 lands; no change
  needed here.
- `_try_discharge_lifecycle` / `_try_discharge_discriminative` /
  `_try_discharge_structural` — unaffected, do not add the SLA-expiry
  behavior to them; this plan is scoped to `ANTI_FORENSICS` only.
- `plans/017-graph-ledger-attack-graph-visualization.md` work (frontend) —
  unrelated.

## Git workflow

- Branch: `advisor/018-anti-forensics-obligation-deadlock`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Add `current_round` to `discharge()` and thread it through

In `src/trace_agent/obligation_integration/obligation_ledger.py`, change the
`discharge` signature to accept an optional `current_round` (default `0` to
preserve every existing 2-arg call site) and pass it to the anti-forensics
branch:

```python
    def discharge(self, graph: dict, ledger, current_round: int = 0) -> List[str]:
        """
        关闭已满足/不再适用的义务。

        Returns:
            已关闭义务 ID 列表
        """
        discharged_ids: List[str] = []

        # 收集图中已确认的 tactics
        confirmed_tactics: set = set()
        for node in graph.get("nodes", []):
            tactic = node.get("tactic", "")
            if tactic and node.get("fact_confirmed", False):
                confirmed_tactics.add(tactic)

        # 收集图中已有出边的节点
        edge_sources = {e.get("src") for e in graph.get("edges", [])}

        for ob in self.obligations:
            if ob.discharged:
                continue

            if ob.type == ObligationType.LIFECYCLE:
                self._try_discharge_lifecycle(ob, confirmed_tactics, ledger, discharged_ids)

            elif ob.type == ObligationType.DISCRIMINATIVE:
                self._try_discharge_discriminative(ob, ledger, discharged_ids)

            elif ob.type == ObligationType.STRUCTURAL:
                self._try_discharge_structural(ob, graph, edge_sources, discharged_ids)

            elif ob.type == ObligationType.ANTI_FORENSICS:
                self._try_discharge_anti_forensics(ob, graph, discharged_ids, current_round)

        return discharged_ids
```

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` → all pass (existing 2-arg calls still work via the default).

### Step 2: Add the SLA-expiry de-escalation path

In the same file, replace `_try_discharge_anti_forensics` with a version that
accepts `current_round` and de-escalates (does NOT discharge) once the
obligation is past its deadline and still unresolved:

```python
    def _try_discharge_anti_forensics(self, ob: Obligation, graph: dict,
                                      discharged_ids: List[str],
                                      current_round: int = 0) -> None:
        """尝试关闭反取证义务：对应证据已被补全或确认。

        若证据在 SLA 期限内未被恢复/裁定，义务不会被"关闭"（仍计入
        unresolved_obligations 供报告审查），但会从硬阻断降级为
        VOI 门控，避免调查因结构性无法自动满足的验收条件而永久卡死。
        """
        criterion = ob.intent.acceptance_criterion if ob.intent else {}
        evidence_id = str(criterion.get("evidence_id") or "")
        for node in graph.get("nodes", []):
            if node.get("id") == evidence_id and (
                node.get("visibility_restored", False)
                or node.get("source_unavailable_decision", False)
            ):
                ob.discharge(f"evidence_recovered:{evidence_id}")
                discharged_ids.append(ob.id)
                return

        if ob.hard and ob.is_overdue(current_round):
            ob.hard = False
            ob.blocked_reason = "sla_expired_no_recovery_path"
```

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` → all pass.

### Step 3: Pass `current_round` from the two active call sites

In `src/trace_agent/phases/veto_phase.py`, change:

```python
        # 2. Discharge met obligations
        try:
            session.obligations.discharge(graph_dict, session.ledger)
        except (TypeError, AttributeError):
            pass
```

to:

```python
        # 2. Discharge met obligations
        try:
            session.obligations.discharge(
                graph_dict, session.ledger, current_round=session.budget.rounds_used,
            )
        except (TypeError, AttributeError):
            pass
```

In `src/trace_agent/phases/k_phase.py`, change:

```python
        # 6. Obligation discharge
        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])
        try:
            session.obligations.discharge(graph_dict, session.ledger)
        except (TypeError, AttributeError):
            pass
```

to:

```python
        # 6. Obligation discharge
        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])
        try:
            session.obligations.discharge(
                graph_dict, session.ledger, current_round=session.budget.rounds_used,
            )
        except (TypeError, AttributeError):
            pass
```

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` → all pass (no change to rounds/stop_reason/graph size for scenarios without anti-forensics obligations — see STOP conditions).

### Step 4: Add a guardrail flag so the de-escalated obligation still shows up in the final report

In `src/trace_engine/decision_guardrails.py`, add a new helper next to
`_lifecycle_obligation_unresolved` (same style):

```python
def _anti_forensics_obligation_expired(
    obligations: list[dict[str, Any]],
) -> bool:
    for item in obligations:
        if str(item.get("type") or "") != "anti_forensics":
            continue
        if item.get("blocked_reason") == "sla_expired_no_recovery_path":
            return True
        if item.get("overdue"):
            return True
    return False
```

Wire it into `collect_guardrail_flags`, right after the existing lifecycle
check:

```python
    if _lifecycle_obligation_unresolved(obligations):
        flags.append("obligation_lifecycle_1_unresolved")

    if _anti_forensics_obligation_expired(obligations):
        flags.append("telemetry_gap_unresolved_after_sla")
```

Add the new flag to the `critical` set inside `should_force_inconclusive`:

```python
    critical = {
        "data_collection_critical_failure",
        "attack_chain_unresolved",
        "obligation_lifecycle_1_unresolved",
        "telemetry_gap_unresolved_after_sla",
        "planner_non_functional",
        "telemetry_coverage_insufficient",
        "score_action_mismatch",
        "confidence_unavailable",
        "investigation_budget_exhausted",
    }
```

Do **not** add `"telemetry_gap_unresolved_after_sla"` to `DEMO_WARNING_FLAGS`
— an anti-forensics/absence signal should stay blocking-critical even under
the demo profile, consistent with `attack_chain_unresolved` and
`obligation_lifecycle_1_unresolved` (neither of those is in
`DEMO_WARNING_FLAGS` either).

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_decision_guardrails.py tests\engine\test_decision_guardrails_demo.py -q` → all pass.

## Test plan

Add to `src/trace_agent/tests/test_obligation_ledger.py`, in the discharge
test section (model after `test_discharge_structural_orphan_resolved` at
line 414-441, using the existing `MockLedger` helper):

- `test_discharge_anti_forensics_evidence_recovered` — unchanged behavior:
  a node with `id` matching the obligation's `evidence_id` and
  `visibility_restored=True` still discharges it (`ob.discharged is True`,
  `ob.discharged_by.startswith("evidence_recovered:")`). This guards the
  existing path you are not allowed to break.
- `test_discharge_anti_forensics_deescalates_after_sla_expiry` — build an
  `Obligation` with `type=ObligationType.ANTI_FORENSICS`, `hard=True`,
  `created_round=0`, `deadline_round=3`,
  `intent=ObligationIntent(affected_entity_ids=["ev1"], host_ids=[], question="", allowed_operators=[], acceptance_criterion={"type": "visibility_restored_or_unavailable", "evidence_id": "ev1"}, reason_code="anti_forensics_indicator")`.
  Call `ledger.discharge({"nodes": [], "edges": []}, MockLedger(), current_round=4)`.
  Assert: `ob.discharged is False`, `ob.hard is False`,
  `ob.blocked_reason == "sla_expired_no_recovery_path"`, and the obligation's
  id is **not** in the returned `discharged_ids` list.
- `test_discharge_anti_forensics_still_open_hard_before_sla_expiry` — same
  setup but `current_round=2` (before deadline `3`): assert `ob.hard is True`
  and `ledger.open_hard() is True` (loop still correctly blocked during the
  grace period).
- `test_open_hard_false_after_anti_forensics_sla_expiry` — after the
  de-escalation from the second test above, assert `ledger.open_hard() is False`.

Add to `tests/engine/test_decision_guardrails.py` (model after the existing
`_ubuntu_t1110_review_fixture` pattern at the top of the file):

- `test_anti_forensics_sla_expiry_flags_telemetry_gap` — build a report fixture
  whose `decision["unresolved_obligations"]` contains one item with
  `"type": "anti_forensics", "overdue": True, "blocked_reason": "sla_expired_no_recovery_path", "hard": False`
  and `decision["action"] = "contain_escalate"`. Call
  `apply_decision_guardrails(report)` and assert
  `"telemetry_gap_unresolved_after_sla" in result["decision"]["guardrail_flags"]`
  and `result["decision"]["action"] == "inconclusive"` (forced by
  `should_force_inconclusive`, since the action was an `AFFIRMATIVE_ACTIONS`
  member and the flag is in `critical`).

Verification: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_obligation_ledger.py tests\engine\test_decision_guardrails.py tests\engine\test_decision_guardrails_demo.py -q` → all pass, including the new tests.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `python -m pytest src\trace_agent\tests\test_obligation_ledger.py -q` passes, including 4 new tests
- [ ] `python -m pytest tests\engine\test_decision_guardrails.py tests\engine\test_decision_guardrails_demo.py -q` passes, including 1 new test
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes unchanged (27 tests, same pass count as before this plan)
- [ ] `python -m pytest tests\engine\test_phase_event_contract.py -q` passes
- [ ] `grep -rn "def discharge" src/trace_agent/obligation_integration/obligation_ledger.py` shows the 3-parameter signature with a default
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 018 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The code at `obligation_ledger.py`, `veto_phase.py`, or `k_phase.py` does
  not match the "Current state" excerpts (drift).
- `test_full_loop.py` changes its pass/fail counts, rounds-used, stop_reason,
  or graph size for any existing test — this plan must only change behavior
  for scenarios that create `ANTI_FORENSICS` obligations; if a currently
  passing test's numeric assertions shift, you changed something broader than
  intended. Revert and report.
- You find any other place besides `open_hard()` and `materialize_open()`
  that branches on `Obligation.hard` in a way that would misbehave once a
  previously-hard obligation flips to `hard=False` mid-session (e.g. anything
  assuming `hard` never changes after construction) — report the location
  instead of silently patching it.
- The `unresolved()` output shape in "Current state" doesn't match live code
  (e.g. a field was renamed) — `decision_guardrails.py`'s new function reads
  `item.get("type")`, `item.get("overdue")`, `item.get("blocked_reason")`; if
  any of those keys don't exist in the live `unresolved()` dict, stop.

## Maintenance notes

- This fix only applies to the modular phase path (`veto_phase.py` +
  `k_phase.py`), which is what the Deep Agent's `run_veto_phase` /
  `run_k_phase` / `run_full_loop` tools use. The legacy
  `src/trace_agent/agents/orchestrator.py` orchestrator still has the
  original unbounded deadlock — this is acceptable because plan 012 deletes
  that file; if plan 012 is deprioritized, revisit whether the legacy path
  needs the same fix.
- If a future obligation type is added with an acceptance criterion that has
  no automated setter (like `visibility_restored`), it will hit the exact
  same deadlock class. Consider generalizing the SLA-expiry de-escalation
  from `_try_discharge_anti_forensics` into a shared helper on `Obligation`
  or `ObligationLedger` at that point, rather than copy-pasting per type.
- A reviewer should scrutinize: that `ob.hard = False` is set only after
  `is_overdue()`, never eagerly; that `unresolved()`'s `hard` field correctly
  reflects the post-de-escalation value (it reads `obligation.hard` live, so
  no extra wiring needed there); and that the new guardrail flag correctly
  forces `action = "inconclusive"` for affirmative actions rather than
  silently downgrading confidence without operator visibility.
- Deferred (not in this plan): giving the model/agent an explicit tool action
  to record a human "source unavailable" decision (which would set
  `source_unavailable_decision=True` on the node and cleanly discharge the
  obligation) — plan 021 exposes `blocked_reason` so at least the *existence*
  of this gap is visible; wiring an actual resolution action is future work.
