# Plan 021: Expose obligation blocked_reason and hard/soft state in get_obligation_status

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- deep-agent-backend/src/trace_deep_agent/query_tools.py `
>   deep-agent-backend/tests/test_tools.py
> ```
> The worktree is dirty relative to `9dadd88` (plans 014–016 landed uncommitted,
> unrelated to this plan's files). Compare the "Current state" excerpt below
> against the live code before proceeding; on a mismatch, treat it as a STOP
> condition.

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none (recommended to land after plan 018, which introduces
  the `"sla_expired_no_recovery_path"` value this tool should surface — but
  this plan is independently useful and does not require 018 to be applied
  first)
- **Category**: dx (observability)
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

During a real investigation, the agent and a human reviewer both spent
several rounds unable to tell *why* the investigation wouldn't stop. The
`Obligation` dataclass already computes and stores exactly this information —
`blocked_reason` (a human-readable string set when an obligation can't be
materialized or resolved) and a `blocked` property — but the
`get_obligation_status` tool, the one surface an agent or reviewer would
naturally check, never returns either field. The agent had to run 4 rounds
and eventually call `force_stop` before writing a report that manually
diagnosed the obligations as unresolvable. Surfacing `blocked_reason` (and
whether an obligation is still `hard`) directly in the tool's `open` list
would let the agent notice this in round 1 and either explain the wait
clearly or decide to `force_stop` sooner with an accurate justification.

## Current state

- `src/trace_agent/decision/runtime_types.py:169-195` — the fields already
  exist on `Obligation`:

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

  `blocked_reason` is populated by `ObligationLedger.materialize_open`
  (`src/trace_agent/obligation_integration/obligation_ledger.py`, e.g.
  `ob.blocked_reason = "missing_typed_intent"` and
  `ob.blocked_reason = "affected_host_unresolved"`).

- `deep-agent-backend/src/trace_deep_agent/query_tools.py:282-349`
  (`get_obligation_status`) — the tool's full current body, **missing
  `blocked_reason` and `hard` from the open-item entries**:

```python
@tool
def get_obligation_status(session_id: str = "") -> str:
    """查看义务台账的当前状态。

    返回开放、已履行、逾期的义务列表，
    包含每个义务的类型（结构/生命周期/反取证/判别）、
    锚点、deadline、当前状态。

    Args:
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    obligations = ctx.lock_session.obligations
    if obligations is None:
        return _json({"status": "error", "error": "Obligation ledger not initialised."})

    try:
        current_round = ctx.lock_session.round

        open_list = []
        discharged_list = []
        overdue_list = []

        for ob in obligations.obligations:
            ob_type = ob.type.value if hasattr(ob.type, "value") else str(ob.type)
            if ob.discharged:
                discharged_list.append({
                    "id": ob.id,
                    "type": ob_type,
                    "anchor": ob.anchor,
                    "discharged_by": getattr(ob, "discharged_by", "") or "",
                })
            else:
                is_overdue = ob.is_overdue(current_round) if hasattr(ob, "is_overdue") else False
                entry = {
                    "id": ob.id,
                    "type": ob_type,
                    "anchor": ob.anchor,
                    "deadline": ob.deadline_round,
                    "priority": "hard" if ob.hard else "voi_gated",
                    "attempts": getattr(ob, "attempts", 0),
                }
                open_list.append(entry)
                if is_overdue:
                    overdue_list.append({
                        "id": ob.id,
                        "type": ob_type,
                        "anchor": ob.anchor,
                        "deadline": ob.deadline_round,
                        "overdue_rounds": current_round - ob.deadline_round,
                    })

        return _json({
            "status": "ok",
            "open": open_list,
            "discharged": discharged_list,
            "overdue": overdue_list,
            "summary": {
                "open_count": len(open_list),
                "discharged_count": len(discharged_list),
                "overdue_count": len(overdue_list),
            },
        })
    except Exception as exc:
        return _json({"status": "error", "error": f"Failed to read obligation ledger: {exc}"})
```

Note: `entry["priority"]` already reflects `ob.hard` at read-time (not
cached), so if plan 018 lands first and flips `ob.hard = False` on SLA
expiry, this tool will automatically start reporting `"priority": "voi_gated"`
for those items with zero changes from this plan — the two plans compose
without conflict.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Deep-agent-backend tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |

Use system Python 3.11.5. Do NOT use `deep-agent-backend/.venv`. PowerShell on
this machine does not support `&&` — use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `deep-agent-backend/src/trace_deep_agent/query_tools.py`
- `deep-agent-backend/tests/test_tools.py` (add a regression test)

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_agent/decision/runtime_types.py` — the `blocked_reason`/`hard`
  fields already exist; no schema change needed.
- `src/trace_agent/obligation_integration/obligation_ledger.py` — no change
  to how/when `blocked_reason` gets set.
- Plan 018's `obligation_ledger.py` / `veto_phase.py` / `k_phase.py` /
  `decision_guardrails.py` changes — independent; this plan only changes the
  read-side tool.
- Other query tools in the same file (`get_session_state`,
  `get_decision_ledger`, `get_voi_ranking`, `get_evidence_trust`,
  `get_attack_graph`) — do not modify them.

## Git workflow

- Branch: `advisor/021-expose-obligation-blocked-reason`
- One commit, short imperative message.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Add `blocked_reason` and `hard` to the open-item entries

In `deep-agent-backend/src/trace_deep_agent/query_tools.py`, inside
`get_obligation_status`, change:

```python
                entry = {
                    "id": ob.id,
                    "type": ob_type,
                    "anchor": ob.anchor,
                    "deadline": ob.deadline_round,
                    "priority": "hard" if ob.hard else "voi_gated",
                    "attempts": getattr(ob, "attempts", 0),
                }
```

to:

```python
                entry = {
                    "id": ob.id,
                    "type": ob_type,
                    "anchor": ob.anchor,
                    "deadline": ob.deadline_round,
                    "priority": "hard" if ob.hard else "voi_gated",
                    "attempts": getattr(ob, "attempts", 0),
                    "blocked_reason": getattr(ob, "blocked_reason", "") or "",
                }
```

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass.

### Step 2: Add a summary count so the agent can spot the problem without inspecting every item

Change:

```python
        return _json({
            "status": "ok",
            "open": open_list,
            "discharged": discharged_list,
            "overdue": overdue_list,
            "summary": {
                "open_count": len(open_list),
                "discharged_count": len(discharged_list),
                "overdue_count": len(overdue_list),
            },
        })
```

to:

```python
        blocked_count = sum(1 for item in open_list if item["blocked_reason"])
        return _json({
            "status": "ok",
            "open": open_list,
            "discharged": discharged_list,
            "overdue": overdue_list,
            "summary": {
                "open_count": len(open_list),
                "discharged_count": len(discharged_list),
                "overdue_count": len(overdue_list),
                "blocked_count": blocked_count,
            },
        })
```

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass.

## Test plan

Add to `deep-agent-backend/tests/test_tools.py`, following the structural
pattern of `test_phase_progress_cb_tags_custom_events_with_tool_call_id` in
the same file (direct construction, no LangGraph runtime plumbing needed
since `get_obligation_status` only takes `session_id`):

- `test_get_obligation_status_exposes_blocked_reason` — construct a minimal
  `SessionContext`-compatible session the way
  `tests/engine/test_phase_event_contract.py`'s `_session()` helper does
  (import `LOCKSession`, `BudgetState` from `trace_agent.agents.lock_session`,
  build a session via `LOCKSession.from_seed(...)`), then directly append an
  `Obligation` with `blocked_reason="affected_host_unresolved"`,
  `discharged=False`, `hard=True` to `session.obligations.obligations` (you
  will need `session.obligations = ObligationLedger()` if not already
  populated by `from_seed` — check `LOCKSession.from_seed`'s defaults first).
  Register the session via `trace_deep_agent.phase_tools._store_session` with
  a `SessionContext(session_id=..., orch=<any object with no attrs touched>,
  lock_session=session, runner=<unused>)` — if constructing a full
  `SessionContext` is impractical without a real `ModularOrchestrator`, instead
  call `get_obligation_status.func` against a `SessionContext` built the same
  way `deep-agent-backend/tests/test_full_loop_streaming.py` builds sessions
  via `init_investigation.func(...)` against the `pipeline_18` scenario, run
  enough phases to get at least one obligation into
  `ctx.lock_session.obligations.obligations`, then call
  `get_obligation_status.func(session_id=...)` and assert on whatever
  `blocked_reason` values actually appear (may be empty string for a
  same-host obligation — assert the **key exists** in every open-item dict,
  which is the actual regression this test guards, rather than asserting a
  specific non-empty value if the scenario doesn't naturally produce a
  blocked obligation).
  - Minimum bar for this test, in order of preference:
    1. If you can cheaply construct a session with a manually-appended
       blocked `Obligation`, assert `blocked_reason == "affected_host_unresolved"`
       for that item.
    2. Otherwise, at minimum assert every dict in `open` has a
       `"blocked_reason"` key (guards the field always being present, which
       is the core regression this plan fixes) and `"blocked_count"` is a
       key in `summary`.

Verification: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass, including the new test.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "blocked_reason" deep-agent-backend/src/trace_deep_agent/query_tools.py` shows it inside the `get_obligation_status` open-item entry, not just read elsewhere
- [ ] `grep -n "blocked_count" deep-agent-backend/src/trace_deep_agent/query_tools.py` shows it in the `summary` dict
- [ ] `python -m pytest deep-agent-backend\tests -q` passes, including the new test
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 021 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `get_obligation_status`'s live code doesn't match the "Current state"
  excerpt (drift).
- Constructing a test session that reaches
  `ctx.lock_session.obligations.obligations` with a real or synthetic
  `Obligation` proves impractical after a genuine attempt with both
  approaches listed in the Test plan — fall back to the minimum-bar
  assertion (every open item has the `blocked_reason` key) rather than
  spending excessive effort on session scaffolding; note in your summary
  which approach you used.

## Maintenance notes

- This is purely additive (new dict keys, new summary count) — no existing
  consumer of `get_obligation_status`'s output shape should break, since JSON
  consumers by convention read known keys and ignore new ones.
- If plan 018 lands, `blocked_reason` will start showing
  `"sla_expired_no_recovery_path"` for anti-forensics obligations that timed
  out — that's the intended payoff of this plan combined with 018: the agent
  can now see *both* that an obligation is no longer hard-blocking *and* why
  it was never fully resolved, in one tool call.
- A reviewer should scrutinize: that `blocked_reason` defaults to `""` (not
  `None`) for obligations that were never blocked, keeping the JSON schema
  stable for every open item.
