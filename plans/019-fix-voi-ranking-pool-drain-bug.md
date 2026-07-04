# Plan 019: Fix get_voi_ranking's non-iterable CandidatePool bug and O-phase's destructive drain

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/phases/o_phase.py `
>   src/trace_agent/loop/candidate_pool.py `
>   deep-agent-backend/src/trace_deep_agent/query_tools.py `
>   src/trace_agent/tests/test_l_phase.py
> ```
> The worktree is dirty relative to `9dadd88` (plans 014–016 landed uncommitted,
> unrelated to this plan's files). Compare the "Current state" excerpts below
> against the live code before proceeding; on a mismatch, treat it as a STOP
> condition.

## Status

- **Priority**: P1
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none
- **Category**: bug
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

During a real investigation transcript, the agent called `get_voi_ranking`
(after `run_k_phase`, i.e. after `run_o_phase` had already executed earlier in
the same round) and got back "VOI 评估中候选池出错" / "VOI 计算失败——候选池
需要重新初始化" instead of a ranking. There are **two distinct bugs** here,
and both must be fixed for the tool to work at all:

1. **Primary, always-reproducing bug**: `get_voi_ranking` does
   `for probe in pool:` and `len(pool)` where `pool` is a `CandidatePool`
   instance. `CandidatePool` (`src/trace_agent/loop/candidate_pool.py`) has
   **no `__iter__` and no `__len__`** — it only exposes `add`, `drain`,
   `size`, `peek`, `remove`. Both operations raise `TypeError` unconditionally
   whenever `session.data["pool"]` holds a real (non-`None`) `CandidatePool`
   object, which is always true once `run_l_phase` has executed. The
   surrounding `try/except Exception as exc` swallows this into
   `{"status": "error", "error": "Failed to compute VOI ranking: 'CandidatePool' object is not iterable"}`
   — this is the literal error the transcript observed. **This bug exists
   regardless of whether O-phase has run** — it would also fire if called
   right after `run_veto_phase`, before O.
2. **Secondary, timing-dependent bug**: even after fixing (1), the ranking
   would come back **empty** any time `get_voi_ranking` is called after
   `run_o_phase` in the same round, because O-phase calls `pool.drain()` on
   the exact same shared `CandidatePool` object referenced by
   `session.data["pool"]`, clearing it in place. The tool's own docstring
   tells users to call it "只在 O 拍之后有意义（需要先执行 run_o_phase）" —
   which is exactly when the pool has just been emptied.

Both bugs must be fixed together: fixing only (1) still leaves the tool
returning an empty, useless ranking after O-phase (matching its own
docstring's recommended calling point); fixing only (2) would leave the tool
permanently broken with a `TypeError` regardless of timing.

## Current state

- `src/trace_agent/loop/candidate_pool.py:9-58` — `CandidatePool`. `drain()`
  clears the pool in place; `peek()` is non-destructive:

```python
class CandidatePool:
    """统一候选池：所有生成器产出的 Probe 去重后汇入此池。

    去重策略：相同 dedup_key() 的探针只保留一个（保留 priority_hint 更高的）。
    """

    def __init__(self) -> None:
        self._pool: dict[str, Probe] = {}  # dedup_key → Probe

    def add(self, probes: list[Probe]) -> int:
        ...

    def drain(self) -> list[Probe]:
        """取出所有候选并清空池。Returns probes ordered by priority_hint desc."""
        probes = sorted(self._pool.values(), key=lambda p: p.priority_hint, reverse=True)
        self._pool.clear()
        return probes

    def size(self) -> int:
        """当前池中候选数量"""
        return len(self._pool)

    def peek(self) -> list[Probe]:
        """查看当前候选（不清空）"""
        return sorted(self._pool.values(), key=lambda p: p.priority_hint, reverse=True)

    def remove(self, probe_ids: list[str]) -> int:
        """移除指定 probe（被 VETO 剪枝后调用）"""
        ...
```

- `src/trace_agent/phases/l_phase.py:56-96` creates a **new** `CandidatePool`
  each round (`pool = CandidatePool()` at line 58) and returns it in
  `PhaseResult.data["pool"]`. Via
  `deep-agent-backend/src/trace_deep_agent/phase_tools.py`'s
  `_apply_phase_data_passing` (phase `"L"`), this becomes
  `session.data["pool"]`.

- `src/trace_agent/phases/veto_phase.py:31-33,110-111` reads
  `session.data.get("pool")` and returns the **same object** (mutated
  in-place by `pool.remove(veto_ids)`) as `data["pool"]`. This again becomes
  `session.data["pool"]` after the Veto phase.

- `src/trace_agent/phases/o_phase.py:44-64` reads the same shared object and
  drains it:

```python
        # 义务物化 → 并入统一池
        pool = session.data.get("pool", CandidatePool())
        known_hosts_lower = (
            {h.lower() for h in session._scenario_hosts}
            if session._scenario_hosts else set()
        )
        graph_dict = graph_to_dict(session.graph, session._scenario_hosts or [])
        ...
        candidates = mandated_probes + pool.drain()
```

  O-phase's `PhaseResult.data` (see the rest of `o_phase.py`, roughly lines
  78-165) does **not** include a `"pool"` key, and
  `phase_tools._apply_phase_data_passing` for phase `"O"` only sets
  `session.data["chosen"]` — nothing reassigns `session.data["pool"]` after
  this point. So the object `session.data["pool"]` points to remains the
  same, now-empty, `CandidatePool` instance until the next L-phase overwrites
  it.

- `deep-agent-backend/src/trace_deep_agent/query_tools.py:177-203`
  (`get_voi_ranking`) — the docstring that gives the wrong calling
  instruction, and the code that silently degrades to an empty/near-empty
  ranking instead of erroring when the pool is empty-but-not-`None`:

```python
@tool
def get_voi_ranking(top_k: int = 10, session_id: str = "") -> str:
    """查看当前候选探针的 VOI（信息价值）排序。

    返回按 VOI 分数从高到低排序的候选探针列表，
    包含每个探针的风险削减和成本分解。

    只在 O 拍之后有意义（需要先执行 run_o_phase）。

    Args:
        top_k: 返回前 K 个探针（默认 10）
        session_id: 会话 ID（可选，留空则自动获取当前活跃会话）
    """
    ctx = _resolve_session(session_id)
    if isinstance(ctx, str):
        return ctx

    session = ctx.lock_session

    # Try to use the pool from session.data (populated by L/Veto phases)
    pool = session.data.get("pool")
    if pool is None:
        return _json({
            "status": "warning",
            "error": "No candidate pool available. Run run_o_phase first to generate VOI ranking.",
            "hint": "The candidate pool is populated after L phase and VOI ranking after O phase.",
        })
```

  Confirmed live at `query_tools.py:222-223` and `query_tools.py:275`:

```python
        results = []
        for probe in pool:
            ...
        return _json({
            "status": "ok",
            "ranking": results,
            "total_candidates": len(pool),
            "top_k": top_k,
        })
```

  Both `for probe in pool:` and `len(pool)` operate on the `CandidatePool`
  object directly — neither `__iter__` nor `__len__` exists on that class, so
  both raise `TypeError` and get caught by the `except Exception as exc:` at
  `query_tools.py:278-279`.

- `src/trace_agent/tests/test_l_phase.py:117,130` calls `pool.drain()`
  directly in test setup — unrelated to `o_phase.py`, do not touch.

- Other callers of `.drain()` you must **not** touch (legacy/eval, listed for
  awareness only): `src/trace_agent/agents/orchestrator.py:848`,
  `src/trace_agent/eval/ablation_experiment.py:337`,
  `src/trace_agent/eval/diag_gt_detail.py:114`.

## Design decision (do not redesign — implement exactly this)

Two independent fixes, both required:

1. In `get_voi_ranking`, replace direct iteration/`len()` on the
   `CandidatePool` object with `pool.peek()` (its documented, non-destructive
   accessor that returns a plain `list[Probe]`, which supports both
   iteration and `len()`). This fixes the always-reproducing `TypeError`.
2. Nothing in the LOCK loop itself depends on the shared `CandidatePool`
   object being physically emptied after O-phase runs — the *only* consumer
   of `session.data["pool"]` after O-phase is read-only introspection
   (`get_voi_ranking`), and the next round's L-phase always creates a
   **brand new** `CandidatePool` instance regardless of what's left in the
   old one. So make O-phase read the candidates via `pool.peek()` instead of
   `pool.drain()` too, leaving the shared object intact for introspection.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| O-phase / L-phase tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_l_phase.py src\trace_agent\tests\test_o_phase.py -q` | all pass (if `test_o_phase.py` doesn't exist, that's fine — just run the ones that do) |
| Full loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass |
| Deep-agent-backend tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |

Use system Python 3.11.5. Do NOT use `deep-agent-backend/.venv`. PowerShell on
this machine does not support `&&` — use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/phases/o_phase.py`
- `deep-agent-backend/src/trace_deep_agent/query_tools.py`
- `deep-agent-backend/tests/test_tools.py` (add a regression test) — check
  this file exists first; if the repo has since added a more specific test
  file for query tools, add the test there instead and note it in your
  summary.

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_agent/loop/candidate_pool.py` — `drain()` and `peek()` are
  correct as-is; do not change `CandidatePool` itself, only which method
  `o_phase.py` calls.
- `src/trace_agent/agents/orchestrator.py`,
  `src/trace_agent/eval/ablation_experiment.py`,
  `src/trace_agent/eval/diag_gt_detail.py` — legacy/eval callers of
  `pool.drain()`; leave them using `drain()` as-is.
- Plan 018's obligation-deadlock work — unrelated, may land independently.

## Git workflow

- Branch: `advisor/019-voi-ranking-pool-drain-fix`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Make O-phase read the pool non-destructively

In `src/trace_agent/phases/o_phase.py`, change:

```python
        candidates = mandated_probes + pool.drain()
```

to:

```python
        candidates = mandated_probes + pool.peek()
```

This is the only functional change needed in this file. Everything downstream
of `candidates` (dedup, scoring, selection) is unaffected because it operates
on the returned list, not on the pool object's internal state.

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` → all pass, same pass count as before this change (selection behavior must be identical — see STOP conditions).

### Step 2: Fix `get_voi_ranking`'s pool iteration, `len()` call, and docstring

In `deep-agent-backend/src/trace_deep_agent/query_tools.py`, confirm the live
code still matches the "Current state" excerpt (`for probe in pool:` at
line ~223 and `len(pool)` at line ~275) before editing; if it has already
been changed to use `pool.peek()`, skip the code changes below and only fix
the docstring/hint text (drift from what was captured when this plan was
written).

Otherwise, change:

```python
        results = []
        for probe in pool:
```

to:

```python
        results = []
        candidates = pool.peek()
        for probe in candidates:
```

and change:

```python
            "total_candidates": len(pool),
```

to:

```python
            "total_candidates": len(candidates),
```

Then fix the docstring — replace:

```python
    只在 O 拍之后有意义（需要先执行 run_o_phase）。
```

with:

```python
    在 L/Veto 拍之后即可调用（候选池由 L 拍生成，Veto 拍过滤）。
    O 拍不再清空该池，因此 O 拍之后调用同样有效。
```

And update the "No candidate pool available" warning's hint text from:

```python
            "hint": "The candidate pool is populated after L phase and VOI ranking after O phase.",
```

to:

```python
            "hint": "The candidate pool is populated after L phase; call run_l_phase first.",
```

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass.

## Test plan

Add to `deep-agent-backend/tests/test_tools.py` (or the query-tools-specific
test file if one already exists — check first), following the structural
pattern of the existing `test_phase_progress_cb_tags_custom_events_with_tool_call_id`
test (constructs a fake runtime, calls the tool's underlying function
directly via `.func(...)`, not `.invoke(...)` — see plan 016's
`deep-agent-backend/tests/test_full_loop_streaming.py` for the working
pattern with `init_investigation.func(...)` / `run_full_loop.func(...)`):

- `test_get_voi_ranking_works_before_o_phase` — call
  `init_investigation.func(technique="T1059.001", asset="SRV-MAIL-01", scenario_id="pipeline_18", backend="scenario", max_rounds=3, runtime=<fake>)`,
  then `run_l_phase.func(session_id=..., runtime=<fake>)`, then
  `run_veto_phase.func(session_id=..., runtime=<fake>)`, then call
  `get_voi_ranking.func(session_id=...)` (import from
  `trace_deep_agent.query_tools`) and assert the parsed JSON has
  `status == "ok"` (not `"error"` with a `"not iterable"` message) and
  `total_candidates > 0`. This repros the always-reproducing `TypeError` bug
  (1) — must pass even without O-phase having run.
- `test_get_voi_ranking_works_after_o_phase` — same setup, additionally call
  `run_o_phase.func(session_id=..., runtime=<fake>)` before
  `get_voi_ranking.func(...)`, and assert `status == "ok"` and
  `total_candidates > 0` (not the empty-pool result). This repros the
  timing-dependent bug (2) from the original transcript.

Verification: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass, including the new test.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "pool.drain()" src/trace_agent/phases/o_phase.py` returns no matches
- [ ] `grep -n "pool.peek()" src/trace_agent/phases/o_phase.py` returns at least one match
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes with the same pass count as before this plan (27 as of this writing)
- [ ] `python -m pytest deep-agent-backend\tests -q` passes, including the two new tests `test_get_voi_ranking_works_before_o_phase` and `test_get_voi_ranking_works_after_o_phase`
- [ ] `get_voi_ranking`'s docstring no longer says "只在 O 拍之后有意义（需要先执行 run_o_phase）"
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 019 updated

## STOP conditions

Stop and report back (do not improvise) if:

- `o_phase.py`'s use of `pool.drain()` doesn't match the "Current state"
  excerpt (drift) — e.g. if it has since been refactored to reassign
  `session.data["pool"]` after draining, this plan may already be moot;
  report instead of re-applying the fix blindly.
- Changing `drain()` → `peek()` changes any assertion in
  `test_full_loop.py` (rounds used, stop_reason, chosen probes, graph
  size) — this would mean something *does* depend on the pool being
  physically emptied; revert and report exactly which test changed and how.
- `get_voi_ranking`'s pool iteration already uses `pool.peek()` (not a bare
  `for probe in pool:`) — then only the docstring/hint text portion of Step 2
  applies; do not invent a second fix for a bug that isn't there.

## Maintenance notes

- If a future change reintroduces a destructive read of
  `session.data["pool"]` anywhere in the L→Veto→O chain, the same class of
  bug will resurface for any tool reading `session.data["pool"]` after that
  point. The generalizable rule for reviewers: any phase that needs to
  "consume" the pool should either reassign `session.data["pool"]` to a
  fresh/updated object afterward, or use the non-destructive `peek()`.
- Plan 011 (state-machine unification) may touch inter-phase data passing;
  when it lands, re-verify this invariant still holds.
- This plan does not change `CandidatePool.drain()` itself — it's still used
  correctly by the legacy orchestrator and eval scripts, which have their own
  separate lifecycle and are not affected by this fix.
