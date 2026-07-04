# Plan 026: Add a minimum-probability floor to the runtime posterior update

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/decision/runtime_ledger.py `
>   src/trace_agent/tests/test_c_phase.py
> ```
> This file is tracked at `9dadd88` and unmodified relative to it as of this
> plan's writing (should print nothing).

## Status

- **Priority**: P2
- **Effort**: S
- **Risk**: LOW
- **Depends on**: none (pairs well with Plan 022 — that plan reduces how
  often `__null__` gets driven this low in the first place; this plan adds a
  numerical safety net regardless of cause)
- **Category**: bug (numerics / robustness)
- **Planned at**: commit `9dadd88`, 2026-07-04

## Why this matters

A reviewer noted the `null_anchor` posterior dropped to `2.9e-18` in a
report and asked whether the engine does Laplace smoothing or has a
lower-bound guard — flagging that, combined with the false-positive-ATTACH
issue (Plan 022), this posterior is probably being driven artificially low
by evidence that should never have counted against it.

The seed-time null anchor (`DecisionLedger._compute_null_anchor` in
`src/trace_agent/decision/belief.py`) **does** have bounds — `benign`/`oos`
are each clamped to `[0.05, 0.70]` before the investigation starts. But that
clamp only applies once, at seeding. The **runtime** posterior update
(`RuntimeDecisionLedger.update()`, called every K-phase round) has no
equivalent floor: each event's log-likelihood contribution to `__null__` is
individually floored at `-3.0` (via `max(-3.0, ...)` in
`_null_log_likelihood_v2`), but nothing prevents the **cumulative** log
posterior across many rounds/events from drifting arbitrarily low. With,
say, 14 events each contributing close to the `-3.0` floor against
`__null__` in the "strong attack" branch, `14 × -3.0 = -42` in log-space,
and `exp(-42) ≈ 5.7e-19` — the same order of magnitude as the reported
`2.9e-18`. This is architecturally consistent with "no smoothing", not a
one-off numeric glitch.

A posterior this extreme is a red flag independent of whether the
underlying ATTACH decisions were correct (Plan 022) — even a *correctly*
confident investigation should carry an explicit floor so "we are very
confident" (e.g. `1e-4`) is distinguishable from "the math underflowed
past any meaningful precision" (`1e-18`), and so a single later
disconfirming event can still move the posterior within a finite number of
rounds instead of requiring an astronomically large log-likelihood swing to
climb back out of a `-40`+ log-posterior hole.

## Current state

- `src/trace_agent/decision/runtime_ledger.py:751-760`
  (`_normalize_log_post`) — pure log-sum-exp normalization, no floor:

```python
    def _normalize_log_post(self) -> None:
        """归一化对数后验（log-sum-exp）"""
        if not self.log_post:
            return
        max_lp = max(self.log_post.values())
        log_sum = max_lp + math.log(
            sum(math.exp(lp - max_lp) for lp in self.log_post.values())
        )
        for key in self.log_post:
            self.log_post[key] -= log_sum
```

- `runtime_ledger.py:762-776` (`_get_probabilities`) — converts log-space
  back to probability space, again with no floor:

```python
    def _get_probabilities(self) -> Dict[str, float]:
        """将对数后验转为概率空间"""
        if not self.log_post:
            return {}
        max_lp = max(self.log_post.values())
        probs = {}
        total = 0.0
        for key, lp in self.log_post.items():
            p = math.exp(lp - max_lp)
            probs[key] = p
            total += p
        if total > 0:
            for key in probs:
                probs[key] /= total
        return probs
```

- `runtime_ledger.py:363-399` (`_null_log_likelihood_v2`) — each event's
  contribution against `__null__` is floored per-event at `-3.0`, but there
  is no cap on how many events can each apply that floor in the same
  direction across a session:

```python
        if signal == "attack_strong":
            fit_null = 0.08 * (1.0 + max(0.0, 1.0 - w_trust) * 0.3)
            return max(-3.0, math.log(max(fit_null, 0.02)))
```

- `src/trace_agent/decision/belief.py:506-508` (`_compute_null_anchor`,
  **seed-time only**, for contrast — this is the bound that already exists
  but doesn't apply after the investigation starts):

```python
        benign = min(max(benign, 0.05), 0.70)
        oos = min(max(oos, 0.05), 0.70)
        return NullAnchor(benign=round(benign, 3), oos=round(oos, 3), reasons=reasons)
```

- `src/trace_agent/utils/config.py` — read this file to confirm the existing
  constant naming convention (`EPS_CULL`, `TAU_SPAWN`, `TAU_MERGE`, etc. are
  imported into `runtime_ledger.py` at the top) before adding a new
  constant, to match style.

## Design decision (do not redesign — implement exactly this)

Add a configurable minimum-probability floor, applied inside
`_normalize_log_post` (the one place all posterior updates already flow
through), not scattered across individual likelihood functions:

1. Define a new constant, e.g. `MIN_POSTERIOR_FLOOR = 1e-6` (matches the
   `1e-6` epsilon already used elsewhere in this file for `log(0)`
   protection at seed time — see `RuntimeDecisionLedger.__init__`'s
   `p = max(e.prior_probability, 1e-6)` — so this is consistent with
   existing precedent, not a new arbitrary number).
2. After normalizing, if any key's probability would fall below
   `MIN_POSTERIOR_FLOOR`, raise its log-posterior to `log(MIN_POSTERIOR_FLOOR)`
   and re-normalize once more (so the floor doesn't itself break the
   invariant that probabilities sum to 1).
3. Apply this **only** in `_normalize_log_post` (called from `update()`
   after every round, from `spawn_merge_cull()` after culling/merging, and
   from `hypothetical_update()`'s VOI-lookahead copy) so both the "real"
   posterior and VOI's one-step-lookahead posterior get the same floor
   consistently.
4. Do **not** change the per-event `-3.0` log-likelihood floors in
   `_log_likelihood_v2`/`_null_log_likelihood_v2` — those are about
   single-event influence, a different (and already-reasonable) concern from
   this plan's cumulative-posterior floor.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Runtime ledger / C-phase tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_c_phase.py -q` | all pass |
| Full loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass, same pass count as before |
| VOI engine tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_voi_engine.py -q` | all pass |

Use system Python 3.11.5. PowerShell on this machine does not support `&&` —
use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/decision/runtime_ledger.py`
- `src/trace_agent/tests/test_c_phase.py` (or a dedicated runtime-ledger test
  file if one exists — check first)

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_agent/decision/belief.py` — its seed-time `_compute_null_anchor`
  clamp is unrelated and already correct; do not "unify" the two mechanisms,
  they operate on different quantities (seed prior components vs. runtime
  posterior).
- `src/trace_agent/utils/config.py` if it would require restructuring how
  constants are organized — just add the one new constant inline at the top
  of `runtime_ledger.py` next to the existing `MAX_CONTESTED_EDGES`-style
  module constants in `belief.py`, or alongside the existing imports from
  `..utils.config` in `runtime_ledger.py`, whichever matches this file's
  existing convention more closely (check both before deciding).
- `EPS_CULL`/`CULL_PATIENCE` culling logic in `spawn_merge_cull` — this plan
  does not change when an explanation gets culled, only the floor applied
  during normalization that happens to also run inside that method.

## Git workflow

- Branch: `advisor/026-posterior-floor`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Add the floor constant and apply it inside `_normalize_log_post`

In `src/trace_agent/decision/runtime_ledger.py`, add near the top (with the
other module-level imports/constants):

```python
# Minimum posterior probability floor. Without this, many rounds of
# strong-attack evidence against __null__ (or against a culled-out
# explanation before it's removed) can drive a log-posterior arbitrarily far
# below any meaningful precision (e.g. 1e-18), which is indistinguishable
# from a genuine "very confident" result but leaves no room to recover if a
# single later disconfirming event arrives. 1e-6 matches the existing
# log(0)-guard epsilon already used at seed time in this class's __init__.
MIN_POSTERIOR_FLOOR = 1e-6
```

Then change `_normalize_log_post`:

```python
    def _normalize_log_post(self) -> None:
        """归一化对数后验（log-sum-exp），并对每一项施加最小概率下限。"""
        if not self.log_post:
            return
        max_lp = max(self.log_post.values())
        log_sum = max_lp + math.log(
            sum(math.exp(lp - max_lp) for lp in self.log_post.values())
        )
        for key in self.log_post:
            self.log_post[key] -= log_sum

        floor_log = math.log(MIN_POSTERIOR_FLOOR)
        below_floor = [key for key, lp in self.log_post.items() if lp < floor_log]
        if below_floor:
            for key in below_floor:
                self.log_post[key] = floor_log
            # Re-normalize once more so probabilities still sum to 1 after
            # raising any floored entries.
            max_lp2 = max(self.log_post.values())
            log_sum2 = max_lp2 + math.log(
                sum(math.exp(lp - max_lp2) for lp in self.log_post.values())
            )
            for key in self.log_post:
                self.log_post[key] -= log_sum2
```

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` → all pass.

### Step 2: Confirm the floor is visible through the existing query paths

No code change needed — `posterior()`, `leading()`, `margin()`, `entropy()`,
and `get_state()` all already read from `self.log_post`/`_get_probabilities()`,
so they automatically reflect the floor once Step 1 lands. Re-run the full
test suite to confirm nothing downstream hard-codes an assumption that
`__null__`'s probability can be arbitrarily small.

**Verify**: `python -m pytest src\trace_agent\tests\test_full_loop.py src\trace_agent\tests\test_voi_engine.py -q` → all pass, same pass counts as before.

## Test plan

Add to `src/trace_agent/tests/test_c_phase.py` (or the dedicated
runtime-ledger test file, matching its existing fixture-construction style
for `RuntimeDecisionLedger`):

- `test_null_posterior_never_drops_below_floor_after_many_strong_attack_events`
  — construct a `RuntimeDecisionLedger` with one explanation, then call
  `update(...)` repeatedly (15-20 iterations) with synthetic `ATTACH`-routed,
  attribution-confirmed events (matching the fixture pattern other
  `update()` tests already use). Assert `ledger.posterior("__null__") >=
  MIN_POSTERIOR_FLOOR / 2` (allow a small numerical margin) after the loop,
  proving it never underflows past the floor regardless of how many rounds
  run.
- `test_normalize_log_post_still_sums_to_one_after_flooring` — after
  triggering the floor path (same setup as above), assert
  `sum(ledger._get_probabilities().values())` is within `1e-9` of `1.0`.
- `test_floor_does_not_change_behavior_when_no_extreme_posterior_exists` —
  run a normal, short `update()` sequence (2-3 events) where no posterior
  would naturally approach the floor; assert posteriors are numerically
  identical (within floating-point tolerance) to what they'd be without the
  floor logic — i.e. prove Step 1 is a no-op for the common case.

Verification: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` → all pass, including the new tests.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "MIN_POSTERIOR_FLOOR" src/trace_agent/decision/runtime_ledger.py` shows the constant and its use inside `_normalize_log_post`
- [ ] `python -m pytest src\trace_agent\tests\test_c_phase.py -q` passes, including 3 new tests
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py src\trace_agent\tests\test_voi_engine.py -q` pass with the same pass counts as before this plan
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 026 updated

## STOP conditions

Stop and report back (do not improvise) if:

- Any existing test asserts an exact posterior value that would shift once
  the floor is applied (e.g. a test that runs many rounds and checks
  `__null__`'s posterior against a very small literal) — read it fully; if
  it's asserting a value smaller than `MIN_POSTERIOR_FLOOR`, that test was
  implicitly relying on unbounded underflow and its expectation needs
  updating to reflect the (now intentionally bounded) floor — describe the
  before/after values in your summary rather than silently patching the
  assertion.
- `spawn_merge_cull`'s culling threshold `EPS_CULL` is at or below
  `MIN_POSTERIOR_FLOOR` — this would mean an explanation could get stuck at
  exactly the floor without ever being culled (since its probability never
  drops further to trigger `EPS_CULL`'s comparison). Check `EPS_CULL`'s
  value in `src/trace_agent/utils/config.py` before implementing; if
  `EPS_CULL <= MIN_POSTERIOR_FLOOR`, report this instead of picking an
  arbitrary floor value that happens to avoid the collision.
- The re-normalization after flooring (the second `log_sum2` pass in Step 1)
  would need to run more than once to converge (e.g. flooring one key pushes
  another key below the floor) — if you observe this in testing, report it;
  do not add an unbounded loop to "make it converge" without understanding
  why multiple keys are colliding with the floor simultaneously.

## Maintenance notes

- `MIN_POSTERIOR_FLOOR = 1e-6` is chosen to match the existing seed-time
  epsilon in this same class, not derived from a calibration study. A
  reviewer should treat this as a numerics safety net, not a claim that
  `1e-6` is the "right" minimum confidence for any real hypothesis — if
  calibration work (see plans 003/004, already DONE per `plans/README.md`)
  later needs a different floor for calibrated-probability purposes, that is
  a separate concern from this plan's raw-posterior numerics guard.
- This floor is per-key, not a joint constraint across all keys — with many
  explanations plus `__null__`, it's possible (though unlikely given
  `K_MAX` bounds the explanation count) for the floor to be applied to
  several keys in the same normalization pass; the re-normalization step
  handles this correctly by construction (log-sum-exp over whatever values
  remain after flooring), but a reviewer should still confirm the "Test
  plan"'s sum-to-one test passes robustly, not just for the specific fixture
  used.
