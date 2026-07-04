# Plan 022: Stop misclassifying Wazuh infrastructure events as ATTACH evidence once one hypothesis dominates

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/loop/ingest.py `
>   src/trace_agent/decision/runtime_ledger.py src/trace_agent/tests/test_c_phase.py `
>   src/trace_agent/tests/test_runtime_ledger.py
> ```
> `ingest.py` and `runtime_ledger.py` are tracked at commit `9dadd88` and were
> **not** modified relative to it as of this plan's writing (verify with the
> command above — it should print nothing). Compare the "Current state"
> excerpts below against the live code before proceeding; on a mismatch,
> treat it as a STOP condition.

## Status

- **Priority**: P0
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug (correctness / false positive)
- **Planned at**: commit `9dadd88`, 2026-07-04

## Why this matters

A server-side reviewer of a `real_trace_01` investigation found that two
Wazuh **infrastructure/informational events** — `"Wazuh server started."`
(built-in rule, `level: 3`, fired because the Manager was restarted during
scenario deployment) and a log-rotation event — were routed to `ATTACH` and
folded into the leading hypothesis `H1 (credential_theft_v1)` in rounds 2–3,
even though they are semantically unrelated to the attack chain. The
reviewer's hypothesis was that once a hypothesis's posterior is saturated
(≈1.0), new evidence stops being evaluated on its own merits and defaults to
attaching to the leading hypothesis.

Reading the code shows the mechanism is real but indirect — there is no
explicit `if posterior > threshold: attach_to_leading` branch. Instead, four
independent permissive defaults compound once the graph has grown and
competing explanations have been culled down to one:

1. **L1 structural attachment has an "unknown tactic → allow" fallback.**
   `_tactic_can_follow` (`src/trace_agent/loop/ingest.py:705-724`) is used to
   decide whether an event's tactic can plausibly follow a frontier node's
   tactic. When either tactic string isn't one of the 14 known MITRE tactics
   — which is exactly the case for a Wazuh infrastructure event with no
   `mitre_technique`/`mitre_tactic` mapping — `.index()` raises `ValueError`,
   and the method returns `True` ("unknown tactics — allow by default"). This
   means an event with a garbage/absent tactic is *structurally easier* to
   attach than one with a real, mismatched tactic.
2. **The temporal window that gates attachment grows with graph size**, up to
   24 hours once the graph has ≥10 nodes (`ingest.py:309-337`), so late-round
   infrastructure events (fired by an unrelated Manager restart hours away
   from the real attack) still fall inside the window.
3. **Structural fit is a flat bonus, not a technique-specific score.** Once L1
   marks an event `_l1_attachable`, `_compute_fit_struct`
   (`src/trace_agent/decision/runtime_ledger.py:221-253`) returns a flat
   `0.5` for **any** remaining explanation, regardless of whether the event's
   technique has anything to do with that explanation's technique context.
   This is the same score every surviving explanation gets, so it does not
   discriminate — it just makes the event easier to clear the ATTACH
   threshold for whichever explanation happens to still be alive.
4. **Lifecycle-type explanations (typically `H1`, since it's seeded first —
   see `src/trace_agent/decision/belief.py:110-133`) get a stage-fit bonus for
   *any* tactic.** `_compute_fit_stage` / `_compute_fit_stage_v2`
   (`runtime_ledger.py:287-291`, `324-328`) return `0.4`/`0.5` for lifecycle
   explanations regardless of the event's tactic, versus `0.35` for
   non-lifecycle explanations with no match. Combined with (3), a lifecycle
   `H1` needs very little from an event to clear
   `TH_ATTR_ATTACH = -2.0` (`ingest.py:21`) once it's the only or dominant
   surviving explanation (competing explanations are removed by
   `spawn_merge_cull` once their posterior stays below `EPS_CULL` for
   `CULL_PATIENCE` rounds — `runtime_ledger.py:662-680`).

None of this requires reading `ledger.posterior()` directly — it is an
emergent effect of (a) L1 admitting the event at all via the unknown-tactic
default, (b) every surviving explanation getting the same generic structural
bonus, and (c) the K-phase route-aware likelihood boost
(`_log_likelihood_v2`, `runtime_ledger.py:181-219`, `+0.8` for
`attack_strong` signal) reinforcing whatever got ATTACHed. Separately, there
is **no filter anywhere in the C-phase pipeline for Wazuh's own
informational/infrastructure events** — nothing checks `rule.level`,
`rule_level`, or an "informational" flag before an event enters L0–L4 triage.

## Current state

- `src/trace_agent/loop/ingest.py:1-26` — required fields and thresholds:

```python
PROMOTABLE_TIERS = ("medium", "high", "forge_resistant")
TH_ATTR_ATTACH = -2.0
TH_ATTR_BACKWARD = -2.5

# Required fields for a valid event
_REQUIRED_FIELDS = {"id", "technique", "tactic", "timestamp", "source"}
```

  Note: an event only needs a **non-empty string** in `tactic` to pass L0 —
  it does not need to be one of the 14 known MITRE tactic values. A Wazuh
  informational event normalized with, e.g., `tactic="unknown"` or a raw
  Wazuh rule group name would still pass L0.

- `ingest.py:705-724` — the unknown-tactic default-allow bug:

```python
    @staticmethod
    def _tactic_can_follow(current_tactic: str, next_tactic: str) -> bool:
        """Check if tactic progression is plausible in attack lifecycle."""
        tactic_order = [
            "reconnaissance", "resource-development", "initial-access",
            "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery",
            "lateral-movement", "collection", "command-and-control",
            "exfiltration", "impact",
        ]
        try:
            ci = tactic_order.index(current_tactic)
            ni = tactic_order.index(next_tactic)
            # Allow same phase and forward progression (up to 4 steps);
            # no backward progression (prevents unrelated tactic attachment)
            diff = ni - ci
            return 0 <= diff <= 4
        except ValueError:
            # Unknown tactics — allow by default
            return True
```

  This same method is called from the bootstrap-relaxation path at
  `ingest.py:376-388`:

```python
        # Bootstrap relaxation: 延长bootstrap松弛期，前6个节点允许宽松附着
        if not parent_candidates and node_count <= 6 and event_tactic:
            # Must pass tactic progression check to avoid attaching unrelated events
            for nid in frontier:
                node = self._graph.get_node(nid)
                if node and self._tactic_can_follow(node.tactic, event_tactic):
                    parent_candidates.append(nid)
                    temporal_fit = True
                    break
```

  and from the main frontier scan at `ingest.py:348-362`:

```python
        frontier = self._graph.frontier()
        for nid in frontier:
            node = self._graph.get_node(nid)
            if node is None:
                continue

            # Temporal proximity check (adaptive window)
            if abs(node.timestamp - event_ts) <= temporal_window:
                temporal_fit = True
                # Check if tactic progression makes sense or target matches
                if node.attributes.get("target") == event_target:
                    parent_candidates.append(nid)
                elif self._tactic_can_follow(node.tactic, event_tactic):
                    parent_candidates.append(nid)
```

- `ingest.py:309-337` — temporal window grows with graph size, up to 24h:

```python
        if node_count <= 6:
            temporal_window = 7200    # 2 hours (bootstrap)
        elif node_count <= 10:
            temporal_window = 3600    # 1 hour (early growth)
        else:
            host_count = self._compute_host_count()
            if host_count > 1:
                temporal_window = 1800
            else:
                temporal_window = 600
        if node_count >= 10:
            try:
                ts_vals = [
                    n.timestamp for n in self._graph._nodes.values()
                    if n.timestamp > 0
                ]
                if ts_vals:
                    graph_span = max(ts_vals) - min(ts_vals)
                    adaptive_window = int(graph_span * 0.5)
                    if adaptive_window > temporal_window:
                        temporal_window = max(adaptive_window, 86400)  # 至少24h
```

- `ingest.py:571-585` — the ATTACH-eligibility check that ultimately reads
  these scores:

```python
    def _has_clear_attribution(
        self,
        event: dict,
        alert_context: Optional[dict] = None,
    ) -> bool:
        attribution_scores = event.get("_l3_attribution_scores", {})
        if not attribution_scores:
            return False
        best_score = max(attribution_scores.values())
        if best_score > TH_ATTR_ATTACH:
            return True
        alert_context = alert_context or {}
        if self._is_backward_provenance_candidate(event, alert_context):
            return best_score > TH_ATTR_BACKWARD
        return False
```

- `ingest.py:505-541` (`_l4_route`) — routing rules 2/2b/3 that consume
  `_has_clear_attribution`:

```python
        high_trust = trust_tier in ("forge_resistant", "high")
        medium_trust = trust_tier == "medium"
        has_attribution = self._has_clear_attribution(event, alert_context=alert_context)

        # Rule 2: ATTACH — high trust + attachable + clear attribution
        if high_trust and attachable and has_attribution:
            return ROUTE_ATTACH

        # Rule 2b: ATTACH — medium trust + attachable + clear attribution (growth phase)
        if medium_trust and attachable and has_attribution:
            return ROUTE_ATTACH

        # Rule 3: WEAK — attachable but weak trust or weak attribution
        if attachable and (not has_attribution):
            return ROUTE_WEAK
```

  Wazuh's own informational rules default to `trust_tier="medium"` in
  practice (no adversary control, moderate integrity), so once `attachable`
  and `has_attribution` are both true, Rule 2b fires.

- `src/trace_agent/decision/runtime_ledger.py:221-253`
  (`_compute_fit_struct`) — the flat structural bonus for any attachable
  event:

```python
    def _compute_fit_struct(self, event: dict, explanation: Explanation) -> float:
        """结构匹配：事件 technique 与解释的技术上下文 overlap"""
        event_technique = event.get("technique_id", "") or event.get("technique", "")

        if event_technique and event_technique == explanation.current_technique:
            return 0.9
        if explanation.technique_context:
            for ctx in explanation.technique_context:
                if event_technique in (ctx.get("src", ""), ctx.get("dst", "")):
                    return 0.7
        if explanation.predecessor_tactics:
            for pred in explanation.predecessor_tactics:
                related = pred.get("related_techniques", [])
                if event_technique in related:
                    return 0.5

        # Graph-aware 加分：若事件已被 L1 结构挂接（有 parent candidates），
        # 说明它在攻击图中有位置，应获得更高的结构匹配分
        if event.get("_l1_attachable") and event.get("_l1_parent_candidates"):
            return 0.5

        if explanation.lifecycle_template and explanation.support:
            template_id = explanation.support.get("template_id", "")
            if template_id and event_technique:
                return 0.3

        return 0.3  # 无明显关联（中性，不惩罚）
```

  Note this method receives `explanation` as an argument but the
  `_l1_attachable` branch never inspects it — the `0.5` is identical for
  every explanation the caller iterates over.

- `runtime_ledger.py:255-291` (`_compute_fit_stage`, used by
  `_log_likelihood`) and `runtime_ledger.py:293-328`
  (`_compute_fit_stage_v2`, used by `_log_likelihood_v2`, the one K-phase
  actually calls) — the lifecycle-type "any tactic" bonus, at the tail of
  each function:

```python
        # lifecycle template 阶段匹配
        if explanation.support and explanation.support.get("type") == "lifecycle":
            return 0.4    # _compute_fit_stage tail
```
```python
        # lifecycle template
        if explanation.support and explanation.support.get("type") == "lifecycle":
            return 0.5    # _compute_fit_stage_v2 tail
```

- `runtime_ledger.py:157-179` (`_log_likelihood`, called from
  `spawn_merge_cull` and from `ingest.py`'s `_l3_attribution`) — where these
  three factors combine, each independently floored at `0.05` before
  `log()`:

```python
    def _log_likelihood(self, event: dict, explanation: Explanation, trust) -> float:
        fit_struct = self._compute_fit_struct(event, explanation)
        fit_stage = self._compute_fit_stage(event, explanation)
        evidence_id = event.get("id", "")
        w_trust = trust.weight_likelihood(1.0, evidence_id) if trust else 0.5
        log_struct = max(-3.0, min(0.0, math.log(max(fit_struct, 0.05))))
        log_stage = max(-3.0, min(0.0, math.log(max(fit_stage, 0.05))))
        log_trust = max(-3.0, min(0.0, math.log(max(w_trust, 0.05))))
        return log_struct + log_stage + log_trust
```

  Worked example matching the reviewer's scenario: an infra event with
  `_l1_attachable=True` (via the unknown-tactic default) against a lifecycle
  `H1` gets `fit_struct=0.5` (log ≈ `-0.69`), `fit_stage=0.4` (lifecycle tail,
  log ≈ `-0.92`), and `w_trust≈0.5` (log ≈ `-0.69`) → total ≈ `-2.30`. That is
  *below* `TH_ATTR_ATTACH=-2.0` by itself, but `_l3_attribution`
  (`ingest.py:459-503`) uses `_log_likelihood` — wait, it actually iterates
  `self._ledger.explanations` and if `H1` is the *only* surviving explanation
  (competitors already culled — see `runtime_ledger.py:662-680`), `best_id`
  is `H1` by construction and any score above the threshold routes to
  ATTACH. With `w_trust` around `0.55-0.6` (typical for Wazuh's own
  first-party informational rules, which are not adversary-controllable),
  the total clears `-2.0`.

- No informational-event filter exists anywhere in `ingest.py` — confirmed by
  reading the full `L0`–`L4` pipeline (`_l0_denoise` at `267-286` only checks
  required-field presence and event-id dedup) and by grep: there is no
  `rule_level`, `rule.level`, or `informational` check in
  `src/trace_agent/loop/ingest.py`. `src/trace_engine/attack_chain_materializer.py`
  has a `_rule_level()` helper (`131-143`) but it is only used to *rank*
  events during the Bootstrap chain-materialization step, not to gate the
  C-phase `IngestPipeline.triage()` 5-bucket router used by the live
  Deep Agent phase path.

## Design decision (do not redesign — implement exactly this)

Four independent, additive fixes. Land all four; they close different parts
of the same failure mode and the existing tests (see "Test plan") pin the
combination.

1. **Remove the unknown-tactic default-allow in `_tactic_can_follow`.** An
   event whose tactic isn't a recognized MITRE tactic must not be treated as
   "plausibly follows" the frontier node — flip the `except ValueError`
   fallback to `return False`.
2. **Add an L0 filter for Wazuh informational/infrastructure events.** Before
   an event enters `_l1_structural`, drop (route to `DISCARD`, matching the
   existing hard-veto-adjacent semantics) events with no MITRE technique
   mapping **and** a low rule level. Use the already-normalized
   `attributes.rule_level` field (see
   `src/trace_engine/normalizer.py:70-72`, aliased in `_telemetry_attributes`)
   — if `rule_level` is present and `<= 3` **and** `technique` is falsy, this
   is a Wazuh-native informational/housekeeping event, not an attack
   candidate.
3. **Make `_compute_fit_struct`'s attachable-bonus technique-aware, not
   flat.** Require some minimal signal that the event's technique or tactic
   is plausibly related to *this specific* explanation before granting the
   `0.5` bonus — reuse the same kill-chain-adjacency check already used by
   `_compute_fit_stage_v2` (`_is_kill_chain_predecessor`) instead of granting
   it unconditionally to any `_l1_attachable` event.
4. **Do not give lifecycle explanations a stage-fit bonus for tactics with no
   relationship to the template.** Only grant the lifecycle tail bonus
   (`0.4`/`0.5`) when the event's tactic is one of the template's own stage
   tactics (check against `explanation.support` template stages via the
   already-available `lifecycle_template_candidates`/support data), not for
   every tactic.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| C-phase / ingest tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_c_phase.py -q` | all pass |
| Runtime ledger tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_runtime_ledger.py -q` (if this file doesn't exist, search for ledger coverage inside `test_c_phase.py`/`test_integration.py` and run those instead — note which in your summary) | all pass |
| Full loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass, same pass count as before |
| Full trace_agent suite | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests -q` | same pass/fail counts as baseline (see STOP conditions — 2 pre-existing failures in `test_integration.py`/`test_trust_registry.py` about `log_source_trust.json` having 15 vs 14 sources are unrelated to this plan; do not try to fix them) |

Use system Python 3.11.5. PowerShell on this machine does not support `&&` —
use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/loop/ingest.py`
- `src/trace_agent/decision/runtime_ledger.py`
- `src/trace_agent/tests/test_c_phase.py` (add regression tests)
- A runtime-ledger-focused test file (add regression tests; use whichever
  existing file covers `RuntimeDecisionLedger` unit behavior — check for
  `test_runtime_ledger.py` first, fall back to adding to `test_c_phase.py`
  if a dedicated file doesn't exist and note this in your summary)

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_agent/decision/belief.py` — this is the **seed-time** explanation
  builder (runs once per alert), not the runtime per-event scorer. Its
  `_compute_null_anchor` bounds are a separate concern from this plan (see
  plan 026 for the runtime posterior-floor issue).
- `src/trace_engine/attack_chain_materializer.py` — its `_rule_level()`
  scoring only affects Bootstrap candidate-chain ranking for the
  `pipeline_18`-style materializer, a different code path from the live
  `IngestPipeline.triage()` this plan fixes. Do not add cross-wiring between
  them.
- `src/trace_agent/loop/llm_ingest.py` — the LLM tie-break path already has
  its own guard (`test_llm_breaks_tie_but_cannot_create_attach_likelihood`)
  and is only invoked when rule scores are ambiguous; it is not the source of
  this bug and should not need changes. If your fix to `_compute_fit_struct`
  or `_compute_fit_stage_v2` changes behavior observed by
  `LLMIngestPipeline`'s tests, treat that as a STOP condition, not something
  to patch around.

## Git workflow

- Branch: `advisor/022-false-positive-evidence-attach`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Remove the unknown-tactic default-allow

In `src/trace_agent/loop/ingest.py`, change:

```python
        try:
            ci = tactic_order.index(current_tactic)
            ni = tactic_order.index(next_tactic)
            # Allow same phase and forward progression (up to 4 steps);
            # no backward progression (prevents unrelated tactic attachment)
            diff = ni - ci
            return 0 <= diff <= 4
        except ValueError:
            # Unknown tactics — allow by default
            return True
```

to:

```python
        try:
            ci = tactic_order.index(current_tactic)
            ni = tactic_order.index(next_tactic)
            # Allow same phase and forward progression (up to 4 steps);
            # no backward progression (prevents unrelated tactic attachment)
            diff = ni - ci
            return 0 <= diff <= 4
        except ValueError:
            # Unknown/unmapped tactic (e.g. a Wazuh infrastructure event with
            # no MITRE mapping) must not be treated as a plausible
            # progression — that would make non-attack events *easier* to
            # attach than genuinely mismatched attack tactics.
            return False
```

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` →
watch for any test that relied on the old permissive default (a test
explicitly asserting attachment for an event with an unrecognized tactic);
if one exists and fails, read it fully and report instead of changing the
test's expected behavior — that test may be encoding an intentional
different case (e.g. `"unknown"` used as a deliberate wildcard sentinel
somewhere), which would be a STOP condition per below.

### Step 2: Add an L0 filter for Wazuh informational/infrastructure events

In `src/trace_agent/loop/ingest.py`, add a new constant near the top (next to
`TH_ATTR_ATTACH`):

```python
# Wazuh built-in informational/infrastructure rules (server start/stop, log
# rotation, agent connect/disconnect, ...) are always low severity and never
# carry a MITRE mapping. Treat them as noise, not attack candidates.
INFORMATIONAL_RULE_LEVEL_MAX = 3
```

Then extend `_l0_denoise` to drop these events instead of letting them reach
L1:

```python
    def _l0_denoise(self, events: list[dict]) -> list[dict]:
        """L0: Remove duplicates and malformed events."""
        clean: list[dict] = []
        for event in events:
            # Check required fields
            if not _REQUIRED_FIELDS.issubset(event.keys()):
                continue

            # Check for empty/None required values
            if any(not event.get(f) for f in _REQUIRED_FIELDS):
                continue

            # Wazuh informational/infrastructure events: no MITRE mapping and
            # low rule severity. These are housekeeping noise (e.g. "Wazuh
            # server started", log rotation), never attack-chain evidence.
            if self._is_informational_event(event):
                continue

            # Dedup by event id
            eid = event["id"]
            if eid in self._seen_ids:
                continue
            self._seen_ids.add(eid)

            clean.append(event)
        return clean

    @staticmethod
    def _is_informational_event(event: dict) -> bool:
        if event.get("technique"):
            return False
        attrs = event.get("attributes") or {}
        rule_level = attrs.get("rule_level")
        if rule_level in (None, ""):
            return False
        try:
            return float(rule_level) <= INFORMATIONAL_RULE_LEVEL_MAX
        except (TypeError, ValueError):
            return False
```

This is deliberately conservative: it only drops events that have **both**
no MITRE technique **and** an explicit low `rule_level` — it will never drop
a real attack event that happens to lack a technique mapping unless Wazuh
also scored it at level ≤3 (which real attack rules never are in the
`real_trace_01` custom rule set — see `config/custom_rules/local_real_trace_rules.xml`
referenced in `REAL_TRACE_SCENARIO.md`).

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` → all
pass.

### Step 3: Make the attachable structural bonus technique-aware

In `src/trace_agent/decision/runtime_ledger.py`, change `_compute_fit_struct`:

```python
        # Graph-aware 加分：若事件已被 L1 结构挂接（有 parent candidates），
        # 说明它在攻击图中有位置，应获得更高的结构匹配分
        if event.get("_l1_attachable") and event.get("_l1_parent_candidates"):
            return 0.5
```

to require the event's own tactic to be a plausible kill-chain neighbor of
the explanation's stage, not just "attached to *some* frontier node
somewhere":

```python
        # Graph-aware 加分：若事件已被 L1 结构挂接，且事件 tactic 与本解释
        # 的阶段存在 kill-chain 邻接关系，才给结构匹配加分——避免任何可挂接
        # 事件对所有存活解释一律获得相同加分（无法区分"挂接"与"属于这个
        # 解释"）。
        if event.get("_l1_attachable") and event.get("_l1_parent_candidates"):
            event_tactic = event.get("tactic", "")
            stage = getattr(explanation, "stage", None)
            if event_tactic and stage and (
                event_tactic == stage
                or self._is_kill_chain_predecessor(event_tactic, stage)
                or self._is_kill_chain_predecessor(stage, event_tactic)
            ):
                return 0.5
            return 0.35
```

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` → all
pass; re-run and inspect any newly-failing assertions about ATTACH counts —
this is the highest-risk step, see STOP conditions.

### Step 4: Restrict the lifecycle "any tactic" stage-fit bonus

In `runtime_ledger.py`, change the tail of `_compute_fit_stage`:

```python
        # lifecycle template 阶段匹配
        if explanation.support and explanation.support.get("type") == "lifecycle":
            # lifecycle explanation，任何攻击战术都有中等匹配
            return 0.4
```

to:

```python
        # lifecycle template 阶段匹配：仅当事件 tactic 是该 lifecycle 模板
        # 声明的某个阶段战术时才给中等匹配，而非对任意战术一律给分。
        if explanation.support and explanation.support.get("type") == "lifecycle":
            template_stages = explanation.support.get("template_stage_tactics") or []
            if norm_tactic in {_norm(t) for t in template_stages}:
                return 0.4
            return 0.3
```

and the equivalent tail of `_compute_fit_stage_v2`:

```python
        # lifecycle template
        if explanation.support and explanation.support.get("type") == "lifecycle":
            return 0.5
```

to:

```python
        # lifecycle template：仅当事件 tactic 属于该模板声明的阶段战术集合
        if explanation.support and explanation.support.get("type") == "lifecycle":
            template_stages = explanation.support.get("template_stage_tactics") or []
            if event_tactic in template_stages:
                return 0.5
            return 0.35
```

`explanation.support` does not currently carry `template_stage_tactics` — you
must populate it. In `src/trace_agent/decision/belief.py`, in
`_build_explanations`, the lifecycle branch (`id="H1"`, `support={"type":
"lifecycle", ...}` around line 124-129) has access to `c` (the matched
lifecycle candidate dict from `self.prior.lifecycle_candidates(...)`). Check
what fields that dict exposes for the template's stage tactics (read
`src/trace_agent/prior_v2.py`'s `lifecycle_candidates` implementation and
`src/trace_agent/data/lifecycle_templates.json`'s `stages[].expected_tactics`
shape — this is the same shape `scan_lifecycle` in `obligation_ledger.py:270-276`
already reads). Populate `support["template_stage_tactics"]` with the
flattened, normalized list of `expected_tactics` across all of the matched
template's stages.

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py src\trace_agent\tests\test_full_loop.py -q` → all pass.

## Test plan

Add to `src/trace_agent/tests/test_c_phase.py` (model after the existing
ATTACH/WEAK/PARK routing tests in that file — read a couple of them first to
match fixture-construction style, e.g. how `IngestPipeline` and
`SessionGraph` are built with a `trust`/`ledger` double):

- `test_wazuh_informational_event_is_discarded_not_attached` — build a
  6-node graph resembling a saturated single-hypothesis investigation
  (one lifecycle explanation, posterior near 1.0, all competitors already
  culled — or simplify by constructing a ledger with exactly one
  explanation, matching how existing tests build minimal ledgers). Feed
  `triage()` an event with `technique=None`, `tactic="unknown"` (or empty
  string handling per your L0 change), `attributes={"rule_level": 3}`,
  `source="wazuh"`. Assert the event ends up in `result.routed["DISCARD"]`
  (or `PARK` if your L0 change routes there instead of dropping outright —
  match whatever `_l4_route`/`_apply_trust_gated_veto` produces once L0 no
  longer passes it through as attachable; state clearly in your summary
  which bucket it lands in and why) — critically, assert it is **not** in
  `result.routed["ATTACH"]`.
- `test_unrecognized_tactic_does_not_attach_via_default` — directly unit-test
  `IngestPipeline._tactic_can_follow("initial-access", "totally-not-a-tactic")`
  returns `False` (was `True` before this plan).
- `test_lifecycle_explanation_stage_fit_requires_template_tactic_match` — in
  the runtime-ledger test file, build a lifecycle-type `Explanation` with a
  known `template_stage_tactics` list, call `_compute_fit_stage_v2` (or
  `_compute_fit_stage`) with an event tactic **not** in that list, and assert
  it returns the new lower value (`0.35`/`0.3`), not the old flat
  `0.5`/`0.4`.

Verification: `python -m pytest src\trace_agent\tests\test_c_phase.py src\trace_agent\tests\test_full_loop.py -q` → all pass, including the new tests.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "Unknown tactics — allow by default" src/trace_agent/loop/ingest.py` returns no matches (comment and behavior both changed)
- [ ] `grep -n "_is_informational_event" src/trace_agent/loop/ingest.py` shows the new method and its call site in `_l0_denoise`
- [ ] `python -m pytest src\trace_agent\tests\test_c_phase.py -q` passes, including the 2-3 new tests
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes with the same pass count as before this plan
- [ ] `python -m pytest src\trace_agent\tests -q` shows no *new* failures versus the pre-existing 2 (`test_integration.py::test_factory_function_default`, `test_trust_registry.py::test_load_real_registry` — both about `log_source_trust.json` count, unrelated to this plan)
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 022 updated

## STOP conditions

Stop and report back (do not improvise) if:

- Any existing test explicitly asserts that an event with an unrecognized/empty
  tactic *should* attach (i.e., relies on the old default-`True` behavior as
  intentional, not incidental) — read it fully; this may indicate a real use
  case (e.g. a deliberately tactic-less "wildcard" event type) this plan
  didn't anticipate.
- Step 3 or Step 4 changes the ATTACH/WEAK/PARK bucket counts for any
  existing scenario fixture in `test_full_loop.py` or `test_c_phase.py` in a
  way not explained by "an event that should never have attached now
  correctly doesn't" — if a *legitimate* attack-chain event stops attaching,
  your kill-chain-adjacency check in Step 3 or your template-tactic list in
  Step 4 is too narrow; report the specific event/tactic/template
  combination instead of loosening the check back toward the old flat bonus.
- `lifecycle_candidates()` / `lifecycle_templates.json` doesn't expose stage
  tactics in the shape you expected — report the actual shape found instead
  of guessing a mapping.
- Fixing Step 1 (tactic default) causes `test_full_loop.py`'s bootstrap-phase
  fixtures (small graphs, `node_count <= 6`) to fail to build a graph at all
  — this would mean some legitimate bootstrap path relies on the permissive
  default even for real attack techniques with genuinely novel tactics;
  report the fixture and its tactics instead of reverting Step 1 globally.

## Maintenance notes

- This plan does not touch the temporal-window growth logic
  (`ingest.py:309-337`) even though it's cited above as a contributing
  factor — widening/narrowing that window is a separate, riskier tuning
  decision affecting legitimate slow multi-day attack chains, out of scope
  here. If false-positive attachment persists after this plan lands with the
  window still very wide, that is the next place to look.
- `_compute_fit_struct`, `_compute_fit_stage`, and `_compute_fit_stage_v2` are
  called from both `spawn_merge_cull` (culling/spawning decisions) and
  `_log_likelihood`/`_log_likelihood_v2` (K-phase posterior update) — Steps 3
  and 4 change scores read by both call sites. Re-verify
  `test_full_loop.py`'s culling/merging assertions specifically, not just
  ATTACH routing.
- A reviewer should scrutinize whether `INFORMATIONAL_RULE_LEVEL_MAX = 3` is
  the right cutoff for non-`real_trace_01` production Wazuh deployments —
  this plan picks 3 because it matches the reviewer's cited example
  (`"level": 3`) and Wazuh's own documented severity bands (levels 0-3 are
  "no action"/informational), but a production tenant could plausibly tune
  their custom rules differently.
