# Plan 024: Fix non-deterministic parent-edge selection (temporal direction) and clarify round-vs-cumulative graph metrics

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
>   src/trace_agent/loop/session_graph.py src/trace_agent/tests/test_c_phase.py `
>   src/trace_agent/tests/test_session_graph.py
> ```
> These files are tracked at `9dadd88` and unmodified relative to it as of
> this plan's writing (should print nothing). `deep-agent-backend/src/trace_deep_agent/presentation.py`
> is untracked (new file) — compare it against the "Current state" excerpt
> directly with `git status --porcelain`.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: none
- **Category**: bug (graph correctness) + dx (reporting clarity)
- **Planned at**: commit `9dadd88`, 2026-07-04

## Why this matters

A reviewer compared a `real_trace_01` investigation report against the
scenario's known-correct design (a single 6-event chain:
`T1110.001 ×2 → T1078 → T1059.004 → T1005 → T1048`) and found two distinct
problems:

1. **The report described the sequence as `T1078 (SSH login) → T1110.001
   (SSH brute-force failure)`, i.e. success-then-failure — backwards from
   the real order (two failed attempts, *then* a successful login).** Reading
   the graph-construction code shows why this is possible, not just a
   wording slip: when an event has more than one plausible parent on the
   graph's frontier (exactly the case here — two `T1110.001` nodes are both
   frontier leaves when `T1078` arrives), the code that turns L1's
   `parent_candidates` list into an actual graph edge always takes
   `candidates[0]` with **no timestamp comparison at all** — the "first"
   candidate is whichever node happened to be inserted first into the
   frontier-scanning dict, not the one that actually precedes the new event
   in time. If dict iteration order ever put the *wrong* node first (e.g.
   after a graph mutation reordered internal dict state, or a future change
   to `frontier()`'s implementation), a parent→child edge could point in the
   wrong temporal direction with nothing to catch it.
2. **The reviewer's own round-by-round arithmetic (`Round1 ATTACH=10, +3,
   +1 → 14`) didn't match the report's final "16 nodes, 16 edges".** The
   engine's internal round diagnostics already track the *correct*,
   non-ambiguous numbers separately (`new_graph_nodes` as a true per-round
   graph delta, and `graph_nodes` as the running total) — but the bucket
   count most prominently surfaced per round (`attach_bucket_count`, i.e.
   "how many events routed to ATTACH this round") is a **different
   metric** that undercounts true graph growth whenever a `WEAK`-bucket
   event gets promoted to a graph-eligible fact in the same round (see
   `IngestPipeline._should_promote_weak_fact` /
   `_finalize_graph_eligibility` in `src/trace_agent/loop/ingest.py`) — those
   promoted facts enter the graph too, but are not part of
   `attach_bucket_count`. Nothing in the round output or its field naming
   warns a reader (human or LLM) against summing `attach_bucket_count`
   across rounds as if it were total graph growth.

## Current state

- `src/trace_agent/loop/session_graph.py:141-146` (`frontier`) — order is
  whatever `dict.items()` yields, which is insertion order in CPython but is
  never sorted by timestamp:

```python
    def frontier(self) -> list[str]:
        """叶节点 ids（没有出边的节点），供 L 拍生成候选。"""
        return [
            nid for nid, edges in self._adj_out.items()
            if not edges
        ]
```

- `src/trace_agent/loop/ingest.py:348-362` (`_l1_structural`, frontier scan)
  — appends every matching frontier node to `parent_candidates` in whatever
  order `frontier()` returned them, without regard to which one is
  chronologically closer to (and before) the new event:

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

  Note `abs(node.timestamp - event_ts)` — this check doesn't even require
  the candidate parent to be *before* the event; a frontier node **later**
  than the new event, within the window, is an equally valid
  `parent_candidate` by this check alone.

- `src/trace_agent/loop/ingest.py:250-265`
  (`_materialize_candidate_link`) — the only place that turns
  `_l1_parent_candidates` into the actual edge, and it unconditionally uses
  index `0`:

```python
    def _materialize_candidate_link(self, event: dict, bucket: str) -> None:
        """Carry the selected candidate edge into K-phase graph insertion."""
        if not event.get("_l1_attachable"):
            return
        candidates = event.get("_l3_parent_node_ids") or event.get(
            "_l1_parent_candidates", []
        )
        if not candidates:
            return
        parent_id = candidates[0]
        if self._graph.get_node(parent_id) is None:
            return
        event["parent_id"] = parent_id
        event["relation"] = event.get("_l3_relation") or "causes"
        best = event.get("_l3_best_explanation")
        event["explanation_ids"] = [best] if best and bucket == ROUTE_ATTACH else []
```

- `src/trace_agent/loop/session_graph.py:56-128` (`add_events`) — consumes
  `event["parent_id"]` verbatim to create the edge, with no timestamp
  validation of its own:

```python
            parent_id = ev.get("parent_id")
            if parent_id and parent_id in self._nodes:
                relation = ev.get("relation", "causes")
                edge_id = self._next_edge_id()
                edge = GraphEdge(
                    id=edge_id,
                    src=parent_id,
                    dst=node_id,
                    relation=relation,
                    explanation_ids=list(ev.get("explanation_ids", [])),
                )
                self._edges[edge_id] = edge
```

- `src/trace_agent/phases/k_phase.py:291-307` (round diagnostics — already
  correctly separates the metrics, this plan does not need to change this
  block, only how it's presented downstream):

```python
        routed = getattr(ingest_result, "routed", {}) or {}
        graph_stats = session.graph.stats()
        self.round_diagnostics.append({
            "round": session.budget.rounds_used,
            ...
            "attach_bucket_count": len(routed.get("ATTACH", [])),
            "weak_bucket_count": len(routed.get("WEAK", [])),
            ...
            "graph_eligible_count": len(getattr(ingest_result, "graph_eligible", []) or []),
            "confirmed_count": len(getattr(ingest_result, "confirmed", []) or []),
            "new_graph_nodes": graph_stats.get("node_count", 0) - prev_node_count,
            "new_graph_edges": graph_stats.get("edge_count", 0) - prev_edge_count,
            "graph_nodes": graph_stats.get("node_count", 0),
            "graph_edges": graph_stats.get("edge_count", 0),
```

  `graph_eligible_count` (ATTACH + promoted-WEAK facts that actually entered
  the graph this round) is the metric that should be quoted alongside
  `attach_bucket_count` whenever a reader might be tempted to treat the
  latter as "how many nodes this round contributed to the graph."

- `deep-agent-backend/src/trace_deep_agent/presentation.py:100-129`
  (`summarize_lock_loop`) — the per-round summary handed to the report/LLM
  layer, which surfaces both fields side by side with no annotation
  distinguishing them:

```python
    for item in round_diag:
        rounds.append({
            "round": item.get("round"),
            "phase_flow": "L → Veto → O → C → K",
            "probes_selected": item.get("probes_selected"),
            "probe_results_count": item.get("probe_results_count"),
            "attach_bucket_count": item.get("attach_bucket_count"),
            "weak_bucket_count": item.get("weak_bucket_count"),
            "graph_eligible_count": item.get("graph_eligible_count"),
            "new_graph_nodes": item.get("new_graph_nodes"),
            "new_graph_edges": item.get("new_graph_edges"),
            "graph_nodes": item.get("graph_nodes"),
            "graph_edges": item.get("graph_edges"),
            ...
        })
```

## Design decision (do not redesign — implement exactly this)

1. **Make parent-candidate selection temporal-direction-aware.** When
   `_l1_structural` collects `parent_candidates`, prefer the frontier node
   with the **latest timestamp that is still ≤ the new event's timestamp**
   (i.e. the nearest true predecessor). Only fall back to a later-timestamp
   node (current behavior) if no candidate precedes the event at all — this
   preserves today's ability to attach an event that arrives "before" its
   logical parent in probe order (bootstrap/backfill cases already handled
   by `link_parent`), while making the *default* choice the causally correct
   one whenever a true predecessor exists.
2. **Sort, don't just pick index 0 blindly.** Change
   `_materialize_candidate_link` and the frontier-scan loop so
   `parent_candidates` is an explicitly time-ordered list (nearest preceding
   first, nearest following second), not whatever order `frontier()`
   happened to yield.
3. **Add an explicit field-level note to `summarize_lock_loop`'s per-round
   output** clarifying that `attach_bucket_count` is a routing count, not a
   graph-growth count, and that `graph_eligible_count` (this round) /
   `graph_nodes` (running total) are the correct fields for reconciling
   "how many nodes are in the graph now."

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| C-phase / ingest tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_c_phase.py -q` | all pass |
| Session graph tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_session_graph.py -q` | all pass |
| Full loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass, same pass count as before |
| Deep-agent-backend tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` | all pass |

Use system Python 3.11.5. PowerShell on this machine does not support `&&` —
use `;` or run commands separately.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/loop/ingest.py`
- `deep-agent-backend/src/trace_deep_agent/presentation.py`
- `src/trace_agent/tests/test_c_phase.py`

**Out of scope** (do NOT touch, even though they look related):
- `src/trace_agent/loop/session_graph.py` — `add_events`/`frontier`/`roots`
  themselves are correct as generic graph primitives; the ordering
  responsibility belongs to the caller (`ingest.py`), which is what this plan
  fixes. Do not add timestamp sorting inside `SessionGraph` itself — it has
  no opinion on event semantics and other callers (e.g. Bootstrap
  materialization in `attack_chain_materializer.py`) already build correctly
  ordered chains before calling `add_events`.
- `src/trace_engine/attack_chain_materializer.py` — its own chain-building
  (`materialize_attack_chain`) already sorts by `trace_step`/timestamp
  correctly (see its `attacks.sort(...)` call); this plan only fixes the
  live incremental `IngestPipeline` path, a different code path.
- `src/trace_agent/phases/k_phase.py` — the round-diagnostics computation
  itself is already correct (see "Current state"); this plan only changes
  how those fields are *presented* downstream, not how they're computed.

## Git workflow

- Branch: `advisor/024-graph-edge-temporal-order`
- One or two commits, short imperative messages.
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Sort parent candidates by nearest-preceding-timestamp first

In `src/trace_agent/loop/ingest.py`, in `_l1_structural`, after all
candidate-collection blocks (frontier scan, non-frontier fallback, bootstrap
relaxation, backward provenance) have populated `parent_candidates` but
before `attachable = len(parent_candidates) > 0`, add a sort step:

```python
        attachable = len(parent_candidates) > 0

        if len(parent_candidates) > 1:
            parent_candidates = self._order_parent_candidates(parent_candidates, event_ts)

        event["_l1_attachable"] = attachable
        event["_l1_parent_candidates"] = parent_candidates
        event["_l1_temporal_fit"] = temporal_fit
        return event

    def _order_parent_candidates(self, candidate_ids: list[str], event_ts: float) -> list[str]:
        """Order candidates so the nearest true predecessor (timestamp <= event_ts)
        sorts first; candidates that are actually *after* the event (a possible
        symptom of loose L1 windowing) sort last, preferring causally-consistent
        edges whenever a real predecessor exists among the candidates."""
        def sort_key(node_id: str) -> tuple[int, float]:
            node = self._graph.get_node(node_id)
            if node is None:
                return (2, 0.0)
            delta = event_ts - node.timestamp
            if delta >= 0:
                return (0, delta)   # true predecessor; smaller delta = nearer = preferred
            return (1, -delta)      # node is after the event; least-bad first
        # Preserve original relative order for exact ties (stable sort).
        return sorted(dict.fromkeys(candidate_ids), key=sort_key)
```

Note `dict.fromkeys(...)` also de-duplicates while preserving first-seen
order for ties, in case the same node id was appended to `parent_candidates`
more than once across the multiple collection blocks in `_l1_structural`.

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py -q` → all pass.

### Step 2: Confirm `_materialize_candidate_link` benefits from the new ordering automatically

No code change needed here — `candidates[0]` (in
`_materialize_candidate_link`, `ingest.py:250-265`) will now be the
temporally-nearest true predecessor whenever one exists, because
`_l1_parent_candidates` is now pre-sorted. Re-read the method after Step 1 to
confirm `candidates[0]` still means the same thing it always did (first
element of the list) — you are not changing this method, only what's already
in the list by the time it runs.

**Verify**: `python -m pytest src\trace_agent\tests\test_c_phase.py src\trace_agent\tests\test_full_loop.py -q` → all pass, same pass counts as before (this step should be a no-op verification, not a code change).

### Step 3: Clarify round-metric semantics in the report summary

In `deep-agent-backend/src/trace_deep_agent/presentation.py`, in
`summarize_lock_loop`, change the per-round dict construction from:

```python
    for item in round_diag:
        rounds.append({
            "round": item.get("round"),
            "phase_flow": "L → Veto → O → C → K",
            "probes_selected": item.get("probes_selected"),
            "probe_results_count": item.get("probe_results_count"),
            "attach_bucket_count": item.get("attach_bucket_count"),
            "weak_bucket_count": item.get("weak_bucket_count"),
            "graph_eligible_count": item.get("graph_eligible_count"),
            "new_graph_nodes": item.get("new_graph_nodes"),
            "new_graph_edges": item.get("new_graph_edges"),
            "graph_nodes": item.get("graph_nodes"),
            "graph_edges": item.get("graph_edges"),
```

to:

```python
    for item in round_diag:
        rounds.append({
            "round": item.get("round"),
            "phase_flow": "L → Veto → O → C → K",
            "probes_selected": item.get("probes_selected"),
            "probe_results_count": item.get("probe_results_count"),
            # attach_bucket_count is a routing count (events judged ATTACH
            # this round); it is NOT the number of nodes added to the graph
            # this round — a promoted WEAK fact also enters the graph but is
            # not counted here. Use new_graph_nodes (this round's true delta)
            # or graph_nodes (running total) to reconcile graph size —
            # do not sum attach_bucket_count across rounds as a proxy for
            # total graph size.
            "attach_bucket_count": item.get("attach_bucket_count"),
            "weak_bucket_count": item.get("weak_bucket_count"),
            "graph_eligible_count": item.get("graph_eligible_count"),
            "new_graph_nodes": item.get("new_graph_nodes"),
            "new_graph_edges": item.get("new_graph_edges"),
            "graph_nodes": item.get("graph_nodes"),
            "graph_edges": item.get("graph_edges"),
```

(A Python comment above a dict literal is documentation for the next reader
of this code, not something the LLM sees at runtime — see Step 3b for the
part that actually reaches model-facing text.)

### Step 3b: Add a machine-readable reconciliation field

Immediately after the loop in `summarize_lock_loop` that builds `rounds`,
add a cumulative check so any consumer (report renderer, LLM prompt
assembly, or a human reading the JSON) gets an explicit, correct total
instead of having to sum `attach_bucket_count` themselves:

```python
    cumulative_attach_bucket = sum(int(r.get("attach_bucket_count") or 0) for r in rounds)
    final_graph_nodes = rounds[-1].get("graph_nodes") if rounds else None
    graph_size_reconciliation = {
        "sum_attach_bucket_count_across_rounds": cumulative_attach_bucket,
        "final_graph_node_count": final_graph_nodes,
        "note": (
            "These two numbers are expected to differ whenever WEAK-bucket "
            "evidence was promoted to a graph fact (see graph_eligible_count "
            "per round) or bootstrap seeded initial nodes outside the ATTACH "
            "bucket. Use final_graph_node_count as authoritative; do not "
            "treat sum_attach_bucket_count_across_rounds as the graph size."
        ),
    }
```

and include `"graph_size_reconciliation": graph_size_reconciliation` in
whatever dict `summarize_lock_loop` returns (read the function's `return`
statement to find the right insertion point — do not restructure the
existing return shape beyond adding this one new key).

**Verify**: `python -m pytest deep-agent-backend\tests -q` → all pass.

## Test plan

Add to `src/trace_agent/tests/test_c_phase.py` (model after existing L1
structural-attachment tests in that file):

- `test_parent_candidate_prefers_nearest_true_predecessor` — build a graph
  with two frontier nodes at, say, `timestamp=100` and `timestamp=200`
  (both plausible parents by tactic/window), then run `_l1_structural` /
  `triage()` on a new event at `timestamp=210` whose target/tactic matches
  both. Assert the resulting `_l1_parent_candidates[0]` (or, after full
  `triage()`, the materialized `parent_id` once added to the graph) is the
  node at `timestamp=200`, not `timestamp=100` and not whichever was
  inserted into the graph first if insertion order were reversed in the
  fixture.
- `test_parent_candidate_never_prefers_later_node_when_earlier_exists` —
  construct the fixture so that, prior to this plan's fix, dict/frontier
  iteration order would have picked the *later* (wrong-direction) node
  first (e.g. add the later-timestamp node to the graph before the
  earlier one, matching how the reviewer's transcript likely reached this
  state) — assert the earlier, correct predecessor is chosen after the fix.
- `test_two_repeated_technique_siblings_both_remain_valid_parent_candidates_ordered_by_time`
  — regression test capturing the reviewer's exact scenario shape: two
  `T1110.001` events at different timestamps as siblings on the frontier,
  then a `T1078` event; assert `_l1_parent_candidates` contains both,
  ordered with the temporally-nearer `T1110.001` first.

Verification: `python -m pytest src\trace_agent\tests\test_c_phase.py deep-agent-backend\tests -q` → all pass, including the new tests.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `grep -n "_order_parent_candidates" src/trace_agent/loop/ingest.py` shows the new method and its call site
- [ ] `grep -n "graph_size_reconciliation" deep-agent-backend/src/trace_deep_agent/presentation.py` shows the new field
- [ ] `python -m pytest src\trace_agent\tests\test_c_phase.py -q` passes, including 3 new tests
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes with the same pass count as before this plan
- [ ] `python -m pytest deep-agent-backend\tests -q` passes
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 024 updated

## STOP conditions

Stop and report back (do not improvise) if:

- Any existing test in `test_c_phase.py` or `test_full_loop.py` asserts a
  specific `parent_id` for a multi-candidate case that this plan's ordering
  change would flip — read it fully; if the test's expected parent was
  itself relying on the old arbitrary order (i.e. it's the same class of bug
  this plan fixes, just pinned by an existing assertion), report it rather
  than silently updating the assertion to match new behavior — the person
  reviewing your diff needs to confirm the old expectation was indeed wrong,
  not incidentally right.
- `frontier()`'s iteration order in the live `SessionGraph` implementation is
  not dict-insertion-order (e.g. because of an intervening change) — verify
  your fixture actually exercises the bug before writing the regression test
  ("prefer node inserted second" only proves something if insertion order
  and timestamp order are deliberately mismatched in the fixture).
- `summarize_lock_loop`'s return statement doesn't have an obvious place to
  add `graph_size_reconciliation` without changing the shape of an existing
  key relied upon elsewhere — report the actual return shape instead of
  guessing where to splice it in.

## Maintenance notes

- This plan does not change `_is_backward_provenance_candidate` (which
  governs cross-host predecessor attachment, a related but distinct
  mechanism) — if backward-provenance edges show similar direction issues
  after this plan lands, that function's own candidate collection (also
  currently order-blind, per `ingest.py:390-400`) is the next place to apply
  the same `_order_parent_candidates` helper.
- `_order_parent_candidates` is intentionally a small, generic helper (takes
  candidate ids + a target timestamp) — if a future plan needs the same
  "nearest preceding" ordering elsewhere (e.g. for the cross-host backward
  path noted above), reuse it rather than duplicating the sort key logic.
- A reviewer should scrutinize whether `dict.fromkeys` dedup in Step 1
  changes behavior for any caller that relied on `parent_candidates`
  containing intentional duplicates (grep for other readers of
  `_l1_parent_candidates` before assuming none exist).
