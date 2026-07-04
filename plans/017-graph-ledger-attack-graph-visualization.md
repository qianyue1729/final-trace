# Plan 017: Visualize the attack graph in the GraphLedger panel with per-round evolution

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md`.
>
> **Drift check (run first)**:
>
> ```powershell
> git diff --stat 9dadd88..HEAD -- src/trace_agent/phases/k_phase.py `
>   src/trace_agent/agents/progress_protocol.py `
>   tests/engine/test_phase_event_contract.py `
>   deep-agents-ui/src/app/types/types.ts `
>   deep-agents-ui/src/app/hooks/useLOCKState.ts `
>   deep-agents-ui/src/app/components/dashboard/GraphLedger.tsx
> ```
> The worktree is dirty relative to `9dadd88` (plans 014–016 landed uncommitted).
> Compare the "Current state" excerpts below against the live code before
> proceeding; on a mismatch, treat it as a STOP condition.

## Status

- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Depends on**: plans/015 (K-phase rich event fields), plans/016 (full-loop rich streaming) — both landed in the dirty worktree
- **Category**: direction (demo capability)
- **Planned at**: commit `9dadd88`, 2026-07-04, dirty worktree snapshot

## Why this matters

The frontend dashboard's 图账本 (`GraphLedger`) panel currently shows only
four numbers: node count, edge count, per-round deltas, and ΔP(atk). The
attack graph — the core artifact the LOCK engine builds — is never actually
drawn. For the demo, the maintainer wants to *see* the whole attack graph in
the panel and scrub through rounds to watch how each K-phase updates it
(new nodes/edges highlighted). This plan streams a bounded graph snapshot in
every K-phase event and renders it as an interactive SVG with a round
scrubber. It makes the engine's incremental chain discovery — the framework's
main selling point — directly visible.

## Current state

### Backend

- `src/trace_agent/agents/progress_protocol.py` — event DTOs streamed to the
  frontend. `KPhaseEvent` (lines 149–178) carries graph **counts only**:

```python
@dataclass
class KPhaseEvent(PhaseProgressEvent):
    """K 拍事件：学习 + 决策账更新。"""
    phase: str = "K"
    ...
    # 图增量
    new_nodes: int = 0
    new_edges: int = 0
    graph_node_count: int = 0
    graph_edge_count: int = 0
```

  `build_phase_event` (lines 342–374) fills these from `result.data`:

```python
    elif phase == Phase.K:
        ...
        if event_kind == EventKind.PHASE_END:
            ...
            evt.new_nodes = data.get("new_nodes", 0)
            evt.new_edges = data.get("new_edges", 0)
            evt.graph_node_count = data.get("graph_node_count", 0)
            evt.graph_edge_count = data.get("graph_edge_count", 0)
```

- `src/trace_agent/phases/k_phase.py` — `KPhaseExecutor.execute` returns
  `PhaseResult` whose `data` dict (lines 343–368) includes the counts. The
  live graph is available as `session.graph` (a `SessionGraph` with `_nodes`
  and `_edges` dicts) at this point in the code.

- `deep-agent-backend/src/trace_deep_agent/query_tools.py:462-493`
  (`get_attack_graph`) already serializes graph nodes/edges in exactly the
  shape the frontend should receive — **copy this shape**:

```python
        nodes_out.append({
            "id": node.id,
            "technique": node.technique or "",
            "tactic": node.tactic or "",
            "host": str(
                attrs.get("host_uid") or attrs.get("asset_id")
                or attrs.get("target") or node.host_id or ""
            ),
            "timestamp": round(float(node.timestamp or 0), 4),
            "explanation_ids": list(node.explanation_ids),
            "attributed": bool(node.explanation_ids),
        })
        ...
        edges_out.append({
            "source": str(edge.src),
            "target": str(edge.dst),
            "relation": edge.relation,
        })
```

- `tests/engine/test_phase_event_contract.py` — contract test asserting the
  K/Veto event payload shape. `test_k_phase_event_has_decision_obligation_and_graph_fields`
  builds a minimal `LOCKSession`, runs `KPhaseExecutor().execute(session)`,
  then `build_phase_event(Phase.K, EventKind.PHASE_END, result, session)` and
  asserts payload fields. Extend this test in Step 3.

### Frontend

- `deep-agents-ui/src/app/types/types.ts:199-214` — `KPhaseEventData` mirrors
  the backend event (fields `new_nodes`, `new_edges`, `graph_node_count`,
  `graph_edge_count`; no node/edge lists yet).
- `deep-agents-ui/src/app/hooks/useLOCKState.ts` — folds the
  `LOCKPhaseEvent[]` stream into panel state. `GraphState` (lines 15–21) has
  counts only. The fold loop (lines 76–141) processes K `phase_end` events in
  stream order.
- `deep-agents-ui/src/app/components/dashboard/GraphLedger.tsx` — renders 图账本
  with two `MetricCard`s and a ΔP(atk) strip. No graph drawing.
- `deep-agents-ui/src/app/components/dashboard/DashboardPanel.tsx:51-54` —
  the panel grid; `GraphLedger` sits in a `PanelCard` of a 2-column grid.
- Styling convention: Tailwind classes with the `cn()` util from
  `@/lib/utils`; dark theme; muted panel chrome
  (`text-muted-foreground`, `border-border`, `bg-background`); Chinese labels
  with `text-[10px] uppercase tracking-widest` panel titles. Match
  `GraphLedger.tsx` / `DecisionLedgerPanel.tsx` as exemplars.
- There is **no graph-drawing dependency** in `deep-agents-ui/package.json`
  and no frontend unit-test infrastructure (verification is build + lint).
  Graphs are small (real scenarios: 6–18 nodes; hard cap in this plan: 60),
  so hand-rolled SVG is sufficient — do NOT add a dependency.

### Data-flow design (decided — do not redesign)

1. Backend: every K `phase_end` event carries a **full bounded snapshot** of
   the graph (`graph_nodes` ≤ 60, `graph_edges` ≤ 100, plus
   `graph_truncated: bool`). No per-round delta is computed on the backend.
2. Frontend: `useLOCKState` collects each round's K snapshot into a
   `graphHistory` array and computes "new this round" by diffing consecutive
   snapshots' node/edge ID sets. The bootstrap-seeded graph in round 1 counts
   as all-new.
3. `GraphLedger` renders the selected round's snapshot as SVG: nodes laid out
   time-ascending on the x-axis, grouped into host swimlanes on the y-axis,
   colored by tactic, new-this-round nodes ringed/highlighted. A round
   scrubber (range input + prev/next buttons) selects which round to view;
   default = latest round, auto-follows while running.

## Commands you will need

| Purpose | Command | Expected on success |
|---|---|---|
| Backend contract tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_phase_event_contract.py -q` | all pass |
| Backend full-loop tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest src\trace_agent\tests\test_full_loop.py -q` | all pass |
| Adapter streaming tests | `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests\test_full_loop_streaming.py -q` | all pass |
| UI build (includes typecheck) | `Set-Location "f:\cursor all\final trace\deep-agents-ui"; npm run build` | exit 0 |
| UI lint | `Set-Location "f:\cursor all\final trace\deep-agents-ui"; npm run lint` | exit 0 |

Use system Python 3.11.5. Do NOT use `deep-agent-backend/.venv` (its binaries
are incompatible with other runtimes). PowerShell does not support `&&` on
this machine — use `;` or separate commands.

## Scope

**In scope** (the only files you should modify):
- `src/trace_agent/agents/progress_protocol.py` — add fields to `KPhaseEvent` + `build_phase_event`
- `src/trace_agent/phases/k_phase.py` — add `graph_nodes` / `graph_edges` / `graph_truncated` to `PhaseResult.data`
- `tests/engine/test_phase_event_contract.py` — extend the K contract test
- `deep-agents-ui/src/app/types/types.ts` — add snapshot types, extend `KPhaseEventData`
- `deep-agents-ui/src/app/hooks/useLOCKState.ts` — build per-round graph history with diffs
- `deep-agents-ui/src/app/components/dashboard/GraphLedger.tsx` — render the SVG graph + scrubber
- `deep-agents-ui/src/app/components/dashboard/AttackGraphView.tsx` — new file, the SVG renderer

**Out of scope** (do NOT touch, even though they look related):
- `deep-agent-backend/src/trace_deep_agent/phase_tools.py` — the rich-event
  streaming (plans 015/016) already forwards whatever `build_phase_event`
  produces; no change needed there.
- `deep-agent-backend/src/trace_deep_agent/query_tools.py` (`get_attack_graph`)
  — copy its serialization shape, do not modify it.
- `src/trace_agent/agents/modular_orchestrator.py` — untouched per plan 016's
  design.
- `deep-agents-ui/src/app/hooks/useChat.ts` — already accumulates
  `kind:"lock_phase"` events; no change.
- Other dashboard panels (`DecisionLedgerPanel`, `BetaLedgerPanel`,
  `ObligationPanel`).
- Do NOT add any npm dependency (no reactflow, no d3).

## Git workflow

- Branch: `advisor/017-graph-ledger-visualization`
- One or two commits, short imperative messages (repo style: `docs: ...`,
  `Initial commit: ...` — plain imperative is fine).
- Do NOT push or open a PR unless instructed.

## Steps

### Step 1: Stream a bounded graph snapshot in the K-phase event (backend)

1a. In `src/trace_agent/phases/k_phase.py`, inside `KPhaseExecutor.execute`,
just before the `return PhaseResult(...)` (around line 343), serialize the
graph. Follow the `get_attack_graph` shape exactly (see "Current state"),
capped at 60 nodes / 100 edges, nodes sorted by `timestamp` ascending so
truncation keeps the earliest chain:

```python
        graph_nodes_payload: list[dict] = []
        graph_edges_payload: list[dict] = []
        graph_truncated = False
        if session.graph is not None:
            all_nodes = sorted(
                session.graph._nodes.values(),
                key=lambda n: float(n.timestamp or 0),
            )
            all_edges = list(session.graph._edges.values())
            graph_truncated = len(all_nodes) > 60 or len(all_edges) > 100
            for node in all_nodes[:60]:
                attrs = node.attributes or {}
                graph_nodes_payload.append({
                    "id": str(node.id),
                    "technique": node.technique or "",
                    "tactic": node.tactic or "",
                    "host": str(
                        attrs.get("host_uid") or attrs.get("asset_id")
                        or attrs.get("target") or node.host_id or ""
                    ),
                    "timestamp": round(float(node.timestamp or 0), 4),
                    "attributed": bool(node.explanation_ids),
                })
            for edge in all_edges[:100]:
                graph_edges_payload.append({
                    "source": str(edge.src),
                    "target": str(edge.dst),
                    "relation": edge.relation,
                })
```

Then add to the `data={...}` dict (after `"graph_edge_count": ...`):

```python
                "graph_nodes": graph_nodes_payload,
                "graph_edges": graph_edges_payload,
                "graph_truncated": graph_truncated,
```

1b. In `src/trace_agent/agents/progress_protocol.py`, add three fields to
`KPhaseEvent` (after `graph_edge_count`):

```python
    graph_nodes: list[dict] = field(default_factory=list)   # [{id, technique, tactic, host, timestamp, attributed}]
    graph_edges: list[dict] = field(default_factory=list)   # [{source, target, relation}]
    graph_truncated: bool = False
```

And in `build_phase_event`'s `Phase.K` / `PHASE_END` branch (after
`evt.graph_edge_count = ...`):

```python
            evt.graph_nodes = list(data.get("graph_nodes", []))
            evt.graph_edges = list(data.get("graph_edges", []))
            evt.graph_truncated = bool(data.get("graph_truncated", False))
```

Do not modify `KPhaseEvent.to_stream_dict` — `asdict` already includes new
fields, and node/edge dicts contain no unrounded floats besides `timestamp`
(already rounded at serialization).

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_phase_event_contract.py src\trace_agent\tests\test_full_loop.py -q` → all pass.

### Step 2: Extend the contract test

In `tests/engine/test_phase_event_contract.py`, inside
`test_k_phase_event_has_decision_obligation_and_graph_fields`, append:

```python
    assert isinstance(payload["graph_nodes"], list)
    assert isinstance(payload["graph_edges"], list)
    assert isinstance(payload["graph_truncated"], bool)
    for node in payload["graph_nodes"]:
        assert {"id", "technique", "tactic", "host", "timestamp", "attributed"} <= set(node)
    for edge in payload["graph_edges"]:
        assert {"source", "target", "relation"} <= set(edge)
```

(The minimal session in this test may produce an empty graph — the shape
assertions must still pass on empty lists.)

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src'; python -m pytest tests\engine\test_phase_event_contract.py -q` → all pass.

### Step 3: Frontend types

In `deep-agents-ui/src/app/types/types.ts`, add above `KPhaseEventData`:

```typescript
/** 图节点快照（K 拍随事件流式下发） */
export interface GraphNodeSnapshot {
  id: string;
  technique: string;
  tactic: string;
  host: string;
  timestamp: number;
  attributed: boolean;
}

/** 图边快照 */
export interface GraphEdgeSnapshot {
  source: string;
  target: string;
  relation: string;
}
```

Extend `KPhaseEventData` with:

```typescript
  graph_nodes?: GraphNodeSnapshot[];
  graph_edges?: GraphEdgeSnapshot[];
  graph_truncated?: boolean;
```

(Optional fields — older sessions/streams may not carry them.)

**Verify**: `Set-Location "f:\cursor all\final trace\deep-agents-ui"; npm run build` → exit 0.

### Step 4: Per-round graph history in `useLOCKState`

In `deep-agents-ui/src/app/hooks/useLOCKState.ts`:

4a. Add exported types:

```typescript
export interface GraphRoundSnapshot {
  round: number;
  nodes: GraphNodeSnapshot[];
  edges: GraphEdgeSnapshot[];
  newNodeIds: Set<string>;
  newEdgeIds: Set<string>;
  truncated: boolean;
}
```

(import `GraphNodeSnapshot` / `GraphEdgeSnapshot` from `@/app/types/types`).

4b. Add `graphHistory: GraphRoundSnapshot[]` to `LOCKSnapshot` and build it in
the fold loop: on each K `phase_end` event that has a `graph_nodes` array,
compute `newNodeIds` = node IDs not present in the **previous** snapshot's
node ID set (first snapshot: all IDs are new), `newEdgeIds` likewise with
edge key `` `${source}->${target}` ``, then push
`{round: k.round ?? 0, nodes, edges, newNodeIds, newEdgeIds, truncated}`.
If the same round appears twice (re-run), replace the last entry instead of
pushing a duplicate.

4c. Return `graphHistory` from the hook (add to the returned object and to
`LOCKSnapshot`).

**Verify**: `npm run build` → exit 0; `npm run lint` → exit 0.

### Step 5: `AttackGraphView` SVG renderer (new file)

Create `deep-agents-ui/src/app/components/dashboard/AttackGraphView.tsx`, a
client component rendering one `GraphRoundSnapshot` as SVG. Requirements:

- **Layout**: deterministic, no physics.
  - Host swimlanes: group nodes by `host` (empty host → lane `"?"`); each
    distinct host is a horizontal lane (lane height ~64px, label at left in
    `text-[9px] text-muted-foreground`).
  - X-position: nodes sorted by `timestamp` ascending across the whole graph;
    x = index-based even spacing (not raw timestamp — real timestamps
    cluster). Same-timestamp nodes keep insertion order.
  - SVG width grows with node count (`min 320px`, ~72px per column);
    wrap in a horizontally scrollable div (`overflow-x-auto`).
- **Nodes**: circle r≈10 with the technique ID label under it
  (`text-[8px] font-mono`). Fill color by tactic — use a fixed map with a
  fallback, e.g.:

```typescript
const TACTIC_COLORS: Record<string, string> = {
  "initial-access": "#ef4444",
  "credential-access": "#f97316",
  execution: "#eab308",
  collection: "#22c55e",
  exfiltration: "#a855f7",
  "lateral-movement": "#3b82f6",
  persistence: "#14b8a6",
};
const DEFAULT_NODE_COLOR = "#64748b";
```

  Nodes whose id is in `newNodeIds` get an animated highlight ring
  (`<circle>` with `stroke` + Tailwind `animate-pulse` on a wrapping `<g>` is
  acceptable). `attributed: false` nodes render at 50% opacity.
- **Edges**: SVG `<path>` cubic curves from source node center to target node
  center, `stroke` muted gray, arrowhead via `<marker>`. Edges in
  `newEdgeIds` use the primary color and slightly thicker stroke. Edges whose
  source/target id is not in the rendered node set are skipped silently.
- **Tooltip**: native `<title>` element inside each node group showing
  `technique · tactic · host · id` (no JS tooltip lib).
- Component props: `{ snapshot: GraphRoundSnapshot }`. Pure render, no state.

**Verify**: `npm run build` → exit 0.

### Step 6: Wire scrubber + view into `GraphLedger`

Rewrite `deep-agents-ui/src/app/components/dashboard/GraphLedger.tsx`:

- New props: `{ state: GraphState; history: GraphRoundSnapshot[]; hasData: boolean }`.
  Update the call site in `DashboardPanel.tsx` (line ~53) to pass
  `history={graphHistory}` from the `useLOCKState` result.
- Keep the existing `MetricCard` row and ΔP(atk) strip unchanged above the
  graph.
- Below them, when `history.length > 0`:
  - Round scrubber: `<input type="range" min={0} max={history.length - 1}>`
    plus `◀` / `▶` buttons and a `R{round} / R{latest}` label
    (`text-[10px] font-mono text-muted-foreground`). Local state
    `selectedIdx: number | null` — `null` means "follow latest"; moving the
    slider sets an explicit index; a "跟随" (follow) button resets to `null`.
    While `selectedIdx === null`, render `history[history.length - 1]`.
  - `<AttackGraphView snapshot={...} />` for the selected round.
  - A one-line delta caption under the graph:
    `本轮新增 {newNodeIds.size} 节点 / {newEdgeIds.size} 边`, and when
    `truncated`, append `（图已截断）`.
- When `history.length === 0` but `hasData` (counts only, e.g. replaying an
  old stream without snapshots), keep today's metric-only rendering.
- Because `GraphLedger` sits in a half-width grid cell, the graph area should
  be `max-h-[280px] overflow-auto`.

**Verify**: `npm run build` → exit 0; `npm run lint` → exit 0.

### Step 7: End-to-end smoke via adapter streaming test

Extend `deep-agent-backend/tests/test_full_loop_streaming.py` — wait, that
file is **not in scope**; instead run it unmodified to confirm the enriched
K events flow through the adapter without breaking streaming:

**Verify**: `Set-Location "f:\cursor all\final trace"; $env:PYTHONPATH='src;deep-agent-backend\src'; python -m pytest deep-agent-backend\tests -q` → all pass.

Then optionally (manual, if a backend/frontend are running): trigger a
scenario investigation from the UI and confirm the 图账本 panel draws the
graph and the scrubber steps through rounds.

## Test plan

- Extended backend contract test (Step 2) — shape of `graph_nodes` /
  `graph_edges` / `graph_truncated` in the K event payload.
- Existing suites as regression gates: `tests/engine/test_phase_event_contract.py`,
  `src/trace_agent/tests/test_full_loop.py`, `deep-agent-backend/tests`.
- Frontend has no unit-test infra: gates are `npm run build` (typecheck) and
  `npm run lint`.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `python -m pytest tests\engine\test_phase_event_contract.py -q` passes,
      including the new `graph_nodes`/`graph_edges` assertions
- [ ] `python -m pytest src\trace_agent\tests\test_full_loop.py -q` passes
- [ ] `python -m pytest deep-agent-backend\tests -q` (with
      `PYTHONPATH=src;deep-agent-backend\src`) passes
- [ ] `npm run build` in `deep-agents-ui` exits 0
- [ ] `npm run lint` in `deep-agents-ui` exits 0
- [ ] `deep-agents-ui/src/app/components/dashboard/AttackGraphView.tsx` exists
      and is imported by `GraphLedger.tsx`
- [ ] No files outside the in-scope list are modified (`git status`)
- [ ] `plans/README.md` status row for 017 updated

## STOP conditions

Stop and report back (do not improvise) if:

- The `KPhaseExecutor.execute` return block or `build_phase_event`'s K branch
  does not match the "Current state" excerpts (drift from a parallel change).
- `SessionGraph` nodes lack `timestamp` / `attributes` / `explanation_ids`
  attributes (the serialization pattern from `get_attack_graph` would then be
  wrong — report, don't guess field names).
- Adding the snapshot makes `test_full_loop.py` fail on anything other than
  an assertion you can trace to serialization (i.e. you changed execution
  behavior, not just payload).
- `npm run build` fails with errors outside the files you touched.
- You find yourself wanting to add an npm dependency for graph layout — the
  decided design is hand-rolled SVG; report instead.

## Maintenance notes

- Payload size: each K event now carries ≤60 nodes + ≤100 edges (~15 KB max).
  If scenarios grow beyond that, raise the caps in `k_phase.py` and the
  `graph_truncated` consumers together, or switch to backend-computed deltas
  (only new nodes per round + a periodic full snapshot).
- Plan 011 (state-machine unification) will consolidate event serialization;
  the new `KPhaseEvent` fields become part of that contract — keep field names
  stable (`graph_nodes`, `graph_edges`, `graph_truncated`).
- Reviewer should scrutinize: the frontend diff logic in `useLOCKState`
  (duplicate-round replacement, first-round all-new semantics) and that
  `AttackGraphView` skips edges referencing truncated-away nodes without
  crashing.
- Deferred (not in this plan): clicking a node to open event details;
  contested-edge overlay from `DecisionState.contested`; export-as-PNG.
