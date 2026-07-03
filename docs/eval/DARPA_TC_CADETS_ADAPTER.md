# DARPA TC CADETS Adapter (B1)

B1 connects a **small CADETS provenance subset** to the existing L1 graph replay contract. It does not run full TC ingestion, multi-performer replay, or real probe executors.

## Scope

| In scope | Out of scope |
| --- | --- |
| Single performer (CADETS) | THEIA / TRACE |
| One scenario subset | Full TC dump |
| `adapter → world_graph → run_graph_case()` | OpTC |
| Technique-pair GT | Event-level GT hard binding (B1.5+) |
| 6 graph metrics (report-only recall/decision) | `decision_accuracy` hard gate |

## Files

```text
src/trace_agent/eval/adapters/darpa_tc_cadets.py   # adapter
tests/replay/data/cadets/cadets_sample_001.json    # raw subset
tests/replay/graph/darpa_cadets_sample_001.json    # committed fixture
tests/replay/test_darpa_tc_cadets_adapter.py     # B1 tests
```

## Usage

```python
from pathlib import Path
from trace_agent.eval.adapters.darpa_tc_cadets import (
    CadetsAdapterConfig,
    load_cadets_graph_fixture,
    write_graph_fixture,
)
from trace_agent.eval.graph_replay import run_graph_case

fixture = load_cadets_graph_fixture(
    CadetsAdapterConfig(
        input_path=Path("tests/replay/data/cadets/cadets_sample_001.json"),
        scenario_id="darpa_cadets_sample_001",
    )
)
write_graph_fixture(fixture, Path("tests/replay/graph/darpa_cadets_sample_001.json"))
result = run_graph_case(fixture)
```

## Raw event format

Each event in the CADETS subset JSON:

```json
{
  "event_id": "cadets:e123",
  "timestamp": "2018-04-06T12:00:01Z",
  "host_id": "cadets-host-1",
  "parent_event_id": "cadets:e_parent",
  "subject": {"id": "proc:bash:1", "type": "process", "name": "bash"},
  "object": {"id": "file:/tmp/x", "type": "file", "name": "/tmp/x"},
  "relation": "network_connect",
  "tactic": "command-and-control",
  "technique": "T1105",
  "role": "attack"
}
```

Roles: `attack` | `benign` | `oos`.

## B1 acceptance

**Hard pass**

1. Adapter produces valid graph fixture
2. `run_graph_case()` runs without error
3. All 6 metrics populated
4. `benign_pollution_rate == 0` (no auto-wiring of benign/oos edges)

**Report-only**

5. `attack_subgraph_recall`
6. `decision_accuracy`

## B1.5 (current)

- **6 CADETS scenarios** (`cadets_sample_001` … `006`)
- **`normalization_stats.py`** — events kept/dropped, entity/relation counts
- **Entry alert strategies:** `explicit`, `auto_leaf`, `auto_terminal`
- **`cadets_benchmark_markdown()`** — CADETS-only paper table
- **`load_all_cadets_graph_fixtures()`** — batch adapter load

## B2 (current)

- **`base.py`** — `ProvenanceAdapterConfig`, `ProvenanceGraphAdapter` protocol
- **`darpa_tc_common.py`** — shared normalization, fixture assembly, `cross_performer_benchmark_markdown()`
- **THEIA** — 3 scenarios (`theia_sample_001` … `003`), source `darpa_tc_theia`
- **TRACE** — 2 scenarios (`trace_sample_001` … `002`), source `darpa_tc_trace`
- **`report_markdown()`** — includes cross-performer benchmark table

Hard pass (B2, all performers):

1. Valid graph fixture
2. `run_graph_case()` OK
3. 6 metrics non-empty
4. `benign_pollution_rate == 0`
5. `normalization_stats` in `adapter_meta`
6. Cross-performer summary in report

## Next steps

- **B1.5**: 3–5 CADETS scenarios, optional event-level GT
- **B2**: THEIA / TRACE adapter (same interface)
- **C**: Corrected OpTC multi-host benchmark
