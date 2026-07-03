"""B2.5-lite normalization loss + optional event-level GT."""
from __future__ import annotations

import pytest

from trace_agent.eval.adapters.darpa_tc_cadets import load_all_cadets_graph_fixtures
from trace_agent.eval.adapters.darpa_tc_common import cross_performer_benchmark_markdown
from trace_agent.eval.adapters.normalization_stats import aggregate_normalization_loss, summarize_normalization_loss
from trace_agent.eval.graph_replay import run_graph_case
from trace_agent.prior_v2 import PriorManager


def test_summarize_normalization_loss_shape():
    stats = {
        "source": "darpa_tc_cadets",
        "events_in": 100,
        "events_kept": 90,
        "events_dropped": 10,
        "dropped_events": {"unsupported_relation": 6, "missing_subject": 4},
        "relations": {"process_spawn": 90},
    }
    loss = summarize_normalization_loss(stats)
    assert loss["events_in"] == 100
    assert loss["events_kept"] == 90
    assert loss["drop_rate"] == 0.1
    assert loss["unsupported_relation_rate"] == 0.06
    assert loss["relation_coverage"] == 0.9


def test_optional_event_level_gt_in_fixtures():
    fixtures = load_all_cadets_graph_fixtures()
    fx = fixtures[0]
    gt = fx["ground_truth_subgraph"]
    assert "attack_edges" in gt
    assert isinstance(gt["attack_edges"][0], list)


def test_cross_performer_markdown_includes_loss_columns():
    fixtures = load_all_cadets_graph_fixtures()[:2]
    pm = PriorManager()
    results = [run_graph_case(f, prior_manager=pm) for f in fixtures]
    md = cross_performer_benchmark_markdown(results, fixtures=fixtures)
    assert "events_kept" in md
    assert "drop_rate" in md
    assert "Normalization loss by source" in md


def test_aggregate_normalization_loss():
    fixtures = load_all_cadets_graph_fixtures()
    stats = [(f.get("adapter_meta") or {}).get("normalization_stats") for f in fixtures]
    stats = [s for s in stats if s]
    agg = aggregate_normalization_loss(stats)
    assert agg["events_in"] >= agg["events_kept"]
