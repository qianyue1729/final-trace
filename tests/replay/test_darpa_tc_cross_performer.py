"""B2.3 cross-performer DARPA TC adapter tests."""
from __future__ import annotations

import pytest

from trace_agent.eval.adapters.base import ProvenanceGraphAdapter
from trace_agent.eval.adapters.darpa_tc_cadets import CadetsAdapter, load_all_cadets_graph_fixtures
from trace_agent.eval.adapters.darpa_tc_common import cross_performer_benchmark_markdown
from trace_agent.eval.adapters.darpa_tc_theia import TheiaAdapter, load_all_theia_graph_fixtures
from trace_agent.eval.adapters.darpa_tc_trace import TraceAdapter, load_all_trace_graph_fixtures
from trace_agent.eval.graph_replay import is_darpa_tc_fixture, report_markdown, run_graph_case
from trace_agent.prior_v2 import PriorManager

REQUIRED_FIXTURE_KEYS = (
    "entry_alert",
    "world_graph",
    "replay_driver",
    "ground_truth_subgraph",
    "expected_decision",
    "adapter_meta",
)


@pytest.fixture(scope="module")
def all_darpa_tc_results():
    fixtures = (
        load_all_cadets_graph_fixtures()
        + load_all_theia_graph_fixtures()
        + load_all_trace_graph_fixtures()
    )
    pm = PriorManager()
    return [run_graph_case(f, prior_manager=pm) for f in fixtures]


def test_adapters_implement_protocol():
    for cls in (CadetsAdapter, TheiaAdapter, TraceAdapter):
        adapter = cls()
        assert isinstance(adapter, ProvenanceGraphAdapter)
        assert adapter.source_name.startswith("darpa_tc_")


def test_all_performers_share_fixture_contract():
    fixtures = (
        load_all_cadets_graph_fixtures()
        + load_all_theia_graph_fixtures()
        + load_all_trace_graph_fixtures()
    )
    assert len(fixtures) >= 11
    for fx in fixtures:
        assert is_darpa_tc_fixture(fx)
        for key in REQUIRED_FIXTURE_KEYS:
            assert key in fx, (fx["case_id"], key)
        assert fx["schema_version"] == "graph_replay_v1"
        assert "normalization_stats" in fx["adapter_meta"]


def test_cross_performer_no_pollution(all_darpa_tc_results):
    for result in all_darpa_tc_results:
        assert result["metrics"]["benign_pollution_rate"]["count"] == 0, result["case_id"]


def test_cross_performer_benchmark_table(all_darpa_tc_results):
    md = cross_performer_benchmark_markdown(all_darpa_tc_results)
    assert "Cross-performer benchmark" in md
    assert "events_kept" in md
    assert "drop_rate" in md
    for source in ("darpa_tc_cadets", "darpa_tc_theia", "darpa_tc_trace"):
        assert source in md


def test_report_markdown_includes_cross_performer(all_darpa_tc_results):
    passed = sum(1 for r in all_darpa_tc_results if r["passed"])
    report = {
        "summary": {
            "total": len(all_darpa_tc_results),
            "passed": passed,
            "failed": len(all_darpa_tc_results) - passed,
        },
        "cases": all_darpa_tc_results,
    }
    md = report_markdown(report)
    assert "darpa_tc_cadets" in md
    assert "darpa_tc_theia" in md
    assert "darpa_tc_trace" in md
