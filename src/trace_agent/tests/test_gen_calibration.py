"""Tests for GenCalibration — per-source reliability + probe cost estimation."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from trace_agent.loop.gen_calibration import (
    DEFAULT_OPERATOR_COST,
    OPERATOR_COST_TABLE,
    GenCalibration,
)


@pytest.fixture
def cal() -> GenCalibration:
    return GenCalibration(eps_floor=0.05)


def _probe(operator: str = "process_tree", source: str = "prior") -> SimpleNamespace:
    return SimpleNamespace(operator=operator, source=source)


# --- Tests ---


def test_cold_start_reliability(cal: GenCalibration):
    """Unseen source returns eps_floor."""
    assert cal.reliability("never_seen") == 0.05


def test_record_hit_increases_reliability(cal: GenCalibration):
    """Hits improve reliability."""
    cal.record("prior", hit=True)
    cal.record("prior", hit=True)
    cal.record("prior", hit=True)
    assert cal.reliability("prior") == 1.0


def test_record_miss_reduces_reliability(cal: GenCalibration):
    """Misses reduce reliability."""
    cal.record("prior", hit=True)
    cal.record("prior", hit=False)
    # 1 hit / 2 total = 0.5
    assert cal.reliability("prior") == 0.5


def test_eps_floor_prevents_zero(cal: GenCalibration):
    """Reliability never below eps_floor even with all misses."""
    for _ in range(20):
        cal.record("bad_source", hit=False)
    assert cal.reliability("bad_source") == 0.05


def test_cost_basic(cal: GenCalibration):
    """Unseen probes shrink to the operator prior rather than an epsilon penalty."""
    probe = _probe(operator="process_tree", source="unknown_src")
    expected = OPERATOR_COST_TABLE["process_tree"]
    assert cal.cost(probe) == pytest.approx(expected)


def test_cost_unknown_operator(cal: GenCalibration):
    """Unknown operator falls back to DEFAULT_OPERATOR_COST."""
    probe = _probe(operator="exotic_tool", source="unknown_src")
    expected = DEFAULT_OPERATOR_COST
    assert cal.cost(probe) == pytest.approx(expected)


def test_cost_uses_measured_queries_failures_and_records(cal: GenCalibration):
    """Measured execution cost replaces generator hit-rate as the cost signal."""
    probe = _probe(operator="process_tree", source="prior")
    cold_cost = cal.cost(probe)
    for _ in range(10):
        cal.record_probe_cost(
            probe,
            latency_ms=60_000,
            query_count=4,
            records_scanned=20_000,
            provider_cost=0.02,
            failed=True,
        )
    assert cal.cost(probe) > cold_cost


def test_record_decision_outcome(cal: GenCalibration):
    """Decision outcome records stored correctly."""
    dist = {"malware": 0.7, "benign": 0.3}
    cal.record_decision_outcome(dist, actual="malware")

    records = cal.get_records()
    assert len(records) == 1
    assert records[0].predicted_dist == dist
    assert records[0].actual == "malware"
    assert records[0].round_num == 0


def test_serialization_roundtrip(cal: GenCalibration):
    """to_dict → from_dict preserves state."""
    cal.record("prior", hit=True)
    cal.record("prior", hit=False)
    cal.record("sigma", hit=True)
    cal.record_decision_outcome({"a": 0.6, "b": 0.4}, actual="a")
    cal.record_probe_cost(
        _probe(),
        query_count=2,
        records_scanned=100,
    )
    cal.advance_round()

    data = cal.to_dict()
    restored = GenCalibration.from_dict(data)

    assert restored.reliability("prior") == cal.reliability("prior")
    assert restored.reliability("sigma") == cal.reliability("sigma")
    assert len(restored.get_records()) == 1
    assert restored.get_records()[0].actual == "a"
    assert restored._round == 1
    assert restored.cost(_probe()) == pytest.approx(cal.cost(_probe()))


def test_version_or_tenant_mismatch_resets_cost_statistics(cal: GenCalibration):
    probe = _probe()
    for _ in range(10):
        cal.record_probe_cost(probe, query_count=20, failed=True)
    data = cal.to_dict()
    restored = GenCalibration.from_dict(
        data,
        expected_tenant_id="different-tenant",
    )
    assert restored.cost(probe) == OPERATOR_COST_TABLE["process_tree"]


def test_source_stats_summary(cal: GenCalibration):
    """Correct hits/total/reliability for each source."""
    cal.record("prior", hit=True)
    cal.record("prior", hit=True)
    cal.record("prior", hit=False)
    cal.record("sigma", hit=False)

    stats = cal.source_stats()
    assert stats["prior"]["hits"] == 2
    assert stats["prior"]["total"] == 3
    assert stats["prior"]["reliability"] == pytest.approx(2 / 3)
    assert stats["sigma"]["hits"] == 0
    assert stats["sigma"]["total"] == 1
    assert stats["sigma"]["reliability"] == 0.05  # eps_floor
