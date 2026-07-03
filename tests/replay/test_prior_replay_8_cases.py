"""80-case prior replay acceptance (Silver-solid behavior suite)."""
from __future__ import annotations

from pathlib import Path

import pytest

from trace_agent.decision.belief import DecisionLedger
from trace_agent.eval.prior_replay import FIXTURES_DIR, load_fixtures, run_all, run_case
from trace_agent.prior_v2 import PriorManager


@pytest.fixture(scope="module")
def ledger():
    return DecisionLedger(PriorManager())


@pytest.fixture(scope="module")
def fixtures():
    return load_fixtures(FIXTURES_DIR)


@pytest.fixture(scope="module")
def report(ledger, fixtures):
    return run_all(FIXTURES_DIR, ledger)


def test_fixture_count(fixtures):
    assert len(fixtures) == 80
    ids = {f["case_id"] for f in fixtures}
    assert "powershell_admin" in ids
    assert "ransomware_chain" in ids


@pytest.mark.parametrize(
    "case_id",
    [
        "powershell_admin",
        "powershell_download_payload",
        "concurrent_miner_ransomware",
        "log_clearing",
        "timestamp_spoofing",
        "linux_gtfobins",
        "cloud_iam_anomaly",
        "ransomware_chain",
    ],
)
def test_replay_case(case_id, ledger, fixtures):
    fixture = next(f for f in fixtures if f["case_id"] == case_id)
    result = run_case(fixture, ledger)
    assert result["metrics"]["explanation_count"] <= 6
    assert result["metrics"]["null_benign"] > 0
    assert result["metrics"]["null_oos"] > 0
    assert result["passed"], f"{case_id} failed checks: {result['checks']}"


def test_replay_summary(report):
    assert report["summary"]["total"] == 80
    assert report["summary"]["passed"] == 80


def test_replay_has_quality_passports(report):
    for c in report["cases"]:
        assert c["quality_gates"]["gates"]["passport_gate"]
        assert c["quality_gates"]["gates"]["max_prior_gate"]


def test_replay_through_orchestrator(ledger, fixtures):
    from trace_agent.eval.prior_replay import run_all

    report = run_all(FIXTURES_DIR, ledger, through_orchestrator=True)
    assert report["summary"]["total"] == 80
    assert report["summary"]["passed"] == 80
    assert report["summary"]["runtime_path"] == "orchestrator"
    assert all(c.get("lock_phase") == "L_INITIALIZED" for c in report["cases"])
