"""REST API 端到端 — 鉴权 / 投递告警 / 完整 LOCK 调查 / 报告读取。"""
import time

import pytest
from fastapi.testclient import TestClient

from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_engine.config import EngineConfig
from trace_engine.service.app import create_app


@pytest.fixture()
def app_client(tmp_path):
    cfg = EngineConfig()
    cfg.backend = "scenario"
    cfg.service.db_path = str(tmp_path / "engine.db")
    cfg.service.audit_log_path = str(tmp_path / "audit.log")
    cfg.service.api_keys = ["test-key-001"]
    app = create_app(cfg)
    with TestClient(app) as client:
        yield client


HEADERS = {"X-API-Key": "test-key-001"}


def _entry_alert_payload(scenario_id: str) -> dict:
    scenario_data, spec = load_scenario(scenario_id)
    entry = find_entry_event(scenario_data, spec)
    alert = build_alert_event(entry)
    return {
        "technique": alert.technique_id,
        "asset": alert.asset_id,
        "tactic": alert.tactic,
        "timestamp": alert.timestamp,
        "log_source": alert.log_source,
        "anomaly_score": alert.anomaly_score,
        "attributes": alert.attributes,
    }


def _wait_done(client, inv_id: str, timeout: float = 300.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        rec = client.get(f"/v1/investigations/{inv_id}", headers=HEADERS).json()
        if rec["status"] in ("completed", "error"):
            return rec
        time.sleep(1.0)
    raise TimeoutError(f"investigation {inv_id} not done in {timeout}s")


def test_health_no_auth_required(app_client):
    resp = app_client.get("/v1/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
    assert resp.json()["backend"] == "scenario"


def test_auth_rejects_missing_key(app_client):
    assert app_client.get("/v1/investigations").status_code == 401
    assert app_client.post(
        "/v1/investigations",
        json={"alert": {"technique": "T1059", "asset": "H1"}},
    ).status_code == 401


def test_scenarios_listed(app_client):
    resp = app_client.get("/v1/scenarios", headers=HEADERS)
    assert resp.status_code == 200
    ids = {s["id"] for s in resp.json()}
    assert {"pipeline_18", "apt_5host", "multipath_12host"} <= ids


def test_report_conflict_before_done(app_client):
    resp = app_client.post(
        "/v1/investigations",
        json={
            "alert": _entry_alert_payload("pipeline_18"),
            "scenario_id": "pipeline_18",
        },
        headers=HEADERS,
    )
    assert resp.status_code == 202
    inv_id = resp.json()["id"]

    # 立刻取报告 → 409 或已完成（极快场景）
    r = app_client.get(f"/v1/investigations/{inv_id}/report", headers=HEADERS)
    assert r.status_code in (200, 409)
    _wait_done(app_client, inv_id)


def test_full_investigation_pipeline_18(app_client):
    resp = app_client.post(
        "/v1/investigations",
        json={
            "alert": _entry_alert_payload("pipeline_18"),
            "scenario_id": "pipeline_18",
        },
        headers=HEADERS,
    )
    assert resp.status_code == 202
    inv_id = resp.json()["id"]

    rec = _wait_done(app_client, inv_id)
    assert rec["status"] == "completed", rec.get("error")
    assert rec["decision"]["action"] in {
        "contain_escalate",
        "monitor",
        "dismiss_benign",
        "escalate_incomplete",
    }
    assert rec["decision"]["confidence"] is None
    assert rec["decision"]["calibrated_probability"] is None
    assert rec["decision"]["confidence_status"] == "unavailable"
    assert rec["decision"]["automation_eligible"] is False
    assert isinstance(rec["decision"]["investigation_score"], float)
    if rec["decision"]["action"] == "escalate_incomplete":
        assert rec["decision"]["incomplete"] is True
        assert rec["decision"]["unresolved_obligations"]

    gt = rec["ground_truth_eval"]
    assert gt["gt_total"] == 18
    assert 0.0 <= gt["recall"] <= 1.0

    report = app_client.get(
        f"/v1/investigations/{inv_id}/report", headers=HEADERS,
    ).json()
    assert report["status"] == "completed"
    assert report["graph"]["attributed_node_count"] >= 1
    assert report["usage"]["rounds"] >= 1
    assert report["usage"]["soar_fetch"]["queries"] >= 1
    assert report["usage"]["soar_fetch"]["logical_queries"] >= 1
    assert report["usage"]["soar_fetch"]["query_diagnostics"]
    assert report["usage"]["voi_audit"]
    assert report["usage"]["model_planner"]
    assert report["usage"]["model_judgement"]["mode"] == "off"
    assert all(
        item["mode"] == "shadow"
        and item["executed_model_probes"] == 0
        for item in report["usage"]["model_planner"]
    )
    assert {
        "probe_id",
        "operator",
        "cost",
        "risk_reduction",
        "outcome_model_version",
        "outcomes",
    } <= report["usage"]["voi_audit"][0].keys()
    first_query = report["usage"]["soar_fetch"]["query_diagnostics"][0]
    assert "requested_from_ms" in first_query
    assert "requested_to_ms" in first_query
    assert "pages" in first_query


def test_unknown_investigation_404(app_client):
    assert app_client.get(
        "/v1/investigations/inv-nonexistent", headers=HEADERS,
    ).status_code == 404
