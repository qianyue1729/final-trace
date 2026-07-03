"""trace-engine REST 服务 — 第三方告警溯源 API。

端点：
    POST   /v1/investigations          投递告警，异步启动 LOCK 调查
    GET    /v1/investigations          列出会话
    GET    /v1/investigations/{id}     会话状态
    GET    /v1/investigations/{id}/report  完整决策报告
    GET    /v1/scenarios               验收场景列表（scenario backend）
    GET    /v1/health                  健康检查（含 SOAR 连通性）

鉴权：配置 api_keys 后要求请求头 X-API-Key；审计日志逐请求落盘 JSONL。
"""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..config import EngineConfig
from ..runner import InvestigationRunner
from ..store import InvestigationStore


# ── 请求模型 ──
class AlertIn(BaseModel):
    """归一化告警入参（第三方 SOC/SOAR 平台投递）。

    technique 现为可选：当缺省时，需提供足够的原始结构化上下文
    （vendor_rule_id/title、process_name、command_line、platform 等）
    供 AlertEnricher 推断候选 ATT&CK 技术。缺省且上下文不足时拒绝。
    """
    technique: Optional[str] = Field(None, description="MITRE ATT&CK 技术 ID，如 T1059.001；可选")
    asset: str = Field(..., description="受影响资产/主机标识")
    tactic: Optional[str] = Field(None, description="战术；缺省按技术推导")
    platform: Optional[str] = Field(None, description="平台：windows / linux / macos / cloud / network")
    timestamp: Optional[str] = Field(None, description="ISO 8601 或 unix epoch")
    log_source: Optional[str] = Field(None, description="产生告警的日志源")
    anomaly_score: float = Field(0.5, ge=0.0, le=1.0)
    # Vendor / rule context for enrichment
    vendor_rule_id: Optional[str] = Field(None, description="厂商规则 ID，如 Sigma rule UUID")
    vendor_rule_title: Optional[str] = Field(None, description="厂商规则标题/描述")
    # Process context (bounded)
    process_name: Optional[str] = Field(None, description="进程名，如 powershell.exe")
    command_line: Optional[str] = Field(None, description="命令行（截断到 max_command_line_length）")
    parent_process_name: Optional[str] = Field(None, description="父进程名")
    # Cloud / network context
    cloud_action: Optional[str] = Field(None, description="云 API action，如 PutBucketPolicy")
    network_direction: Optional[str] = Field(None, description="inbound / outbound / lateral")
    attributes: dict[str, Any] = Field(default_factory=dict)


class InvestigationRequest(BaseModel):
    alert: AlertIn
    scenario_id: Optional[str] = Field(
        None,
        description="验收: soar_mcp_env 场景 ID；生产: Wazuh case 范围（data.scenario / incident）",
    )
    max_rounds: Optional[int] = Field(None, ge=1, le=200)


# ── 应用工厂 ──
def create_app(config: Optional[EngineConfig] = None) -> FastAPI:
    cfg = config or EngineConfig.load()
    runner = InvestigationRunner(cfg)
    store = InvestigationStore(cfg.service.db_path)
    pool = ThreadPoolExecutor(
        max_workers=cfg.service.max_workers, thread_name_prefix="lock-session",
    )
    audit_lock = threading.Lock()
    audit_path = Path(cfg.service.audit_log_path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)

    app = FastAPI(
        title="trace-engine",
        description="LOCK + 决策账 第三方告警溯源引擎（RFC-004-02）",
        version="1.0.0",
    )
    app.state.config = cfg
    app.state.store = store
    app.state.pool = pool

    # ── 审计 ──
    def audit(entry: dict[str, Any]) -> None:
        entry["ts"] = time.time()
        line = json.dumps(entry, ensure_ascii=False, default=str)
        with audit_lock:
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    # ── 鉴权 ──
    def require_api_key(request: Request) -> str:
        if not cfg.service.api_keys:
            return "anonymous"
        key = request.headers.get("X-API-Key", "")
        if key not in cfg.service.api_keys:
            audit({
                "event": "auth_denied",
                "path": request.url.path,
                "client": request.client.host if request.client else "",
            })
            raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")
        return key

    # ── 端点 ──
    @app.get("/v1/health")
    def health() -> dict:
        soar_ok: Optional[bool] = None
        if cfg.backend == "soar_mcp":
            try:
                executor, _ = runner._build_executor(None)
                soar_ok = executor.available()
            except Exception:  # noqa: BLE001
                soar_ok = False
        return {
            "status": "ok",
            "backend": cfg.backend,
            "soar_reachable": soar_ok,
            "version": app.version,
        }

    @app.get("/v1/scenarios")
    def scenarios(_key: str = Depends(require_api_key)) -> list[dict]:
        return runner.list_scenarios()

    @app.post("/v1/investigations", status_code=202)
    def submit(
        req: InvestigationRequest,
        request: Request,
        _key: str = Depends(require_api_key),
    ) -> dict:
        alert_payload = req.alert.model_dump()
        inv_id = store.create(alert_payload, req.scenario_id)
        audit({
            "event": "investigation_submitted",
            "id": inv_id,
            "technique": req.alert.technique or "(pending_enrichment)",
            "asset": req.alert.asset,
            "scenario_id": req.scenario_id,
            "client": request.client.host if request.client else "",
        })

        def job() -> None:
            store.set_status(inv_id, "running")
            report = runner.run(
                alert_payload,
                scenario_id=req.scenario_id,
                max_rounds=req.max_rounds,
            )
            store.set_report(inv_id, report)
            audit({
                "event": "investigation_finished",
                "id": inv_id,
                "status": report.get("status"),
                "decision": (report.get("decision") or {}).get("action"),
                "elapsed": (report.get("usage") or {}).get("elapsed_seconds"),
            })

        pool.submit(job)
        return {"id": inv_id, "status": "queued"}

    @app.get("/v1/investigations")
    def list_investigations(
        limit: int = 50, _key: str = Depends(require_api_key),
    ) -> list[dict]:
        return store.list(limit=min(limit, 200))

    @app.get("/v1/investigations/{inv_id}")
    def get_investigation(
        inv_id: str, _key: str = Depends(require_api_key),
    ) -> dict:
        rec = store.get(inv_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="investigation not found")
        summary = dict(rec)
        report = summary.pop("report", None)
        if report:
            summary["decision"] = report.get("decision")
            summary["usage"] = report.get("usage")
            if "ground_truth_eval" in report:
                summary["ground_truth_eval"] = report["ground_truth_eval"]
            if report.get("status") == "error":
                summary["error"] = report.get("error")
        return summary

    @app.get("/v1/investigations/{inv_id}/report")
    def get_report(
        inv_id: str, _key: str = Depends(require_api_key),
    ) -> JSONResponse:
        rec = store.get(inv_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="investigation not found")
        if rec["status"] in ("queued", "running"):
            raise HTTPException(
                status_code=409,
                detail=f"investigation is {rec['status']}; report not ready",
            )
        return JSONResponse(rec["report"] or {})

    return app
