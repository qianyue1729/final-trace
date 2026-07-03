# trace-engine 部署与接入指南

> 基于 RFC-004-02（LOCK + 决策账）的**第三方告警溯源引擎**，面向「单 SOAR MCP 统一查询、内部多数据源分片路由」的企业环境。
> 内核 `trace_agent`（LOCK 单环 + 四本账）不含任何平台耦合；本服务层 `trace_engine` 提供生产接入。

---

## 1. 架构

```
第三方 SOC/SOAR ──POST /v1/investigations──▶ trace-engine (FastAPI)
                                                │  SQLite 持久化 + 审计日志
                                                ▼
                                    DecisionOrchestrator（LOCK 单环）
                                     L → ②检验 → O(VOI) → C → K(决策账)
                                                │ C 拍
                                                ▼
                                    SoarMcpProbeExecutor
                                     · operator → 数据源映射
                                     · 时间游标分页 / 去重 / 失败降级
                                     · Ranking v2 匹配内核（与验收同一份）
                                                │
                              ┌─────────────────┴─────────────────┐
                     McpHttpTransport（生产）          LocalScenarioTransport（验收/CI）
                     MCP streamable-HTTP JSON-RPC      soar_mcp_env 场景 JSON 回放
```

**两态一内核**：生产与验收只差 `backend` 配置；执行器、匹配、LOCK 循环完全同一份代码——验收指标对生产行为有效。

## 2. 快速启动

```bash
pip install -r requirements-engine.txt

# 验收态（默认，无外部依赖）
python scripts/serve_engine.py --port 8100

# 生产态
cp configs/engine.example.yaml configs/engine.yaml   # 修改 backend/endpoint/api_keys
python scripts/serve_engine.py --config configs/engine.yaml
```

环境变量覆盖（优先级高于配置文件）：

| 变量 | 作用 |
|------|------|
| `TRACE_ENGINE_BACKEND` | `scenario` / `soar_mcp` |
| `TRACE_ENGINE_MCP_ENDPOINT` | SOAR MCP 服务端地址 |
| `TRACE_ENGINE_API_KEYS` | 逗号分隔的 API Key 列表 |
| `TRACE_ENGINE_DB_PATH` | SQLite 路径 |
| `TRACE_ENGINE_PORT` | 服务端口 |

## 3. REST API

鉴权：配置 `service.api_keys` 后所有业务端点要求请求头 `X-API-Key`。

### 3.1 投递告警

```bash
curl -X POST http://localhost:8100/v1/investigations \
  -H "X-API-Key: <key>" -H "Content-Type: application/json" \
  -d '{
    "alert": {
      "technique": "T1059.001",
      "asset": "WS-FIN-07",
      "timestamp": "2026-07-01T08:30:00Z",
      "anomaly_score": 0.87,
      "attributes": {"process_name": "powershell.exe"}
    }
  }'
# → 202 {"id": "inv-xxxx", "status": "queued"}
```

`technique` + `asset` 必填；`tactic` 缺省按 ATT&CK 技术号推导。验收模式额外传 `scenario_id`。

### 3.2 其余端点

| 端点 | 说明 |
|------|------|
| `GET /v1/investigations/{id}` | 状态 + 决策摘要（queued/running/completed/error） |
| `GET /v1/investigations/{id}/report` | 完整报告：决策/置信度/次优解释/边界决策/攻击图/用量 |
| `GET /v1/investigations?limit=50` | 会话列表 |
| `GET /v1/scenarios` | 验收场景列表 |
| `GET /v1/health` | 健康检查（生产态含 SOAR 连通性） |

报告结构（节选）：

```json
{
  "decision": {
    "action": "contain_escalate",
    "confidence": null,
    "investigation_score": 0.73,
    "calibrated_probability": null,
    "confidence_status": "unavailable",
    "calibrator_version": null,
    "automation_eligible": false,
    "reason_codes": ["calibrator_missing", "calibration_not_stable"],
    "stop_reason": "robust",
    "leading_explanation": "...",
    "alternatives": [...],
    "boundary_decisions": {"edge": "contested"}
  },
  "graph": {"nodes": [...], "edges": [...], "attributed_node_count": 4},
  "usage": {"rounds": 22, "soar_fetch": {"queries": 220, "records": 3100, "errors": 0}},
  "ground_truth_eval": {"gt_hits": 18, "gt_total": 18, "recall": 1.0}
}
```

`investigation_score` 仅用于相对排序，不是概率。兼容字段
`confidence` 只有在版本化校准器状态为 `stable` 时才有数值；自动化系统
必须同时检查 `automation_eligible`，不得把调查分数显示成百分比。

## 4. 接入真实 SOAR MCP

服务端需暴露一个 MCP 工具（默认名 `soar_query`），入参约定：

```json
{"query": "host:WS-FIN-07 source:EDR", "from_ms": 0, "to_ms": 0, "limit": 200}
```

返回 `structuredContent.records` 或 `content[0].text`（JSON 数组）。**必须按时间升序**返回（引擎依赖时间游标分页突破 limit）。

适配三处配置即可，不改代码：

1. **`soar_mcp.operator_datasource_map`** — LOCK 探针算子 → 你方数据源名（进查询串）
2. **`soar_mcp.query_template`** — 查询串模板，可用 `{host} {datasource} {operator} {tactic}`
3. **`normalizer.field_map`** — 你方记录字段 → 引擎标准字段（点分路径），必需：`ref`（唯一 ID）、`timestamp`、`host`；建议：`technique`、`action`、`anomaly_score`

若返回记录无 MITRE technique，引擎按 `action` 回退推导战术（映射见 `trace_agent/loop/scenario_executor.py`）。

## 5. 验收与测试

```bash
# 引擎测试套件（18 项：归一化 / 执行器 / API E2E）
python -m pytest tests/engine -q

# 三场景 GT 验收（生产执行器路径，验收线 recall≥90%）
python scripts/engine_acceptance.py
```

当前验收结果（2026-07-02）：

| 场景 | 决策 | GT recall | 轮数 | SOAR 查询 |
|------|------|-----------|------|-----------|
| pipeline_18 | contain_escalate | 18/18 (100%) | 22 | 220 |
| apt_5host | contain_escalate | 25/25 (100%) | 12 | 190 |
| multipath_12host | contain_escalate | 31/31 (100%) | 16 | 160 |

## 6. 运维要点

- **持久化**：SQLite（WAL），`service.retention_days` 控制保留期；多实例部署需外置共享存储或按告警源分片
- **审计**：`service.audit_log_path` JSONL 逐事件（投递/完成/鉴权拒绝），含客户端 IP
- **并发**：`service.max_workers` 控制并行调查会话数；单会话纯规则路径 1–3s
- **失败语义**：SOAR 查询失败计入 `fetch_stats.errors` 并降级（该探针本轮空手），不中断调查；后端完全不可达则会话报 error
- **预算护栏**：`budget.total_rounds / total_probes` 硬停，杜绝失控查询

## 7. 已知边界

- LLM triage（C 拍 L4）默认关闭；接入需配置 `trace_agent.llm` 的 DeepSeek client，成本与时延显著增加
- 决策置信度未做 ECE 标定（RFC §16 标签门控项）：需接入 IR 收口真值后启用
- MCP 传输实现为 streamable-HTTP JSON-RPC 单请求模式；SSE 长连接、OAuth 层未实现（预留 `headers` 注入）
