# final-trace

LOCK 决策导向安全告警溯源引擎 + Deep Agent 前后端，支持离线场景回放与真实 Wazuh/SOAR MCP 生产调查。

## 架构

| 目录 | 说明 |
|------|------|
| `src/trace_engine/` | 溯源引擎内核（runner、MCP transport、scenario registry） |
| `src/trace_agent/` | LOCK 单环编排（L→Veto→O→C→K） |
| `deep-agent-backend/` | LangGraph Deep Agent 服务（`trace_agent` graph） |
| `deep-agents-ui/` | Deep Agents 调试 UI |
| `configs/` | 引擎配置（含 `engine_demo_wazuh.yaml` demo profile） |
| `soar_mcp_env/` | SOAR MCP 场景 registry 与契约 |
| `reference/` | 参考攻击链与查询契约（如 `pipeline_18`） |
| `scripts/` | 启动、校验、部署脚本 |
| `tests/` | 引擎与 Deep Agent 单测 |

## 快速开始

### 1. 依赖

```powershell
pip install -r requirements-engine.txt
cd deep-agent-backend; pip install -e .
cd ../deep-agents-ui; npm install
```

### 2. 配置

```powershell
copy .env.example .env
# 编辑 .env，填入 DEEPSEEK_API_KEY 等
```

生产 MCP 接入见 [HOST_CLIENT_HANDOFF.md](HOST_CLIENT_HANDOFF.md)。

### 3. 启动 Deep Agent（场景模式）

```powershell
.\scripts\start_deep_agent_backend.ps1
.\scripts\start_deep_agents_ui.ps1 -Port 3002
```

打开 http://localhost:3002，Assistant ID：`trace_agent`。

### 4. 生产演示（pipeline_18）

```powershell
.\scripts\start_deep_agent_backend.ps1 -EnableProduction -DemoProfile
```

在前端执行：`对 pipeline_18 运行生产溯源`。

## 展示语义

`escalate_incomplete` + 候选链 ≥18 **不是溯源失败**，compact_report 会返回：

- `investigation_status`: `completed_needs_review`
- `display_headline`: **调查完成 · 建议人工复核**
- `chain_build_label`: **建链成功**
- `attribution_label`: **归因待确认**
- `lock_loop`: 每轮 L→Veto→O→C→K 诊断

详见 `deep-agent-backend/src/trace_deep_agent/presentation.py`。

## pipeline_18 契约

Bootstrap 等价查询：

```text
data.incident_id:"INC-PIPELINE_18" AND data.is_attack:true
```

校验：

```powershell
python scripts/validate_pipeline_18_contract.py
```

参考数据与说明：`reference/pipeline_18/`。

## 测试

```powershell
python -m pytest tests/ -q
python -m pytest tests/deep_agent/test_presentation.py -q
```

## 文档

- [HOST_CLIENT_HANDOFF.md](HOST_CLIENT_HANDOFF.md) — Windows 主机接入 MCP
- [docs/DEEP_AGENTS_SETUP.md](docs/DEEP_AGENTS_SETUP.md)
- [docs/TRACE_ENGINE_DEPLOYMENT.md](docs/TRACE_ENGINE_DEPLOYMENT.md)
- [reports/pipeline_18.md](reports/pipeline_18.md) — 生产溯源报告样例

## 安全说明

`.env`、`host-client.env`、`mcp-ca.crt` 含密钥或证书，已在 `.gitignore` 中排除。请仅使用 `*.example` 模板。
