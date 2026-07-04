# 溯源 Agent：Deep Agents 前后端

唯一官方 UI 为 `deep-agents-ui`（LangGraph SDK 客户端）。旧版 `demo/` Vite 作战室已下线。

## 架构

```text
deep-agents-ui :3002（或 :3001）
        │ @langchain/langgraph-sdk
        ▼
LangGraph Agent Server :2024
        │ assistant_id = trace_agent
        ▼
Deep Agents graph（create_deep_agent）
        │ LOCK 拍级 tools
        ├─ init_investigation / run_l_phase … run_k_phase / run_full_loop
        ├─ get_session_state / get_voi_ranking / get_decision_ledger …
        └─ inspect_trace_prior
                │
                ▼
ModularOrchestrator + trace_engine + SOAR/Wazuh MCP
```

前端通过 `onCustomEvent` 展示 LOCK 相位流（`LockLoopPanel`、`LOCKPhaseStream`）。

## 本地调试

分别启动两个 PowerShell 终端：

```powershell
.\scripts\start_deep_agent_backend.ps1
.\scripts\start_deep_agents_ui.ps1 -Port 3002
```

打开 http://localhost:3002。前端默认连接：

- Deployment URL：`http://127.0.0.1:2024`
- Assistant ID：`trace_agent`

后端启动器只会从根 `.env` 读取模型相关变量，不会把 Wazuh、云平台、
MCP 或其他业务凭据批量注入 Agent 进程。

启动器同时启用 Python UTF-8 模式，以规避 Windows 中文区域设置下
LangGraph API 读取 OpenAPI 资源时的 GBK 解码错误。

## 生产查询开关

默认只能跑 `soar_mcp_env` 本地场景。若确需连接真实后端：

```powershell
.\scripts\start_deep_agent_backend.ps1 -EnableProduction -DemoProfile
```

`-DemoProfile` 加载 `configs/engine_demo_wazuh.yaml`（平台期早停、guardrail 降级）。

生产配置必须使用 `backend: soar_mcp`。请先为服务配置鉴权并轮换工作区中
曾经暴露的密钥。

`-EnableProduction` 从 `host-client.env` 导入 MCP endpoint/token，并设置：

- `TRACE_AGENT_ALLOW_PRODUCTION=1`
- `TRACE_AGENT_ENGINE_CONFIG=<仓库>/configs/engine.yaml`（或 demo profile）

若要使用其他配置：

```powershell
.\scripts\start_deep_agent_backend.ps1 `
  -EnableProduction `
  -EngineConfigPath "D:\secure\trace-engine.yaml"
```

## 验证

```powershell
cd deep-agent-backend
$env:PYTHONPATH = "..\src"
uv run --python 3.11 --extra dev pytest

cd ..\deep-agents-ui
npm run lint
npm run build
```
