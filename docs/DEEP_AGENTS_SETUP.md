# 溯源 Agent：Deep Agents 前后端

调试前端来自 `langchain-ai/deep-agents-ui`。该仓库已于 2026-06-28
归档，因此这里只把它作为可替换的本地调试壳；后端保持标准 LangGraph
API，不依赖该 UI 的私有接口。

## 架构

```text
deep-agents-ui :3001
        │ LangGraph SDK
        ▼
LangGraph Agent Server :2024
        │ assistant_id = trace_agent
        ▼
Deep Agents graph
        │ 受限工具
        ├─ list_trace_scenarios
        ├─ inspect_trace_prior
        ├─ run_trace_scenario
        └─ run_production_trace（默认禁用）
                │
                ▼
trace_agent + trace_engine + SOAR/Wazuh
```

## 本地调试

分别启动两个 PowerShell 终端：

```powershell
.\scripts\start_deep_agent_backend.ps1
.\scripts\start_deep_agents_ui.ps1
```

打开 `http://localhost:3001`。前端默认连接：

- Deployment URL：`http://127.0.0.1:2024`
- Assistant ID：`trace_agent`

后端启动器只会从根 `.env` 读取模型相关变量，不会把 Wazuh、云平台、
MCP 或其他业务凭据批量注入 Agent 进程。

启动器同时启用 Python UTF-8 模式，以规避 Windows 中文区域设置下
LangGraph API 读取 OpenAPI 资源时的 GBK 解码错误。

## 生产查询开关

默认只能跑 `soar_mcp_env` 本地场景。若确需连接真实后端：

```powershell
.\scripts\start_deep_agent_backend.ps1 -EnableProduction
```

生产配置必须使用 `backend: soar_mcp`。请先为服务配置鉴权并轮换工作区中
曾经暴露的密钥。

`-EnableProduction` 只从 `host-client.env` 导入 MCP endpoint/token，并设置：

- `TRACE_AGENT_ALLOW_PRODUCTION=1`
- `TRACE_AGENT_ENGINE_CONFIG=<仓库>/configs/engine.yaml`

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
yarn lint
yarn build
```
