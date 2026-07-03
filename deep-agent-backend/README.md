# LOCK Trace Deep Agent

This package exposes the existing LOCK trace engine as a Deep Agents graph.
It is designed for the archived `langchain-ai/deep-agents-ui` debugging client.

## Safe defaults

- The graph ID / assistant ID is `trace_agent`.
- Scenario replay is enabled by default.
- Production SOAR/Wazuh access is denied unless
  `TRACE_AGENT_ALLOW_PRODUCTION=1`.
- The agent uses a state-only filesystem backend. It cannot execute local shell
  commands or read arbitrary host files.
- Tool results omit raw credentials and Python tracebacks.

## Start

From the repository root:

```powershell
.\scripts\start_deep_agent_backend.ps1
.\scripts\start_deep_agents_ui.ps1
```

Open `http://localhost:3001`. The UI defaults to:

- Deployment URL: `http://127.0.0.1:2024`
- Assistant ID: `trace_agent`

Example prompts:

```text
列出可用场景，并分析 pipeline_18。
运行 apt_5host 溯源，解释最终决策和未解决义务。
查询 T1059.001 的先验解释，不要执行生产查询。
```

## Production mode

Production mode can query the configured SOAR/Wazuh backend and may incur
latency or external cost. Enable it only in the backend process:

```powershell
.\scripts\start_deep_agent_backend.ps1 -EnableProduction
```
