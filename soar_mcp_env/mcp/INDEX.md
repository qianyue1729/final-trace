# MCP 模拟器索引

SOAR 数据环境依赖下列 **benchmarks** 脚本（未重复拷贝，避免双份维护）。

| 脚本 | 用途 |
|------|------|
| `benchmarks/local_mcp_server.py` | `LocalLogStore`：场景 JSON → 时间窗查询；Web/run-soar **查询桥**默认实现 |
| `benchmarks/soar_mcp_server.py` | 单进程 7 源 SOAR MCP（stdio）；支持 splits 分片加载 |
| `benchmarks/stress_test_runner.py` | `run-soar` 压测；`_run_soar_investigation()` 与 `setup.create_soar_toolbox` 等价 |
| `benchmarks/edr_mcp_server.py` | 单源 EDR MCP（多进程编排对比用） |
| `benchmarks/siem_mcp_server.py` | 单源 SIEM MCP |

## 启动示例

```powershell
cd trace_agent

# 本地 CLS 风格 MCP（单场景文件）
python benchmarks/local_mcp_server.py soar_mcp_env/scenarios/apt_5host.json

# 统一 SOAR MCP（多分片）
python benchmarks/soar_mcp_server.py soar_mcp_env/scenarios/multipath_scenario.json
```

## 与 Agent 集成

`setup._make_soar_query_bridge(path)` 在进程内直接调用 `LocalLogStore`，无需起 MCP 子进程；适合 Web 演示与快速压测。

真实 MCP stdio 集成见 `trace_agent/mcp_tools/mcp_client.py`（`-m benchmarks.local_mcp_server`）。
