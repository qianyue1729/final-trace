# 统一 SOAR MCP 多源测试数据环境

Web 演示、压力测试 `run-soar`、benchmark 场景生成共用的**单 SOAR MCP + 多数据源分片**环境。场景 JSON、注册表、Toolbox 装配逻辑集中在本目录。

## 架构

```
┌─────────────────────────────────────────────────────────┐
│  soar_mcp_env/scenarios/*.json                          │
│  meta: CMDB, NAT, IAM, source_count, multi_source       │
│  events: Entity-Event（含噪声）                          │
│  ground_truth: attack_edge_refs                         │
└────────────────────────┬────────────────────────────────┘
                         │
         ┌───────────────▼────────────────┐
         │  setup.create_soar_toolbox()   │
         │  LogStore + EntityResolver     │
         │  enable_multi_source(          │
         │    soar:global → query_bridge) │
         └───────────────┬────────────────┘
                         │
    ┌────────────────────┼────────────────────┐
    │                    │                    │
    ▼                    ▼                    ▼
 Web 演示           run-soar 压测      factory (apt5/…)
 runner.py          stress_test_runner
```

**查询桥**：`LocalLogStore`（`benchmarks/local_mcp_server.py`）按时间窗读场景 JSON，模拟 SOAR 统一查询接口。

**可选 MCP 进程**：`benchmarks/soar_mcp_server.py`（7 源 stdio MCP，见 `mcp/INDEX.md`）。

## 目录

```
soar_mcp_env/
  README.md                 ← 本说明
  registry.json             ← 场景 ID、入口覆盖、run 预算
  data_sources.json         ← EDR/SIEM/FW/NDR/WAF/Email/CloudAudit
  paths.py
  setup.py                  ← create_soar_toolbox, build_scenario_api_info
  scenarios/                ← 正式测试场景 JSON
    scenario_pipeline_18steps.json
    apt_5host.json
    multipath_scenario.json
  results/                  ← 压测结果样例（可选）
  generated/                ← 场景构建中间产物（attacks/noise）
  mcp/INDEX.md              ← MCP Server 脚本索引
```

## 注册场景

| ID | 文件 | 入口（演示） | 数据源分片 |
|----|------|-------------|-----------|
| `pipeline_18` | `scenario_pipeline_18steps.json` | meta 默认 | 7 |
| `apt_5host` | `apt_5host.json` | **evt_015** | 9 |
| `multipath_12host` | `multipath_scenario.json` | **evt_005** | 18 |

`entry_alert_ref` 覆盖见 `registry.json`（原 meta 入口在部分场景图连通性差）。

## 使用

```powershell
cd trace_agent

# Web 演示（自动加载本目录场景）
python webapp/run.py

# 压力测试 SOAR 模式
python -m benchmarks run-soar --scenario soar_mcp_env/scenarios/apt_5host.json

# 代码中装配 Toolbox
python -c "
import sys; sys.path.insert(0,'.')
from soar_mcp_env.setup import create_soar_toolbox
tb, res, store = create_soar_toolbox('pipeline_18')
print(store.meta.get('source_count'), 'sources')
"
```

## 场景 JSON 要点

每个 `scenarios/*.json` 含：

- **meta**：`entry_alert_ref`, `cmdb`, `nat_sessions`, `dhcp_leases`, `iam`, `internal_cidrs`, `source_count`, `multi_source`
- **events**：`EntityEvent` 列表（攻击 + 噪声）
- **ground_truth**：`attack_edge_refs`, `root_cause_technique`

## 兼容旧路径

`benchmarks/stress_test_scenarios/` 已迁移至本目录；生成类命令默认输出到 `soar_mcp_env/scenarios` 或 `generated/`。

Web 层仍通过 `trace_agent.webapp.soar_scenarios`  re-export，内部指向本目录。
