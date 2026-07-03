# 主机端（Windows）接入说明

> 更新：2026-07-03  
> 服务器：192.144.151.189  
> MCP：**HTTPS** `https://192.144.151.189/mcp`（Nginx :443 终结 TLS；HTTP :80 自动 301）  
> 服务端测试：`trace_tools_test_report.json`、`https_pagination_report.json`

---

## 0. 服务端验证（已通过）

| 类别 | 结果 |
|------|------|
| 溯源 MCP 工具 | **16/16** PASS（含 HTTPS） |
| search_after 分页 | PASS（无重叠） |
| offset 分页 | PASS |
| Token 签发 (HTTPS) | PASS |

### 溯源核心查询（6/6 ✅）

| 工具 | 场景 | 命中数 |
|------|------|--------|
| `search_security_events` | pipeline_18 攻击链 | 19 |
| `search_security_events` | apt_5host 攻击链 | 25 |
| `search_security_events` | multipath 攻击链 | 31 |
| `search_security_events` | 入口告警 evt_018 | 3 |
| `search_security_events` | MITRE T1566.001 | 2 |
| `search_security_events` | 溯源结果事件 | 11 |

攻击链召回与集成测试一致（18/25/31）。另已通过：告警分析 5 项、报告/风险评估 2 项、主机取证 3 项（含 `get_wazuh_agents`）。

**结论：Windows 端下载 `host-client.env` 后即可接入真实溯源流程。**

---

## 1. 下载配置 + 信任 CA

```powershell
scp ubuntu@192.144.151.189:/home/ubuntu/host-client.env "F:\cursor all\final trace\host-client.env"
scp ubuntu@192.144.151.189:/home/ubuntu/ssl/mcp-tls/ca.crt "F:\cursor all\final trace\mcp-ca.crt"
```

可选：导入 Windows 受信任根（管理员 PowerShell）：

```powershell
Import-Certificate -FilePath "F:\cursor all\final trace\mcp-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root
```

或使用 `engine.yaml` 的 `ca_bundle`（无需系统级导入）。

加载环境变量：

```powershell
Get-Content "F:\cursor all\final trace\host-client.env" | ForEach-Object {
  if ($_ -match '^\s*([^#=]+)=(.*)$') {
    [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), 'Process')
  }
}
Write-Host "MCP endpoint:" $env:TRACE_ENGINE_MCP_ENDPOINT
Write-Host "Token loaded:" ($env:WAZUH_MCP_TOKEN.Substring(0,20) + "...")
```

**注意：`host-client.env` 含密钥，不要提交 Git 或发到聊天。**

---

## 2. Windows 快速验证

```powershell
cd "F:\cursor all\final trace"
$env:PYTHONPATH = "F:\cursor all\final trace\src"
Get-Content host-client.env | ForEach-Object {
  if ($_ -match '^\s*([^#=]+)=(.*)$') {
    [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), 'Process')
  }
}

python scripts/validate_wazuh_runtime.py --config configs/engine.yaml --incident pipeline_18 --limit 5
python scripts/upload_soar_scenarios_to_wazuh.py probe
```

`validate_wazuh_runtime.py` 会检查：TLS CA、MCP 初始化、工具可用、遥测查询、**search_after 分页**。

### 工具名映射

| 配置项 | 实际 MCP 工具 |
|--------|--------------|
| 主查询 | **`search_security_events`** |
| 告警列表 | `get_wazuh_alerts` |
| IoC / 威胁 | `analyze_security_threat` / `check_ioc_reputation` |
| 报告 | `generate_security_report` |
| Agent 列表 | `get_wazuh_agents` |

---

## 3. 场景数据（已在服务器，Windows 无需再上传）

```
/home/ubuntu/soar_mcp_env/     # 11,019 实体事件 + 56 溯源结果
/home/ubuntu/soar-logs/events.jsonl
```

重新 ingest（仅当更新了 `soar_mcp_env` 时）：

```bash
ssh ubuntu@192.144.151.189 "python3 /home/ubuntu/scripts/ingest_soar_mcp_env.py --mode replace && cd /home/ubuntu/wazuh-docker/single-node && docker compose restart wazuh.manager"
```

### MCP 查询语法

| 查询目的 | query 示例 |
|---------|-----------|
| pipeline_18 攻击链 | `data.scenario:pipeline_18 AND data.is_attack:true` |
| apt_5host 攻击链 | `data.scenario:apt_5host AND data.is_attack:true` |
| 入口告警 | `data.raw_log_ref:"attack:idx_stress:evt_018"` |
| MITRE 技术 | `data.mitre_technique:T1566.001 AND data.scenario:pipeline_18` |
| 溯源结果 | `data.event_kind:trace_result` |

字段前缀均为 `data.*`；日志 ingest 须扁平（见 `/home/ubuntu/soar-logs/SCHEMA.md`）。

---

## 4. 启动 trace-engine（生产模式）

`configs/engine.yaml` 已预置 Wazuh 配置，核心项：

```yaml
backend: soar_mcp
soar_mcp:
  endpoint: "https://192.144.151.189/mcp"
  verify_tls: true
  ca_bundle: "mcp-ca.crt"
  tool_profile: "wazuh"
  tool_name: "search_security_events"
  wazuh_compact: false
  wazuh_attacks_only: false
  asset_inventory:
    wazuh_agents_enabled: true
```

引擎 transport 已支持 `data.pagination.next_search_after` 自动翻页，消除 `coverage_truncated`。

```powershell
$env:TRACE_ENGINE_BACKEND = "soar_mcp"
python scripts/serve_engine.py --config configs/engine.yaml
```

---

## 5. 第一次真实溯源（HTTP API）

```powershell
$body = @{
  scenario_id = "pipeline_18"    # 生产态 = Wazuh case 范围，不读本地 JSON
  alert = @{
    technique = "T1041"
    asset = "DB-PROD-01"
    timestamp = "2026-06-11T06:00:00.000Z"
    anomaly_score = 0.92
    attributes = @{ raw_log_ref = "attack:idx_stress:evt_018" }
  }
} | ConvertTo-Json -Depth 5

Invoke-RestMethod -Uri "http://localhost:8100/v1/investigations" -Method Post -Body $body -ContentType "application/json"
```

调查完成后 GET `/v1/investigations/{id}/report`，关注：

- `decision.action` — 处置结论（如 `contain_escalate`）
- `graph.attack_node_count` — 攻击图节点数
- `trace_coverage` — 生产态覆盖（发现主机、缓存攻击事件数、bootstrap 统计）

### 生产态 bootstrap 流程（自动）

1. 按 `scenario_id` 预取 case 内攻击链（MCP 只读）
2. 可选：`get_wazuh_agents` / CMDB HTTP 补充资产清单
3. LOCK 主循环 + 跨主机探针 fan-out

---

## 6. CMDB API（可选）

```yaml
soar_mcp:
  asset_inventory:
    cmdb:
      enabled: true
      url: "https://cmdb.corp/api/v1/hosts"
      hosts_json_path: "data.items"
      hostname_field: "hostname"
```

或环境变量：`$env:TRACE_ENGINE_CMDB_URL = "https://..."`

---

## 7. Cursor MCP 配置

```json
{
  "mcpServers": {
    "wazuh": {
      "type": "http",
      "url": "http://192.144.151.189/mcp",
      "headers": {
        "Authorization": "Bearer <WAZUH_MCP_TOKEN>"
      }
    }
  }
}
```

---

## 8. Token 过期后换新

```powershell
$body = '{"api_key": "' + $env:MCP_API_KEY + '"}'
$r = Invoke-RestMethod -Uri "http://192.144.151.189/auth/token" -Method Post -ContentType "application/json" -Body $body
$env:WAZUH_MCP_TOKEN = $r.access_token
```

Token 有效期约 **1 年**。

---

## 9. 服务端已完成项

- [x] SOAR 全量 ingest（pipeline_18 / apt_5host / multipath_12host）
- [x] 溯源 MCP 工具链测试 16/16 通过
- [x] Nginx 反代 MCP（80 → `/mcp`）
- [x] `host-client.env` + JWT
- [x] trace-engine 生产 bootstrap + `trace_coverage` 报告字段
