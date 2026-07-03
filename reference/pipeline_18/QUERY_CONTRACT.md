# pipeline_18 引擎查询契约（Wazuh MCP）

> 版本：1.0  
> 更新：2026-07-03  
> 服务器：192.144.151.189  
> MCP 工具：`search_security_events`  
> 参考数据：`attack_chain_18_events.json`

---

## 1. 场景概览

| 项 | 值 |
|----|-----|
| 场景 ID | `pipeline_18` |
| 事件 ID | `INC-PIPELINE_18` |
| 攻击链步数 | **18**（`attack:idx_stress:evt_001` ~ `evt_018`） |
| 噪声事件 | **~1,811**（`noise:idx_stress:evt_*`，`is_attack:false`） |
| 种子告警（生产溯源入口） | `attack:idx_stress:evt_018` / **T1041** / **DB-PROD-01** |
| 跨场景 ref 冲突 | `evt_018` 亦存在于 `apt_5host`、`multipath_12host` |

**核心原则：** 所有溯源查询必须限定 **攻击分区**，否则噪声将占满分页并导致图与锚点断裂。

---

## 2. MCP 连接

```yaml
soar_mcp:
  endpoint: "https://192.144.151.189/mcp"
  verify_tls: true
  ca_bundle: "<path>/mcp-ca.crt"
  tool_name: "search_security_events"
  tool_profile: "wazuh"
  wazuh_time_range: "30d"
  wazuh_incident_prefix: "INC-PIPELINE_18"   # 推荐
  wazuh_attacks_only: true                    # 映射 data.is_attack:true
  wazuh_scope_field: "incident_id"            # 若引擎支持
```

认证：`MCP_API_KEY` → `POST /auth/token` → `Authorization: Bearer <JWT>`

---

## 3. 查询契约（必须 / 禁止）

### 3.1 Bootstrap / 攻击链预取（必须）

拉取完整 18 步攻击链：

```text
data.incident_id:INC-PIPELINE_18 AND data.is_attack:true
```

| 参数 | 值 |
|------|-----|
| `time_range` | `30d` |
| `limit` | `18`（或 `20` 留余量） |
| 预期 `total_affected_items` | `18` |

**禁止用于 bootstrap：**

```text
data.scenario:pipeline_18
host:DB-PROD-01
data.hostname:DB-PROD-01
```

原因：无 `is_attack:true` 时 Indexer 按时间倒序返回噪声，DB-PROD-01 前 30 条可为 **0 attack / 30 noise**。

---

### 3.2 种子告警精确回查（必须）

```text
data.raw_log_ref:"attack:idx_stress:evt_018" AND data.scenario:pipeline_18 AND data.is_attack:true
```

或：

```text
data.raw_log_ref:"attack:idx_stress:evt_018" AND data.incident_id:INC-PIPELINE_18
```

| 预期字段 | 值 |
|----------|-----|
| `mitre_technique` | `T1041` |
| `hostname` | `DB-PROD-01` |
| `trace_step` | `connect` |
| `src_process` | `sqlservr.exe` |
| `dst_process` | `HTTPS` |
| `incident_id` | `INC-PIPELINE_18` |

**禁止：**

```text
ref:attack:idx_stress:evt_018
data.raw_log_ref:"attack:idx_stress:evt_018"
```

原因：同一 `raw_log_ref` 在 Indexer 有 **3 条**（pipeline_18 / apt_5host / multipath_12host），不加场景或 incident 会归一化到错误技术/host。

---

### 3.3 按主机补充上下文（可选）

```text
data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.hostname:DB-PROD-01
```

预期：**2 条**（evt_017 T1115、evt_018 T1041）。

```text
data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.hostname:WS-USER-01
```

预期：**10 条**（evt_001 ~ evt_010）。

---

### 3.4 按 MITRE 技术扩散（可选）

```text
data.incident_id:INC-PIPELINE_18 AND data.is_attack:true AND data.mitre_technique:T1041
```

预期：**1 条**（evt_018）。

---

### 3.5 噪声分区（仅基线/负样本，禁止用于攻击图）

```text
data.scenario:pipeline_18 AND data.is_attack:false
```

预期 `total_affected_items`：**~1,811**。  
`raw_log_ref` 前缀为 `noise:idx_stress:`，**不得**与 `attack:` 锚点连边。

---

## 4. 分页

| 场景 | 建议 |
|------|------|
| 攻击链（18 条） | `limit: 18`，通常无需翻页 |
| 噪声探索 | 使用 `search_after`（见 `pagination.next_search_after`） |
| `max_pages: 20` × `page_limit: 1000` | 对攻击链无意义；对无过滤 scenario 查询会放大噪声 |

---

## 5. 归一化字段映射（Wazuh → 引擎事件）

引擎 flatten 后应保留以下字段（路径：`data.*` 或扁平化后顶层）：

| Wazuh `data` 字段 | 引擎归一化目标 | 说明 |
|-------------------|----------------|------|
| `raw_log_ref` | `raw_log_ref` | 稳定 ID；格式 `attack:idx_stress:evt_NNN` |
| `incident_id` | `incident_id` / scope | 攻击链分组键 |
| `scenario` | `scenario` | 场景消歧（ref 冲突时必须） |
| `is_attack` | `is_attack` | 字符串 `"true"` / `"false"` |
| `mitre_technique` | `technique` | 如 `T1041` |
| `hostname` / `agent_name` | `src_entity.attrs.host_uid` | 主机锚点 |
| `trace_step` | `action` 或 `attributes.trace_step` | exec/fork/connect/inject/write |
| `src_process` | `src_entity.attrs.process` | 进程边起点 |
| `dst_process` | `dst_entity.attrs.process` | 进程边终点 |
| `src_entity_type` | `src_entity.type` | process / netconn / file |
| `dst_entity_type` | `dst_entity.type` | process / netconn / file |
| `srcip` / `dstip` | `attributes.srcip` / `dstip` | 网络上下文 |
| `anomaly_score` | `anomaly_score` | 浮点 |
| `timestamp` | `ts` | ISO8601 |
| `event_kind` | `source` 辅助 | 固定 `soar_entity_event` |

**Wazuh 顶层字段（非 data）：**

| 字段 | 用途 |
|------|------|
| `id` | Wazuh 告警 ID（`wazuh:<id>` 回查） |
| `rule.id` | SOAR 规则 `100010` |
| `agent.name` | 采集 Agent（多为 `wazuh.manager`，**不等于**场景主机） |

---

## 6. 图构建契约

### 6.1 节点

- 每个 `attack:idx_stress:evt_NNN`（`is_attack:true`）→ **1 个节点**
- 预期节点数：**18**（跨 5 台主机：WS-USER-01、WS-USER-02、SRV-WEB-03、DB-PROD-01 等）
- `noise:idx_stress:*` 节点不得作为攻击链主路径（可作为背景噪声层，且须与锚点显式隔离）

### 6.2 边（推荐规则）

**边 A — 链内时序（必须）**

在同一 `incident_id:INC-PIPELINE_18` 内，按 `evt_NNN` 序号：

```text
evt_001 → evt_002 → … → evt_018
```

关系类型建议映射 `trace_step`：

| trace_step | 边类型 |
|------------|--------|
| `exec` / `fork` | `executes` / `spawns` |
| `connect` / `inject` | `connects_to` / `lateral_to` |
| `write` | `writes_to` |

**边 B — 进程实体（同事件内）**

```text
src_process --[trace_step]--> dst_process
```

示例 evt_018：`sqlservr.exe` → `HTTPS`（connect）

**边 C — 跨主机（主机名变化时）**

| 过渡 | 事件 |
|------|------|
| WS-USER-01 → WS-USER-02 | evt_010 → evt_011 |
| WS-USER-02 → SRV-WEB-03 | evt_013 → evt_014 |
| SRV-WEB-03 → DB-PROD-01 | evt_016 → evt_017 |

**禁止：** 仅用 `noise:` 事件的 `lateral_to` 连接锚点 N1（命名空间不同，无因果关联）。

### 6.3 锚点

| 项 | 值 |
|----|-----|
| 节点 ID | N1（引擎侧） |
| `raw_log_ref` | `attack:idx_stress:evt_018` |
| `technique` | T1041 |
| `host` | DB-PROD-01 |

图中 **至少应存在** `evt_017 → evt_018` 边直达锚点。

---

## 7. 验收标准（引擎侧对照）

下载参考 JSON：

```powershell
scp ubuntu@192.144.151.189:/home/ubuntu/soar-logs/pipeline_18/attack_chain_18_events.json .
scp ubuntu@192.144.151.189:/home/ubuntu/soar-logs/pipeline_18/attack_chain_18_compact.json .
scp ubuntu@192.144.151.189:/home/ubuntu/soar-logs/pipeline_18/QUERY_CONTRACT.md .
```

| 检查项 | 通过条件 |
|--------|----------|
| Bootstrap 查询 | 使用 §3.1，返回 18 条 |
| 种子回查 | §3.2 仅返回 T1041 @ DB-PROD-01 |
| 归一化 | 18 条均有 `technique` + `host_uid` + `raw_log_ref` |
| 图节点 | ≥ 18（攻击链），锚点可达 |
| 图边 | ≥ 17（链内顺序边） |
| 噪声污染 | 攻击主图无 `noise:idx_stress` 节点 |
| ref 冲突 | 无 apt_5host / multipath 技术混入 |

---

## 8. 攻击链速查表

| Step | raw_log_ref | MITRE | Host | trace_step |
|------|-------------|-------|------|------------|
| 1 | attack:idx_stress:evt_001 | T1566.001 | WS-USER-01 | exec |
| 2 | attack:idx_stress:evt_002 | T1059.001 | WS-USER-01 | fork |
| 3 | attack:idx_stress:evt_003 | T1053.005 | WS-USER-01 | exec |
| 4 | attack:idx_stress:evt_004 | T1053.005 | WS-USER-01 | write |
| 5 | attack:idx_stress:evt_005 | T1548 | WS-USER-01 | exec |
| 6 | attack:idx_stress:evt_006 | T1055 | WS-USER-01 | fork |
| 7 | attack:idx_stress:evt_007 | T1070 | WS-USER-01 | write |
| 8 | attack:idx_stress:evt_008 | T1003 | WS-USER-01 | exec |
| 9 | attack:idx_stress:evt_009 | T1016 | WS-USER-01 | connect |
| 10 | attack:idx_stress:evt_010 | T1021.001 | WS-USER-01 | inject |
| 11 | attack:idx_stress:evt_011 | T1005 | WS-USER-02 | write |
| 12 | attack:idx_stress:evt_012 | T1570 | WS-USER-02 | connect |
| 13 | attack:idx_stress:evt_013 | T1021.001 | WS-USER-02 | inject |
| 14 | attack:idx_stress:evt_014 | T1059.003 | SRV-WEB-03 | fork |
| 15 | attack:idx_stress:evt_015 | T1021.001 | SRV-WEB-03 | connect |
| 16 | attack:idx_stress:evt_016 | T1068 | SRV-WEB-03 | inject |
| 17 | attack:idx_stress:evt_017 | T1115 | DB-PROD-01 | write |
| 18 | attack:idx_stress:evt_018 | T1041 | DB-PROD-01 | connect |

---

## 9. 文件清单

| 文件 | 说明 |
|------|------|
| `attack_chain_18_events.json` | 完整 Wazuh 告警 JSON（18 条） |
| `attack_chain_18_compact.json` | 链摘要（归一化对照用） |
| `QUERY_CONTRACT.md` | 本文档 |

---

## 10. 常见问题

**Q: 为何 `host:DB-PROD-01` 拿不到攻击事件？**  
A: 噪声 1,811 条 >> 攻击 18 条，宽查询按时间倒序返回噪声。必须加 `is_attack:true` 与 `incident_id`。

**Q: 为何图有 9 边但锚点断裂？**  
A: 边来自 `noise:` 分区的横向时序，与 `attack:` 锚点不在同一命名空间。

**Q: 加预算能否修复？**  
A: 不能。18 条攻击链已在 Indexer 中，需修正查询分区与建边规则。
