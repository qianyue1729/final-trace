# Wazuh 其他主机接入配置方案

> 服务器：192.144.151.189  
> Wazuh 版本：4.14.5（Manager / Indexer / Dashboard）  
> 当前已注册 Agent：`ubuntu-server` (ID 004)

---

## 1. 先分清两种「主机」角色

| 角色 | 做什么 | 连什么端口 | 是否安装 Agent |
|------|--------|-----------|----------------|
| **被监控主机** | 采集本机日志/态势 → 上报 Wazuh | **1514 / 1515** | ✅ 必须 |
| **溯源分析机**（Windows） | 通过 MCP 查询 Indexer 做调查 | **443** (HTTPS) | ❌ 不需要 |

本文档重点：**被监控主机** 接入。溯源分析机见 `HOST_CLIENT_HANDOFF.md`。

---

## 2. 网络与安全组（必须先放行）

在云安全组 / 防火墙中，对 **Manager 公网 IP** `192.144.151.189` 放行：

| 端口 | 协议 | 方向 | 用途 | 当前 Docker 映射 |
|------|------|------|------|------------------|
| **1514** | TCP | 入站 | Agent 通信（加密） | ✅ `0.0.0.0:1514` |
| **1515** | TCP | 入站 | Agent 注册/Enrollment | ✅ `0.0.0.0:1515` |
| 514 | UDP | 入站 | Syslog 转发（可选） | ✅ `0.0.0.0:514` |
| 443 | TCP | 入站 | MCP / Dashboard | Nginx |
| 55000 | TCP | — | Wazuh API | ❌ 仅 127.0.0.1（不对外） |
| 9200 | TCP | — | Indexer | ❌ 仅 127.0.0.1（不对外） |

**客户端出站要求：** 被监控主机只要能访问 `192.144.151.189:1514` 和 `:1515` 即可，无需开放入站。

---

## 3. 推荐方案：Wazuh Agent 主动注册（Enrollment）

Manager 已启用 `wazuh-authd`（1515），且 `use_password=no`（免密码自动注册，适合集成测试）。

```
新主机 Agent                    Wazuh Manager (Docker)
     │                                │
     │──── TCP 1515  enrollment ─────►│ authd 签发密钥
     │◄─── 分配 Agent ID ─────────────│
     │──── TCP 1514  持续上报 ────────►│ 分析 → Indexer
```

---

## 4. Linux 主机接入

### 4.1 Ubuntu / Debian（与 Manager 同版本 4.14.5）

```bash
# 在目标 Linux 主机执行
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list

sudo apt update
sudo WAZUH_MANAGER='192.144.151.189' WAZUH_AGENT_NAME='srv-web-03' \
  apt install -y wazuh-agent=4.14.5-1

sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

`WAZUH_AGENT_NAME` 建议与场景命名一致（如 `SRV-WEB-03`、`DB-PROD-01`），便于 MCP 查询：

```text
agent.name:SRV-WEB-03
```

### 4.2 手动配置（`/var/ossec/etc/ossec.conf`）

```xml
<client>
  <server>
    <address>192.144.151.189</address>
    <port>1514</port>
    <protocol>tcp</protocol>
  </server>
  <config-profile>ubuntu, ubuntu22, ubuntu24</config-profile>
  <notify_time>10</notify_time>
  <time-reconnect>60</time-reconnect>
  <auto_restart>yes</auto_restart>
  <enrollment>
    <enabled>yes</enabled>
    <manager_address>192.144.151.189</manager_address>
    <port>1515</port>
    <agent_name>srv-web-03</agent_name>
  </enrollment>
</client>
```

修改后：

```bash
sudo systemctl restart wazuh-agent
```

### 4.3 追加日志采集（auth / syslog）

在 Agent 的 `ossec.conf` 或 `agent.conf` 片段中添加：

```xml
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/auth.log</location>
</localfile>
<localfile>
  <log_format>syslog</log_format>
  <location>/var/log/syslog</location>
</localfile>
```

---

## 5. Windows 主机接入

### 5.1 MSI 静默安装（推荐）

在目标 Windows 主机 PowerShell（管理员）：

```powershell
$Manager = "192.144.151.189"
$AgentName = "WIN-USER-01"   # 与资产命名一致

Invoke-WebRequest `
  -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"

msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q `
  WAZUH_MANAGER="$Manager" `
  WAZUH_AGENT_NAME="$AgentName" `
  WAZUH_REGISTRATION_SERVER="$Manager" `
  WAZUH_REGISTRATION_PORT="1515"
```

### 5.2 服务管理

```powershell
# 查看状态
Get-Service WazuhSvc

# 重启
Restart-Service WazuhSvc
```

### 5.3 Windows 日志采集

默认已采集 Security / System / Application。可追加：

`C:\Program Files (x86)\ossec-agent\ossec.conf`：

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

---

## 6. 服务器端验证

在 **192.144.151.189** 上：

```bash
# 方式 A：Docker Manager 内
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l

# 方式 B：Wazuh API（本机）
curl -sk -u wazuh-wui:'<API_PASS>' -X GET \
  "https://127.0.0.1:55000/agents?status=active&pretty=true"
```

预期：新主机显示 `Active`，分配 ID `005`、`006`…

Dashboard 查看：`https://192.144.151.189` → Agents

---

## 7. 接入后 MCP 溯源查询示例

Agent 上线后，Windows 溯源引擎可用 **真实字段** 查询：

```text
# 按主机名（Agent name）
agent.name:WIN-USER-01

# 按 MITRE
rule.mitre.id:T1110.001 AND agent.name:ubuntu-server

# 暴力破解源 IP
data.srcip:159.75.115.184 AND agent.name:ubuntu-server
```

`engine.yaml` 无需按主机修改 endpoint；换场景时调整 `wazuh_time_range` 和查询 scope 即可。

---

## 8. 备选方案：Syslog 转发（不装 Agent）

适用于网络设备、无法装 Agent 的系统。Manager 已开 `514/udp`，但 **仅允许私网段**：

```xml
<allowed-ips>10.0.0.0/8</allowed-ips>
<allowed-ips>172.16.0.0/12</allowed-ips>
<allowed-ips>192.168.0.0/16</allowed-ips>
```

若公网主机要走 Syslog，需在服务器修改  
`/home/ubuntu/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`：

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>203.0.113.50/32</allowed-ips>  <!-- 替换为发送方公网 IP -->
</remote>
```

然后：

```bash
cd /home/ubuntu/wazuh-docker/single-node && docker compose restart wazuh.manager
```

发送方（rsyslog 示例）：

```bash
*.* @192.144.151.189:514
```

**限制：** Syslog 模式无 syscollector/主动响应，进程/端口取证能力弱于 Agent。

---

## 9. 多主机命名规范（建议）

与 SOAR 合成场景对齐，便于溯源构图：

| 主机名 (agent.name) | 角色 | 场景 |
|---------------------|------|------|
| `ubuntu-server` | Linux 服务器（已有 ID 004） | 真实告警 |
| `DB-PROD-01` | 数据库 | pipeline_18 |
| `SRV-WEB-03` | Web 服务器 | pipeline_18 |
| `WS-USER-01` | 工作站 | pipeline_18 |
| `WIN-USER-01` | Windows 工作站 | 真实环境 |

---

## 10. 常见问题

**Q: 注册失败 / Active 变 Disconnected**  
- 检查安全组 1514、1515  
- `telnet 192.144.151.189 1515` 或 `Test-NetConnection 192.144.151.189 -Port 1515`  
- 查看 Agent 日志：`/var/ossec/logs/ossec.log` 或 Windows `ossec.log`

**Q: Agent 版本必须一致吗？**  
- 建议 Agent **4.14.x** 与 Manager 4.14.5 对齐

**Q: 溯源 Windows 机要不要装 Agent？**  
- 分析机只跑 trace-engine → **不装**  
- 若也要监控该 Windows 主机 → **装 Agent** + 可选跑 trace-engine

**Q: 装 Agent 后 MCP 能自动构图吗？**  
- 能查到 `agent.name:*` 的真实告警  
- 构图仍依赖引擎归一化规则；暴力破解类告警边仍可能较少

---

## 11. 快速检查清单

| 步骤 | 命令/位置 | 通过标准 |
|------|-----------|----------|
| 安全组 | 云平台控制台 | 1514/1515 入站开放 |
| Agent 安装 | 目标主机 | `wazuh-agent` 服务 running |
| 注册 | Manager | `agent_control -l` 显示 Active |
| 告警入库 | MCP 查询 | `agent.name:<新主机>` 有结果 |
| 溯源 | Windows 引擎 | `validate_wazuh_runtime.py` 通过 |
