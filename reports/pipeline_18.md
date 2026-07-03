# pipeline_18 生产溯源报告 (T1041 / DB-PROD-01)

## 执行摘要

| 阶段 | 现象 | 根因 |
|------|------|------|
| **修复前** | 11 节点 / 9 边，10× `noise:idx_stress`，锚点断裂 | Bootstrap 用 `data.scenario:pipeline_18` 拉到 1811 noise / 18 attack，noise 占满分页 |
| **修复后** | **19 节点 / 17 边**，18× `attack:idx_stress`，`eval_attack_prefix` | Registry 映射 `INC-PIPELINE_18` + `is_attack:true` |

**结论：** 不是 MCP 连通问题，不是预算问题，是 **查询分区错误**——引擎在拉噪声，没在拉攻击链。

---

## Indexer 数据分布（服务器侧）

| 类型 | 数量 | 命名空间 |
|------|------|----------|
| 攻击事件 | 18 | `attack:idx_stress:evt_001~018` |
| 噪声事件 | 1,811 | `noise:idx_stress:evt_17xx` |
| incident_id | — | `INC-PIPELINE_18`（18 条共享） |

### 关键查询对比

| 查询 | 返回 |
|------|------|
| `hostname:DB-PROD-01`（无 is_attack） | 30 条 noise，0 attack |
| `hostname:DB-PROD-01 AND is_attack:true` | 2 条 attack |
| `incident_id:INC-PIPELINE_18 AND is_attack:true` | **18 条完整攻击链** |

---

## 为何锚点 N1 与图断裂？（修复前）

1. **命名空间隔离** — `attack:` vs `noise:` 无法时序/前缀自动连边
2. **raw_log_ref 跨场景冲突** — `evt_018` 在 3 个 incident 中存在
3. **Bootstrap 过宽** — `data.scenario:pipeline_18` 预取 1000 条，noise 主导

---

## 已实施修复

### 1. Scenario Registry → Wazuh 查询分区

`soar_mcp_env/registry.json` 为 `pipeline_18` 增加：

```json
"wazuh_scope": {
  "incident_prefix": "INC-PIPELINE_18",
  "scope_field": "incident",
  "attacks_only": true,
  "indexed_attack_chain": true,
  "scenario_slug": "pipeline_18"
}
```

Bootstrap 等价查询：

```text
data.incident_id:"INC-PIPELINE_18" AND data.is_attack:true
```

### 2. 代码路径

- `src/trace_engine/scenario_registry.py` — scenario_id → Wazuh scope
- `src/trace_engine/runner.py` — 生产路径自动应用 registry scope
- `src/trace_engine/transports.py` — ref 查询加 `data.scenario` 消歧

### 3. 修复后实测（Wazuh MCP）

| 指标 | 修复前 | 修复后 |
|------|--------|--------|
| bootstrap prefetch | ~1000（noise 主导） | **18 attack** |
| 节点来源 | 10 noise + 1 attack | **18 attack + 锚点** |
| 边 | 9（lateral_to 噪声链） | **17（evt 序号链）** |
| candidate_mode | production_fallback | **eval_attack_prefix** |
| noise_refs | 10 | **0** |

---

## Demo Profile 结论层（并行）

即使图正确，posterior 仍可能平台期（`P_atk=0.457`）。Demo Profile 负责：

- `evidence_plateau_partial_chain` early stop
- `escalate_incomplete` + `require_human_review`
- guardrail warnings 降级

---

## 不应做 vs 应该做

| 行动 | 建议 |
|------|------|
| 追加 12→50 轮 budget | ❌ VOI 平台期下无效 |
| 提高 max_pages 拉更多 | ❌ 只会多拉 noise |
| **修 bootstrap 查询分区** | ✅ 已做 |
| **incident_id + is_attack** | ✅ 已做 |
| 修 posterior attach 路径 | ⏳ P1 后续 |

---

## 演示命令

```powershell
.\scripts\start_deep_agent_backend.ps1 -EnableProduction -DemoProfile
```

UI 输入：`pipeline_18`, `T1041`, `DB-PROD-01`, `max_rounds=12`

**预期：** 18 步攻击链入图，~19/17 图，`escalate_incomplete`，无 noise 节点。
