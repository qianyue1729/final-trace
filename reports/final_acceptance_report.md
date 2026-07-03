# LOCK 框架溯源优化 — 最终验收报告

> **状态**: 全部验收通过  
> **日期**: 2026-06-30  
> **验收标准**: 三场景 GT 覆盖率 ≥ 80%、所有 GT 主机入图、258 测试全部通过  
> **最终结果**: 三场景 **100% GT 覆盖率**，0 条漏失，0 个漏失主机

---

## 1. 最终验收结果

| 场景 | GT 总量 | 命中 | 覆盖率 | 图中主机 | GT 主机 | 漏失主机 |
|------|---------|------|--------|----------|---------|----------|
| pipeline_18 | 18 | 18 | **100.0%** | 10 | 4 | 0 |
| apt_5host | 25 | 25 | **100.0%** | 8 | 4 | 0 |
| multipath_12host | 31 | 31 | **100.0%** | 14 | 8 | 0 |

### 验证通过项

- `diag_gt_detail`: 三场景 100%，漏失 0 条
- `lock_step9_gt_coverage --all`: 三场景 100%，根因主机与 technique 均命中
- `lock_step7_full_loop --all`: 全部 12 项校验 OK（预算内、节点单调、停止原因合法）
- `pytest src/trace_agent/tests/`: **258 passed**

---

## 2. 覆盖率演进曲线

```
100% ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ●━━━━━●
 95% ─                                                               ○       │
 90% ─                                          ○                    │       │
 85% ─                     ●─────────────────────┼────────●          │       │
 80% ═══════ 验收线 ═══════╪══════════════════════╪════════╪══════════╪═══════╪══
 75% ─                     │                     │        │          │       │
 70% ─                     │                 ◇   │        │          │       │
 65% ─                     │                 │   │        │          │       │
 60% ─                     │                 │   │        │          │       │
 55% ─                     │                 │   │        │          │       │
 50% ─                     │                 │   │        │          │       │
 45% ─  ◆  ◇              │                 │   │        │          │       │
 40% ─  │  │              │                 │   │        │          │       │
 35% ─  │  │              │                 │   │        │          │       │
 30% ─  │  │              │                 │   │        │          │       │
 25% ─  │  │              │             ◇   │   │        │          │       │
 20% ─  │  │              │             │   │   │        │          │       │
 15% ─  │  │              │             │   │   │        │          │       │
 10% ─  │  ◇              │             │   │   │        │          │       │
  5% ─  │  │              │             │   │   │        │          │       │
  0% ───┴──┴──────────────┴─────────────┴───┴───┴────────┴──────────┴───────┴──
       原始       Fix A~F          Fix G~I        Fix J       Fix K~L
       基线       (探针/扇出/      (入图判假/      (停止条件     (动作映射/
                  时间窗口)        backward prov)  动量检查)     主机轮换)

图例: ● pipeline_18  ○ apt_5host  ◇ multipath_12host  ◆ 重叠点
```

### 数值演进表

| 阶段 | pipeline_18 | apt_5host | multipath_12host | 关键修复 |
|------|-------------|-----------|------------------|----------|
| **原始基线** | 44.4% | 40.0% | 12.9% | — |
| **Fix A~F** | 83.3% | 44.0% | 25.8% | 时间窗口/扇出/探针过滤/commit |
| **Fix G~I** | 100.0% | 92.0% | 67.7% | L1 7天窗口/PARK提升/backward prov |
| **Fix J** | 100.0% | 96.0% | 87.1% | 停止条件动量检查 |
| **Fix K~L (最终)** | 100.0% | 100.0% | 100.0% | READ映射/主机轮换R4门控 |

---

## 3. Fix A~L 完整修复清单

### 3.1 Phase 1: 探针调度与时间窗口 (Fix A~F)

| # | 修复项 | 文件 | 核心修改 | 根因 |
|---|--------|------|----------|------|
| **A** | TIME_WINDOW_STEP 扩展 | `loop/scenario_executor.py` | 3600→86400 (24h/轮) | 多日跨度场景需数十轮才能覆盖所有GT时间戳 |
| **B** | 非主机名探针过滤 | `agents/orchestrator.py` | `_veto_phase()` 添加 `_known_hosts_lower` 过滤 | L-phase 生成的伪主机名(如 'frontier-attack:...') 浪费扇出slot |
| **C** | BudgetState 配置 | `eval/lock_step2_l_phase.py` | `fanout_per_round=8, total_rounds=50, total_probes=400` | 原 fanout=3 太少 |
| **D** | VOI 引擎回退 | `probe/voi_engine.py` | `VOI_EXPLORE_THRESHOLD=0.001`, `EXPLORE_WEIGHT=0.5` | exploration_voi 主导选择导致严重覆盖率回退 |
| **E** | commit_event_refs 全量提交 | `agents/orchestrator.py` | `_c_phase()` commit ALL raw_events | WEAK/PARK/SPAWN 未commit → executor每轮返回相同事件 |
| **F** | cross_host 包含告警主机 | `loop/generators.py` | 候选: `not in graph_hosts or == alert_lower` | 告警主机有最多攻击事件但被排除 |

### 3.2 Phase 2: 入图判假级联修复 (Fix G~I)

| # | 修复项 | 文件 | 核心修改 | 根因 |
|---|--------|------|----------|------|
| **G** | L1 attack 事件时间窗口 | `loop/ingest.py` | attack事件: 604800s (7天), bootstrap: 7200s | GT事件距图节点17~145小时, 超2h窗口 → `attachable=False` → PARK |
| **H** | PARK/SPAWN 攻击事件提升 | `loop/ingest.py` | `_finalize_graph_eligibility()` 扩展覆盖 PARK+SPAWN | 原来只提升WEAK → PARK/SPAWN中GT事件永远无法入图 |
| **I** | backward provenance 包含告警主机 | `loop/ingest.py` | 移除 `event_host == alert_host: return False` | 告警主机上的前序事件(如initial-access)被排除于backward provenance |

### 3.3 Phase 3: 停止条件增强 (Fix J)

| # | 修复项 | 文件 | 核心修改 | 根因 |
|---|--------|------|----------|------|
| **J** | 停止条件动量检查 | `agents/orchestrator.py` | 条件5: min_rounds_after_root=8; 条件6: 动量检查(`_stagnation_rounds==0`不允许停) | multipath在R4过早停止, 但DC01/DB-PROD-01上GT需R6~R7才能发现 |

### 3.4 Phase 4: 最终收尾 (Fix K~L)

| # | 修复项 | 文件 | 核心修改 | 根因 |
|---|--------|------|----------|------|
| **K** | READ 动作映射 | `loop/scenario_executor.py` | `OPERATOR_ACTION_MAP` 中 file_hash_lookup 添加 READ; `ACTION_TACTIC_FALLBACK` 添加 READ→collection | multipath evt_027 (T1005, action=READ) 是执行器的死角 |
| **L** | O 拍主机探索轮换 | `agents/orchestrator.py` | `_adjusted_voi`: staleness bonus (每闲置轮+0.06, 上限0.30) + 同主机≥3探针轻度惩罚; **R4门控** | 后期探针集中在WS-USER-01, DC01/DB-PROD-01/SRV-FILE-01未充分覆盖 |

---

## 4. 修改文件总览

| 文件 | 涉及修复项 | 修改类型 |
|------|-----------|----------|
| `src/trace_agent/loop/scenario_executor.py` | Fix A, K | 时间窗口 + 动作映射 |
| `src/trace_agent/agents/orchestrator.py` | Fix B, E, J, L + VOI回退 + bootstrap | 探针过滤/commit/停止/轮换 |
| `src/trace_agent/loop/ingest.py` | Fix G, H, I | L1窗口/PARK提升/backward prov |
| `src/trace_agent/loop/generators.py` | Fix F | cross_host候选 |
| `src/trace_agent/probe/voi_engine.py` | Fix D (VOI回退) | 探索阈值/权重 |
| `src/trace_agent/eval/lock_step2_l_phase.py` | Fix C | BudgetState配置 |
| `src/trace_agent/eval/diag_gt_detail.py` | Bug修复 | walrus bug + 大小写比较 |

---

## 5. 关键教训总结

### 5.1 Fix L: R4 门控设计经验 (最重要的教训)

**问题**: 主机轮换机制 (staleness bonus + 同主机惩罚) 的第一版从 R1 就生效且惩罚过强，把 pipeline_18 从 100% 打回 77.8%。

**根因分析**:
- **早期轮次 (R1~R3)**: 告警主机 (如 DB-PROD-01, WS-USER-01) 集中了最多的攻击证据。此阶段需要多算子对告警主机集中覆盖 (auth_log, process_tree, network_flow, file_hash_lookup 等)，才能建立基础因果图。
- **后期轮次 (R4+)**: 基础图已建立，initial-access 已发现，此时需要向远端主机 (DC01, SRV-FILE-01 等) 扩展横向移动路径。

**设计决策**: 轮换逻辑仅在 `rounds_used >= 4` 时启用。

**通用原则**:
> 多轮迭代式溯源系统中，"深度集中"与"广度探索"存在阶段性矛盾。正确的做法不是简单加权平衡，而是**按轮次分阶段切换策略**——早期集中建立锚点，后期轮换扩展边界。

### 5.2 VOI 参数敏感性

**教训**: `VOI_EXPLORE_THRESHOLD` 从 0.15 调到 0.5 导致灾难性回退 (apt_5host 40%→8%)。

**原因**: exploration_voi 包含 host_novelty 等项，在阈值过高时完全主导选择，使系统追求"新奇性"而非"攻击相关性"。

**原则**: VOI exploration 只应在 decision_voi 接近零时作为 fallback，而非常态驱动力。

### 5.3 入图判假级联的路由死角

**教训**: L4 五桶路由中，PARK/SPAWN 桶的事件即使是 GT 攻击边也永远无法入图。

**原因**: `_finalize_graph_eligibility()` 原来只提升 WEAK 事件。设计者假设"不可挂接 (non-attachable) 的事件不应入图"，但忽略了：
1. L1 时间窗口过窄导致远端事件被误判为 non-attachable
2. attack-like 的 PARK/SPAWN 事件应享受更宽松的入图条件

**原则**: 入图判假级联的每个桶都需要明确的"逃逸路径"——否则某类事件一旦被路由到死角桶，就永远丢失。

### 5.4 commit 机制的必要性

**教训**: 不 commit 的事件会在后续轮次被重复返回，看似"有货"实则是重复数据。

**原则**: 任何迭代式探测系统都需要"已消费"标记——否则系统会在信息幻觉中空转。

### 5.5 时间窗口与场景跨度的匹配

**教训**: 固定 2h 窗口无法处理 8 天跨度的 APT 场景。

**最终方案**: attack-like 事件 7 天窗口 + 非攻击事件 bootstrap 阶段 2h 窗口。

**原则**: 安全场景的时间粒度差异巨大 (分钟级扫描 vs 周级APT)，时间窗口必须对场景类型自适应。

### 5.6 停止条件的"否定性证据"

**教训**: `_stagnation_rounds == 0` (最近一轮仍有新节点入图) 是停止决策中最重要的否定信号。

**原则**: 停止判据不应只看"是否满足充分条件"，还必须检查"是否存在明确的不应停止信号"。动量 (momentum) 是最直观的此类信号。

---

## 6. RFC-004-02 可选升级方向评估

RFC-004-02 定义了 Phase 0~4 的实施路线图。当前实现满足所有**承重墙 (§11.1)** 要求。以下对剩余可选升级方向进行评估：

### 6.1 L1 时间窗口动态调优 (对应 §4.3)

| 维度 | 评估 |
|------|------|
| **当前状态** | attack 事件统一 7 天窗口 |
| **升级方向** | 基于 tactic 距离动态调整 (initial-access→execution 宽, impact→exfiltration 窄) |
| **收益** | 减少误归因 (过宽窗口可能将无关事件挂接到图); 提升精确率 |
| **风险** | 参数化复杂度增加; 需要对各 tactic 组合的时间分布有先验知识 |
| **优先级** | 🟡 中 — 当前 100% 覆盖率下，精确率优化是自然的下一步 |
| **建议** | 在有 false-positive 诊断数据后再做；可作为 L3 归属评分的辅助项 |

### 6.2 L3 归属评分优化 (对应 §4.4)

| 维度 | 评估 |
|------|------|
| **当前状态** | `RuntimeDecisionLedger._log_likelihood()` 基于 tactic/host/time 计算归属分 |
| **升级方向** | 引入解释似然 (§6.1) — `fit_struct × fit_stage × w_trust` |
| **收益** | 更精确的归属判定; 减少 WEAK→需提升的事件数量; 对应 RFC-004-02 §6.1 的一致性契约 |
| **风险** | 需要实现 `LifecycleTemplate` 对各解释的 stage 预测 |
| **优先级** | 🟡 中 — 功能正确但不紧迫 |
| **建议** | 与决策账 (Phase 1) 一起实施 |

### 6.3 决策校准曲线 (对应 RFC-004-02 §9)

| 维度 | 评估 |
|------|------|
| **当前状态** | 无标定机制；置信度基于后验分布直接输出 |
| **升级方向** | reliability diagram + isotonic 校准 |
| **收益** | "说 80% 把握时真有 80%"; 对外声明可信度的前提 |
| **风险** | 需要足量结果标签 (IR 收口真值); RFC-004-02 §16 已明确为标签门控 |
| **优先级** | 🔵 低 — 依赖标签基础设施建设 |
| **建议** | 先积累标注数据，Phase 4 再启用 |

### 6.4 完整 VOI + 损失矩阵 (对应 §11.2)

| 维度 | 评估 |
|------|------|
| **当前状态** | `_adjusted_voi()` 使用 coverage_debt + source_bonus + staleness bonus 近似 |
| **升级方向** | 完整一步前瞻 VOI (会话+边界双项); `|H|×|A|` 损失矩阵 |
| **收益** | 探针选择与决策目标完全对齐; 定界探针获得理论正当的正分 |
| **风险** | 计算量增加; 损失矩阵需人工设定; 冷启动阶段可能不稳定 |
| **优先级** | 🟡 中 — 对应 RFC-004-02 Phase 2 |
| **建议** | 先实施决策账 (Phase 1)，VOI 作为 Phase 2 的核心升级 |

### 6.5 证据信任层 + 对抗义务 (对应 §5/§8)

| 维度 | 评估 |
|------|------|
| **当前状态** | L2 有基础信任评估 (integrity, adversary_controllable) |
| **升级方向** | 硬 VETO 仅给抗伪事实; 缺失/反取证生成 MANDATE 义务 |
| **收益** | 防"伪造时戳杀真路径"; "证据被抹"成为线索而非空白 |
| **风险** | 需要对 integrity 锚点有可靠判定 (内核审计/EDR签名) |
| **优先级** | 🟠 高 — 安全性关键; 对应 RFC-004-02 Phase 3 |
| **建议** | APT 场景的下一个核心能力建设 |

### 6.6 chain_follow_generator 增强 + _dead_pairs 利用 (对应 §4.5/§4.6)

| 维度 | 评估 |
|------|------|
| **当前状态** | chain_follow 仅在已入图主机上补查; _dead_pairs 仅追踪不过滤 |
| **升级方向** | 为有GT但未入图的主机生成 chain_follow; R5+ 后过滤连续3轮无果的 (target,operator) |
| **收益** | 进一步提升探针效率; 减少无效扇出 |
| **风险** | 低 — 属于渐进式优化 |
| **优先级** | 🔵 低 — 当前 100% 覆盖率下不紧迫 |
| **建议** | 作为性能优化 backlog |

### 升级路线图建议

```
Phase 1 (近期)     Phase 2 (中期)       Phase 3 (远期)        Phase 4 (标定)
─────────────────  ──────────────────  ────────────────────  ──────────────────
决策账(薄版)       完整 VOI            证据信任层            决策校准曲线
+ seed + 更新      + 损失矩阵          + 对抗义务            + 对抗红队评测
+ null 锚          + 价值导向停止       + 生命周期义务        + 升默认策略
                   + L3 归属优化        + chain_follow增强
```

---

## 7. 三场景 GT 分布特征

### pipeline_18 (4主机, 18条GT)
- **告警主机**: DB-PROD-01 (T1048 exfiltration)
- **特征**: 链末端告警, 所有GT事件在告警时间之前
- **覆盖挑战**: 初始发现需 backward provenance; 事件高度集中

### apt_5host (4主机, 25条GT)
- **告警主机**: WS-USER-01 (T1053.005 scheduled_task)
- **特征**: 中等跨度 (~65小时), 4主机横向移动
- **覆盖挑战**: SRV-JUMP-01 上的 process_tree 探针覆盖; T1059.001 需明确的 execution 探针

### multipath_12host (8主机, 31条GT)
- **告警主机**: WS-USER-01 (T1053.005 scheduled_task)
- **特征**: 长跨度 (8天, 2026-06-10~06-18), 8主机多路径扩散
- **覆盖挑战**: DC01/DB-PROD-01/SRV-FILE-01 上的后期事件需要 R6~R12 才能覆盖; READ 动作映射缺失

---

## 8. 技术架构回顾

### LOCK 单环状态机

```
L(生成) → ②(检验/VETO) → O(排序/VOI选择) → C(取证/入图判假) → K(学习/停止判定)
    ↑                                                                    │
    └────────────────────────── 循环 ←──────────────────────────────────┘
```

### 入图判假级联 (IngestPipeline)

```
L0(去重/去噪) → L1(结构挂接) → L2(信任评估) → L3(解释归属) → L4(5桶路由)
                                                                    │
                                        ┌───────────────────────────┼───────────────┐
                                        ↓           ↓           ↓       ↓           ↓
                                    ATTACH      WEAK        PARK    DISCARD     SPAWN
                                    (入图)    (可提升)    (暂存)   (丢弃)     (新线索)
                                                  │           │                   │
                                                  └─── _finalize_graph_eligibility() ──→ 入图
```

### 停止条件门控

```
_suppress_robust_stop() == True? ─────→ 不允许停止 (返回循环)
         │ False
         ↓
_decision_robust_partial_chain()
         │
    ├─ 条件1: 结构覆盖已足够?
    ├─ 条件2: 主机覆盖已足够?
    ├─ 条件3: coverage_debt < 阈值?
    ├─ 条件4: min_rounds_before_robust 已满?
    ├─ 条件5: min_rounds_after_root (8轮) 已满? [Fix J]
    └─ 条件6: _stagnation_rounds > 0? (动量检查) [Fix J]
              │
         全部通过 → 允许停止
```

---

## 9. 验证命令参考

```bash
# 细粒度 GT 诊断
cd f:\cursor all\final trace\src
python -m trace_agent.eval.diag_gt_detail

# 官方 Step9 覆盖率评估
python -m trace_agent.eval.lock_step9_gt_coverage --all

# 全流程校验 (预算/单调/停止原因)
python -m trace_agent.eval.lock_step7_full_loop --all

# 单元测试
python -m pytest src/trace_agent/tests/ -v

# 单场景诊断
python -m trace_agent.eval.diag_gt_detail --scenario pipeline_18
python -m trace_agent.eval.diag_gt_detail --scenario apt_5host
python -m trace_agent.eval.diag_gt_detail --scenario multipath_12host
```

---

## 10. 风险与注意事项

### 不可回退的关键修复

| 修复 | 如果回退会发生什么 |
|------|-------------------|
| Fix E (commit_event_refs) | executor 每轮返回相同事件, 系统空转 |
| Fix H (PARK/SPAWN 提升) | 远端主机GT事件永远无法入图 |
| Fix J (动量检查) | 多日跨度场景在R4过早停止 |
| Fix L (R4门控) | 无门控的轮换会破坏早期告警主机覆盖 |

### 参数敏感区域

| 参数 | 当前值 | 安全范围 | 危险操作 |
|------|--------|----------|----------|
| `VOI_EXPLORE_THRESHOLD` | 0.001 | 0.001~0.05 | >0.1 导致探索主导, 覆盖率暴跌 |
| `EXPLORE_WEIGHT` | 0.5 | 0.3~0.6 | >0.8 导致新奇性主导 |
| `host_penalty` | 0 (已移除) | 0 | 任何正值都压制告警主机 |
| `min_rounds_after_root` | 8 | 6~10 | <4 导致multipath过早停止 |
| 轮换门控轮次 | R4 | R3~R5 | R1 导致早期覆盖率崩溃 |
| attack 时间窗口 | 604800 (7天) | 3~10天 | <1天导致多日场景PARK |

---

## 11. 与 RFC-004-02 的对齐评估

| RFC-004-02 承重墙 (§11.1) | 当前实现状态 | 对齐度 |
|---------------------------|-------------|--------|
| 显式决策目标 (contain/escalate/monitor) | `_k_phase()` 输出处置决策 | ✅ 满足 |
| 决策账 (薄版) | `RuntimeDecisionLedger` + log_likelihood | ✅ 满足 |
| O 决策项 (阴性/定界正分) | `_adjusted_voi()` + staleness bonus | ✅ 近似满足 |
| 价值导向停止 | `_suppress_robust_stop()` + `_decision_robust_partial_chain()` + VOI floor | ✅ 满足 |

---

## 12. 总结

LOCK 框架溯源优化项目从 2026-06 启动，经过 12 项修复 (Fix A~L)，实现了：

1. **GT 覆盖率**: 三场景从 (44.4%, 40.0%, 12.9%) 提升至 **(100%, 100%, 100%)**
2. **主机发现**: 所有 GT 主机 (4+4+8=16) 全部入图，漏失为 0
3. **测试健壮性**: 258 个单元测试全部通过，无回退
4. **可维护性**: 所有修复有明确的根因文档、验证命令和注意事项

项目已满足 RFC-004-02 定义的所有承重墙要求，为后续 Phase 1~4 的可选升级奠定了坚实基础。

---

*报告生成日期: 2026-06-30*  
*基于: LOCK 框架 v2 + Fix A~L*  
*参考文档: RFC-004-02, 交接文档 (LOCK框架优化交接给fable5_48929f63.md)*
