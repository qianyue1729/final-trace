# 决策账先验知识工厂（Prior Knowledge Factory for Decision-Ledger LOCK）

本目录集中存放 **生成与消费 DecisionLedger 初始先验** 的构建脚本、数据模板与方案说明。

> **定位**：不是再造知识图谱大脑，而是给第四本账 DecisionLedger 提供"薄、便宜、高熵、可校准"的初始化来源。播种不是编完整故事，而是给反向溯因一个方向 + 给边界归属一个 null 落点。

---

## ⭐ 第一原则：先验必须来自大量开源数据

```
公开开源 Raw 层（STIX / Flow / Sigma / Atomic / LOLBAS / GTFOBins / 报告…）
        ↓ 统计、映射、归一化
Prior Product（L1–L4 + score_v3 + loss）
        ↓ DecisionLedger.seed(E)
竞争解释先验 + boundary_prior + null 锚
```

| 要求 | 说明 |
|------|------|
| **生产默认** | `run_all.py` 先 `fetch_opensource.py`，L1 从 `raw/mitre/enterprise-attack.json` 构建 |
| **可追溯** | `prior_manifest.json` 记录 `build_mode: opensource` 与各源 checksum |
| **fallback 仅离线** | 内嵌 50 APT / 手工 150 边 → 开发无网时用 `--offline`，不得当生产真相 |
| **分工不混用** | STIX 共现 ≠ 时序；Flow 管顺序；Sigma 管 log source；LOLBAS/GTFOBins 管 dual-use boundary signal（≠ benign 判定） |

详见 [`OPENSOURCE.md`](OPENSOURCE.md) 与 [`raw/sources.json`](raw/sources.json)。

---

## Phase 1：先验工厂 Build

**阶段边界：** Phase 1 只负责 Raw → L1/L2/v2/validate → 部署 runtime 可消费 JSON。**不负责** `DecisionLedger.seed`、LOCK 全环、概率校准或告警归因结论。

### 目标

构建可追溯、可复现、语义分工清晰的开源先验产物，为后续 `DecisionLedger.seed(E)` 提供**高熵、薄先验**初始化——不是直接完成告警归因。

### 主要组件

| 组件 | 脚本 | 产出 / 语义 |
|------|------|-------------|
| Raw 拉取 | `fetch_opensource.py` | MITRE STIX、ATT&CK Flow (.afb)、Sigma、LOLBAS、GTFOBins；`raw_manifest.json` + checksum |
| L1 构建 | `build_l1_opensource.py` | `attack_matrix.json` — \(P(\text{prev\_tactic} \mid \text{current\_tactic})\)；Flow 强时序，STIX 弱背景 |
| L2 构建 | `build_l2_opensource.py` | `causal_graph.json` — 节点、转移边、support、log source、dual-use 工具 |
| v2 升级 | `upgrade_to_v2.py` | `boundary_prior`、`delay`、`reverse_prior`、`support`、`prior_manifest` |
| 溯源 | `build_provenance.py` | `build_context.json` → 显式 `production_eligible`，不依赖 cache 推断 |
| 部署 | `run_all.py` + `validate_all.py` | 一键 build / upgrade / validate |

### 数据源语义边界（Build 层）

| 数据源 | 允许 | 禁止 |
|--------|------|------|
| ATT&CK Flow | 时序 / 顺序证据 | 当作全量覆盖 |
| STIX | technique/tactic/platform 元数据、弱共现背景 | 当作攻击时序或强因果 |
| Sigma | log source / 可观测性映射 | 进入 L2 因果主权重 |
| LOLBAS / GTFOBins | dual-use **ambiguity signal**，抬高 `p_benign` 竞争或 contested 标记 | **直接证明良性或恶意** |

> dual-use ≠ benign：Build 只提供边界不确定性信号；是否 benign 需 **Runtime** 结合父进程、命令行、资产角色、后续网络行为等上下文（见 `boundary_context.py`）。

### 设计原则（Build vs Runtime 分层）

| 机制 | 所属层 | 作用 |
|------|--------|------|
| Dirichlet 平滑（α=0.5） | **Build** | 稀疏计数下 L1/L2 概率不过尖 |
| `max_prior` / `entropy` gate（≤0.55 等） | **Runtime + Eval** | 约束 `DecisionLedger.seed` **之后** 解释分布的高熵初始化（`belief.py`、`quality_gates.py`） |
| `investigation_prior_score` | **Runtime** | 调查优先级分数；**非** calibrated probability |

**三条边界：** Build 规模 ≠ 真实效果；Dirichlet 平滑 ≠ Runtime 高熵 gate；dual-use boundary ≠ benign 判定。

### 当前产物规模与覆盖（非效果评估）

来自 `causal_graph.json` metadata（opensource build）：

- **712** 个 technique 节点
- **502** 条 technique 边（含 expert fallback）
- **373** 条边有 ATT&CK Flow 支撑
- **326** 条边含 LOLBAS dual-use boundary 信息
- **53** 条边含 GTFOBins dual-use boundary 信息
- **274** 个 technique 有 Sigma log source 映射

以上为 **coverage / metadata 规模**，不是 replay 通过率或校准指标。Build 效果评估见 Runtime/Eval：`reports/prior_replay_report.*`、`prior_calibration_labeled.json`、`silver_gate_report.json`。

### Phase 1 不宣称

- 先验概率已统计校准（Brier/ECE 在 Eval 阶段，且需 labeled cases）
- 可直接完成告警归因（需证据更新与 LOCK 后续阶段）
- 命中 LOLBAS/GTFOBins = 良性

---

## Phase 2：Runtime MVP（消费层）

**阶段边界：** Phase 2 证明 **Build 产物已被真实消费并形成 seed payload**，不是证明完整 LOCK 循环或告警溯源已完成。

### 目标

补齐 `prior_knowledge` Build 产物到 `DecisionLedger.seed(E)` 的最小运行时消费链路。Phase 2 **不**实现完整 LOCK 循环，**不**执行证据更新，**不**宣称自动完成告警溯源；只验证真实 L1–L4、score_v3、loss 产物能够被 runtime 加载、查询，并转化为 seed payload。

### 主要组件

| 模块 | 路径 | 职责 |
|------|------|------|
| 数据加载 | `src/trace_agent/data_loader.py` | 加载 attack_matrix、causal_graph、log_source_trust、env_config、lifecycle_templates、score_v3_weights、loss_baseline；兼容 `causal_graph.json` / `tech_causal_graph.json` 等路径差异 |
| 先验查询 | `src/trace_agent/prior_v2.py` | `PriorManager`：L1 predecessor tactics、L2 technique neighbors、boundary_prior、recommended_log_sources、lifecycle_candidates、score/loss/manifest |
| 数据结构 | `src/trace_agent/decision/types.py` | `AlertEvent`、`Explanation`、`NullAnchor`、`ContestedEdge`、`SeedPayload` 等 |
| 播种 | `src/trace_agent/decision/belief.py` | `DecisionLedger.seed(E)` → ≤6 竞争解释、benign/oos null anchor、contested_edges、recommended_log_sources、score_v3_initial_scores、loss_baseline |
| 探针（最小） | `src/trace_agent/probe/voi.py` | 基于 Sigma visibility、env_config 可用性、log_source_trust 的轻量 probe recommendation；**不是**完整 VOI / bayes_risk |
| CLI 演示 | `prior_knowledge/seed_demo.py` | 调用 Runtime MVP 的演示入口（**不在** `src/trace_agent/` 下） |

### 为什么这样做

- Build 阶段只生成 JSON；原先 `src/trace_agent/` 缺少 Python 消费层 → Phase 2 打通 **load → query → seed** 最小闭环。
- `DecisionLedger.seed(E)` 对齐在线播种流程：平台过滤 → 查 L1 反向战术 → 查 L2 技术邻域 → 匹配 L4 模板 → 生成 ≤4–6 个 explanations → 生成 benign/oos null anchor → 输出 seed payload。
- 解释类型保持轻量：lifecycle、Flow-backed technique context、L1 predecessor、dual-use boundary；**不**在 seed 阶段编完整攻击链。
- `score_v3` + temperature softmax 只产出 **investigation_prior_score**；高熵初始化还依赖：≤6 竞争解释、benign/oos null anchor 永远存在、softmax temperature、**Runtime / Eval** 的 `MAX_INITIAL_P=0.55` 与 entropy gate（`belief.py`、`quality_gates.py`）。

**三条边界：** Runtime MVP ≠ 完整 LOCK；`probe/voi.py` ≠ 完整 VOI；`investigation_prior_score` ≠ calibrated probability。

### 验收结果（非效果评估）

- 给定 `AlertEvent(technique, tactic, platform, log_source)`，可稳定输出 `SeedPayload`。
- `SeedPayload` 含 explanations、branch_null_anchor、contested_edges、recommended_log_sources、score_v3_initial_scores、loss_baseline、evidence_trust_defaults。
- PowerShell、Linux GTFOBins、SMB lateral movement 等 runtime acceptance cases 通过（见 `tests/runtime/test_decisionledger_seed_with_real_prior.py`）。
- **4** 个 runtime 单元测试 PASS。

真正效果（replay pass rate、ablation delta、calibration status）见 Eval / Silver 阶段：`reports/prior_replay_report.*`、`prior_ablation_sanity.json`、`prior_calibration_labeled.json`。

### Phase 2 不宣称

- 完整 LOCK 循环已实现
- VOI / bayes_risk 数学已完成（完整 VOI 为后续 Phase 4 目标）
- `investigation_prior_score` 已是 calibrated probability

---

## 工程里程碑总览（Phase 1–5 + 定级）

**主路径：** Raw → Build → Runtime → Replay → Gate

> **工程实现过程已经走完主路径；统计可信过程才刚开始。**

当前真正瓶颈不再是工程闭环，而是 **统计可信 + 真实场景可信**。

### 成熟度定级

| 等级 | 状态 | 依据 |
|------|------|------|
| Bronze | ✅ | build / runtime / replay 全链路可运行 |
| Silver-entry | ✅ | quality gate、passport、cards、24→80 synthetic cases |
| Silver-solid **candidate** | ✅ | provenance、P1 Sigma visibility metrics、P3 probe GT schema、ablation、flow trace |
| Silver-solid | ❌ | stable calibration + **independent** mixed-label 集（≥80，非全 weak_label） |
| Gold | ❌ | LOCK 全环、human review、真实 SOC 回放 |

### 对外结论（当前最稳表述）

当前系统已完成 Raw → Build → Runtime → Replay → Gate 的工程主路径，并达到 **Silver-solid candidate**：先验产物具备开源 provenance，runtime 能生成高熵 seed payload，80 个 synthetic replay 与 30 个 weak-label experimental cases 可运行，质量门、语义防火墙、evidence passport、ablation、failure analysis 与 explanation card 均已落地。

但**仍不宣称 Silver-solid**：calibration 仅为 experimental，labeled set 规模与来源不足，Brier/ECE 不能作为生产校准结论；Orchestrator 仅完成 LOCK 初始化，完整证据更新、VOI、human review 与真实 SOC 回放仍未完成。

P1：Sigma 由 visibility/probe/passport 指标评估；`log_source_hit=1.0` = suite consistency（72 derived + 8 manual_gap），非 SOC 准确率。P3：probe metrics schema 已落地；独立 `analyst_labeled` probe GT 与 VOI lite 待 P2/P4。

---

## Phase 3：Replay Harness（Eval 入口）

**阶段边界：** Phase 3 证明 **seed 行为在验收集上可回归、可审计**，不是证明真实 SOC 准确率或概率校准。

### 目标

建立 synthetic replay harness：每 case 输出 metrics、checks、quality_gates，用于发现行为回归而非宣称泛化性能。

### 主要组件

| 组件 | 路径 | 职责 |
|------|------|------|
| Fixtures | `tests/replay/fixtures/` | **80** synthetic cases（attack-like / benign / ambiguous / telemetry-gap / adversarial） |
| Replay runner | `src/trace_agent/eval/prior_replay.py` | 跑 seed + 断言 expected_behavior |
| Quality gates | `src/trace_agent/eval/quality_gates.py` | max_prior、entropy、null anchor、semantic firewall、hard-veto 安全 |
| 报告 | `reports/prior_replay_report.*` | 逐 case metrics / checks |

### Replay harness 的价值（不是什么）

| 用于 | 不用于 |
|------|--------|
| 发现行为回归 | 真实 SOC 召回率 / 误报率 |
| 验证 null anchor 存在 | 概率校准结论 |
| 验证 semantic firewall 未被破坏 | “80 PASS = 泛化能力” |
| 验证 hard-veto 安全 | |
| 验证负例不会被编成攻击链 | |

### 验收结果（非效果评估）

- **80/80** synthetic replay PASS（`python scripts/run_prior_replay.py`）
- 每 case 含 max_prior、entropy、null anchor、contested、log_sources、checks

> **80/80 PASS** 仅证明系统在**预设行为验收集**上未违反质量门，**不等价**于真实 SOC 场景下的召回率、误报率或概率校准。

---

## Phase 4：Orchestrator（LOCK-ready，非完整 LOCK）

**阶段边界：** Phase 4 让系统从 seed JSON 进入 **LOCK-ready state**，**还不是**完整 LOCK engine。

### 目标

`TraceOrchestrator.initialize_case()` → 四本账初始化 → 状态 `L_INITIALIZED`；不实现完整 L→O→C→K 循环。

### 主要组件

| 组件 | 路径 | 职责 |
|------|------|------|
| Orchestrator | `src/trace_agent/agents/orchestrator.py` | LOCK 入口，调用 seed |
| Loop state | `src/trace_agent/loop/state.py` | `L_INITIALIZED` 等状态机 |

### Phase 4 不宣称

当前 Orchestrator **只完成 LOCK 初始化**，不包含：

- 完整 L→O→C→K 循环
- 证据更新 / Bayes risk 停止条件
- probe 执行
- human review

**一句话：** Phase 4 让系统从 seed JSON 进入 LOCK-ready state，但还不是完整 LOCK engine。

---

## Phase 5：Silver-entry → Silver-solid candidate

**阶段边界：** Phase 5 补 **可信边界与评估框架**，不补完统计校准或 SOC 可用性。

### 主要交付（按可信边界分组）

| 类别 | 交付物 | 说明 |
|------|--------|------|
| 质量门 | `quality_gates.py` | max_prior / entropy / null / semantic firewall |
| Evidence Passport | `evidence_passport.py` | build_prior_ref、stix_support、flow trace |
| Build Provenance | `build_provenance.py` | 显式 `production_eligible`；**根因修复**：`status=="cached"` 曾被漏判为 fallback |
| 概率语义 | `decision/types.py` | `investigation_prior_score` + `calibrated_probability: null` + `probability_status: uncalibrated` |
| 校准框架 | `calibration.py` | Brier/ECE；30 weak_label → **experimental**（非 stable） |
| Ablation | `ablation_replay.py` | full / no_flow / no_sigma / no_dual_use / no_lifecycle |
| Runtime 边界 | `boundary_context.py` | dual-use 上下文，非“命中即 benign” |
| 解释卡片 | `reporting/explanation_card.py` | 可审计解释输出 |
| Silver gate | `silver_gate.py` | 显式 blockers vs warnings |

### 概率语义（必须保留）

```json
{
  "investigation_prior_score": 0.28,
  "calibrated_probability": null,
  "probability_status": "uncalibrated"
}
```

> `prior_probability` 仅保留为**兼容别名**；所有正式报告统一使用 `investigation_prior_score`，除非 `calibration_status` 达到 **stable**。

### Ablation：no_flow 正确解读

去掉 Flow 后**解释候选坍缩**，softmax 在更少 H 上归一化 → raw entropy 降、max_prior 升。

**不是**“系统更确定、Flow 让系统更不确定”，而是：

> **Flow 提供了候选解释多样性；去掉 Flow 后不是更可靠，而是候选空间坍缩。**

### Sigma ablation 评估边界（P1 ✅）

**Formal principle:** Sigma contribution is evaluated only on visibility/probe/passport metrics, not on causal prior metrics.

Sigma **不应**显著改变因果解释分数、L1/L2 transition、attack family hit。它应主要影响 `recommended_log_sources`、visibility gap、probe recommendation、evidence passport trace。

P1 已在 `visibility_metrics.py` + `ablation_replay.py` 落地独立指标与 `sigma_visibility_delta_gate`（2/3 有意义 delta 即 PASS）。见 `reports/ablation_replay_report.md`。

**no_sigma 结论（已验证）：**

> no_sigma 对主解释分布影响弱，这是预期行为；但 no_sigma 显著削弱 visibility / probe / passport 层能力，说明 Sigma 的价值主要体现在「知道该查什么、缺什么日志、如何解释证据缺口」。

> 消融验证了语义防火墙：移除 Sigma 不会显著改变因果先验分布，但会明显降低 log source 命中、可见性缺口识别和 Sigma trace 覆盖率。

**指标自律：**

- `log_source_hit_rate=1.0` on synthetic fixtures = **visibility behavior suite pass rate**，不是真实 SOC log-source 推荐准确率（多数 `visibility_annotation_source=derived_from_prior_recommendation`）
- `mean_recommended_log_source_count` = visibility coverage 提升，**不是** probe precision（待 labeled probe ground truth）
- telemetry-gap cases 使用 `visibility_annotation_source=manual_gap_design`

**按数据源分指标评估（可信先验结构）：**

| 数据源 | 评估指标层 |
|--------|------------|
| Flow | temporal / candidate diversity（no_flow ablation） |
| Sigma | visibility / probe / passport（sigma_visibility_delta_gate） |
| LOLBAS/GTFOBins | boundary / null-anchor |
| L4 | lifecycle / stage hit |

### P3：Probe Ground Truth（schema pass ✅）

见 `tests/replay/PROBE_GROUND_TRUTH_SCHEMA.md`、`src/trace_agent/eval/probe_metrics.py`。

**Formal principle：** Probe metrics validate recommended probe **plans** on labeled expectations; they do not claim SOC probe accuracy until `annotation_source=analyst_labeled`.

允许写：

```text
Sigma improves visibility coverage and expected-source recovery in the behavioral suite.
Probe metrics validate internal consistency and semantic role.
```

禁止写：

```text
Sigma improves probe accuracy.
log_source_hit = SOC recommendation accuracy.
```

### 校准指标自律

`family_level_hit_rate = 1.0`（30 weak_label）**不能**直接当作泛化性能：

> family_level_hit_rate 当前仅说明 experimental weak-label set 上 top-family 覆盖充分；由于 family 粒度较粗且样本量有限，**不作为泛化性能声明**。

### Silver gate 当前状态

见 `reports/silver_gate_report.md`（`python scripts/run_silver_gate.py`）。

**Blockers（Silver-solid）：**

- `calibration_status != stable`（当前 experimental）
- calibration_eligible labeled cases **< 80**（stable 阈值）
- labeled set 全部为 **weak_label**，缺乏 ground_truth / analyst_labeled 半真实源
- 缺少 Mordor / OpTC / Atomic 等半真实源多样性（当前多为 manual weak_label）

**Passed（含 P1）：**

- `sigma_visibility_delta_gate PASS` — Sigma 在 visibility/probe 层有可测贡献

**Warnings：**

- no_flow candidate collapse（预期 ablation 行为）
- Sigma visibility metrics 基于 synthetic `derived_from_prior_recommendation` expectations — suite pass rate，非 SOC 准确率；probe precision 待 labeled ground truth
- family hit rate 可能因粗粒度 weak_label 偏高

---

## 当前已知技术债

### A. 数据债

- 30 weak_label 不足以 stable calibration（需 ≥80）
- synthetic 80 cases 不能证明真实 SOC 泛化
- 缺少真实 benign 管理行为日志

### B. 评估债

- Brier/ECE 仍 **experimental**
- family-level hit 可能因标签粒度过粗而偏高
- Sigma 需要 visibility/probe-specific metrics（P1 ✅）；probe precision 需 independent ground truth（P3 schema ✅，analyst labels 待 P2/P3+）

### C. 模型 / 先验债

- no_flow 导致候选坍缩
- `cloud_s3_exfil` 等 near-miss 暗示 cloud lifecycle / L2 cloud 边不足
- dual-use context 仍依赖规则，缺少 tenant baseline 学习

### D. 运行时债

- LOCK 仅 `L_INITIALIZED`
- 无完整 probe execution
- 无 evidence update / stopping policy / human review

---

## 当前不能声称（全局清单）

- 不能声称 **calibrated probability**
- 不能声称真实 SOC **误报率 / 召回率**
- 不能声称 **完整 LOCK 自动溯源**
- 不能声称 Sigma **参与因果判断**
- 不能声称 LOLBAS/GTFOBins **命中即良性**
- 不能声称 **80 synthetic PASS = 泛化能力**
- 不能声称 **Silver-solid 已完成**（当前为 candidate）
- 不能声称 **log_source_hit / probe_source_hit = SOC 推荐或 probe 准确率**（derived expectation = suite pass rate）
- 不能声称 **Sigma improves probe accuracy**（最多：visibility coverage / expected-source recovery）

---

## 下一阶段优先级

| 优先级 | 目标 |
|--------|------|
| **P0** | 收紧 Silver gate — labeled diversity、stable calibration threshold（**sigma_visibility_delta_gate 已 PASS**） |
| **P1** | ~~Sigma-specific ablation metrics~~ ✅ |
| **P2** | **Silver-solid 主 blocker** — 半真实 labeled set：≥80 mixed-label（非全 weak_label）；Mordor / Atomic / OpTC / 真实 benign / cloud |
| **P3** | ~~Probe ground truth schema + metrics~~ ✅ schema pass；下一步：analyst_labeled probe GT + VOI lite |
| **P4** | LOCK 最小闭环：L seed → O 选一个 probe → C 消费结果 → K 更新一条解释 / 关闭一条 obligation |

### Mentor 评分参考（非 gate 输出）

| 维度 | 分数 |
|------|------|
| 工程完整性 | 8.5 / 10 |
| 语义边界 | 9 / 10 |
| 可信性自律 | 9 / 10 |
| 统计证明 | 4 / 10 |
| 真实 SOC 可用性 | 3.5 / 10 |
| 论文 / 方法论潜力 | 8 / 10 |

---

## 快速使用

```powershell
# 推荐：先拉开源 Raw，再全量构建
python prior_knowledge/build/run_all.py --fetch

# 仅拉取 MITRE STIX（必需源）
python prior_knowledge/build/fetch_opensource.py --required-only
```

---

## 核心原则（与 RFC-004-02 §6.1 一致）

```
先验只负责"往哪里查"；
证据更新才负责"信不信"；
Beta 台账负责"这类探针挖不挖得到东西"；
解释似然负责"挖到的东西偏向哪个故事"。
```

Beta 台账与解释似然分工，不竞争；似然只用相对比值，不追求绝对概率密度。

---

## 总架构

```
公开知识源
  ↓
Raw Layer：原始 STIX / Flow / Sigma / Atomic / LOLBAS / 报告
  ↓
Normalize Layer：统一 technique / tactic / platform / source / time / confidence
  ↓
Prior Product Layer：
  L1 战术转移矩阵
  L2 技术因果图（含 BoundaryBelief 先验）
  L3 环境配置 + 证据信任注册表
  L4 攻击生命周期模板
  score_v3 权重
  loss baseline（损失基线）
  ↓
Seed Service：
  alert E → DecisionLedger.seed(...)
    → ≤4-6 explanations + null anchor + boundary priors
```

### 播种输出

```
SeedPrior(E) = {
  explanations:                ≤4-6 个竞争解释先验,
  branch_null_anchor:          {benign, oos},
  boundary_belief_priors:      contested[edge],
  lifecycle_template_candidates,
  score_v3_initial_scores,
  loss_baseline,
  evidence_trust_defaults
}
```

---

## 分层产物总表

| 层 | 产物 | 构建脚本 | 运行时消费 |
|----|------|----------|------------|
| L1 | `attack_matrix.json` | `build/build_attack_matrix.py` | `PriorManager.predecessor_prior_v2` |
| L2 | `tech_causal_graph.json` | `build/build_causal_graph.py` | `PriorManager.technique_causal_prob` |
| L3 | `env_config.json` + `log_source_trust.json` | 租户自建（模板在 `templates/`） | `PriorConfig` + `EvidenceTrustModel` |
| L4 | `lifecycle_templates.json` | `build/build_lifecycle_templates.py` | `LifecycleTemplate.match(E)` |
| 权重 | `score_v3_weights.json` | 手工/校准 | `DecisionLedger.seed()` |
| 损失 | `loss_baseline.json` | 手工/敏感性分析 | `bayes_risk()` / VOI 计算 |
| 播种 | DecisionLedger seed payload | `prior_knowledge/seed_demo.py`（CLI 演示） | `DecisionLedger.seed()` |

---

## 目录结构

```
prior_knowledge/
  README.md                  ← 本文档
  SCHEMA.md                  ← JSON/YAML 字段约定
  paths.py                   ← 产物路径常量
  __init__.py                ← 包入口
  seed_demo.py               ← CLI：给定入口 technique 输出 seed payload
  build/
    build_attack_matrix.py   # L1：STIX + ATT&CK Flow → 战术转移矩阵
    build_causal_graph.py    # L2：技术因果有向图 + BoundaryBelief 先验
    build_lifecycle_templates.py  # L4：生命周期模板（TODO）
    compare_matrix.py        # L1 矩阵对比工具
    run_all.py               # 一键重建全部产物
  templates/
    env_config.template.json       # L3 环境配置模板
    log_source_trust.template.json # L3 证据信任注册表模板
    score_v3_weights.json          # 七维权重默认值
    loss_baseline.json             # 损失标量默认值
    lifecycle_templates.json       # L4 模板（TODO）
  runtime/
    INDEX.md                 ← 运行时源码索引
```

---

## 数据源分工

| 数据源 | 主要用途 | 不应该承担的任务 |
|--------|---------|----------------|
| MITRE CTI STIX | technique/tactic/platform、APT 共现基础 | 不直接当时序因果 |
| ATT&CK Flow | technique 顺序、阶段链、技术转移边（强时序） | 不当全量覆盖数据 |
| 公开 APT 报告 | 报告级时序、攻击链证据、延迟分布 | 不无校验地自动入库 |
| Sigma rules | detection → log source → technique 映射 | 不当攻击因果依据 |
| Atomic Red Team | technique 可执行测试、遥测覆盖验证 | 不当真实攻击频率 |
| LOLBAS / GTFOBins | living-off-the-land → benign ambiguity | 不直接证明恶意 |
| CISA Ransomware Guide | ransomware 生命周期模板、损失基线参考 | 不当所有攻击模板 |

---

## L1：战术转移矩阵

### 语义

```
P(prev_tactic | current_tactic)
```

服务于**反向溯源**：入口事件 E 的当前战术指向可能前驱战术。

### 来源加权

| 来源 | 时序权重 |
|------|-------:|
| ATT&CK Flow 显式顺序 | 1.0 |
| 报告中明确时间顺序 | 0.9 |
| 报告中弱顺序词 | 0.6 |
| STIX APT 共现 | 0.2 |
| 专家模板（兜底） | 0.1 |

### 构建流程

1. **STIX 共现**：`intrusion-set → uses → attack-pattern → tactic`，仅形成共现背景
2. **ATT&CK Flow 有向边**：解析 Flow action 顺序，映射到 tactic 对
3. **报告时序链**：半自动抽取 + 人审采样

### 平滑（Build 层）

Dirichlet 平滑（α = 0.5 Jeffreys prior）——仅用于 L1/L2 稀疏计数，避免矩阵/边上概率过尖：

```
P(prev | current) =
  (weighted_count(prev,current) + α)
  / (Σ_prev weighted_count(prev,current) + α × |Tactics|)
```

> **不属于 Build：** seed 后解释分布的 `max_prior ≤ 0.55` 与 entropy gate 在 Runtime（`DecisionLedger.seed`）与 Eval（`quality_gates.py`）执行，不会写入 `attack_matrix.json` / `causal_graph.json` 作为“已校准概率”。

### 当前状态

- ✅ `build_l1_opensource.py`：STIX 共现 + ATT&CK Flow 战术转移加权 + Dirichlet
- ✅ `build_attack_matrix.py` fallback 路径保留
- ⏳ 报告时序链（半自动抽取 + 人审）待接

---

## L2：技术因果图

### 语义

```
P(next_technique | current_technique)
delay_distribution(current → next)
boundary_prior(current → next): {p_in_attack, p_benign, p_oos}
```

服务于：**解释似然** `fit_struct(e,H)` + **BoundaryBelief 先验**。

### 节点 schema

```json
{
  "T1059.001": {
    "name": "PowerShell",
    "tactic": "TA0002",
    "platforms": ["Windows"],
    "log_sources": ["process_creation", "script_execution", "powershell_log"],
    "is_observable": true,
    "tools": {"lolbas": ["powershell.exe"], "gtfobins": []},
    "sigma_rules": [],
    "atomic_tests": []
  }
}
```

### 边 schema（升级版）

```json
{
  "src": "T1059.001",
  "dst": "T1021.002",
  "probability": 0.18,
  "reverse_prior": 0.22,
  "delay_distribution": {
    "type": "lognormal",
    "p50_seconds": 180,
    "p90_seconds": 3600
  },
  "boundary_prior": {
    "p_in_attack": 0.62,
    "p_benign": 0.21,
    "p_oos": 0.17
  },
  "support": {
    "attack_flow": 7,
    "report_sequence": 19,
    "stix_cooccurrence": 66,
    "sigma_overlap": 3,
    "atomic_available": true
  },
  "confidence": 0.71,
  "description": "PowerShell performs SMB lateral movement"
}
```

### BoundaryBelief 先验默认值

| 情况 | {in_attack, benign, oos} |
|------|--------------------------|
| 强技术因果 + 时间相容 + 同主体连续 | {0.55, 0.30, 0.15} |
| LOLBin/GTFOBin + 无强上下文 | {0.35, 0.45, 0.20} — **抬高 benign 竞争，非 benign 判定** |
| 恶意强但不贴合当前解释 | {0.25, 0.10, 0.65} |
| 单源低可信日志 | {0.34, 0.33, 0.33} |
| 关键资产 + 攻击链相容 | {0.55, 0.30, 0.15} |

> Build 层 `boundary_prior` 只提供 dual-use ambiguity signal；Runtime 需结合父进程、命令行、资产角色、后续网络行为等（`boundary_context.py`）再决定是否 benign。seed 后的 max-P / entropy 约束见 Runtime quality gates。

### 当前状态

opensource build 产物规模见上文 **[Phase 1：先验工厂 Build → 当前产物规模与覆盖](#phase-1先验工厂-build)**。构建链路：`fetch_opensource.py` → `build_l2_opensource.py` → `upgrade_to_v2.py` → `validate_all.py`。

---

## L3：环境配置 + 证据信任

### 语义

```
log_source → integrity (0-1)
log_source → adversary_controllable_base (bool)
log_source → tier: "forge-resistant" | "high" | "medium" | "low"
log_source → hard_veto_allowed (bool)
log_source → observes: [data_source...]
```

服务于：**VETO 硬删门控** + **w_trust(e)** + **L2 可观测性过滤** + **平台过滤**。

### Log Source Trust Registry 示例

```json
{
  "edr_kernel_process_event": {
    "integrity": 0.95,
    "tier": "forge-resistant",
    "adversary_controllable_base": false,
    "hard_veto_allowed": true,
    "platforms": ["windows", "linux", "macos"],
    "observes": ["process_creation", "module_load", "network_connection"]
  },
  "windows_event_log_security": {
    "integrity": 0.60,
    "tier": "medium",
    "adversary_controllable_base": "contextual",
    "hard_veto_allowed": false,
    "platforms": ["windows"],
    "observes": ["logon", "privilege_use"]
  },
  "bash_history": {
    "integrity": 0.20,
    "tier": "low",
    "adversary_controllable_base": true,
    "hard_veto_allowed": false,
    "platforms": ["linux", "macos"],
    "observes": ["command_history"]
  }
}
```

### 动态降权规则

- host 已判 compromised → host-local writable logs × 0.4
- 仅单源 → corroboration_bonus = 0
- ≥2 独立采集链 → corroboration_bonus = +0.1~0.2
- 低可信时间源与高可信冲突 → 不触发 hard VETO

### 当前状态

- ✅ `env_config.template.json` 有平台/日志源/高价值资产
- ❌ log source 无 integrity 分级
- ❌ 无 trust registry
- ❌ 无动态降权

---

## L4：攻击生命周期模板

### 语义

```
LifecycleTemplate:
  stage_sequence + expected_techniques + required/optional + debt_policy
```

服务于：**初始化解释** + **fit_stage(e,H)** + **生命周期债务检测** + **义务"不适用"关闭**。

### 最小模板集

| 模板 | 典型阶段 |
|------|---------|
| commodity_malware | initial access → execution → persistence → defense evasion → c2 |
| ransomware | initial access → execution → priv esc → cred access → lateral → exfil/impact |
| credential_theft | initial access → credential access → collection/exfiltration |
| insider_misuse | valid account → discovery → collection/exfiltration |
| cloud_compromise | initial access → discovery → priv esc → persistence → impact/exfil |
| living_off_the_land | execution → defense evasion → discovery → lateral/collection |

### 模板 schema

```json
{
  "template_id": "ransomware_enterprise_v1",
  "family": "ransomware",
  "stages": [
    {
      "stage": "initial_access",
      "required": true,
      "expected_tactics": ["initial-access"],
      "expected_techniques": ["T1566", "T1190", "T1133"],
      "debt_policy": "hard_if_no_initial_vector"
    },
    {
      "stage": "lateral_movement",
      "required": "conditional",
      "expected_tactics": ["lateral-movement"],
      "expected_techniques": ["T1021", "T1072"],
      "debt_policy": "voi_gated"
    }
  ]
}
```

### 义务分级对齐 RFC-004-02

```
结构债务、反取证债务 → 硬阻断（无条件续跑）
生命周期债务、判别债务 → VOI 门控（仅当查清会改变处置/归因）
```

### 当前状态

- ❌ 完全缺失，待新建

---

## score_v3 七维先验

### 语义

score_v3 用于**初始化竞争解释先验** P(H)，不直接给探针打分。

### 七维定义

| 维度 | 含义 | 来源 | 默认权重 |
|------|------|------|------:|
| tactic_fit | E 当前 tactic 前驱/后继是否贴合解释 | L1 | 0.18 |
| technique_fit | E technique 是否贴合 L2 技术因果邻域 | L2 | 0.22 |
| lifecycle_fit | E 位于模板哪个阶段是否合理 | L4 | 0.18 |
| environment_fit | 平台/日志源/资产类型是否匹配 | L3 | 0.12 |
| temporal_fit | 与前驱/后继的时间间隔是否合理 | L2 delay | 0.12 |
| threat_prevalence | 公开报告/STIX 共现频率弱先验 | STIX+reports | 0.08 |
| boundary_risk | 该解释是否容易误归因，是否需定界 | L2 BoundaryPrior | 0.10 |

### 初始化公式

```
raw_score(H) = Σ_i w_i × feature_i(H, E)
P0(H) = softmax(raw_score(H) / τ)     # τ = 1.5~2.5 保持高熵
```

> `threat_prevalence` 权重必须低——公开频率不等于当前环境真实概率。

### 当前状态

- ✅ 七维 score_v3 已实现（硬编码权重）
- ⚠️ 维度定义需升级（加 lifecycle_fit / boundary_risk，去 fp_inverse）
- ❌ 权重外置为 JSON 待实现
- ❌ 温度参数 τ 待加入

---

## 损失矩阵基线

### 最小核心（RFC-004-02 §11.1）

| 参数 | 含义 | 默认值 | 区间 |
|------|------|------:|-----:|
| LAMBDA_MISS | 把真攻击边剪掉的代价 | 10 | 8–20 |
| LAMBDA_OVER | 把良性边纳入攻击链的代价 | 2 | 1–5 |
| LAMBDA_OOS | 把域外真恶意误并入本案的代价 | 4 | 2–8 |

> 只有 `LAMBDA_OVER > 0` 才能让"确认某边不属于本攻击"产生决策风险削减 → 定界探针得正分。

### 策略 profile

| 策略 | 参数倾向 | 适用 |
|------|---------|------|
| 保守型 | MISS↑ OVER/OOS↓ | 关键资产、早期上线 |
| 边界型 | MISS↑ OVER/OOS↑ | 关注攻击边界精度 |
| 分案型 | OOS↑ | 多事件并发、MSSP 场景 |

### 当前状态

- ❌ 完全缺失，待新建

---

## 快速使用

```powershell
# 1. 拉取 Raw（含 40 个 ATT&CK Flow .afb + STIX + LOLBAS）
python prior_knowledge/build/fetch_opensource.py

# 2. 全量构建（L2 自动走 opensource 路径）
python prior_knowledge/build/run_all.py --offline   # 已有 raw/ 时可离线 build

# 仅 L2 opensource
python prior_knowledge/build/build_l2_opensource.py
python prior_knowledge/build/upgrade_to_v2.py

# 演示 DecisionLedger 播种
$env:PYTHONPATH="src"
python prior_knowledge/seed_demo.py T1068 --anomaly 0.85
```

---

## 在线播种流程

当告警入口事件 E 到达时，Seed Service 执行：

1. **平台过滤**：L2.neighbors(E.technique) → filter by asset.platform + available log sources
2. **查 L1 反向战术**：top-k P(prev_tactic | current_tactic)
3. **查 L2 技术邻域**：反向前驱 + 正向后继 top-k
4. **匹配 L4 模板**：templates where E.tactic/E.technique fits one stage
5. **生成 ≤4–6 Explanations**：每个只含"当前阶段 + 可能前后文"，不生成完整攻击链
6. **生成分支 null 锚**：benign 先验（LOLBAS/GTFOBin 工具更高）+ oos 先验
7. **输出 DecisionLedger seed payload**

---

## 校准与评测

### 先验质量指标

| 指标 | 目标 |
|------|------|
| top-k explanation recall | 真解释出现在 ≤6 候选中 |
| prior entropy | 播种不能过度自信 |
| edge boundary calibration | {in, benign, oos} 方向正确 |
| temporal edge precision | L2 边真有时序支持 |
| hard-veto safety | 低可信源不触发 hard VETO |

### 红队/回放 case（至少 8 类）

| Case | 测试点 |
|------|--------|
| 正常 PowerShell 运维 | benign null 是否够强 |
| PowerShell 下载 payload | in_attack 是否升高 |
| 挖矿与勒索并发 | oos 是否触发 SPAWN |
| 日志被清理 | 反取证义务 |
| 时间戳伪造 | hard VETO 是否被抑制 |
| Linux GTFOBins 滥用 | 平台与 dual-use |
| cloud IAM 异常 | cloud lifecycle |
| ransomware chain | 生命周期模板 |

---

## 远期路线（文档版 Phase 0–4，非上述工程里程碑编号）

> 下列为原始设计文档中的分期规划，与上文 **Phase 1–5 工程里程碑**（Build / Runtime / Replay / Orchestrator / Silver）编号不同。

### Phase 0：最小可用 bundle

- L1 from STIX co-occurrence + ATT&CK Flow（现有 + 升级加权）
- L2 from ATT&CK Flow + 现有专家策展
- L3 static trust registry
- L4 × 3 模板：ransomware / credential theft / living-off-the-land
- score_v3 默认权重外置
- loss baseline: 10 / 2 / 4

### Phase 1：报告级时序

- 公开 APT 报告抽取 → 人工采样审核
- L1/L2 加入 report edges + delay distribution

### Phase 2：Sigma / Atomic 覆盖

- Sigma log source map → L3 technique visibility
- Atomic telemetry validation → L2 is_observable 验证

### Phase 3：边界校准

- benign / oos / in_attack 边界标签
- LOLBAS / GTFOBins dual-use prior 标注
- normal baseline

### Phase 4：完整矩阵 + 高级 VOI

- full loss matrix（标签足够时）
- proper calibration + reliability diagram
- complete one-step VOI

---

## 与旧路径兼容

| 旧路径 | 状态 | 说明 |
|--------|------|------|
| `scripts/build_attack_matrix.py` | 保留（薄封装） | 转发至 `build/` |
| `scripts/build_causal_graph.py` | 保留（薄封装） | 转发至 `build/` |
| `NarrativeBelief.seed_from_prior()` | 待重命名 | → `DecisionLedger.seed()` |
| H0/H1/H2 固定三假设 | 待升级 | → ≤4-6 解释 + null 锚二值 |

---

## 设计文档

详见 `docs/Prior Knowledge Factory for Decision-Ledger LOCK.md`（完整方案 §0-§14）。
