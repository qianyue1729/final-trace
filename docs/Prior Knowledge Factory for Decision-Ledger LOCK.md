下面给你一套可以直接并入 RFC-004-02 的  **“先验知识搭建方案”** 。它的定位不是再造一个知识图谱大脑，而是给第四本账 **DecisionLedger** 提供一个“薄、便宜、高熵、可校准”的初始化来源。RFC-004-02 本身要求播种不是编完整故事，而是在告警 E 到达时给反向溯因一个方向，并给边界归属一个 null 落点；同时决策账保持少数竞争解释，并用 `contested[edge]` 承载 `{in_attack, benign, oos}` 边粒度信念。

---

# 0. 总体目标

这套先验知识系统要在告警入口事件 **E** 到达时，输出：

```text
SeedPrior(E) =
  {
    explanations: ≤4-6 个竞争解释先验,
    branch_null_anchor: {benign, oos},
    boundary_belief_priors: contested[edge],
    lifecycle_template_candidates,
    score_v3_initial_scores,
    loss_baseline,
    evidence_trust_defaults
  }
```

它只做  **初始化** ，不做最终判断。

最重要的原则：

```text
先验只负责“往哪里查”；
证据更新才负责“信不信”；
Beta 台账负责“这类探针挖不挖得到东西”；
解释似然负责“挖到的东西偏向哪个故事”。
```

这一点必须和 RFC-004-02 的 §6.1 保持一致：Beta 台账与解释似然分工，不竞争；似然只用相对比值，不追求绝对概率密度。

---

# 1. 总架构：Prior Knowledge Factory

建议把先验知识搭建成一个离线工厂 + 一个在线播种服务。

```text
公开知识源
  ↓
Raw Layer：原始 STIX / Flow / Sigma / Atomic / LOLBAS / 报告
  ↓
Normalize Layer：统一 technique / tactic / platform / source / time / confidence
  ↓
Prior Product Layer：
  L1 战术转移矩阵
  L2 技术因果图
  L3 环境配置
  L4 生命周期模板
  score_v3 权重
  loss baseline
  ↓
Seed Service：
  alert E → ≤4-6 explanations + null anchor + boundary priors
```

官方 ATT&CK STIX 可以通过 MITRE 的 ATT&CK TAXII 2.1 server 获取；ATT&CK Flow 则是描述攻击者如何组合、排序 ATT&CK techniques 的语言，因此更适合补足 STIX 本身缺失的时序语义。([MITRE ATT&amp;CK](https://attack.mitre.org/resources/attack-data-and-tools/ "ATT&amp;CK Data &amp; Tools | MITRE ATT&amp;CK®"))

---

# 2. 数据源分工

不要把所有数据源都混着用。每个数据源只承担它最擅长的任务。

| 数据源                | 主要用途                                                            | 不应该承担的任务   |
| --------------------- | ------------------------------------------------------------------- | ------------------ |
| MITRE CTI STIX        | technique、tactic、platform、APT 使用 technique 的共现基础          | 不直接当时序因果   |
| ATT&CK Flow           | technique 顺序、阶段链、技术转移边                                  | 不当全量覆盖数据   |
| 公开 APT 报告         | 报告级时序、攻击链证据、延迟分布                                    | 不无校验地自动入库 |
| Sigma rules           | detection → log source → technique 映射                           | 不当攻击因果依据   |
| Atomic Red Team       | technique 可执行测试、遥测覆盖验证                                  | 不当真实攻击频率   |
| LOLBAS / GTFOBins     | living-off-the-land 工具 → technique / platform / benign ambiguity | 不直接证明恶意     |
| CISA Ransomware Guide | ransomware 生命周期模板、响应阶段、损失基线参考                     | 不当所有攻击模板   |

Sigma 主规则库提供大量检测规则，可用于提取 log source、detection 字段和 ATT&CK tag；Atomic Red Team 是映射到 MITRE ATT&CK 的测试库，可用来验证某 technique 在本环境中是否能产生日志；LOLBAS 和 GTFOBins 分别覆盖 Windows 与 Unix-like 场景下可被滥用的合法工具，非常适合构造 benign/oos 边界先验；CISA 的 StopRansomware Guide 可作为 ransomware 生命周期模板和响应损失基线的参考。([GitHub](https://github.com/sigmahq/sigma "GitHub - SigmaHQ/sigma: Main Sigma Rule Repository · GitHub"))

---

# 3. L1：战术转移矩阵

## 3.1 目标

构建：

```text
L1_TacticTransition:
P(prev_tactic | current_tactic, platform, attack_family, source_confidence)
```

它服务于  **反向溯源** 。

例如入口事件 E 是：

```text
current_tactic = Lateral Movement
```

L1 应该告诉系统：

```text
可能前驱：
Credential Access
Discovery
Defense Evasion
Persistence
Initial Access
```

但这只是先验方向，不是结论。

---

## 3.2 为什么不能只用 MITRE STIX 共现

MITRE STIX 里 APT → technique → tactic 的关系主要说明“某组织使用过哪些技术”，但 APT 的 technique 集合本身不等于时间序列。

所以：

```text
APT uses {T1, T2, T3}
≠
T1 → T2 → T3
```

正确做法是：

| 来源                      | 用法                   |
| ------------------------- | ---------------------- |
| STIX APT-technique-tactic | 共现弱证据，只用于平滑 |
| ATT&CK Flow               | 强时序证据             |
| 报告级事件链              | 强时序证据             |
| 专家模板                  | 只作兜底，不作主来源   |

ATT&CK Flow 明确用于表示攻击者如何组合和排序 techniques，因此它应该比 STIX 共现有更高的时序权重。([GitHub](https://github.com/center-for-threat-informed-defense/attack-flow "GitHub - center-for-threat-informed-defense/attack-flow: Attack Flow helps executives, SOC managers, and defenders easily understand how attackers compose ATT&amp;CK techniques into attacks by developing a representation of attack flows, modeling attack flows for a small corpus of incidents, and creating visualization tools to display attack flows. · GitHub"))

---

## 3.3 构建流程

### Step 1：从 STIX 抽取共现

抽取：

```text
intrusion-set / campaign
  → uses
  → attack-pattern technique
  → kill_chain_phases.tactic
```

得到：

```text
Group G used tactic set = {TA0001, TA0002, TA0005, ...}
```

这一步只形成共现背景。

---

### Step 2：从 ATT&CK Flow 抽取有向边

解析 Flow 中的 action 顺序：

```text
technique_i → technique_j
```

映射到 tactic：

```text
tactic(technique_i) → tactic(technique_j)
```

因为引擎做反向溯源，所以最终存：

```text
P(prev_tactic = tactic_i | current_tactic = tactic_j)
```

---

### Step 3：从公开报告抽取时序链

报告级抽取要保守，建议用半自动流程：

```text
报告文本
  → 事件句子抽取
  → technique 标注
  → 时间/顺序词识别
  → 人审采样
  → 入库
```

可识别的顺序词：

```text
after / before / then / subsequently / followed by / later /
initially / once / using X to / via / dropped / launched / connected to
```

每条边必须保留：

```json
{
  "src_technique": "T1059",
  "dst_technique": "T1021",
  "src_tactic": "Execution",
  "dst_tactic": "Lateral Movement",
  "source_type": "report",
  "source_id": "report_sha256",
  "evidence_span": "...",
  "direction_confidence": 0.72
}
```

---

## 3.4 加权规则

建议权重：

| 来源                 | 时序权重 |
| -------------------- | -------: |
| ATT&CK Flow 显式顺序 |      1.0 |
| 报告中明确时间顺序   |      0.9 |
| 报告中弱顺序词       |      0.6 |
| STIX APT 共现        |      0.2 |
| 专家模板             |      0.1 |

最终：

```text
count(prev, current) =
  Σ source_weight × confidence × recency_weight
```

再做 Dirichlet 平滑：

```text
P(prev | current) =
  (count(prev,current) + α)
  / (Σ_prev count(prev,current) + α × |Tactics|)
```

---

## 3.5 L1 输出 schema

```yaml
l1_tactic_transition:
  version: "2026.06"
  domain: "enterprise"
  matrix:
    - current_tactic: "lateral-movement"
      prev_tactic: "credential-access"
      probability: 0.31
      log_odds: 1.24
      support:
        attack_flow_edges: 18
        report_edges: 42
        stix_cooccurrence: 133
      confidence: 0.78
      notes: "Temporal evidence dominated by Attack Flow and report-level chains."
```

---

# 4. L2：技术因果图

## 4.1 目标

构建：

```text
L2_TechniqueCausalGraph:
P(next_technique | current_technique)
delay_distribution(current → next)
boundary_prior(current → next): {p_in_attack, p_benign, p_oos}
```

它给两类模块用：

1. **解释似然** ：`fit_struct(e,H)`；
2. **BoundaryBelief 先验** ：争议边初始 `{in_attack, benign, oos}`。

RFC-004-02 已经把边界信念设计成 `{p_in_attack, p_benign, p_oos}`，它是定界 VOI 能获得正分的载体。

---

## 4.2 L2 图结构

每个节点：

```yaml
technique_node:
  technique_id: "T1059.001"
  tactic: "execution"
  platforms: ["Windows"]
  data_sources: ["Process Creation", "Command Execution"]
  tools:
    lolbas: ["powershell.exe"]
    gtfobins: []
  sigma_rules: [...]
  atomic_tests: [...]
```

每条边：

```yaml
technique_edge:
  src: "T1059.001"
  dst: "T1021.002"
  direction: "forward"
  p_next: 0.18
  reverse_prior: 0.22
  delay_distribution:
    type: "lognormal"
    p50_seconds: 180
    p90_seconds: 3600
  boundary_prior:
    p_in_attack: 0.62
    p_benign: 0.21
    p_oos: 0.17
  support:
    attack_flow: 7
    report_sequence: 19
    stix_cooccurrence: 66
    sigma_overlap: 3
    atomic_available: true
  confidence: 0.71
```

---

## 4.3 技术边来源优先级

### 第一优先级：ATT&CK Flow

直接抽：

```text
technique_i → technique_j
```

这是最适合 L2 的来源。

---

### 第二优先级：报告级时序

抽取报告中的技术链：

```text
phishing attachment → script execution → payload download → credential dump → lateral movement
```

映射为：

```text
T1566 → T1059 → T1105 → T1003 → T1021
```

---

### 第三优先级：共现关联

STIX APT 共现只做弱连接：

```text
如果同一 group/campaign 同时使用 T_i 与 T_j：
  edge_weight += 0.2
```

不能把它当强因果。

---

### 第四优先级：Sigma / Atomic / LOLBAS / GTFOBins 辅助标注

它们不主要提供因果方向，而提供：

| 来源     | 给 L2 补什么                                  |
| -------- | --------------------------------------------- |
| Sigma    | 哪些日志源能看到这条技术                      |
| Atomic   | 本环境能否生成可观测信号                      |
| LOLBAS   | Windows 合法工具滥用，增加 benign ambiguity   |
| GTFOBins | Unix-like 合法工具滥用，增加 benign ambiguity |

LOLBAS 页面本身列出工具、功能和 ATT&CK 技术 ID，例如 Bitsadmin、Mshta 等工具可对应下载、执行或防御规避类技术；GTFOBins 明确覆盖 Unix-like 可被滥用的合法二进制。([lolbas-project.github.io](https://lolbas-project.github.io/ "LOLBAS"))

---

## 4.4 延迟分布

每条技术边需要 delay prior：

```text
Δt = timestamp(dst_event) - timestamp(src_event)
```

来源：

1. ATT&CK Flow 若有顺序但无时间，只给阶段性先验；
2. 报告若有时间戳，抽真实 Δt；
3. Atomic Red Team 可用于本环境下估计“技术执行到日志出现”的观测延迟；
4. 没数据时用 tactic-level fallback。

建议层级：

```text
technique-pair delay
  fallback → tactic-pair delay
  fallback → lifecycle-stage delay
  fallback → global weak prior
```

延迟分布用分位数比均值更稳：

```yaml
delay_distribution:
  p10: 5s
  p50: 180s
  p90: 3600s
  confidence: 0.64
```

---

## 4.5 BoundaryBelief 先验

对一条候选边 `edge = A → B`，初始化：

```text
p_in_attack = f(
  L2 edge support,
  temporal compatibility,
  same principal / host / session continuity,
  lifecycle compatibility,
  source trust
)

p_benign = f(
  known admin tool,
  maintenance window,
  Sigma benign tags if any,
  LOLBAS/GTFOBins dual-use ambiguity,
  normal baseline frequency
)

p_oos = f(
  malicious-looking but poor fit to current explanation,
  different campaign/tool family,
  different host cluster,
  different objective,
  high maliciousness but low relatedness
)
```

归一化：

```text
p_in_attack + p_benign + p_oos = 1
```

默认建议：

| 情况                               | 初始边界先验           |
| ---------------------------------- | ---------------------- |
| 强技术因果 + 时间相容 + 同主体连续 | `{0.70, 0.20, 0.10}` |
| LOLBin/GTFOBin + 无强上下文        | `{0.35, 0.45, 0.20}` |
| 恶意强但不贴合当前解释             | `{0.25, 0.10, 0.65}` |
| 单源低可信日志                     | `{0.34, 0.33, 0.33}` |
| 关键资产 + 攻击链相容              | `{0.60, 0.25, 0.15}` |

这里要保持高熵，不要一上来给 0.95。

---

# 5. L3：环境配置与证据信任

## 5.1 目标

构建：

```text
L3_EnvironmentConfig:
log_source → integrity
log_source → adversary_controllable_base
log_source → supported_platforms
log_source → technique_visibility
```

它给：

* VETO 硬删门控；
* `w_trust(e)`；
* L2 技术边可观测性；
* SeedPrior 的平台过滤。

RFC-004-02 里 EvidenceTrust 包含 `integrity`、`provenance`、`adversary_controllable`、`corroboration`，且只有抗伪事实可以 hard VETO。

---

## 5.2 Log Source Trust Registry

建议直接做一个 YAML 注册表。

```yaml
log_source_registry:
  edr_kernel_process_event:
    integrity: 0.95
    tier: "forge-resistant"
    adversary_controllable_base: false
    hard_veto_allowed: true
    platforms: ["windows", "linux", "macos"]
    observes:
      - "process_creation"
      - "module_load"
      - "network_connection"

  cloudtrail_management_event:
    integrity: 0.90
    tier: "high"
    adversary_controllable_base: false
    hard_veto_allowed: true
    platforms: ["aws"]
    observes:
      - "cloud_api_call"
      - "iam_change"

  windows_event_log_security:
    integrity: 0.60
    tier: "medium"
    adversary_controllable_base: "contextual"
    hard_veto_allowed: false
    platforms: ["windows"]
    observes:
      - "logon"
      - "privilege_use"

  bash_history:
    integrity: 0.20
    tier: "low"
    adversary_controllable_base: true
    hard_veto_allowed: false
    platforms: ["linux", "macos"]
    observes:
      - "command_history"
```

---

## 5.3 动态降权规则

静态 trust 不够，还要看上下文。

```text
如果 host 已被判 compromised：
  host-local writable logs × 0.4
  shell history × 0.2
  attacker-writable file artifacts × 0.3
  remote immutable audit logs 不降权

如果 evidence 只有单源：
  corroboration_bonus = 0

如果 evidence 来自 ≥2 独立采集链：
  corroboration_bonus = +0.1 ~ +0.2

如果 evidence 与高可信时间源冲突：
  low-trust timestamp 不触发 hard veto
```

---

## 5.4 平台过滤

L3 还必须提供：

```text
technique_id → supported_platforms
asset → platform
```

播种时先过滤：

```text
Windows-only technique 不播给 Linux asset；
Linux-only GTFOBins prior 不播给 Windows host；
Cloud technique 只在 cloud asset / identity event 上启用。
```

这样能显著减少无意义解释。

---

# 6. L4：攻击生命周期模板

## 6.1 目标

构建：

```text
LifecycleTemplate:
stage_sequence + expected_techniques + required/optional stage + stopping relevance
```

它用于：

1. 初始化解释；
2. `fit_stage(e,H)`；
3. 生命周期债务检测；
4. 判断某阶段是否“不适用”并关闭义务。

---

## 6.2 模板不要只有一套

至少需要这些模板：

| 模板                          | 典型阶段                                                                                                            |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| commodity malware             | initial access → execution → persistence → defense evasion → c2                                                 |
| ransomware                    | initial access → execution → privilege escalation → credential access → lateral movement → exfiltration/impact |
| credential theft              | initial access → credential access → collection/exfiltration                                                      |
| insider misuse                | valid account → discovery → collection/exfiltration                                                               |
| cloud compromise              | initial access → discovery → privilege escalation → persistence → impact/exfiltration                           |
| living-off-the-land intrusion | execution → defense evasion → discovery → lateral movement / collection                                          |

CISA ransomware 指南可作为 ransomware 模板和响应检查项的参考来源；但不能把 ransomware 模板套到所有攻击上。([网络安全和基础设施安全局](https://www.cisa.gov/stopransomware/ransomware-guide?utm_source=chatgpt.com "StopRansomware Guide"))

---

## 6.3 LifecycleTemplate schema

```yaml
lifecycle_template:
  template_id: "ransomware_enterprise_v1"
  family: "ransomware"
  stages:
    - stage: "initial_access"
      required: true
      expected_tactics: ["initial-access"]
      expected_techniques: ["T1566", "T1190", "T1133"]
      debt_policy: "hard_if_no_initial_vector"

    - stage: "execution"
      required: true
      expected_tactics: ["execution"]
      expected_techniques: ["T1059", "T1204"]
      debt_policy: "hard"

    - stage: "credential_access"
      required: "conditional"
      expected_tactics: ["credential-access"]
      expected_techniques: ["T1003", "T1555"]
      debt_policy: "voi_gated"

    - stage: "lateral_movement"
      required: "conditional"
      expected_tactics: ["lateral-movement"]
      expected_techniques: ["T1021", "T1072"]
      debt_policy: "voi_gated"

    - stage: "impact"
      required: "conditional"
      expected_tactics: ["impact"]
      expected_techniques: ["T1486"]
      debt_policy: "hard_if_ransomware_claimed"
```

重点：生命周期债务不要全部 hard。
和 RFC-004-02 一致：

```text
结构债务、反取证债务：硬阻断；
生命周期债务、判别债务：VOI 门控。
```

---

# 7. score_v3 七维先验

## 7.1 目标

score_v3 用于初始化解释先验，而不是直接给探针打分。RFC-004-02 也明确说，`score_v3` 的新角色是初始化非空解释先验。

建议七维如下：

```text
score_v3(H | E) =
  w1 * tactic_fit
+ w2 * technique_fit
+ w3 * lifecycle_fit
+ w4 * environment_fit
+ w5 * temporal_fit
+ w6 * threat_prevalence
+ w7 * boundary_risk
```

---

## 7.2 七维定义

| 维度              | 含义                                      | 来源             |
| ----------------- | ----------------------------------------- | ---------------- |
| tactic_fit        | E 当前 tactic 的可能前驱/后继是否贴合解释 | L1               |
| technique_fit     | E technique 是否贴合 L2 技术因果邻域      | L2               |
| lifecycle_fit     | E 位于某模板哪个阶段，是否合理            | L4               |
| environment_fit   | 平台、日志源、资产类型是否匹配            | L3               |
| temporal_fit      | E 与前驱/后继的时间间隔是否合理           | L2 delay         |
| threat_prevalence | 公开报告 / STIX 共现频率弱先验            | STIX + reports   |
| boundary_risk     | 该解释是否容易误归因，是否需要 null 定界  | L2 BoundaryPrior |

---

## 7.3 初始化公式

```text
raw_score(H) =
  Σ_i w_i * feature_i(H,E)

P0(H) =
  softmax(raw_score(H) / τ)
```

建议用较高温度 `τ` 保持高熵：

```text
τ = 1.5 ~ 2.5
```

这样不会开局过度自信。

---

## 7.4 默认权重

0-1 期建议：

| 维度              | 默认权重 |
| ----------------- | -------: |
| tactic_fit        |     0.18 |
| technique_fit     |     0.22 |
| lifecycle_fit     |     0.18 |
| environment_fit   |     0.12 |
| temporal_fit      |     0.12 |
| threat_prevalence |     0.08 |
| boundary_risk     |     0.10 |

注意：

```text
threat_prevalence 权重必须低。
```

原因是公开报告频率不等于当前环境真实概率，否则容易把常见攻击模板到处套。

---

## 7.5 权重校准

用三类数据校准：

| 数据         | 用途                                |
| ------------ | ----------------------------------- |
| 历史 IR case | 校准解释先验是否过度自信            |
| 红队 replay  | 校准 tactic/technique/lifecycle fit |
| 人工反馈     | 校准 boundary_risk 和 null 归属     |

损失函数：

```text
minimize:
  cross_entropy(true_explanation, P0)
+ λ1 * overconfidence_penalty
+ λ2 * wrong_null_penalty
+ λ3 * wrong_oos_penalty
```

0-1 期如果没有标签，就只做：

```text
专家审查 + replay case + sensitivity analysis
```

---

# 8. 损失矩阵基线

## 8.1 最小核心必须是两/三标量

不能只用 `LAMBDA_MISS`。
因为只惩罚漏报，无法让“误把良性边纳入攻击链”产生风险下降空间。RFC-004-02 已经明确：`LAMBDA_OVER > 0` 是治过度归因的真正下限。

建议：

```text
LAMBDA_MISS  = 10
LAMBDA_OVER  = 2
LAMBDA_OOS   = 4
```

含义：

| 参数        | 含义                         | 默认 |
| ----------- | ---------------------------- | ---: |
| LAMBDA_MISS | 把真攻击边剪掉的代价         |   10 |
| LAMBDA_OVER | 把良性边纳入攻击链的代价     |    2 |
| LAMBDA_OOS  | 把域外真恶意误并入本案的代价 |    4 |

为什么 `LAMBDA_OOS > LAMBDA_OVER`？

因为 oos 是“真恶意但非本案”。如果误并入当前攻击链，可能导致：

* 案件边界错误；
* 处置范围错误；
* 另一起事件被漏建；
* 归因报告混乱。

---

## 8.2 敏感性分析区间

| 参数        | 建议区间 |
| ----------- | -------: |
| LAMBDA_MISS |    8–20 |
| LAMBDA_OVER |     1–5 |
| LAMBDA_OOS  |     2–8 |

需要测试三种策略：

| 策略   | 参数倾向               | 适用                  |
| ------ | ---------------------- | --------------------- |
| 保守型 | miss 高，over/oos 低   | 关键资产、早期上线    |
| 边界型 | miss 高，over/oos 中高 | 关注攻击边界精度      |
| 分案型 | oos 高                 | 多事件并发、MSSP 场景 |

---

## 8.3 损失基线如何进入 BoundaryRisk

```text
risk_include_edge =
  p_benign * LAMBDA_OVER
+ p_oos * LAMBDA_OOS

risk_prune_edge =
  p_in_attack * LAMBDA_MISS
```

选择风险小的动作，但 VOI 排序会优先查那些能显著改变三元概率的探针。

---

# 9. 在线播种流程

当告警入口事件 E 到达：

```json
{
  "event_id": "E",
  "technique": "T1059.001",
  "tactic": "execution",
  "asset": "host-123",
  "platform": "windows",
  "log_source": "edr_kernel_process_event",
  "timestamp": "...",
  "principal": "userA",
  "process": "powershell.exe"
}
```

Seed Service 执行：

---

## Step 1：平台过滤

```text
candidate_techniques = L2.neighbors(E.technique)
filter by asset.platform
filter by available log sources
```

---

## Step 2：查 L1 反向战术

```text
prev_tactics = top_k P(prev_tactic | current_tactic)
```

---

## Step 3：查 L2 技术邻域

反向找可能前驱：

```text
possible_predecessor_techniques =
  top_k P(E.technique | prev_technique)
```

正向找可能后继：

```text
possible_successor_techniques =
  top_k P(next_technique | E.technique)
```

但播种解释时不要全展开，只保留摘要。

---

## Step 4：匹配 L4 生命周期模板

```text
template_candidates =
  templates where E.tactic / E.technique fits one stage
```

例如：

```text
E = powershell execution
可能解释：
1. malware execution
2. ransomware early execution
3. living-off-the-land admin/attack ambiguity
4. credential theft chain
```

---

## Step 5：生成 ≤4–6 个 Explanation

每个 Explanation 只包含：

```yaml
explanation:
  eid: "H1"
  label: "ransomware_early_execution"
  lifecycle_template: "ransomware_enterprise_v1"
  current_stage: "execution"
  seed_technique: "T1059.001"
  expected_prev:
    tactics: ["initial-access"]
    techniques: ["T1566", "T1190", "T1133"]
  expected_next:
    tactics: ["credential-access", "lateral-movement", "impact"]
    techniques: ["T1003", "T1021", "T1486"]
  log_prior: -1.13
  score_v3:
    tactic_fit: 0.71
    technique_fit: 0.66
    lifecycle_fit: 0.74
    environment_fit: 0.88
    temporal_fit: 0.50
    threat_prevalence: 0.42
    boundary_risk: 0.55
```

不要生成完整攻击链。
只生成“当前阶段 + 可能前后文”。

---

## Step 6：生成分支 null 锚

```yaml
branch_null_anchor:
  benign:
    prior: 0.35
    meaning: "域内良性或运维行为，不属于本案"
  oos:
    prior: 0.15
    meaning: "像真恶意，但不属于当前攻击故事，应 SPAWN/FEEDBACK"
```

对于 LOLBAS / GTFOBins 工具，benign 先验可以更高，因为它们天然具有双用性；但如果上下文强恶意，`p_in_attack` 仍然可以被证据更新拉高。

---

## Step 7：输出 DecisionLedger seed

```json
{
  "decision_ledger_seed": {
    "explanations": ["H1", "H2", "H3", "H4"],
    "log_post": {
      "H1": -1.11,
      "H2": -1.28,
      "H3": -1.42,
      "H4": -1.61
    },
    "contested": {
      "edge:E": {
        "p_in_attack": 0.45,
        "p_benign": 0.40,
        "p_oos": 0.15
      }
    },
    "entropy": "high",
    "source_version": "prior-bundle-2026.06"
  }
}
```

---

# 10. 关键数据表设计

## 10.1 prior_bundle manifest

```yaml
prior_bundle:
  version: "2026.06.29"
  attack_stix_version: "v19.x"
  attack_flow_version: "v3.2.0"
  sigma_commit: "..."
  atomic_red_team_commit: "..."
  lolbas_commit: "..."
  gtfobins_commit: "..."
  report_corpus_version: "..."
  generated_at: "2026-06-29"
  checksums:
    l1: "sha256..."
    l2: "sha256..."
    l3: "sha256..."
    l4: "sha256..."
```

ATT&CK Flow 的 GitHub 项目在 2026 年仍维护，并列出了 v3.2.0 / ATT&CK v19.1 release，这种版本信息应进入 manifest，避免先验不可复现。([GitHub](https://github.com/center-for-threat-informed-defense/attack-flow "GitHub - center-for-threat-informed-defense/attack-flow: Attack Flow helps executives, SOC managers, and defenders easily understand how attackers compose ATT&amp;CK techniques into attacks by developing a representation of attack flows, modeling attack flows for a small corpus of incidents, and creating visualization tools to display attack flows. · GitHub"))

---

## 10.2 technique_normalization 表

```yaml
technique:
  id: "T1059.001"
  name: "PowerShell"
  parent: "T1059"
  tactics: ["execution"]
  platforms: ["Windows"]
  data_sources: [...]
  external_refs:
    attack: "..."
```

---

## 10.3 evidence_source_map 表

```yaml
evidence_source_map:
  sigma_rule_id: "..."
  technique_id: "T1059.001"
  logsource:
    product: "windows"
    category: "process_creation"
  required_fields:
    - "Image"
    - "CommandLine"
  trust_source: "windows_event_log_security"
```

---

# 11. 校准与评测

## 11.1 先验质量指标

| 指标                      | 目标                              |
| ------------------------- | --------------------------------- |
| top-k explanation recall  | 真解释是否出现在 ≤6 个候选中     |
| prior entropy             | 播种不能过度自信                  |
| edge boundary calibration | `{in, benign, oos}`是否方向正确 |
| temporal edge precision   | L2 边是否真有时序支持             |
| source diversity          | 不被单一报告污染                  |
| platform mismatch rate    | 平台过滤错误率                    |
| hard-veto safety          | 低可信源不触发 hard VETO          |

---

## 11.2 红队/回放 case

至少构造 8 类：

| Case                    | 测试点               |
| ----------------------- | -------------------- |
| 正常 PowerShell 运维    | benign null 是否够强 |
| PowerShell 下载 payload | in_attack 是否升高   |
| 挖矿与勒索并发          | oos 是否触发 SPAWN   |
| 日志被清理              | 反取证义务           |
| 时间戳伪造              | hard VETO 是否被抑制 |
| Linux GTFOBins 滥用     | 平台与 dual-use      |
| cloud IAM 异常          | cloud lifecycle      |
| ransomware chain        | 生命周期模板         |

---

## 11.3 校准方式

先做离线回放：

```text
event E → SeedPrior(E) → 人工标注真解释/边界 → 评估 top-k 和边界先验
```

再做在线反馈：

```text
分析员确认：
  edge in_attack / benign / oos
  explanation accepted / rejected
  prior too strong / too weak
```

更新：

```text
score_v3 weights
boundary prior parameters
source weights
delay distributions
loss sensitivity profile
```

---

# 12. 实施路线

## Phase 0：先做最小可用 bundle

产物：

```text
L1 tactic transition from STIX co-occurrence + Attack Flow
L2 technique graph from Attack Flow
L3 static trust registry
L4 3 个模板：ransomware / credential theft / living-off-the-land
score_v3 默认权重
loss baseline: 10 / 2 / 4
```

---

## Phase 1：加入报告级时序

做：

```text
公开 APT 报告抽取
人工采样审核
report edge confidence
delay distribution
```

---

## Phase 2：加入 Sigma / Atomic 覆盖

做：

```text
Sigma log source map
Atomic telemetry validation
environment visibility score
```

---

## Phase 3：加入 boundary calibration

做：

```text
benign / oos / in_attack 边界标签
LOLBAS / GTFOBins dual-use prior
normal baseline
```

---

## Phase 4：加入完整矩阵和高级 VOI

只有当标签足够时，再做：

```text
full loss matrix
proper calibration
complete one-step VOI
reliability diagram
```

这符合 RFC-004-02 的最小核心优先思想：完整 VOI 和完整损失矩阵是升级项，不是 0-1 期硬依赖。

---

# 13. 最终交付物清单

你最终应该交付一个 `prior-bundle`：

```text
prior-bundle/
  manifest.yaml
  l1_tactic_transition.parquet
  l2_technique_causal_graph.parquet
  l2_delay_distribution.parquet
  l2_boundary_prior.parquet
  l3_log_source_trust.yaml
  l3_platform_filter.yaml
  l4_lifecycle_templates.yaml
  score_v3_weights.yaml
  loss_baseline.yaml
  source_registry.yaml
  calibration_report.md
  validation_cases/
```

以及一个在线接口：

```http
POST /seed-prior
input: alert event E
output: DecisionLedger.seed payload
```

---

# 14. 最核心的设计结论

这套先验知识系统必须坚持一个边界：

> **先验不是“攻击剧本库”，而是“高熵溯因初始化器”。**

它不应该在 E 到达时告诉系统：

```text
这就是勒索软件。
```

而应该告诉系统：

```text
基于当前 technique、tactic、平台、时间、数据源和公开时序知识，
最值得保留的 4–6 个解释是这些；
这条边有多少可能属于本案、良性、或域外真恶意；
接下来哪些方向最可能降低决策风险。
```

最推荐的命名是：

```text
Prior Knowledge Factory for Decision-Ledger LOCK
```

中文可以叫：

```text
决策账先验知识工厂
```

它的价值不是让 Agent “更相信先验”，而是让 Agent **从一开始就知道：哪些故事值得保留，哪些边可能不是本案，哪些证据源值得信，哪些生命周期缺口需要后续证据来填。**
