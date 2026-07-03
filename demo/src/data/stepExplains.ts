import type { StepExplain } from '../types';

export const bootstrapExplain: StepExplain = {
  title: '会话启动 · bootstrap + 薄播种决策账',
  action:
    '初诊门控通过后，执行 triage_entry、bootstrap_chain，并初始化四本账中的决策账（第四本账）。',
  inputs: [
    '告警 E：db-prod-01 上 PowerShell + 文件加密（初诊：恶意 ✓ · 核心资产 ✓）',
    '七维 score_v3 先验、LifecycleTemplate 模板库',
    '空 SessionGraph（仅告警锚点）',
  ],
  outputs: [
    'SessionGraph 初始因果草图（告警节点 + frontier）',
    'DecisionLedger.seed：H1 勒索链 45% · H2 运维误报 35% · null 锚 20%（高熵，会被冲刷）',
    'contested[e-rdp]：zhangsan RDP 边三元信念 {50%, 35%, 15%}',
    'BetaLedger / ObligationLedger 空账就绪',
  ],
  computation: [
    'score_v3 → 各非空解释 P(H) 初始化（非直接给探针打分）',
    'null 锚 = 分支定界落点，非「整案误报」主战场',
    '与 Beta 台账 prior_value 初始化同性质：廉价先验',
  ],
  maintenance: [
    '【图】写入 bootstrap 节点',
    '【决策账⭐】explanations + contested 初始化',
    '【Beta】α0,β0 默认先验',
    '【义务】空',
  ],
};

/** 与 mockSession.rounds 各 phase 一一对应 */
export const phaseStepExplains: StepExplain[][] = [
  // ═════════════════════════════════════════════════════════════
  // Round 1
  // ═════════════════════════════════════════════════════════════
  [
    {
      title: 'L 拍 · 选哪条（生成层投候选）',
      action: 'prior_generator + rule_gap_generator 向统一候选池 Probe[] 投掷同型探针，去重合并来源。',
      inputs: [
        'SessionGraph（告警 + bootstrap frontier）',
        'DecisionLedger 当前后验（H1/H2/null）',
        '七维 prior、上一轮 graph.stats()',
      ],
      outputs: [
        '候选池 +8 条：邮件 hash、PowerShell 父进程、zhangsan 登录、scheduled task…',
        '每条 Probe(target + operator) 带 dedup-key',
      ],
      computation: [
        'prior：沿竞争解释子图 frontier 反向延伸「下一跳可能查什么」',
        'rule_gap：结构缺口（孤儿进程、悬空凭据）触发必查型候选',
        '尚未 VOI 排序——本拍只负责「入池」',
      ],
      maintenance: ['【图】只读', '【决策账】只读（供 prior 方向）', '【Beta/义务】未写'],
    },
    {
      title: '② 拍 · 检验（VETO + MANDATE + 证据信任）',
      action:
        '证据信任闸门 → graded VETO 硬删/软降 → MANDATE 扫描开放义务并物化预占槽（≤⌈B/2⌉）。',
      inputs: [
        '候选池 8 条',
        'SessionGraph 不变量 / 时序约束',
        'EvidenceTrust 向量（integrity、对手可控）',
      ],
      outputs: [
        '永久剪枝 2 条（违反抗伪不变量）→ 审计日志',
        '1 条标 adversary_controllable → 仅强负向先验，不硬删',
        '幸存池 6 条',
        '新义务 o1：结构债务「恶意孤儿 ps1」hard 🔒',
      ],
      computation: [
        '硬 VETO 前置：TemporalOrder/Disconfirmed 须 is_forge_resistant()',
        '对手可控「证伪」→ 降为软负向，防止伪造时戳杀死真路径',
        'scan()：恶意孤儿 / 桥接主机 → 结构义务',
      ],
      maintenance: [
        '【义务】+o1 structure hard',
        '【证据信任】入账标签（本步无新取证，用图内已有边）',
        '【候选池】缩减为幸存集',
      ],
    },
    {
      title: 'O 拍 · 怎么查（VOI 排序 + 填槽）',
      action: '对幸存候选按 VOI 降序排序；义务槽价值×紧迫预占；余槽填满 fanout_budget=3。',
      inputs: [
        '幸存候选池 6 条',
        'DecisionLedger（H1 leading，margin=34%）',
        'Beta 台账 + 生成器标定 λ（估 P(no_data)）',
        '开放义务 mandated 1 条',
      ],
      outputs: [
        '选中 Top-3：邮件 hash · PowerShell 父进程 · scheduled task 触发源',
        'budgetUsed: 0 → 3',
      ],
      computation: [
        'VOI(p) = risk_now − E[risk_after] − cost(p)',
        'risk = 会话级 BayesRisk + Σ 边界 contested 风险',
        '本 round margin 大 → 会话项主导 → 补全 H1 探针排前',
        '边界项对 zhangsan 边尚小 → 定界探针未排第一',
      ],
      maintenance: ['【决策账】只读（O 拍读 VOI）', '【义务】mandated 预占槽位', '【Beta】只读'],
    },
    {
      title: 'C 拍 · 验真（扇出取证 + 入图判假）',
      action: 'pivot_agent.execute_fanout(chosen×3) 并发取证 → L0–L4 级联 → 路由 ATTACH/PARK… → 信任标注。',
      inputs: [
        '选中 3 条 Probe',
        'EDR / 邮件网关 / 主机 telemetry API',
      ],
      outputs: [
        '原始 events[]：附件 hash 命中、宏执行链、task 元数据',
        'confirmed_events：钓鱼附件边、宏→PowerShell 边',
        'EvidenceTrust：网关签名高 integrity；task 源标记 adversary-controlled',
      ],
      computation: [
        'L0 去噪 → L1 结构挂接（fit_struct）→ L2 信任 → L3 解释归属',
        'P(e|H) ∝ fit_struct · fit_stage · w_trust（对数似然比更新决策账在 K 拍）',
        '扇出并发，非串行',
      ],
      maintenance: [
        '【图】+2 确认边（mail→ws-07, ws-07→ps1）',
        '【证据信任】ingest(triaged) 新向量',
        '【决策账/Beta】本拍不写，等 K',
      ],
    },
    {
      title: 'K 拍 · 收尾（学习 + 决策账 + 停止判定）',
      action:
        '串行入图 → ledger.update 贝叶斯（含 null 锚 + contested）→ Beta hit/miss → 义务 discharge → should_stop()。',
      inputs: [
        'C 拍 confirmed_events + trust',
        'chosen Probes ×3',
      ],
      outputs: [
        '决策账：H1 45%→62%，H2 28%，null 10%，margin 34%',
        'Beta：email.hash 8/11，process.parent 5/9',
        'stopSignals：全 false → CONTINUE',
      ],
      computation: [
        'log_post(H) += log P(e|H) − log P(e|null)；归一化',
        'hit = count_attributable > 0；beta.update(learning_key)',
        'should_stop：hard 义务 open → CONTINUE',
      ],
      maintenance: [
        '【图】最终确认（与 C 一致）',
        '【决策账⭐】写后验 + margin',
        '【Beta】+3 次更新',
        '【义务】o1 仍 open',
      ],
    },
  ],

  // ═════════════════════════════════════════════════════════════
  // Round 2
  // ═════════════════════════════════════════════════════════════
  [
    {
      title: 'L 拍 · 第二轮投候选',
      action: '沿新 frontier（mail→ws→ps1→db-prod）继续 prior + 规则缺口投池。',
      inputs: ['Round1 图（+2 边）', 'decisionLedger margin 仍可观', 'stats Δ：新增 RDP 关联 pivot'],
      outputs: ['+6 候选：zhangsan 票据、scheduled task 链、横向协议、ws-07 进程…', '图增 contested 边 e-rdp（虚线）'],
      computation: ['prior 读 ledger.leading 子图 frontier', 'rule_gap：RDP 登录无机制解释 → 候选'],
      maintenance: ['【图】+e-rdp contested', '【决策账】只读'],
    },
    {
      title: '② 拍 · 歧义区检验',
      action: 'VETO 保留 scheduled task 路径（非抗伪证伪）；扫描生成判别义务 o2。',
      inputs: ['候选 6 条', 'H1 vs H2 margin 已缩小', 'e-task 潜在 adversary-controlled'],
      outputs: ['幸存池 5 条', 'o2 判别义务 soft（hard=false）', 'o1 structure 因 ps1 已挂接 → discharged'],
      computation: [
        'margin(H1,H2) < τ_disc → 判别义务',
        'discharged_by：结构闭合可关闭 o1',
      ],
      maintenance: ['【义务】+o2 discrimination soft；o1 discharged', '【候选池】缩减'],
    },
    {
      title: 'O 拍 · margin 6% · 定界与判别竞争',
      action: 'VOI 排序；mandated + VOI 填 3 槽。',
      inputs: ['ledger margin=8%→临界歧义', 'contested[e-rdp] 仍 45/40/15', 'o2 判别 VOI=0.41'],
      outputs: [
        '选中：zhangsan 票据 · scheduled task 链 · （未选挖矿探针）',
        'budgetUsed: 3→6',
      ],
      computation: [
        'zhangsan 探针：boundary 0.28 + session 0.08 → VOI 0.38',
        'task 链：session 0.31 主导 → 判别 H1/H2',
        '两者几乎同分 → 歧义区典型形态',
      ],
      maintenance: ['【决策账】只读', '【义务】mandated 预占'],
    },
    {
      title: 'C 拍 · H2 证据上升',
      action: '扇出查询；scheduled task 确认挂接；RDP 仍 contested。',
      inputs: ['选中 2–3 Probe', '主机 task scheduler API'],
      outputs: [
        'confirmed：ws-07→db-prod scheduled task 边（trust: adversary-controlled）',
        'RDP 边仍虚线 contested',
        '原始 event 支持 H2 批处理叙事',
      ],
      computation: [
        'L3 解释归属：task 边 fit H2 > fit H1 部分',
        '低 integrity 证据 → w_trust 降权，不硬删 H1',
      ],
      maintenance: ['【图】+e-task', '【证据信任】task 标 adversary-controlled'],
    },
    {
      title: 'K 拍 · 后验逼近 · 判别义务仍 open',
      action: '贝叶斯更新 → H1 48% / H2 42% / margin 6%；软义务不阻断停止判定。',
      inputs: ['C 拍 events', 'task + RDP 似然'],
      outputs: [
        '决策账 margin 6%（歧义警告）',
        'contested[e-rdp] 45/40/15 基本不变',
        'o2 仍 open（VOI 门控，非 hard 阻断）',
        'stopSignals: hardObligations=true（o1 已清）',
      ],
      computation: [
        'P(task|H2) > P(task|H1) → H2 后验升',
        'should_stop：open_hard()=false → 检查 VOI',
        'maxVOI 仍高 → CONTINUE',
      ],
      maintenance: ['【决策账⭐】写后验', '【Beta】+4 条更新', '【义务】o2 仍 open'],
    },
  ],

  // ═════════════════════════════════════════════════════════════
  // Round 3 — 定界 + lifecycle
  // ═════════════════════════════════════════════════════════════
  [
    {
      title: 'L 拍 · 定界候选 + lifecycle 缺口',
      action: '争议边高熵 → 定界探针候选入池；H1 推进到 lateral-movement 但 impact 未确立 → lifecycle 候选。',
      inputs: ['R2 终态图（+e-rdp contested, +e-task）', 'ledger margin=6%（歧义）', 'contested[e-rdp] 高熵 45/40/15'],
      outputs: [
        '+4 候选：zhangsan 票据、scheduled task 链、db-prod 文件加密痕迹、ws-07 挖矿',
        'prior 读 H1 lifecycle_stage → impact 缺口',
      ],
      computation: [
        '争议边 p_benign=0.4 → 确认 benign 能大幅削边界风险',
        'LifecycleTemplate：H1 推进到 lateral-movement，impact 未确认',
      ],
      maintenance: ['【图】只读', '【决策账】只读'],
    },
    {
      title: '② 拍 · lifecycle 义务出现',
      action: '扫描生成 lifecycle 义务 o4（impact 阶段未确认）；判别义务 o2 仍 open。',
      inputs: ['H1 lifecycle_stage=lateral-movement', '图中无 impact 级 tactic（加密/外泄）', 'o2 仍 open'],
      outputs: [
        'o4 lifecycle 义务 soft（hard=false，走 VOI 门控）',
        'o2 仍 open（VOI 门控）',
      ],
      computation: [
        'LifecycleTemplate.unexplained_stages() → impact 缺失',
        'lifecycle 义务 hard=false → 不无条件阻断停止',
      ],
      maintenance: ['【义务】+o4 lifecycle soft', '【候选池】无 VETO 剪枝'],
    },
    {
      title: 'O 拍 · ⭐ 定界探针 VOI #1',
      action: 'VOI 排序；定界探针因边界项排第一（RFC-004-02 核心差异）。',
      inputs: ['margin 仍小但 H1 略领先', 'contested[e-rdp] 高熵', 'LAMBDA_OVER > 0 边界损失'],
      outputs: ['#1 查 zhangsan 登录来源（VOI 0.42，boundary 0.32）', '#2 查 db-prod 文件加密（lifecycle impact）', 'budgetUsed: 6→8'],
      computation: [
        'boundary_risk = min(p_benign·LAMBDA_OVER, p_in·LAMBDA_MISS)',
        '确认 benign → boundary_risk 大降 → VOI 高',
        '对比 RFC-003：hitRate 0.12 → 命中率排序会垫底',
      ],
      maintenance: ['【决策账】只读', '【义务】o4 VOI 仍计入 max_voi'],
    },
    {
      title: 'C 拍 · 定界取证 + impact 确认',
      action: '查询 zhangsan RDP 票据与登录源；文件系统确认加密行为 → lifecycle 履行。',
      inputs: ['Probe：zhangsan 登录来源与票据', 'AD / 堡垒机日志（抗伪）', 'Probe：db-prod 文件加密痕迹'],
      outputs: [
        'event：日常运维 RDP，票据合法 → outcome=benign',
        'event：文件系统确认大量 .lock 文件 → impact 确认',
        'contested[e-rdp].p_benign ↑',
        '图边 e-rdp 标记 pruned',
      ],
      computation: [
        'P(benign|probe) 高 → hypothetical_update 降边界熵',
        'fit_struct：运维窗口与 change ticket 一致',
        'impact 阶段确认 → lifecycle 义务可 discharge',
      ],
      maintenance: ['【图】e-rdp pruned 态', '【证据信任】forge-resistant 登录日志'],
    },
    {
      title: 'K 拍 · 剪枝定界 · H1 回升 · lifecycle 履行',
      action: 'contested 收敛 benign 90%；H1 68%；margin 46%；o2/o4 可 discharge。',
      inputs: ['benign 归属证据 + impact 确认', '剪枝边 e-rdp'],
      outputs: [
        '决策账：H1 68% · H2 22% · margin 46%',
        'contested[e-rdp]：5% / 90% / 5%',
        '攻击边界：zhangsan 边灰色剪枝',
        'o2 discharged（歧义已消解）',
        'o4 discharged（impact 阶段已确认）',
        'stopSignals: hardObligations=true（无硬义务 open）',
      ],
      computation: [
        'log_post(H1) ↑（爆炸半径缩小）',
        'boundary 熵 → 0（单轴收敛 benign）',
        'LAMBDA_OVER 惩罚已消除',
      ],
      maintenance: ['【决策账⭐】写后验+contested', '【图】确认 pruned', '【义务】o2/o4 discharged', '【Beta】+2 条更新'],
    },
  ],

  // ═════════════════════════════════════════════════════════════
  // Round 4 — 反取证 + oos
  // ═════════════════════════════════════════════════════════════
  [
    {
      title: 'L 拍 · 反取证缺口 + C2 候选',
      action: 'db-prod 审计完整性需验证；ws-07 可能有其他恶意进程；C2 外泄探查。',
      inputs: ['R3 终态图（e-rdp pruned, e-task confirmed）', 'H1 68% margin 46%', 'prior：impact 阶段应查反取证'],
      outputs: ['+5 候选：审计完整性、ws-07 进程树、C2 外泄、网络流…'],
      computation: [
        'prior 读 H1 lifecycle_stage=impact → 反取证阶段候选',
        'rule_gap：db-prod 审计可能有断层',
      ],
      maintenance: ['【图】只读', '【决策账】只读'],
    },
    {
      title: '② 拍 · 反取证义务 hard 🔒',
      action: 'AntiForensicsScanner 检出 db-prod 审计日志断层 → 生成反取证义务（hard 阻断）。',
      inputs: ['候选 5 条', '图中无反取证标记但 prior 建议查审计'],
      outputs: [
        'o3 反取证义务 hard 🔒（未清不能停）',
        '生命周期/判别义务已全部 discharged',
      ],
      computation: [
        '缺失即信号（§5）：不应视为「此处无事」',
        'scan() → anti-forensics 义务，hard=true',
        '硬义务预占 ≤⌈B/2⌉ 槽位',
      ],
      maintenance: ['【义务】+o3 anti-forensics hard', '【候选池】无 VETO 剪枝'],
    },
    {
      title: 'O 拍 · 反取证探针 VOI 最高',
      action: '硬义务预占槽位；余槽填 VOI 排序的 ws-07 进程树探针。',
      inputs: ['o3 hard 预占 1 槽', '余候选 VOI 排序'],
      outputs: [
        '#1 查 db-prod 审计日志完整性（VOI 0.52，硬义务预占）',
        '#2 查 ws-07 进程树全量（VOI 0.31）',
        'budgetUsed: 9→10',
      ],
      computation: [
        '硬义务物化为探针 → 价值×紧迫预占',
        '余槽 VOI 排序：审计 > 进程树 > C2',
      ],
      maintenance: ['【决策账】只读', '【义务】mandated 预占'],
    },
    {
      title: 'C 拍 · 日志断层 + xmrig 发现',
      action: '扇出查 db-prod 审计完整性；检出 40min 日志断层 → 缺失即信号。ws-07 进程树发现 xmrig → oos。',
      inputs: ['Probe：db-prod 审计链完整性', 'SIEM / 内核审计 API', 'Probe：ws-07 进程树全量'],
      outputs: [
        'event：40min 审计日志断层（missing 信号）',
        'EvidenceTrust.trust=missing',
        'event：ws-07 发现 xmrig 挖矿进程',
        'outcome=oos → 不并入 H1，标记 SPAWN 候选',
      ],
      computation: [
        '缺失即信号（§5）：日志断层 → 反取证义务',
        'L3 解释归属：xmrig 在所有现存解释下 fit < τ_spawn → SPAWN',
        'oos 与 benign 不同：是真恶意但域外',
      ],
      maintenance: ['【图】+e-loggap missing, +e-miner oos, +miner 节点', '【证据信任】missing 入账', '【义务】o3 履行中'],
    },
    {
      title: 'K 拍 · 反取证履行 + oos SPAWN',
      action: 'o3 discharged（反取证源已追）；xmrig 标 oos → SPAWN 候选另案。H1 78%。',
      inputs: ['o3 履行探针结果', 'ws-07 进程树结果'],
      outputs: [
        'o3 discharged',
        'e-miner oos 边 + xmrig 节点',
        'H1 78%；contested 清空（边界已稳）',
        'SPAWN 候选：另案溯源挖矿',
        'stopSignals: hardObligations=true（o3 已清）',
      ],
      computation: [
        'outcome=oos → contested.p_oos（若存在）→ spawn_merge_cull',
        'o3 履行后 discharge → open_hard()=false',
        'H1 ↑（反取证确认攻击者试图掩盖痕迹）',
      ],
      maintenance: ['【决策账⭐】H1↑；spawn 候选', '【图】+oos 边', '【义务】o3 discharged', '【Beta】+2 条更新'],
    },
  ],

  // ═════════════════════════════════════════════════════════════
  // Round 5 — 价值导向停止
  // ═════════════════════════════════════════════════════════════
  [
    {
      title: 'L 拍 · 残余探查候选',
      action: '图已稳定，唯一悬而未决的是 C2 外泄——但 H1 已达 78%，外泄不影响处置结论。',
      inputs: ['R4 终态图（全边确认）', 'H1 78% margin 63%', '义务全清'],
      outputs: ['+2 候选：C2 外泄通道、db-prod 数据库审计（VOI 均极低）'],
      computation: [
        'prior 读 H1 lifecycle → impact 已确认，残余候选少',
        'rule_gap：无新结构缺口',
      ],
      maintenance: ['【图】只读', '【决策账】只读'],
    },
    {
      title: '② 拍 · 全部义务已清',
      action: 'scan() 无新义务；VETO 无剪枝。候选通过检验。',
      inputs: ['候选 2 条', '无开放义务'],
      outputs: ['幸存池 2 条', '义务台账空'],
      computation: [
        'scan_structural / scan_lifecycle / scan_anti_forensics / scan_discriminative → 均无触发',
        'open_hard()=false, open_voi_gated()=[]',
      ],
      maintenance: ['【义务】空', '【候选池】不变'],
    },
    {
      title: 'O 拍 · maxVOI < ε · 余槽仅填 1 条',
      action: '所有候选 VOI 均 < ε；仅填 1 条做最后确认。预算允许最后一步。',
      inputs: ['候选 2 条 VOI 均 < 0.05', 'budget remaining = 1'],
      outputs: ['选中 1 条：C2 外泄通道（VOI 0.03）', 'budgetUsed: 11→12'],
      computation: [
        'maxVOI = 0.03 < EPS_VOI=0.05 → 接近 VOI 地板',
        '但预算未耗尽 → 最后一步确认',
      ],
      maintenance: ['【决策账】只读'],
    },
    {
      title: 'C 拍 · C2 查询无发现',
      action: '扇出执行 C2 外泄查询，结果为空——不影响决策。',
      inputs: ['Probe：C2 外泄通道', '网络流日志 API'],
      outputs: ['无新 confirmed_events', '图无变化'],
      computation: [
        'L0 去噪 → 无有效事件',
        'Beta：network.flow miss → 灵敏度下降',
      ],
      maintenance: ['【图】无变化', '【Beta】+1 miss'],
    },
    {
      title: 'K 拍 · 停止判定',
      action: 'should_stop() 四条件检查；maxVOI=0.03 < ε；decision_robust=true。',
      inputs: [
        'ledger H1 82% margin 67%',
        'hard 义务全清',
        'max_voi(probe_pool)=0.03',
        'LOSS 矩阵 + 置信扰动',
      ],
      outputs: [
        'stopSignals：budget ✓ hard ✓ voiFloor ✓ robust ✓',
        'StopDecision：robust + voi_floor',
        'budgetUsed: 12/12',
      ],
      computation: [
        'open_hard()=false',
        '生命周期/判别 soft 义务：VOI<EPS 不阻断',
        'decision_robust：CONTAIN 在 CI 扰动下不 flip',
        'maxVOI < EPS_VOI → 继续查「C2 外泄」不值',
      ],
      maintenance: ['【决策账】终态只读', '【Beta/义务/图】冻结', '准备 narrate → 报告'],
    },
    {
      title: 'STOP · 生成决策报告',
      action: 'narrate_agent 从 DecisionLedger + SessionGraph 生成交付物。',
      inputs: [
        '终态 DecisionLedger（H1 82%, H2 15%）',
        '剪枝边 + oos 列表',
        'stop_reason',
      ],
      outputs: [
        '处置：CONTAIN / ESCALATE',
        '标定置信 82%',
        '次优解释 + 反事实 + 攻击边界图',
      ],
      computation: [
        'MAP 解释 → leadingExplanation',
        'runner-up → suboptimal + reason',
        '敏感性探针 → counterfactual 一句',
      ],
      maintenance: ['【四本账】会话只读归档', '【报告】写入 demo report 页'],
    },
  ],
];

export function getStepExplain(roundIndex: number, phaseIndex: number): StepExplain | undefined {
  return phaseStepExplains[roundIndex]?.[phaseIndex];
}

/** 启动时将 stepExplain 挂到 mock 各 phase */
export function attachStepExplains<T extends { rounds: { phases: { stepExplain?: StepExplain }[] }[] }>(
  session: T,
): T {
  session.rounds.forEach((round, ri) => {
    round.phases.forEach((phase, pi) => {
      const explain = getStepExplain(ri, pi);
      if (explain) phase.stepExplain = explain;
    });
  });
  return session;
}
