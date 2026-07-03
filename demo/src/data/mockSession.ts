import type { DemoSession, GraphSnapshot, PhaseSnapshot } from '../types';
import { attachStepExplains } from './stepExplains';

const baseNodes = [
  { id: 'mail-gw', label: 'mail-gw', kind: 'host' as const, x: 80, y: 120 },
  { id: 'ws-07', label: 'workstation-07', kind: 'host' as const, x: 220, y: 80 },
  { id: 'zhangsan', label: 'zhangsan', kind: 'user' as const, x: 220, y: 180 },
  { id: 'db-prod', label: 'db-prod-01', kind: 'host' as const, x: 400, y: 120, malicious: true },
  { id: 'ps1', label: 'powershell.exe', kind: 'process' as const, x: 400, y: 200, malicious: true },
  { id: 'encrypted', label: 'encrypted/*.lock', kind: 'file' as const, x: 520, y: 120 },
];

function graph(edges: GraphSnapshot['edges'], extraNodes: GraphSnapshot['nodes'] = []): GraphSnapshot {
  return { nodes: [...baseNodes, ...extraNodes], edges };
}

const r1EndGraph = graph([
  { id: 'e-mail', source: 'mail-gw', target: 'ws-07', label: '钓鱼附件', confirmed: true },
  { id: 'e-macro', source: 'ws-07', target: 'ps1', label: '宏执行', confirmed: true },
]);

const r2EndGraph = graph([
  { id: 'e-mail', source: 'mail-gw', target: 'ws-07', label: '钓鱼附件', confirmed: true },
  { id: 'e-macro', source: 'ws-07', target: 'ps1', label: '宏执行', confirmed: true },
  { id: 'e-rdp', source: 'zhangsan', target: 'db-prod', label: 'RDP 登录', confirmed: false, contested: true },
  { id: 'e-task', source: 'ws-07', target: 'db-prod', label: 'scheduled task', confirmed: true, trust: 'adversary-controlled' },
]);

const r3EndGraph = graph([
  { id: 'e-mail', source: 'mail-gw', target: 'ws-07', label: '钓鱼附件', confirmed: true },
  { id: 'e-macro', source: 'ws-07', target: 'ps1', label: '宏执行', confirmed: true },
  { id: 'e-rdp', source: 'zhangsan', target: 'db-prod', label: 'RDP 登录', confirmed: false, pruned: true },
  { id: 'e-task', source: 'ws-07', target: 'db-prod', label: 'scheduled task', confirmed: true, trust: 'adversary-controlled' },
]);

const r4EndGraph = graph(
  [
    { id: 'e-mail', source: 'mail-gw', target: 'ws-07', label: '钓鱼附件', confirmed: true },
    { id: 'e-macro', source: 'ws-07', target: 'ps1', label: '宏执行', confirmed: true },
    { id: 'e-rdp', source: 'zhangsan', target: 'db-prod', label: 'RDP 登录', confirmed: false, pruned: true },
    { id: 'e-task', source: 'ws-07', target: 'db-prod', label: 'scheduled task', confirmed: true, trust: 'adversary-controlled' },
    { id: 'e-loggap', source: 'db-prod', target: 'ps1', label: '日志断层 40min', confirmed: true, trust: 'missing' },
    { id: 'e-miner', source: 'ws-07', target: 'miner', label: 'xmrig (oos)', confirmed: true, oos: true },
  ],
  [{ id: 'miner', label: 'xmrig.exe', kind: 'process', x: 120, y: 240, malicious: true }],
);

const seedLedger = {
  explanations: [
    { eid: 'h1', label: '勒索软件投递链', posterior: 0.45, leading: true, lifecycleStage: 'initial-access' },
    { eid: 'h2', label: '合法运维批处理误报', posterior: 0.35 },
    { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.2, isNull: true },
  ],
  contested: [
    {
      edgeId: 'e-rdp',
      edgeLabel: 'zhangsan RDP → db-prod-01',
      pInAttack: 0.5,
      pBenign: 0.35,
      pOos: 0.15,
    },
  ],
  margin: 0.1,
};

function phase(partial: Partial<PhaseSnapshot> & Pick<PhaseSnapshot, 'phase' | 'summary'>): PhaseSnapshot {
  return {
    narration: '',
    graph: graph([]),
    decisionLedger: seedLedger,
    probePool: [],
    obligations: [],
    betaEntries: [],
    stopSignals: { budget: false, hardObligations: false, voiFloor: false, robust: false },
    budgetUsed: 0,
    ...partial,
  };
}

const _mockSession: DemoSession = {
  id: 'sess-ransom-001',
  alert: {
    title: '可疑 PowerShell 执行 + 文件加密行为',
    asset: 'db-prod-01（核心数据库）',
    triage: { malicious: true, critical: true },
  },
  budgetTotal: 12,
  rounds: [
    // ═══════════════════════════════════════════════════════════
    // Round 1: bootstrap + 薄播种决策账
    // ═══════════════════════════════════════════════════════════
    {
      round: 1,
      title: 'bootstrap + 薄播种决策账',
      phases: [
        phase({
          phase: 'L',
          summary: 'prior / 规则图诊断 → 8 条探针入池',
          narration: '开局只有告警 E。生成层往统一候选池投掷探针想法。',
          probePool: [
            { probe: '查邮件网关附件 hash', voi: 0.28, hitRate: 0.72, breakdown: { session: 0.24, boundary: 0, cost: 0.04 } },
            { probe: '查 db-prod PowerShell 父进程', voi: 0.22, hitRate: 0.65, breakdown: { session: 0.18, boundary: 0, cost: 0.04 } },
            { probe: '查 zhangsan 登录来源', voi: 0.08, hitRate: 0.15, breakdown: { session: 0.02, boundary: 0.04, cost: 0.04 } },
          ],
          budgetUsed: 0,
        }),
        phase({
          phase: 'VETO',
          summary: '2 条硬删 · 1 条标对手可控（仅软降权）',
          narration: '硬 VETO 只给抗伪事实；被污染证据不能永久杀死真路径。',
          probePool: [
            { probe: '查邮件网关附件 hash', voi: 0.28, hitRate: 0.72, breakdown: { session: 0.24, boundary: 0, cost: 0.04 } },
            { probe: '查 db-prod PowerShell 父进程', voi: 0.22, hitRate: 0.65, breakdown: { session: 0.18, boundary: 0, cost: 0.04 } },
          ],
          obligations: [
            { id: 'o1', type: 'structure', anchor: '恶意孤儿进程 ps1', hard: true, voi: 0.35, deadline: 'R+2' },
          ],
          budgetUsed: 0,
        }),
        phase({
          phase: 'O',
          summary: 'VOI 排序 · Top-3 选中（补全 H1 为主）',
          narration: 'O 拍读决策账：按期望决策风险削减排序，不是单纯命中率。',
          probePool: [
            { probe: '查邮件网关附件 hash', voi: 0.28, hitRate: 0.72, breakdown: { session: 0.24, boundary: 0, cost: 0.04 }, selected: true },
            { probe: '查 db-prod PowerShell 父进程', voi: 0.22, hitRate: 0.65, breakdown: { session: 0.18, boundary: 0, cost: 0.04 }, selected: true },
            { probe: '查 scheduled task 触发源', voi: 0.15, hitRate: 0.41, breakdown: { session: 0.12, boundary: 0, cost: 0.04 }, selected: true },
          ],
          budgetUsed: 3,
        }),
        phase({
          phase: 'C',
          summary: '扇出取证 · 邮件宏 → db-prod 新边入图',
          narration: 'C 拍并发查出去，结果经入图判假级联后写入攻击图。',
          graph: r1EndGraph,
          probePool: [
            { probe: '查邮件网关附件 hash', voi: 0.28, selected: true, breakdown: { session: 0.24, boundary: 0, cost: 0.04 } },
          ],
          budgetUsed: 3,
        }),
        phase({
          phase: 'K',
          summary: '决策账 H1: 45%→62% · Beta +1 hit',
          narration: 'K 拍写第四本账——不是外环，就在同一循环里。',
          graph: r1EndGraph,
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.62, leading: true, lifecycleStage: 'execution' },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.28 },
              { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.1, isNull: true },
            ],
            contested: seedLedger.contested,
            margin: 0.34,
          },
          betaEntries: [
            { key: 'email.hash × gateway', hits: 8, total: 11 },
            { key: 'process.parent × db-prod', hits: 5, total: 9 },
          ],
          obligations: [
            { id: 'o1', type: 'structure', anchor: '恶意孤儿进程 ps1', hard: true, voi: 0.35, deadline: 'R+2' },
          ],
          stopSignals: { budget: false, hardObligations: false, voiFloor: false, robust: false },
          budgetUsed: 3,
        }),
      ],
    },

    // ═══════════════════════════════════════════════════════════
    // Round 2: 歧义上升 · 判别义务
    // ═══════════════════════════════════════════════════════════
    {
      round: 2,
      title: '歧义上升 · 判别义务',
      phases: [
        phase({
          phase: 'L',
          summary: '规则缺口 + prior → 6 条新候选',
          graph: r1EndGraph,
          budgetUsed: 3,
        }),
        phase({
          phase: 'VETO',
          summary: 'scheduled task 路径保留（未抗伪证伪 → 软降权）',
          graph: graph([
            { id: 'e-mail', source: 'mail-gw', target: 'ws-07', label: '钓鱼附件', confirmed: true },
            { id: 'e-macro', source: 'ws-07', target: 'ps1', label: '宏执行', confirmed: true },
            { id: 'e-rdp', source: 'zhangsan', target: 'db-prod', label: 'RDP 登录', confirmed: false, contested: true },
          ]),
          obligations: [
            { id: 'o2', type: 'discrimination', anchor: 'H1 vs H2 @ scheduled task', hard: false, voi: 0.41, deadline: 'R+1' },
            { id: 'o1', type: 'structure', anchor: '恶意孤儿进程 ps1', hard: true, voi: 0.35, deadline: 'R+2', discharged: true },
          ],
          budgetUsed: 3,
        }),
        phase({
          phase: 'O',
          summary: 'margin 缩小 · 判别探针与定界探针竞争',
          graph: graph([
            { id: 'e-mail', source: 'mail-gw', target: 'ws-07', label: '钓鱼附件', confirmed: true },
            { id: 'e-macro', source: 'ws-07', target: 'ps1', label: '宏执行', confirmed: true },
            { id: 'e-rdp', source: 'zhangsan', target: 'db-prod', label: 'RDP 登录', confirmed: false, contested: true },
          ]),
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.55, leading: true, lifecycleStage: 'lateral-movement' },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.35 },
              { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.1, isNull: true },
            ],
            contested: seedLedger.contested,
            margin: 0.08,
          },
          probePool: [
            { probe: '查 zhangsan 登录来源与票据', voi: 0.38, hitRate: 0.12, breakdown: { session: 0.08, boundary: 0.28, cost: 0.04 }, selected: true },
            { probe: '查 scheduled task 父进程链', voi: 0.35, hitRate: 0.58, breakdown: { session: 0.31, boundary: 0, cost: 0.04 }, selected: true },
            { probe: '查 ws-07 挖矿进程', voi: 0.18, hitRate: 0.22, breakdown: { session: 0.05, boundary: 0.11, cost: 0.04 } },
          ],
          budgetUsed: 6,
        }),
        phase({
          phase: 'C',
          summary: 'H2 证据上升 · 争议边仍悬而未决',
          graph: r2EndGraph,
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.48, leading: true },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.42 },
              { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.1, isNull: true },
            ],
            contested: [
              { edgeId: 'e-rdp', edgeLabel: 'zhangsan RDP → db-prod-01', pInAttack: 0.45, pBenign: 0.4, pOos: 0.15 },
            ],
            margin: 0.06,
          },
          budgetUsed: 6,
        }),
        phase({
          phase: 'K',
          summary: '决策账更新 · 判别义务仍 open（VOI 门控）',
          graph: r2EndGraph,
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.48, leading: true },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.42 },
              { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.1, isNull: true },
            ],
            contested: [
              { edgeId: 'e-rdp', edgeLabel: 'zhangsan RDP → db-prod-01', pInAttack: 0.45, pBenign: 0.4, pOos: 0.15 },
            ],
            margin: 0.06,
          },
          betaEntries: [
            { key: 'email.hash × gateway', hits: 9, total: 12 },
            { key: 'process.parent × db-prod', hits: 5, total: 10 },
            { key: 'auth.log × zhangsan', hits: 3, total: 7 },
            { key: 'task.scheduler × ws-07', hits: 4, total: 8 },
          ],
          obligations: [
            { id: 'o2', type: 'discrimination', anchor: 'H1 vs H2 @ scheduled task', hard: false, voi: 0.41, deadline: 'R+1' },
          ],
          stopSignals: { budget: false, hardObligations: true, voiFloor: false, robust: false },
          budgetUsed: 6,
        }),
      ],
    },

    // ═══════════════════════════════════════════════════════════
    // Round 3: 定界探针 VOI 排第一 · 剪枝
    // ═══════════════════════════════════════════════════════════
    {
      round: 3,
      title: '定界探针 VOI 排第一 · 剪枝',
      phases: [
        phase({
          phase: 'L',
          summary: '定界候选 + lifecycle 缺口 → 4 条入池',
          narration: '争议边高熵 → 定界探针候选入池；H1 推进到 lateral-movement 但 impact 未确立 → lifecycle 候选。',
          graph: r2EndGraph,
          probePool: [
            { probe: '查 zhangsan 登录来源与票据', voi: 0.38, hitRate: 0.12, breakdown: { session: 0.08, boundary: 0.28, cost: 0.04 } },
            { probe: '查 scheduled task 父进程链', voi: 0.29, hitRate: 0.58, breakdown: { session: 0.25, boundary: 0, cost: 0.04 } },
            { probe: '查 db-prod 文件加密痕迹', voi: 0.2, hitRate: 0.45, breakdown: { session: 0.18, boundary: 0, cost: 0.04 } },
            { probe: '查 ws-07 挖矿进程', voi: 0.18, hitRate: 0.22, breakdown: { session: 0.05, boundary: 0.11, cost: 0.04 } },
          ],
          budgetUsed: 6,
        }),
        phase({
          phase: 'VETO',
          summary: 'lifecycle 义务出现（impact 阶段未确立）· 判别义务 o2 仍 open',
          narration: 'H1 推进到 lateral-movement，但 impact 阶段（加密/外泄）尚未在图中确认 → lifecycle 义务。',
          graph: r2EndGraph,
          obligations: [
            { id: 'o2', type: 'discrimination', anchor: 'H1 vs H2 @ scheduled task', hard: false, voi: 0.41, deadline: 'R+1' },
            { id: 'o4', type: 'lifecycle', anchor: 'H1 缺失 impact 阶段', hard: false, voi: 0.25, deadline: 'R+2' },
          ],
          budgetUsed: 6,
        }),
        phase({
          phase: 'O',
          summary: '⭐ 定界探针 VOI #1（边界项 0.32 > 会话项 0.08）',
          narration: '确认「不属于本案」和「挖到恶意」一样值钱——这是 RFC-004-02 的核心差异。',
          graph: r2EndGraph,
          probePool: [
            { probe: '查 zhangsan 登录来源与票据', voi: 0.42, hitRate: 0.12, breakdown: { session: 0.08, boundary: 0.32, cost: 0.04 }, selected: true },
            { probe: '查 db-prod 文件加密痕迹', voi: 0.2, hitRate: 0.45, breakdown: { session: 0.18, boundary: 0, cost: 0.04 }, selected: true },
            { probe: '查 scheduled task 父进程链', voi: 0.15, hitRate: 0.58, breakdown: { session: 0.13, boundary: 0, cost: 0.04 } },
          ],
          budgetUsed: 8,
        }),
        phase({
          phase: 'C',
          summary: 'RDP 为日常运维 → 边界收敛到 benign · 加密痕迹确认 impact',
          narration: 'AD 日志确认 zhangsan RDP 为日常运维；文件系统确认加密行为 → lifecycle 履行。',
          graph: r3EndGraph,
          budgetUsed: 9,
        }),
        phase({
          phase: 'K',
          summary: 'zhangsan 边剪枝定界 · H1 回升至 68% · lifecycle 履行（加密确认 impact）',
          narration: '剪掉一条良性边 → 爆炸半径缩小 → H1 后验上升。lifecycle 义务因 impact 确认而 discharge。',
          graph: r3EndGraph,
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.68, leading: true, lifecycleStage: 'impact' },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.22 },
              { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.1, isNull: true },
            ],
            contested: [
              { edgeId: 'e-rdp', edgeLabel: 'zhangsan RDP → db-prod-01', pInAttack: 0.05, pBenign: 0.9, pOos: 0.05 },
            ],
            margin: 0.46,
          },
          betaEntries: [
            { key: 'email.hash × gateway', hits: 9, total: 12 },
            { key: 'process.parent × db-prod', hits: 6, total: 11 },
            { key: 'auth.log × zhangsan', hits: 4, total: 8 },
            { key: 'file.forensics × db-prod', hits: 7, total: 10 },
          ],
          obligations: [
            { id: 'o2', type: 'discrimination', anchor: 'H1 vs H2 @ scheduled task', hard: false, voi: 0.41, deadline: 'R+1', discharged: true },
            { id: 'o4', type: 'lifecycle', anchor: 'H1 缺失 impact 阶段', hard: false, voi: 0.25, deadline: 'R+2', discharged: true },
          ],
          stopSignals: { budget: false, hardObligations: true, voiFloor: false, robust: false },
          budgetUsed: 9,
        }),
      ],
    },

    // ═══════════════════════════════════════════════════════════
    // Round 4: 反取证义务 · 日志断层
    // ═══════════════════════════════════════════════════════════
    {
      round: 4,
      title: '反取证义务 · 日志断层',
      phases: [
        phase({
          phase: 'L',
          summary: '反取证缺口 + C2 探查候选 → 5 条入池',
          narration: 'db-prod 审计完整性需验证；ws-07 可能有其他恶意进程。',
          graph: r3EndGraph,
          probePool: [
            { probe: '查 db-prod 审计日志完整性', voi: 0.52, hitRate: 0.3, breakdown: { session: 0.22, boundary: 0.3, cost: 0.04 } },
            { probe: '查 ws-07 进程树全量', voi: 0.31, hitRate: 0.55, breakdown: { session: 0.28, boundary: 0, cost: 0.04 } },
            { probe: '查 C2 外泄通道', voi: 0.12, hitRate: 0.18, breakdown: { session: 0.1, boundary: 0, cost: 0.06 } },
          ],
          budgetUsed: 9,
        }),
        phase({
          phase: 'VETO',
          summary: '反取证义务 hard 🔒 · 生命周期/判别已清',
          narration: '「没叫的狗」——缺失即信号，不是空白。反取证义务 hard 阻断停止。',
          graph: r3EndGraph,
          obligations: [
            { id: 'o3', type: 'anti-forensics', anchor: 'db-prod-01 审计日志断层', hard: true, voi: 0.52, deadline: 'R+1' },
          ],
          budgetUsed: 9,
        }),
        phase({
          phase: 'O',
          summary: '反取证探针 VOI 最高（硬义务预占槽）',
          narration: '硬义务预占 ≤⌈B/2⌉ 槽位；余槽填 VOI 排序的 ws-07 进程树探针。',
          graph: r3EndGraph,
          probePool: [
            { probe: '查 db-prod 审计日志完整性', voi: 0.52, hitRate: 0.3, breakdown: { session: 0.22, boundary: 0.3, cost: 0.04 }, selected: true },
            { probe: '查 ws-07 进程树全量', voi: 0.31, hitRate: 0.55, breakdown: { session: 0.28, boundary: 0, cost: 0.04 }, selected: true },
          ],
          budgetUsed: 10,
        }),
        phase({
          phase: 'C',
          summary: 'db-prod 日志断层 → 反取证义务 🔒 · ws-07 发现 xmrig',
          narration: '40 分钟审计日志断层 → 缺失即信号。ws-07 进程树发现 xmrig 挖矿 → oos 标记。',
          graph: r4EndGraph,
          obligations: [
            { id: 'o3', type: 'anti-forensics', anchor: 'db-prod-01 审计日志断层', hard: true, voi: 0.52, deadline: 'R+1', discharged: true },
          ],
          stopSignals: { budget: false, hardObligations: false, voiFloor: false, robust: false },
          budgetUsed: 11,
        }),
        phase({
          phase: 'K',
          summary: '反取证查完 · ws-07 挖矿标 oos → SPAWN 候选',
          narration: 'o3 discharged；xmrig 是真恶意但域外 → SPAWN 另案。',
          graph: r4EndGraph,
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.78, leading: true, lifecycleStage: 'impact' },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.15 },
              { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.07, isNull: true },
            ],
            contested: [],
            margin: 0.63,
          },
          betaEntries: [
            { key: 'email.hash × gateway', hits: 9, total: 12 },
            { key: 'process.parent × db-prod', hits: 6, total: 11 },
            { key: 'auth.log × zhangsan', hits: 4, total: 8 },
            { key: 'file.forensics × db-prod', hits: 8, total: 11 },
            { key: 'audit.integrity × db-prod', hits: 2, total: 3 },
            { key: 'process.scan × ws-07', hits: 7, total: 12 },
          ],
          obligations: [
            { id: 'o3', type: 'anti-forensics', anchor: 'db-prod-01 审计日志断层', hard: true, voi: 0.52, deadline: 'R+1', discharged: true },
          ],
          stopSignals: { budget: false, hardObligations: true, voiFloor: false, robust: false },
          budgetUsed: 11,
        }),
      ],
    },

    // ═══════════════════════════════════════════════════════════
    // Round 5: 价值导向停止 → 交付
    // ═══════════════════════════════════════════════════════════
    {
      round: 5,
      title: '价值导向停止 → 交付',
      phases: [
        phase({
          phase: 'L',
          summary: '残余探查候选（C2 外泄通道）→ 2 条入池',
          narration: '图已稳定，唯一悬而未决的是 C2 外泄——但 H1 已达 78%，外泄不影响处置结论。',
          graph: r4EndGraph,
          probePool: [
            { probe: '查 C2 外泄通道', voi: 0.03, hitRate: 0.18, breakdown: { session: 0.02, boundary: 0, cost: 0.06 } },
            { probe: '查 db-prod 数据库审计', voi: 0.02, hitRate: 0.12, breakdown: { session: 0.01, boundary: 0, cost: 0.06 } },
          ],
          budgetUsed: 11,
        }),
        phase({
          phase: 'VETO',
          summary: '全部义务已清 · 候选通过 VETO',
          narration: '无硬义务阻断；候选 VOI 均极低。',
          graph: r4EndGraph,
          obligations: [],
          budgetUsed: 11,
        }),
        phase({
          phase: 'O',
          summary: 'maxVOI = 0.03 < ε · 余槽仅填 1 条',
          narration: '继续查也不改处置结论——但预算允许最后一步确认。',
          graph: r4EndGraph,
          probePool: [
            { probe: '查 C2 外泄通道', voi: 0.03, hitRate: 0.18, breakdown: { session: 0.02, boundary: 0, cost: 0.06 }, selected: true },
          ],
          budgetUsed: 11,
        }),
        phase({
          phase: 'C',
          summary: 'C2 查询无发现 · 无新确认事件',
          narration: '扇出执行，结果为空——不影响决策。',
          graph: r4EndGraph,
          budgetUsed: 12,
        }),
        phase({
          phase: 'K',
          summary: 'maxVOI < ε · 决策鲁棒 · 硬义务已清',
          narration: '再查也不改处置结论——溯源够了。',
          graph: r4EndGraph,
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.82, leading: true, lifecycleStage: 'impact' },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.15 },
              { eid: 'null', label: '分支定界 (null 锚)', posterior: 0.03, isNull: true },
            ],
            contested: [],
            margin: 0.67,
          },
          betaEntries: [
            { key: 'email.hash × gateway', hits: 9, total: 12 },
            { key: 'process.parent × db-prod', hits: 6, total: 11 },
            { key: 'auth.log × zhangsan', hits: 4, total: 8 },
            { key: 'file.forensics × db-prod', hits: 8, total: 11 },
            { key: 'audit.integrity × db-prod', hits: 2, total: 3 },
            { key: 'process.scan × ws-07', hits: 7, total: 12 },
            { key: 'network.flow × gateway', hits: 0, total: 1 },
          ],
          probePool: [
            { probe: '查 C2 外泄通道', voi: 0.03, breakdown: { session: 0.02, boundary: 0, cost: 0.06 } },
          ],
          stopSignals: { budget: true, hardObligations: true, voiFloor: true, robust: true },
          budgetUsed: 12,
        }),
        phase({
          phase: 'STOP',
          summary: '会话结束 → 生成决策报告',
          narration: '再查也不改处置结论——溯源够了。',
          graph: r4EndGraph,
          decisionLedger: {
            explanations: [
              { eid: 'h1', label: '勒索软件投递链', posterior: 0.82, leading: true },
              { eid: 'h2', label: '合法运维批处理误报', posterior: 0.15 },
            ],
            contested: [],
            margin: 0.67,
          },
          stopSignals: { budget: true, hardObligations: true, voiFloor: true, robust: true },
          budgetUsed: 12,
        }),
      ],
    },
  ],
  report: {
    action: 'CONTAIN / ESCALATE',
    confidence: 0.82,
    stopReason: '决策鲁棒 + maxVOI < ε + 硬义务已清',
    leadingExplanation: '勒索软件投递链：钓鱼邮件 → 宏 → PowerShell → 加密 db-prod-01',
    suboptimalExplanation: {
      label: '合法运维批处理误报',
      posterior: 0.15,
      reason: 'scheduled task 存在但无法解释加密行为与宏投递链',
    },
    counterfactual: '若 C 内核日志显示 zhangsan 登录票据伪造失败，则横向路径需重评',
    prunedEdges: ['zhangsan RDP → db-prod-01（良性运维，已剪枝定界）'],
    oosItems: ['workstation-07 xmrig 挖矿 → 建议 SPAWN 另案溯源'],
  },
};

export const mockSession: DemoSession = attachStepExplains(_mockSession);
