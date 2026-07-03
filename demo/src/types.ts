export type LockPhase = 'L' | 'VETO' | 'O' | 'C' | 'K' | 'STOP';

export type DemoMode = 'guide' | 'investigator' | 'compare';

export type GraphNodeKind = 'host' | 'user' | 'process' | 'file' | 'email';

export interface GraphNode {
  id: string;
  label: string;
  kind: GraphNodeKind;
  x: number;
  y: number;
  malicious?: boolean;
  host?: string;
  tactic?: string;
  technique?: string;
  timestamp?: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  confirmed: boolean;
  contested?: boolean;
  pruned?: boolean;
  oos?: boolean;
  trust?: 'forge-resistant' | 'adversary-controlled' | 'missing';
}

export interface GraphSnapshot {
  nodes: GraphNode[];
  edges: GraphEdge[];
  meta?: {
    totalNodes: number;
    attackNodes: number;
    defaultFilter?: 'attack' | 'all';
  };
}

export interface Explanation {
  eid: string;
  label: string;
  posterior: number;
  isNull?: boolean;
  leading?: boolean;
  lifecycleStage?: string;
}

export interface BoundaryBelief {
  edgeId: string;
  edgeLabel: string;
  pInAttack: number;
  pBenign: number;
  pOos: number;
}

export interface DecisionLedgerSnapshot {
  explanations: Explanation[];
  contested: BoundaryBelief[];
  margin: number;
}

export interface ProbeCandidate {
  probe: string;
  voi: number;
  hitRate?: number;
  breakdown: { session: number; boundary: number; cost: number };
  selected?: boolean;
}

export interface Obligation {
  id: string;
  type: 'structure' | 'lifecycle' | 'anti-forensics' | 'discrimination';
  anchor: string;
  hard: boolean;
  voi: number;
  deadline: string;
  discharged?: boolean;
}

export interface BetaEntry {
  key: string;
  hits: number;
  total: number;
}

export interface StopSignals {
  budget: boolean;
  hardObligations: boolean;
  voiFloor: boolean;
  robust: boolean;
}

/** 每步弹出说明：做了什么 / 输入 / 产出 / 怎么算 / 维护了什么 */
export interface StepExplain {
  title: string;
  action: string;
  inputs: string[];
  outputs: string[];
  computation: string[];
  maintenance: string[];
}

/** 探针详情（L/VETO/O 拍） */
export interface ProbeDetail {
  id: string;
  operator: string;
  target: string;
  source: string;
  tactic: string;
  label: string;
}

/** 事件详情（C 拍） */
export interface EventDetail {
  technique: string;
  tactic: string;
  host: string;
  isAttack: boolean;
  isOos: boolean;
  source: string;
  routeBucket: string;
  id: string;
}

/** 每拍具体行为详情 */
export interface PhaseDetails {
  // L 拍
  probeCount?: number;
  probes?: ProbeDetail[];
  targets?: string[];
  sources?: string[];
  operators?: string[];
  // VETO 拍
  vetoedCount?: number;
  survivingCount?: number;
  survivingProbes?: ProbeDetail[];
  survivingTargets?: string[];
  // O 拍
  chosenCount?: number;
  chosenProbes?: ProbeDetail[];
  budgetRemaining?: number;
  // C 拍
  totalEvents?: number;
  confirmedCount?: number;
  graphEligibleCount?: number;
  bucketSummary?: Record<string, number>;
  attackEvents?: EventDetail[];
  allEventDetails?: EventDetail[];
  hostsTouched?: string[];
  // K 拍
  stopReason?: string;
  shouldStop?: boolean;
  probChanges?: Record<string, { before: number; after: number; delta: number }>;
  leading?: string;
  margin?: number;
  newGtHits?: string[];
  newGtCount?: number;
  gtTotal?: number;
  gtCumulative?: number;
  nodesBefore?: number;
  nodesAfter?: number;
  nodesAdded?: number;
  edgesBefore?: number;
  edgesAfter?: number;
  edgesAdded?: number;
}

export interface PhaseSnapshot {
  phase: LockPhase;
  summary: string;
  narration?: string;
  stepExplain?: StepExplain;
  graph: GraphSnapshot;
  decisionLedger: DecisionLedgerSnapshot;
  probePool: ProbeCandidate[];
  obligations: Obligation[];
  betaEntries: BetaEntry[];
  stopSignals: StopSignals;
  budgetUsed: number;
  phaseDetails?: PhaseDetails;
}

export interface RoundReplay {
  round: number;
  title: string;
  phases: PhaseSnapshot[];
}

export interface DemoSession {
  id: string;
  scenarioId?: string;
  scenarioName?: string;
  entryRef?: string;
  alert: {
    title: string;
    asset: string;
    triage: { malicious: boolean; critical: boolean };
  };
  budgetTotal: number;
  gtCoverage?: { hits: number; total: number; pct: number };
  rounds: RoundReplay[];
  report: DecisionReport;
}

export interface ScenarioInfo {
  id: string;
  name: string;
  description: string;
  tags: string[];
  gtTotal: number;
}

/** 每轮溯源发现摘要 */
export interface RoundNarrative {
  round: number;
  title: string;
  discovery: string;          // 本轮发现了什么
  techniques: string[];       // 发现的技术 ID
  tactics: string[];          // 发现的战术
  posteriorAfter: number;     // 本轮后 H1 后验
  nodesAdded: number;         // 新入图节点数
  edgesAdded: number;         // 新入图边数
}

/** 完整溯源过程叙事 */
export interface TraceNarrative {
  caseId: string;
  analyst: string;
  generatedAt: string;
  alertSummary: string;
  investigationGoal: string;
  killChainStages: { stage: string; technique: string; evidence: string; confidence: string }[];
  roundNarratives: RoundNarrative[];
  posteriorEvolution: { round: number; h1: number; h2: number; hNull: number }[];
  attackPath: string;         // 攻击路径文字描述
  conclusion: string;         // 最终结论
  recommendation: string;     // 处置建议
}

export interface DecisionReport {
  action: string;
  confidence: number;
  stopReason: string;
  leadingExplanation: string;
  suboptimalExplanation: { label: string; posterior: number; reason: string };
  counterfactual: string;
  prunedEdges: string[];
  oosItems: string[];
  traceNarrative?: TraceNarrative;
}
