export interface LockProgressEvent {
  kind: "lock_progress";
  tool_name: string;
  tool_call_id?: string;
  stage: string;
  phase?: "bootstrap" | "L" | "Veto" | "O" | "C" | "K";
  round?: number;
  status?: string;
  candidate_count?: number;
  probes_selected?: string[];
  events?: number;
  attached?: number;
  delta_p_atk?: number;
  stop_reason_candidate?: string;
  [key: string]: unknown;
}

export interface ToolCall {
  id: string;
  name: string;
  args: Record<string, unknown>;
  result?: string;
  status: "pending" | "completed" | "error" | "interrupted";
}

export interface SubAgent {
  id: string;
  name: string;
  subAgentName: string;
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
  status: "pending" | "active" | "completed" | "error";
}

export interface FileItem {
  path: string;
  content: string;
}

export interface TodoItem {
  id: string;
  content: string;
  status: "pending" | "in_progress" | "completed";
  updatedAt?: Date;
}

export interface Thread {
  id: string;
  title: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface InterruptData {
  value: any;
  ns?: string[];
  scope?: string;
}

export interface ActionRequest {
  name: string;
  args: Record<string, unknown>;
  description?: string;
}

export interface ReviewConfig {
  actionName: string;
  allowedDecisions?: string[];
}

export interface ToolApprovalInterruptData {
  action_requests: ActionRequest[];
  review_configs?: ReviewConfig[];
}

// ── LOCK Phase Progress Protocol (RFC-004-02) ──

export type LOCKPhase = "L" | "Veto" | "O" | "C" | "K";
export type LOCKEventKind = "phase_start" | "phase_end" | "stop_decision" | "round_summary";

/** 基类：所有 LOCK 拍级事件 */
export interface LOCKPhaseProgressEvent {
  kind: "lock_phase";        // 前端识别键
  event_kind: LOCKEventKind;
  phase: LOCKPhase;
  round: number;
  tool_name: string;
  tool_call_id?: string;
  timestamp: number;
}

/** L 拍：候选生成 */
export interface LPhaseEventData extends LOCKPhaseProgressEvent {
  phase: "L";
  candidates_count: number;
  pool_summary: Record<string, number>;
  prior_sources: string[];
}

/** ② 检验拍 */
export interface VetoPhaseEventData extends LOCKPhaseProgressEvent {
  phase: "Veto";
  vetoed_count: number;
  veto_reasons: Record<string, number>;
  mandated_count: number;
  obligation_types: Record<string, number>;
  surviving_count: number;
  trust_revisions: number;
}

/** O 拍：VOI 排序 */
export interface OPhaseEventData extends LOCKPhaseProgressEvent {
  phase: "O";
  voi_ranking: VOIRankingEntry[];
  slots_total: number;
  slots_filled: number;
  obligation_slots: number;
  llm_gate_triggered: boolean;
  max_voi: number;
}

/** VOI 排序条目（模型选择的 Wazuh 工具/探针） */
export interface VOIRankingEntry {
  probe: string;
  operator: string;      // Wazuh 操作符（如 query_alerts, get_process_tree 等）
  target: string;        // 目标资产/主机
  voi_score: number;
  risk_reduction: number;
  cost: number;
  source: string;
}

/** C 拍：扇出取证（包含 LLM 研判结果） */
export interface CPhaseEventData extends LOCKPhaseProgressEvent {
  phase: "C";
  events_fetched: number;
  attached: number;
  parked: number;
  discarded: number;
  spawned: number;
  weak_attached: number;
  trust_scores: Record<string, number>;
  delta_p_atk: number | null;
  // LLM 研判结果
  llm_judgements: LLMJudgementEntry[];
  wazuh_queries: WazuhQueryResult[];
  mcp_compiler_audit?: McpCompilerRoundAudit | null;
  triage_pipeline?: TriagePipeline;
}

/** L0-L4 Triage 级联管道 */
export interface TriagePipeline {
  raw_events: number;
  l0_clean: number;
  filtered: number;
  trust_tier_distribution: Record<string, number>;
  attribution_status_distribution: Record<string, number>;
  events: TriageEvent[];
}

export interface TriageEvent {
  id: string;
  technique: string;
  tactic: string;
  host: string;
  action: string;
  bucket: string;
  trust_tier: string;
  integrity: number;
  attribution_status: string;
  graph_eligible: boolean;
  probe_id: string;
}

/** LLM 研判条目（L4 入图研判） */
export interface LLMJudgementEntry {
  event_ref: string;
  verdict: "attach" | "park" | "discard" | "spawn" | "weak";
  confidence: number;
  reasoning: string;
}

/** Wazuh 查询结果 */
export interface WazuhQueryResult {
  operator: string;
  target: string;
  events_returned: number;
  events_matched?: number;
  records_returned?: number;
  shared_records?: number;
  query_group_size?: number;
  elapsed_ms: number;
  source?: "template" | "model_plan";
  mcp_tool?: string;
  query_preview?: string;
  validator_reasons?: string[];
  transport?: string;
}

export interface McpCompilerRoundAudit {
  round: number;
  mode: "off" | "shadow" | "assist";
  proposed: number;
  accepted: number;
  executed: number;
  fallback_probes: number;
  provider_status: string;
  plans?: McpCompilerPlanAudit[];
}

export interface McpCompilerPlanAudit {
  plan_id: string;
  source_probe_id: string;
  mcp_tool: string;
  accepted: boolean;
  query_preview?: string;
  validator_reasons: string[];
  hits?: number;
  latency_ms?: number;
  execution_status?: string;
}

/** K 拍：学习 + 决策账更新 */
/** 图节点快照（K 拍随事件流式下发） */
export interface GraphNodeSnapshot {
  id: string;
  technique: string;
  tactic: string;
  host: string;
  timestamp: number;
  attributed: boolean;
}

/** 图边快照 */
export interface GraphEdgeSnapshot {
  source: string;
  target: string;
  relation: string;
}

export interface KPhaseEventData extends LOCKPhaseProgressEvent {
  phase: "K";
  explanations: ExplanationSnapshot[];
  contested_edges: BoundaryBeliefSnapshot[];
  leading_explanation: string;
  margin: number;
  entropy: number;
  beta_updates: BetaUpdateEntry[];
  obligations_open: number;
  obligations_discharged: number;
  obligations_overdue: number;
  new_nodes: number;
  new_edges: number;
  graph_node_count: number;
  graph_edge_count: number;
  graph_nodes?: GraphNodeSnapshot[];
  graph_edges?: GraphEdgeSnapshot[];
  graph_truncated?: boolean;
}

/** 决策账中的解释快照 */
export interface ExplanationSnapshot {
  eid: string;
  label: string;
  posterior: number;
  is_null: boolean;
  null_kind: "benign" | "oos" | null;
  lifecycle_stage?: string;
}

/** 边界信念快照 */
export interface BoundaryBeliefSnapshot {
  edge_id: string;
  p_in_attack: number;
  p_benign: number;
  p_oos: number;
}

/** Beta 更新条目 */
export interface BetaUpdateEntry {
  probe_key: string;
  hit: boolean;
  new_alpha: number;
  new_beta: number;
}

/** 停止决策事件 */
export interface StopDecisionEventData extends LOCKPhaseProgressEvent {
  event_kind: "stop_decision";
  decision: "continue" | "stop";
  stop_reason: string;
  max_voi: number;
  eps_voi: number;
  decision_robust: boolean;
  hard_obligations_open: number;
  budget_remaining: { rounds: number; probes: number };
  reasoning: string;
}

/** 轮次汇总事件 */
export interface RoundSummaryEventData extends LOCKPhaseProgressEvent {
  event_kind: "round_summary";
  round_elapsed_seconds: number;
  total_rounds: number;
  graph_snapshot: Record<string, any>;
  ledger_snapshot: Record<string, any>;
  budget_snapshot: Record<string, any>;
}

/** 联合类型：所有拍级事件 */
export type LOCKPhaseEvent =
  | LPhaseEventData
  | VetoPhaseEventData
  | OPhaseEventData
  | CPhaseEventData
  | KPhaseEventData
  | StopDecisionEventData
  | RoundSummaryEventData;

/** 决策账完整快照（用于查询工具 get_decision_ledger 的返回） */
export interface DecisionLedgerSnapshot {
  explanations: ExplanationSnapshot[];
  contested: BoundaryBeliefSnapshot[];
  leading: string;
  margin: number;
  entropy: number;
  log_posteriors: Record<string, number>;
}

/** LOCK 阶段流数据（在 ChatInterface 中累积的拍级事件列表） */
export interface LOCKPhaseStream {
  events: LOCKPhaseEvent[];
  currentRound: number;
  currentPhase: LOCKPhase | null;
  isRunning: boolean;
}
