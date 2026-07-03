import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { DemoMode, LockPhase, PhaseSnapshot, StepExplain, DemoSession, PhaseDetails } from '../types';
import { mockSession } from '../data/mockSession';
import { fetchSession } from '../data/apiSession';

const PHASE_ORDER: LockPhase[] = ['L', 'VETO', 'O', 'C', 'K', 'STOP'];

/** Generate a rich StepExplain from phase snapshot data + phaseDetails. */
function generateStepExplain(phase: PhaseSnapshot, round: number): StepExplain {
  const phaseLabels: Record<LockPhase, string> = {
    L: 'L 拍 · 候选生成',
    VETO: '② 拍 · 检验过滤',
    O: 'O 拍 · VOI 排序填槽',
    C: 'C 拍 · 扇出取证入图',
    K: 'K 拍 · 学习 + 停止判定',
    STOP: 'STOP · 会话结束',
  };

  const d = phase.phaseDetails;
  const ledger = phase.decisionLedger;
  const leading = ledger.explanations.find((e) => e.leading) ?? ledger.explanations[0];
  const obligationsActive = phase.obligations.filter((o) => !o.discharged);

  // ── Phase-specific rich content ──
  const inputs: string[] = [];
  const outputs: string[] = [];
  const computation: string[] = [];
  const maintenance: string[] = [];
  let action = phase.summary;

  if (d) {
    switch (phase.phase) {
      case 'L': {
        const probes = d.probes ?? [];
        const probeLines = probes.slice(0, 8).map(p => `  ${p.label} (${p.source})`);
        action = `生成 ${d.probeCount ?? probes.length} 条候选探针，来自 ${d.sources?.length ?? 0} 个生成器`;
        inputs.push(`图 ${(phase.graph.nodes.length)} 节点 · ${(phase.graph.edges.length)} 边`);
        inputs.push(`生成器: ${(d.sources ?? []).join(', ')}`);
        outputs.push(`候选探针 ${d.probeCount ?? probes.length} 条:`);
        outputs.push(...probeLines);
        if (probes.length > 8) outputs.push(`  ...及其他 ${(d.probeCount ?? probes.length) - 8} 条`);
        outputs.push(`目标主机: ${(d.targets ?? []).join(', ')}`);
        computation.push('prior_generator: 沿决策账 leading 解释的 frontier 反向延伸候选');
        computation.push('cross_host / chain_follow / rule_gap: 结构缺口 + 主机覆盖候补');
        maintenance.push('【图】只读', '【决策账】只读（供 prior 方向）', '【Beta/义务】未写');
        break;
      }
      case 'VETO': {
        action = `过滤 ${d.vetoedCount ?? 0} 条 · 幸存 ${d.survivingCount ?? 0} 条`;
        inputs.push(`候选池 ${(d.vetoedCount ?? 0) + (d.survivingCount ?? 0)} 条`);
        inputs.push(`图不变量 / 时序约束 / 已知主机列表`);
        const surviving = d.survivingProbes ?? [];
        outputs.push(`幸存探针 ${(d.survivingCount ?? surviving.length)} 条:`);
        outputs.push(...surviving.slice(0, 8).map(p => `  ${p.label}`));
        outputs.push(`幸存目标: ${(d.survivingTargets ?? []).join(', ')}`);
        computation.push('非主机名过滤: 移除 target 不在已知主机列表中的探针');
        computation.push('Beta 灵敏度 VETO: 历史命中率为 0 的 (target, operator) 对被过滤');
        maintenance.push('【义务】扫描结构缺口 / 生命周期 / 反取证 / 判别', '【候选池】缩减为幸存集');
        break;
      }
      case 'O': {
        const chosen = d.chosenProbes ?? [];
        action = `VOI 排序 · 选中 ${d.chosenCount ?? chosen.length} 条探针`;
        inputs.push(`幸存候选池 ${(d.chosenCount ?? chosen.length) + 0} 条`);
        inputs.push(`DecisionLedger: margin=${(ledger.margin * 100).toFixed(1)}%`);
        inputs.push(`Budget: ${phase.budgetUsed} / ${phase.budgetUsed + (d.budgetRemaining ?? 0)} 已用`);
        outputs.push(`选中探针 ${chosen.length} 条:`);
        outputs.push(...chosen.map(p => `  ${p.label} [${p.tactic}]`));
        outputs.push(`目标主机: ${(d.targets ?? []).join(', ')}`);
        outputs.push(`算子: ${(d.operators ?? []).join(', ')}`);
        computation.push('VOI(p) = 期望决策风险削减 − 成本');
        computation.push('staleness bonus: 长期未探查主机获得加分 (R4+ 生效)');
        computation.push(`Budget 剩余: ${d.budgetRemaining ?? 0}`);
        maintenance.push('【决策账】只读（O 拍读 VOI）', '【义务】mandated 预占槽位', '【Beta】只读');
        break;
      }
      case 'C': {
        const events = d.allEventDetails ?? [];
        const attacks = d.attackEvents ?? [];
        const buckets = d.bucketSummary ?? {};
        action = `扇出取证 · 返回 ${d.totalEvents ?? events.length} 条事件 · ${d.confirmedCount ?? 0} 确认 · ${d.graphEligibleCount ?? 0} 入图`;
        inputs.push(`选中探针 ${phase.probePool.filter(p => p.selected).length} 条`);
        inputs.push(`ScenarioExecutor · SOAR 场景 JSON · 时间游标推进`);
        outputs.push(`事件总计 ${d.totalEvents ?? events.length} 条:`);
        outputs.push(`  桶路由: ${Object.entries(buckets).map(([k, v]) => `${k}=${v}`).join(', ')}`);
        if (attacks.length > 0) {
          outputs.push(`攻击事件 ${attacks.length} 条:`);
          outputs.push(...attacks.slice(0, 6).map(e => `  ${e.technique} @ ${e.host} (${e.tactic}) → ${e.routeBucket || '?'}`));
        }
        outputs.push(`涉及主机: ${(d.hostsTouched ?? []).join(', ')}`);
        computation.push('L0 去重 → L1 结构挂接 (时间窗口+tactic) → L2 信任评估');
        computation.push('L3 解释归属 (log_likelihood 评分) → L4 路由 5 桶');
        computation.push('commit_event_refs: 所有返回事件标记为已消费');
        maintenance.push(`【图】+${d.graphEligibleCount ?? 0} 条入图`, '【证据信任】入账', '【决策账/Beta】本拍不写，等 K');
        break;
      }
      case 'K': {
        const probChanges = d.probChanges ?? {};
        const changeLines = Object.entries(probChanges).map(([eid, ch]) => {
          const arrow = ch.delta > 0 ? '↑' : ch.delta < 0 ? '↓' : '→';
          return `  ${eid}: ${(ch.before * 100).toFixed(1)}% ${arrow} ${(ch.after * 100).toFixed(1)}%`;
        });
        action = `后验更新 · leading=${d.leading ?? '?'} · margin=${((d.margin ?? 0) * 100).toFixed(1)}% · stop=${d.stopReason ?? '?'}`;
        inputs.push('C 拍 confirmed_events + trust');
        inputs.push(`chosen Probes ${(d.nodesAdded ?? 0) > 0 ? '(本轮有新入图)' : '(本轮无新入图)'}`);
        outputs.push('后验变化:');
        outputs.push(...changeLines);
        if ((d.newGtCount ?? 0) > 0) {
          outputs.push(`GT 新增命中 ${d.newGtCount} 条: ${(d.newGtHits ?? []).join(', ')}`);
        }
        outputs.push(`GT 累计: ${d.gtCumulative ?? 0}/${d.gtTotal ?? 0}`);
        outputs.push(`图: ${d.nodesBefore ?? 0}→${d.nodesAfter ?? 0} 节点 (+${d.nodesAdded ?? 0}) · ${d.edgesBefore ?? 0}→${d.edgesAfter ?? 0} 边 (+${d.edgesAdded ?? 0})`);
        computation.push('log_post(H) += log P(e|H) − log P(e|null); 归一化');
        computation.push('Beta hit/miss 更新 · 义务消解');
        if (d.shouldStop) {
          computation.push(`should_stop = True (${d.stopReason})`);
        } else {
          computation.push(`should_stop = False → 继续`);
        }
        maintenance.push(`【图】+${d.nodesAdded ?? 0} 节点 · +${d.edgesAdded ?? 0} 边`);
        maintenance.push(`【决策账⭐】写后验 · margin=${((d.margin ?? 0) * 100).toFixed(1)}%`);
        maintenance.push('【Beta】更新', `【义务】${obligationsActive.length} 条未清`);
        break;
      }
      case 'STOP': {
        action = `会话结束 (${d.stopReason ?? 'budget'}) · 生成决策报告`;
        inputs.push('终态 DecisionLedger', '终态 SessionGraph', 'stop_reason');
        outputs.push(`处置: ${leading?.label ?? '?'}`);
        outputs.push(`GT 最终: ${d.gtCumulative ?? 0}/${d.gtTotal ?? 0}`);
        outputs.push(`图终态: ${d.nodesAfter ?? 0} 节点 · ${d.edgesAfter ?? 0} 边`);
        computation.push('narrate → 标定置信 + 次优解释 + 反事实 + 攻击边界');
        maintenance.push('【四本账】会话只读归档', '【报告】写入 demo report 页');
        break;
      }
    }
  }

  // Fallback: if no phaseDetails, use generic explanation
  if (inputs.length === 0) {
    inputs.push(
      phase.graph.nodes.length > 0
        ? `SessionGraph (${phase.graph.nodes.length} 节点, ${phase.graph.edges.length} 边)`
        : 'SessionGraph (空)',
      `DecisionLedger: margin=${(ledger.margin * 100).toFixed(1)}%`,
      phase.obligations.length > 0
        ? `ObligationLedger: ${phase.obligations.length} 条 (${obligationsActive.length} 未清)`
        : 'ObligationLedger: 空',
    );
    outputs.push(
      phase.probePool.length > 0
        ? `候选池 ${phase.probePool.length} 条 (VOI top: ${phase.probePool[0]?.voi.toFixed(3) ?? 'N/A'})`
        : '候选池空',
      `Budget: ${phase.budgetUsed} probes used`,
      leading
        ? `Leading: ${leading.label} (${(leading.posterior * 100).toFixed(1)}%)`
        : 'Leading: N/A',
    );
    computation.push(
      `Stop signals: budget=${phase.stopSignals.budget}, hard=${phase.stopSignals.hardObligations}, voiFloor=${phase.stopSignals.voiFloor}, robust=${phase.stopSignals.robust}`,
      `Beta entries: ${phase.betaEntries.length}`,
    );
    maintenance.push(
      phase.obligations.length > 0
        ? `【义务】${phase.obligations.map((o) => `${o.id}:${o.type}${o.discharged ? '✓' : '⏳'}`).join(', ')}`
        : '【义务】空',
      `【Beta】${phase.betaEntries.length} 条记录`,
      `【图】${phase.graph.nodes.length} 节点 · ${phase.graph.edges.length} 边`,
      `【决策账⭐】margin=${(ledger.margin * 100).toFixed(1)}%`,
    );
  }

  return {
    title: `${phaseLabels[phase.phase]} · Round ${round}`,
    action,
    inputs,
    outputs,
    computation,
    maintenance,
  };
}

/** Attach stepExplains to API-returned session data. */
function enrichSession(session: DemoSession): DemoSession {
  for (const round of session.rounds) {
    for (const phase of round.phases) {
      if (!phase.stepExplain) {
        phase.stepExplain = generateStepExplain(phase, round.round);
      }
    }
  }
  return session;
}

export interface PlaybackState {
  roundIndex: number;
  phaseIndex: number;
  round: number;
  phase: LockPhase;
  snapshot: PhaseSnapshot;
  roundTitle: string;
  totalRounds: number;
  isFinished: boolean;
  mode: DemoMode;
  isPlaying: boolean;
  narration: string;
}

export function useDemoPlayback(
  initialMode: DemoMode = 'guide',
  playbackBlocked = false,
  scenarioId?: string,
) {
  const [session, setSession] = useState<DemoSession>(mockSession);
  const [isLoading, setIsLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [dataSource, setDataSource] = useState<'mock' | 'api'>('mock');
  const [mode, setMode] = useState<DemoMode>(initialMode);
  const [roundIndex, setRoundIndex] = useState(0);
  const [phaseIndex, setPhaseIndex] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);
  const fetchedRef = useRef<string | null>(null);

  // Fetch real session from backend when scenarioId changes
  useEffect(() => {
    const sid = scenarioId || 'pipeline_18';
    if (fetchedRef.current === sid) return;
    fetchedRef.current = sid;
    setIsLoading(true);
    setLoadError(null);
    fetchSession(sid).then((apiSession) => {
      if (apiSession) {
        enrichSession(apiSession);
        setSession(apiSession);
        setDataSource('api');
        setRoundIndex(0);
        setPhaseIndex(0);
      } else {
        setLoadError(`无法加载场景 ${sid}，请确认 demo/server.py 已启动`);
        setDataSource('mock');
      }
      setIsLoading(false);
    });
  }, [scenarioId]);

  const round = session.rounds[roundIndex] ?? session.rounds[0];
  const snapshot = round?.phases[phaseIndex] ?? round?.phases[0];
  const isFinished = roundIndex === session.rounds.length - 1 && snapshot?.phase === 'STOP';

  const step = useCallback(() => {
    setSession((currentSession) => {
      const currentRound = currentSession.rounds[roundIndex];
      if (!currentRound) return currentSession;
      if (phaseIndex < currentRound.phases.length - 1) {
        setPhaseIndex((p) => p + 1);
        return currentSession;
      }
      if (roundIndex < currentSession.rounds.length - 1) {
        setRoundIndex((r) => r + 1);
        setPhaseIndex(0);
        return currentSession;
      }
      setIsPlaying(false);
      return currentSession;
    });
  }, [phaseIndex, roundIndex]);

  const reset = useCallback(() => {
    setRoundIndex(0);
    setPhaseIndex(0);
    setIsPlaying(false);
  }, []);

  const jumpTo = useCallback((ri: number, pi: number) => {
    setRoundIndex(ri);
    setPhaseIndex(pi);
  }, []);

  useEffect(() => {
    if (!isPlaying || isFinished || playbackBlocked) return;
    // Fast-forward on the last round (stop round)
    const isLast = roundIndex === session.rounds.length - 1;
    const manyRounds = session.rounds.length > 8;
    const delay = isLast
      ? 800
      : mode === 'guide'
        ? manyRounds
          ? 2200
          : 4500
        : manyRounds
          ? 1200
          : 2500;
    const timer = window.setTimeout(step, delay);
    return () => window.clearTimeout(timer);
  }, [isPlaying, isFinished, playbackBlocked, mode, step, roundIndex, phaseIndex, session.rounds.length]);

  const state: PlaybackState = useMemo(
    () => ({
      roundIndex,
      phaseIndex,
      round: round?.round ?? 1,
      phase: snapshot?.phase ?? 'L',
      snapshot: snapshot ?? session.rounds[0]?.phases[0],
      roundTitle: round?.title ?? '',
      totalRounds: session.rounds.length,
      isFinished,
      mode,
      isPlaying,
      narration: snapshot?.narration ?? snapshot?.summary ?? '',
    }),
    [round, snapshot, roundIndex, phaseIndex, isFinished, mode, isPlaying, session],
  );

  return {
    session,
    state,
    phases: PHASE_ORDER,
    setMode,
    setIsPlaying,
    step,
    reset,
    jumpTo,
    isLoading,
    loadError,
    dataSource,
  };
}
