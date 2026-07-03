import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { BottomBar } from '../components/layout/BottomBar';
import { TopBar } from '../components/layout/TopBar';
import { LedgerTabs } from '../components/LedgerTabs';
import { LockStepper } from '../components/LockStepper';
import { ProbeRankTable } from '../components/ProbeRankTable';
import { SessionGraph } from '../components/SessionGraph';
import { StepExplainPanel } from '../components/StepExplainPanel';
import { bootstrapExplain } from '../data/stepExplains';
import { useDemoPlayback } from '../hooks/useDemoPlayback';
import type { StepExplain } from '../types';

type CenterView = 'graph' | 'probes' | 'timeline';
type LedgerTab = 'graph' | 'beta' | 'obligations' | 'decision';

const defaultExplain: StepExplain = {
  title: '本步说明',
  action: '（暂无详细说明）',
  inputs: [],
  outputs: [],
  computation: [],
  maintenance: [],
};

export function SessionPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [explainOpen, setExplainOpen] = useState(true);
  const [bootstrapDone, setBootstrapDone] = useState(false);
  const prevStep = useRef({ roundIndex: 0, phaseIndex: 0 });

  const {
    session,
    state,
    setMode,
    setIsPlaying,
    step,
    reset,
    isLoading,
    loadError,
    dataSource,
  } = useDemoPlayback('guide', explainOpen, id);

  const isLastRound = (ri: number) => ri === session.rounds.length - 1;

  const [centerView, setCenterView] = useState<CenterView>('graph');
  const [ledgerTab, setLedgerTab] = useState<LedgerTab>('decision');
  const [selectedProbe, setSelectedProbe] = useState<string | null>(null);
  const [whyOpen, setWhyOpen] = useState(false);

  const currentExplain = bootstrapDone
    ? (state.snapshot.stepExplain ?? defaultExplain)
    : bootstrapExplain;

  useEffect(() => {
    setBootstrapDone(false);
    setExplainOpen(true);
    prevStep.current = { roundIndex: 0, phaseIndex: 0 };
    reset();
  }, [id, reset]);

  useEffect(() => {
    if (state.phase === 'O') setCenterView('probes');
    if (state.phase === 'C') setCenterView('graph');
    if (state.phase === 'K' || state.phase === 'STOP') setLedgerTab('decision');
  }, [state.phase, state.roundIndex, state.phaseIndex]);

  useEffect(() => {
    if (!bootstrapDone) return;
    const prev = prevStep.current;
    if (prev.roundIndex !== state.roundIndex || prev.phaseIndex !== state.phaseIndex) {
      // On the last round, don't block with explain panel if playing
      if (!(isLastRound(state.roundIndex) && state.isPlaying)) {
        setExplainOpen(true);
      }
      prevStep.current = { roundIndex: state.roundIndex, phaseIndex: state.phaseIndex };
    }
  }, [state.roundIndex, state.phaseIndex, bootstrapDone, state.isPlaying, session.rounds.length]);

  useEffect(() => {
    if (state.isFinished) {
      setExplainOpen(false);
      const t = window.setTimeout(() => navigate(`/demo/session/${id}/report`), 1200);
      return () => window.clearTimeout(t);
    }
  }, [state.isFinished, navigate, id]);

  const handleExplainContinue = useCallback(() => {
    if (!bootstrapDone) {
      setBootstrapDone(true);
      prevStep.current = { roundIndex: state.roundIndex, phaseIndex: state.phaseIndex };
      return;
    }
    setExplainOpen(false);
  }, [bootstrapDone, state.roundIndex, state.phaseIndex]);

  const handleReset = useCallback(() => {
    reset();
    setBootstrapDone(false);
    setExplainOpen(true);
    prevStep.current = { roundIndex: 0, phaseIndex: 0 };
  }, [reset]);

  const handleReopenExplain = useCallback(() => {
    setExplainOpen(true);
  }, []);

  if (isLoading) {
    return (
      <div className="session-loading">
        <strong>正在运行 LOCK 溯源…</strong>
        <span>场景 {id ?? 'pipeline_18'} · soar_mcp_env 真实数据</span>
        <span className="muted">首次加载需数秒至数十秒，请稍候</span>
      </div>
    );
  }

  if (loadError && dataSource === 'mock') {
    return (
      <div className="session-loading">
        <strong>{loadError}</strong>
        <button type="button" className="btn-primary" onClick={() => navigate('/demo/entry')}>
          返回场景选择
        </button>
      </div>
    );
  }

  return (
    <div className="session-page">
      <TopBar
        sessionId={session.id}
        alertTitle={session.alert.title}
        round={state.round}
        budgetUsed={state.snapshot.budgetUsed}
        budgetTotal={session.budgetTotal}
        mode={state.mode}
        isPlaying={state.isPlaying}
        onModeChange={setMode}
        onPlayToggle={() => setIsPlaying((p) => !p)}
        onStep={step}
        onReset={handleReset}
      />

      <div className="session-layout">
        <aside className="session-layout__left">
          {session.gtCoverage && (
            <div className="gt-banner">
              GT 覆盖 {session.gtCoverage.hits}/{session.gtCoverage.total} ({session.gtCoverage.pct}%)
              {dataSource === 'api' && ' · 真实回放'}
            </div>
          )}
          <LedgerTabs
            snapshot={state.snapshot}
            activeTab={ledgerTab}
            onTabChange={setLedgerTab}
            centerView={centerView}
          />
        </aside>

        <main className={`session-layout__center ${explainOpen ? 'session-layout__center--dimmed' : ''}`}>
          <div className="center-toolbar">
            <span className="center-toolbar__title">{state.roundTitle}</span>
            <div className="view-tabs">
              {(['graph', 'probes', 'timeline'] as CenterView[]).map((v) => (
                <button
                  key={v}
                  type="button"
                  className={centerView === v ? 'active' : ''}
                  onClick={() => setCenterView(v)}
                >
                  {v === 'graph' ? '攻击图' : v === 'probes' ? '候选池' : '时间线'}
                </button>
              ))}
            </div>
            <button type="button" className="link-muted btn-link" onClick={handleReopenExplain}>
              本步说明
            </button>
            {isLastRound(state.roundIndex) && (
              <button
                type="button"
                className="btn-skip-report"
                onClick={() => navigate(`/demo/session/${id}/report`)}
              >
                查看报告 →
              </button>
            )}
            <Link to="/demo/compare" className="link-muted">对比模式 →</Link>
          </div>

          {centerView === 'graph' && <SessionGraph graph={state.snapshot.graph} />}
          {centerView === 'probes' && (
            <ProbeRankTable
              probes={state.snapshot.probePool}
              selectedProbe={selectedProbe}
              onSelect={setSelectedProbe}
            />
          )}
          {centerView === 'timeline' && (
            <ol className="timeline">
              {session.rounds.map((r, ri) => (
                <li key={r.round} className={ri === state.roundIndex ? 'timeline__item--current' : ''}>
                  <strong>Round {r.round}</strong> {r.title}
                  <ul>
                    {r.phases.map((p, pi) => (
                      <li
                        key={`${ri}-${pi}`}
                        className={
                          ri === state.roundIndex && pi === state.phaseIndex ? 'timeline__phase--active' : ''
                        }
                      >
                        [{p.phase}] {p.summary}
                      </li>
                    ))}
                  </ul>
                </li>
              ))}
            </ol>
          )}
        </main>

        <aside className="session-layout__right">
          <LockStepper current={state.phase} round={state.round} />
        </aside>
      </div>

      <BottomBar
        snapshot={state.snapshot}
        narration={state.narration}
        onWhyClick={() => setWhyOpen(true)}
      />

      <StepExplainPanel
        open={explainOpen}
        round={state.round}
        phase={bootstrapDone ? state.phase : 'L'}
        roundTitle={bootstrapDone ? state.roundTitle : '会话初始化'}
        explain={currentExplain}
        isPlaying={state.isPlaying}
        onContinue={handleExplainContinue}
        onClose={() => setExplainOpen(false)}
      />

      {whyOpen && (
        <div className="modal-overlay" onClick={() => setWhyOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>为什么这么查？</h3>
            <p>{state.snapshot.summary}</p>
            {selectedProbe ? (
              <>
                <p>
                  选中探针：<strong>{selectedProbe}</strong>
                </p>
                <p className="muted">
                  VOI = 期望决策风险削减 − 成本。边界项让「确认不属于本案」也得正分。
                </p>
              </>
            ) : (
              <p className="muted">在候选池视图中点击一行探针查看详情。</p>
            )}
            <button type="button" onClick={() => setWhyOpen(false)}>关闭</button>
          </div>
        </div>
      )}

      {state.isFinished && !explainOpen && (
        <div className="finish-overlay">
          <p>会话结束 · 正在生成决策报告…</p>
        </div>
      )}
    </div>
  );
}
