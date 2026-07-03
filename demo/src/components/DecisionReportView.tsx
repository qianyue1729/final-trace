import type { DecisionReport as Report, DemoSession, TraceNarrative } from '../types';
import { SessionGraph } from '../components/SessionGraph';

interface Props {
  report: Report;
  session: DemoSession;
}

function KillChainTimeline({ stages }: { stages: TraceNarrative['killChainStages'] }) {
  return (
    <div className="kill-chain-timeline">
      {stages.map((s, i) => (
        <div key={i} className="kill-chain-stage">
          <div className="kill-chain-stage__marker">
            <span className="kill-chain-stage__num">{i + 1}</span>
            {i < stages.length - 1 && <div className="kill-chain-stage__line" />}
          </div>
          <div className="kill-chain-stage__content">
            <h4>{s.stage}</h4>
            <p className="technique-tag">{s.technique}</p>
            <p className="evidence-text">{s.evidence}</p>
            <span className={`confidence-badge confidence-badge--${s.confidence.startsWith('高') ? 'high' : s.confidence.startsWith('中高') ? 'medium-high' : 'medium'}`}>
              {s.confidence}
            </span>
          </div>
        </div>
      ))}
    </div>
  );
}

function PosteriorChart({ data }: { data: TraceNarrative['posteriorEvolution'] }) {
  if (!data.length) return null;
  const maxH1 = Math.max(...data.map((d) => d.h1));
  return (
    <div className="posterior-chart">
      <div className="posterior-chart__header">
        <span className="legend-dot legend-dot--h1" /> H1 勒索链
        <span className="legend-dot legend-dot--h2" /> H2 误报
        <span className="legend-dot legend-dot--null" /> Null
      </div>
      <div className="posterior-chart__bars">
        {data.map((d) => (
          <div key={d.round} className="posterior-bar-group">
            <div className="posterior-bar posterior-bar--h1" style={{ height: `${(d.h1 / maxH1) * 100}%` }}>
              <span className="posterior-bar__val">{(d.h1 * 100).toFixed(0)}%</span>
            </div>
            <div className="posterior-bar posterior-bar--h2" style={{ height: `${Math.max(2, (d.h2 / maxH1) * 100)}%` }} />
            <div className="posterior-bar posterior-bar--null" style={{ height: `${Math.max(2, (d.hNull / maxH1) * 100)}%` }} />
            <span className="posterior-bar-group__label">R{d.round}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function RoundNarrativeList({ rounds }: { rounds: TraceNarrative['roundNarratives'] }) {
  return (
    <div className="round-narratives">
      {rounds.map((r) => (
        <div key={r.round} className="round-narrative-card">
          <div className="round-narrative-card__header">
            <span className="round-badge">R{r.round}</span>
            <strong>{r.title}</strong>
            <span className="posterior-mini">{(r.posteriorAfter * 100).toFixed(1)}%</span>
          </div>
          <p className="round-narrative-card__discovery">{r.discovery}</p>
          <div className="round-narrative-card__meta">
            {r.techniques.length > 0 && (
              <span className="meta-tag">技术: {r.techniques.join(', ')}</span>
            )}
            {r.tactics.length > 0 && (
              <span className="meta-tag">战术: {r.tactics.join(', ')}</span>
            )}
            <span className="meta-tag">+{r.nodesAdded} 节点 / +{r.edgesAdded} 边</span>
          </div>
        </div>
      ))}
    </div>
  );
}

export function DecisionReportView({ report, session }: Props) {
  const finalGraph = session.rounds.at(-1)?.phases.at(-1)?.graph;
  const narrative = report.traceNarrative;

  return (
    <div className="report">
      {/* ─── Hero ─── */}
      <header className="report__hero">
        <div className="report__case-id">{narrative?.caseId ?? 'CASE-UNKNOWN'}</div>
        <h1 className="report__title">威胁溯源调查报告</h1>
        <div className="report__meta">
          <span>分析引擎: {narrative?.analyst ?? 'N/A'}</span>
          <span>生成时间: {narrative?.generatedAt ?? 'N/A'}</span>
        </div>
        <div className="report__action-banner">
          <span className="report__action">{report.action}</span>
          <span className="report__confidence">
            置信度 <strong className="tabular-nums">{Math.round(report.confidence * 100)}%</strong>
          </span>
        </div>
      </header>

      {/* ─── 告警摘要 ─── */}
      {narrative && (
        <section className="report__section">
          <h2>1. 告警摘要</h2>
          <div className="alert-summary-box">
            <p><strong>触发告警:</strong> {narrative.alertSummary}</p>
            <p><strong>调查目标:</strong> {narrative.investigationGoal}</p>
            <p><strong>涉及资产:</strong> {session.alert.asset} ({session.alert.title})</p>
          </div>
        </section>
      )}

      {/* ─── 攻击路径 ─── */}
      {narrative && (
        <section className="report__section">
          <h2>2. 攻击路径总览</h2>
          <div className="attack-path-box">
            <p className="attack-path-text">{narrative.attackPath}</p>
          </div>
        </section>
      )}

      {/* ─── 杀伤链 ─── */}
      {narrative && (
        <section className="report__section">
          <h2>3. 杀伤链重构</h2>
          <KillChainTimeline stages={narrative.killChainStages} />
        </section>
      )}

      {/* ─── 攻击边界图 ─── */}
      <section className="report__section">
        <h2>4. 攻击边界图</h2>
        {finalGraph && <SessionGraph graph={finalGraph} />}
      </section>

      {/* ─── 调查过程 ─── */}
      {narrative && (
        <section className="report__section">
          <h2>5. 调查过程 (LOCK 循环)</h2>
          <RoundNarrativeList rounds={narrative.roundNarratives} />
        </section>
      )}

      {/* ─── 置信度演变 ─── */}
      {narrative && (
        <section className="report__section">
          <h2>6. 后验概率演变</h2>
          <PosteriorChart data={narrative.posteriorEvolution} />
        </section>
      )}

      {/* ─── 决策分析 ─── */}
      <section className="report__section report__grid">
        <div>
          <h3>领先假设</h3>
          <p className="leading-explanation">{report.leadingExplanation}</p>
        </div>
        <div>
          <h3>次优假设 ({Math.round(report.suboptimalExplanation.posterior * 100)}%)</h3>
          <p><strong>{report.suboptimalExplanation.label}</strong></p>
          <p className="muted">{report.suboptimalExplanation.reason}</p>
        </div>
      </section>

      <section className="report__section">
        <h3>反事实分析</h3>
        <blockquote>{report.counterfactual}</blockquote>
      </section>

      {/* ─── 结论与建议 ─── */}
      {narrative && (
        <section className="report__section report__conclusion">
          <h2>7. 结论</h2>
          <p>{narrative.conclusion}</p>
          <h3>处置建议</h3>
          <div className="recommendation-box">
            {narrative.recommendation.split('；').filter(Boolean).map((item, i) => (
              <p key={i} className="recommendation-item">{item.trim()}</p>
            ))}
          </div>
        </section>
      )}

      {/* ─── 定界信息 ─── */}
      <section className="report__section report__grid">
        <div>
          <h3>剪枝定界</h3>
          <ul>
            {report.prunedEdges.length > 0 ? (
              report.prunedEdges.map((e) => <li key={e}>{e}</li>)
            ) : (
              <li className="muted">无剪枝边</li>
            )}
          </ul>
        </div>
        <div>
          <h3>域外 (OOS)</h3>
          <ul>
            {report.oosItems.length > 0 ? (
              report.oosItems.map((e) => <li key={e}>{e}</li>)
            ) : (
              <li className="muted">无域外项</li>
            )}
          </ul>
        </div>
      </section>

      <footer className="report__footer">
        <span>停止原因: {report.stopReason}</span>
        <span>调查轮次: {session.rounds.length}</span>
        <span>最终处置: {report.action}</span>
      </footer>
    </div>
  );
}
