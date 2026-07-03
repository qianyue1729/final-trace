import type { PhaseSnapshot } from '../types';
import { ExplanationBars } from './ExplanationBars';
import { BoundaryBeliefChip } from './BoundaryBeliefChip';
import { ObligationCards } from './ObligationCards';

type LedgerTab = 'graph' | 'beta' | 'obligations' | 'decision';

interface Props {
  snapshot: PhaseSnapshot;
  activeTab: LedgerTab;
  onTabChange: (tab: LedgerTab) => void;
  centerView: 'graph' | 'probes' | 'timeline';
}

export function LedgerTabs({ snapshot, activeTab, onTabChange, centerView }: Props) {
  const tabs: { id: LedgerTab; label: string; star?: boolean }[] = [
    { id: 'graph', label: '攻击图' },
    { id: 'beta', label: 'Beta 台账' },
    { id: 'obligations', label: '义务台账' },
    { id: 'decision', label: '决策账', star: true },
  ];

  return (
    <div className="ledger-tabs">
      <div className="ledger-tabs__nav">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            className={`ledger-tabs__tab ${activeTab === t.id ? 'ledger-tabs__tab--active' : ''} ${t.star ? 'ledger-tabs__tab--decision' : ''}`}
            onClick={() => onTabChange(t.id)}
          >
            {t.star && <span className="ledger-tabs__star">⭐</span>}
            {t.label}
          </button>
        ))}
      </div>
      <div className="ledger-tabs__panel">
        {activeTab === 'graph' && (
          <div className="ledger-panel">
            <p className="ledger-panel__desc">已确认因果子图 · 虚线=争议 · 灰色=已剪枝</p>
            <ul className="edge-list">
              {snapshot.graph.edges.map((e) => (
                <li
                  key={e.id}
                  className={`edge-list__item ${e.pruned ? 'edge-list__item--pruned' : ''} ${e.contested ? 'edge-list__item--contested' : ''} ${e.oos ? 'edge-list__item--oos' : ''}`}
                >
                  {e.label}
                  {e.trust && <span className={`trust-badge trust-badge--${e.trust}`}>{e.trust}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}
        {activeTab === 'beta' && (
          <div className="ledger-panel">
            <p className="ledger-panel__desc">Beta 只管「挖不挖得到」；挖到了归哪个故事看决策账。</p>
            {snapshot.betaEntries.length === 0 ? (
              <p className="muted">尚无更新</p>
            ) : (
              <ul className="beta-list">
                {snapshot.betaEntries.map((b) => (
                  <li key={b.key}>
                    <span>{b.key}</span>
                    <div className="beta-bar">
                      <div className="beta-bar__fill" style={{ width: `${(b.hits / b.total) * 100}%` }} />
                    </div>
                    <span className="tabular-nums">{b.hits}/{b.total}</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
        {activeTab === 'obligations' && (
          <ObligationCards obligations={snapshot.obligations} compact />
        )}
        {activeTab === 'decision' && (
          <div className="ledger-panel ledger-panel--decision">
            <ExplanationBars ledger={snapshot.decisionLedger} />
            {snapshot.decisionLedger.contested.length > 0 && (
              <div className="boundary-section">
                <h4>边界信念 contested</h4>
                {snapshot.decisionLedger.contested.map((b) => (
                  <BoundaryBeliefChip key={b.edgeId} belief={b} />
                ))}
              </div>
            )}
          </div>
        )}
      </div>
      {centerView !== 'graph' && (
        <p className="ledger-tabs__hint muted">中栏当前：{centerView === 'probes' ? '候选池' : '时间线'}</p>
      )}
    </div>
  );
}
