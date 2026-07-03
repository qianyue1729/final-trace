import type { DecisionLedgerSnapshot } from '../types';

interface Props {
  ledger: DecisionLedgerSnapshot;
}

export function ExplanationBars({ ledger }: Props) {
  const lowMargin = ledger.margin < 0.15;

  return (
    <div className="explanation-bars">
      <div className="explanation-bars__header">
        <h4>竞争解释后验</h4>
        <span className="tabular-nums">margin {Math.round(ledger.margin * 100)}%</span>
      </div>
      {lowMargin && (
        <div className="explanation-bars__warn">⚠ 歧义警告：领先与次优解释差距过小</div>
      )}
      {ledger.explanations.map((ex) => (
        <div
          key={ex.eid}
          className={`explanation-row ${ex.leading ? 'explanation-row--leading' : ''} ${ex.isNull ? 'explanation-row--null' : ''}`}
        >
          <div className="explanation-row__label">
            {ex.label}
            {ex.lifecycleStage && <span className="tag">{ex.lifecycleStage}</span>}
          </div>
          <div className="explanation-row__bar-wrap">
            <div
              className="explanation-row__bar"
              style={{ width: `${ex.posterior * 100}%` }}
            />
          </div>
          <span className="explanation-row__pct tabular-nums">{Math.round(ex.posterior * 100)}%</span>
        </div>
      ))}
    </div>
  );
}
