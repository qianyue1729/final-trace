import type { BoundaryBelief } from '../types';

interface Props {
  belief: BoundaryBelief;
}

export function BoundaryBeliefChip({ belief }: Props) {
  const segments = [
    { key: 'in', label: '纳入攻击', value: belief.pInAttack, cls: 'in' },
    { key: 'benign', label: '良性无关', value: belief.pBenign, cls: 'benign' },
    { key: 'oos', label: '域外恶意', value: belief.pOos, cls: 'oos' },
  ];

  return (
    <div className="boundary-chip">
      <div className="boundary-chip__title">{belief.edgeLabel}</div>
      <div className="boundary-chip__bar">
        {segments.map((s) => (
          <div
            key={s.key}
            className={`boundary-chip__seg boundary-chip__seg--${s.cls}`}
            style={{ width: `${s.value * 100}%` }}
            title={`${s.label} ${Math.round(s.value * 100)}%`}
          />
        ))}
      </div>
      <div className="boundary-chip__legend">
        {segments.map((s) => (
          <span key={s.key}>
            {s.label} <strong className="tabular-nums">{Math.round(s.value * 100)}%</strong>
          </span>
        ))}
      </div>
    </div>
  );
}
