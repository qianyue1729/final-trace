import type { Obligation } from '../types';

const TYPE_LABEL: Record<Obligation['type'], string> = {
  structure: '结构债务',
  lifecycle: '生命周期',
  'anti-forensics': '反取证',
  discrimination: '判别',
};

const TYPE_CLASS: Record<Obligation['type'], string> = {
  structure: 'obligation--structure',
  lifecycle: 'obligation--lifecycle',
  'anti-forensics': 'obligation--anti',
  discrimination: 'obligation--disc',
};

interface Props {
  obligations: Obligation[];
  compact?: boolean;
}

export function ObligationCards({ obligations, compact }: Props) {
  if (obligations.length === 0) {
    return <p className="muted">当前无开放义务</p>;
  }

  return (
    <ul className={`obligation-list ${compact ? 'obligation-list--compact' : ''}`}>
      {obligations.map((o) => (
        <li
          key={o.id}
          className={`obligation-card ${TYPE_CLASS[o.type]} ${o.discharged ? 'obligation-card--done' : ''}`}
        >
          <div className="obligation-card__head">
            <span className="obligation-card__type">{TYPE_LABEL[o.type]}</span>
            {o.hard && <span className="obligation-card__hard" title="硬义务：未清不能停">🔒</span>}
          </div>
          <div className="obligation-card__anchor">{o.anchor}</div>
          <div className="obligation-card__meta">
            <span>VOI {o.voi.toFixed(2)}</span>
            <span>deadline {o.deadline}</span>
            {o.discharged && <span className="tag tag--ok">已履行</span>}
          </div>
        </li>
      ))}
    </ul>
  );
}
