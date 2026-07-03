import type { ProbeCandidate } from '../types';

interface Props {
  probes: ProbeCandidate[];
  showHitRate?: boolean;
  selectedProbe?: string | null;
  onSelect?: (probe: string) => void;
}

export function ProbeRankTable({ probes, showHitRate, selectedProbe, onSelect }: Props) {
  if (probes.length === 0) {
    return <p className="muted">本轮无候选探针（或非 O 拍）</p>;
  }

  const sorted = [...probes].sort((a, b) => b.voi - a.voi);

  return (
    <div className="probe-table">
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>探针</th>
            <th>{showHitRate ? '命中率' : 'VOI'}</th>
            <th>分解</th>
          </tr>
        </thead>
        <tbody>
          {sorted.map((p, i) => {
            const score = showHitRate ? (p.hitRate ?? 0) : p.voi;
            return (
              <tr
                key={p.probe}
                className={`${p.selected ? 'probe-table__row--selected' : ''} ${selectedProbe === p.probe ? 'probe-table__row--focus' : ''}`}
                onClick={() => onSelect?.(p.probe)}
              >
                <td>{i + 1}</td>
                <td>{p.probe}</td>
                <td className="tabular-nums">{score.toFixed(2)}</td>
                <td>
                  <div className="voi-breakdown">
                    <span className="voi-breakdown__session" style={{ flex: p.breakdown.session }} title="会话风险↓" />
                    <span className="voi-breakdown__boundary" style={{ flex: p.breakdown.boundary }} title="边界风险↓" />
                    <span className="voi-breakdown__cost" style={{ flex: p.breakdown.cost * 5 }} title="成本" />
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <div className="probe-table__legend">
        <span><i className="swatch swatch--session" /> 会话风险↓</span>
        <span><i className="swatch swatch--boundary" /> 边界风险↓</span>
        <span><i className="swatch swatch--cost" /> 成本</span>
      </div>
    </div>
  );
}
