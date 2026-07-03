import type { StopSignals } from '../types';

const SIGNALS: { key: keyof StopSignals; label: string; hint: string }[] = [
  { key: 'budget', label: '预算', hint: '扇出槽使用情况' },
  { key: 'hardObligations', label: '硬义务', hint: '结构 + 反取证已清' },
  { key: 'voiFloor', label: 'VOI 地板', hint: 'maxVOI < ε' },
  { key: 'robust', label: '决策鲁棒', hint: '扰动下处置不翻转' },
];

interface Props {
  signals: StopSignals;
}

export function StopConditionLights({ signals }: Props) {
  return (
    <div className="stop-lights">
      {SIGNALS.map(({ key, label, hint }) => (
        <div
          key={key}
          className={`stop-light ${signals[key] ? 'stop-light--ok' : 'stop-light--pending'}`}
          title={hint}
        >
          <span className="stop-light__bulb" />
          <span className="stop-light__label">{label}</span>
        </div>
      ))}
    </div>
  );
}
