import type { LockPhase } from '../types';

const STEPS: { phase: LockPhase; label: string; hint: string }[] = [
  { phase: 'L', label: 'L 选哪条', hint: '往候选池投探针' },
  { phase: 'VETO', label: '② 检验', hint: 'VETO + MANDATE 义务' },
  { phase: 'O', label: 'O 怎么查', hint: 'VOI 排序填槽' },
  { phase: 'C', label: 'C 验真', hint: '扇出取证入图' },
  { phase: 'K', label: 'K 收尾', hint: '写四本账 + 停?' },
];

interface Props {
  current: LockPhase;
  round: number;
  onPhaseClick?: (phase: LockPhase) => void;
}

export function LockStepper({ current, round, onPhaseClick }: Props) {
  return (
    <div className="lock-stepper">
      <div className="lock-stepper__header">
        <h3>LOCK 节拍器</h3>
        <span className="lock-stepper__round">Round {round}</span>
      </div>
      <p className="lock-stepper__note">
        全程只有这一个循环。决策账在 <strong>K</strong> 写入、在 <strong>O</strong> 读取——不是外环。
      </p>
      <ol className="lock-stepper__list">
        {STEPS.map(({ phase, label, hint }) => {
          const active = current === phase;
          const past =
            STEPS.findIndex((s) => s.phase === current) > STEPS.findIndex((s) => s.phase === phase);
          return (
            <li
              key={phase}
              className={`lock-step ${active ? 'lock-step--active' : ''} ${past ? 'lock-step--past' : ''}`}
            >
              <button type="button" className="lock-step__btn" onClick={() => onPhaseClick?.(phase)}>
                <span className="lock-step__dot" />
                <span className="lock-step__body">
                  <span className="lock-step__label">{label}</span>
                  <span className="lock-step__hint">{hint}</span>
                </span>
              </button>
            </li>
          );
        })}
        <li className={`lock-step ${current === 'STOP' ? 'lock-step--active lock-step--stop' : ''}`}>
          <span className="lock-step__dot" />
          <span className="lock-step__body">
            <span className="lock-step__label">STOP</span>
            <span className="lock-step__hint">价值导向停止</span>
          </span>
        </li>
      </ol>
    </div>
  );
}
