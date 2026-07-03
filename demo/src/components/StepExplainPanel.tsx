import type { LockPhase, StepExplain } from '../types';

const PHASE_LABEL: Record<LockPhase, string> = {
  L: 'L 选哪条',
  VETO: '② 检验',
  O: 'O 怎么查',
  C: 'C 验真',
  K: 'K 收尾',
  STOP: 'STOP 停止',
};

interface Props {
  open: boolean;
  round: number;
  phase: LockPhase;
  roundTitle: string;
  explain: StepExplain;
  isPlaying: boolean;
  onContinue: () => void;
  onClose: () => void;
}

export function StepExplainPanel({
  open,
  round,
  phase,
  roundTitle,
  explain,
  isPlaying,
  onContinue,
  onClose,
}: Props) {
  if (!open) return null;

  return (
    <div className="step-explain-overlay" role="dialog" aria-modal="true">
      <div className="step-explain-panel">
        <header className="step-explain-panel__header">
          <div>
            <span className="step-explain-panel__badge">
              Round {round} · {PHASE_LABEL[phase]}
            </span>
            <h2>{explain.title}</h2>
            <p className="step-explain-panel__round-title muted">{roundTitle}</p>
          </div>
          <button type="button" className="step-explain-panel__close" onClick={onClose} aria-label="关闭">
            ×
          </button>
        </header>

        <section className="step-explain-section step-explain-section--action">
          <h3>① 做了什么</h3>
          <p>{explain.action}</p>
        </section>

        <div className="step-explain-grid">
          <section className="step-explain-section">
            <h3>② 输入（读了什么）</h3>
            <ul>
              {explain.inputs.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>

          <section className="step-explain-section">
            <h3>③ 产出（生成了什么）</h3>
            <ul>
              {explain.outputs.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </section>
        </div>

        <section className="step-explain-section">
          <h3>④ 怎么算的</h3>
          <ul>
            {explain.computation.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="step-explain-section step-explain-section--maintain">
          <h3>⑤ 维护了什么（哪本账）</h3>
          <ul>
            {explain.maintenance.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <footer className="step-explain-panel__footer">
          {isPlaying && <span className="muted">自动播放已暂停，阅读后点继续</span>}
          <button type="button" className="btn-primary" onClick={onContinue}>
            继续
          </button>
        </footer>
      </div>
    </div>
  );
}
