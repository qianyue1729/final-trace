import type { PhaseSnapshot } from '../../types';
import { StopConditionLights } from '../StopConditionLights';

interface Props {
  snapshot: PhaseSnapshot;
  narration: string;
  onWhyClick?: () => void;
}

export function BottomBar({ snapshot, narration, onWhyClick }: Props) {
  return (
    <footer className="bottom-bar">
      <div className="bottom-bar__summary">
        <strong>本轮：</strong>
        <span>{snapshot.summary}</span>
        {narration && narration !== snapshot.summary && (
          <span className="bottom-bar__narration">{narration}</span>
        )}
      </div>
      <StopConditionLights signals={snapshot.stopSignals} />
      <button type="button" className="btn-why" onClick={onWhyClick}>
        为什么这么查？
      </button>
    </footer>
  );
}
