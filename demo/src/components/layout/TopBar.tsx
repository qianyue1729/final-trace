import type { DemoMode } from '../../types';
import { FaqBubble } from '../FaqBubble';

interface Props {
  sessionId: string;
  alertTitle: string;
  round: number;
  budgetUsed: number;
  budgetTotal: number;
  mode: DemoMode;
  isPlaying: boolean;
  onModeChange: (m: DemoMode) => void;
  onPlayToggle: () => void;
  onStep: () => void;
  onReset: () => void;
}

export function TopBar({
  sessionId,
  alertTitle,
  round,
  budgetUsed,
  budgetTotal,
  mode,
  isPlaying,
  onModeChange,
  onPlayToggle,
  onStep,
  onReset,
}: Props) {
  const pct = Math.min(100, (budgetUsed / budgetTotal) * 100);

  return (
    <header className="top-bar">
      <div className="top-bar__left">
        <span className="top-bar__brand">RFC-004-02 演示</span>
        <span className="top-bar__session">{sessionId}</span>
        <span className="top-bar__alert">{alertTitle}</span>
      </div>
      <div className="top-bar__center">
        <span className="top-bar__round">Round {round}</span>
        <div className="budget-bar" title={`预算 ${budgetUsed}/${budgetTotal}`}>
          <div className="budget-bar__fill" style={{ width: `${pct}%` }} />
          <span className="budget-bar__text tabular-nums">{budgetUsed}/{budgetTotal}</span>
        </div>
      </div>
      <div className="top-bar__right">
        <select value={mode} onChange={(e) => onModeChange(e.target.value as DemoMode)} className="mode-select">
          <option value="guide">导游模式</option>
          <option value="investigator">探员模式</option>
        </select>
        <button type="button" onClick={onPlayToggle}>{isPlaying ? '暂停' : '播放'}</button>
        <button type="button" onClick={onStep}>单步</button>
        <button type="button" onClick={onReset} className="btn-ghost">重置</button>
        <FaqBubble />
      </div>
    </header>
  );
}
