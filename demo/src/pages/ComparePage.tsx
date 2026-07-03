import { Link } from 'react-router-dom';
import { ProbeRankTable } from '../components/ProbeRankTable';
import { mockSession } from '../data/mockSession';

/** Round 3 O-phase snapshot: boundary probe ranks #1 under VOI but not hit-rate */
const compareSnapshot = mockSession.rounds[2].phases[0];

export function ComparePage() {
  const probes = compareSnapshot.probePool;

  return (
    <div className="compare-page">
      <header className="compare-page__header">
        <Link to="/demo/session/sess-ransom-001">← 返回作战室</Link>
        <h1>对比模式：RFC-003 vs RFC-004-02</h1>
        <p className="muted">同一 case · Round 3 · 定界探针场景</p>
      </header>

      <div className="compare-split">
        <section className="compare-panel compare-panel--legacy">
          <h2>RFC-003 · 命中率排序</h2>
          <p className="compare-panel__note">
            「确认 zhangsan 边不属于攻击」命中率低 → 排名靠后 → 过度归因风险
          </p>
          <ProbeRankTable probes={probes} showHitRate />
        </section>
        <section className="compare-panel compare-panel--v4">
          <h2>RFC-004-02 · VOI 排序</h2>
          <p className="compare-panel__note">
            边界项给定界正分 → 定界探针排第一 → 剪枝爆炸半径
          </p>
          <ProbeRankTable probes={probes} />
        </section>
      </div>
    </div>
  );
}
