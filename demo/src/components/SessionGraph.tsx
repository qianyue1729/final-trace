import { useMemo, useState } from 'react';
import type { GraphSnapshot } from '../types';
import {
  defaultGraphFilter,
  layoutGraphSnapshot,
  type GraphFilter,
} from '../utils/graphLayout';

const KIND_ICON: Record<string, string> = {
  host: '🖥',
  user: '👤',
  process: '⚙',
  file: '📄',
  email: '✉',
};

interface Props {
  graph: GraphSnapshot;
  highlightPhase?: boolean;
}

export function SessionGraph({ graph }: Props) {
  const [filter, setFilter] = useState<GraphFilter>(() => defaultGraphFilter(graph));

  const layout = useMemo(() => layoutGraphSnapshot(graph, filter), [graph, filter]);

  const nodeMap = Object.fromEntries(layout.nodes.map((n) => [n.id, n]));
  const nodeCount = graph.meta?.totalNodes ?? graph.nodes.length;
  const attackCount = graph.meta?.attackNodes ?? graph.nodes.filter((n) => n.malicious).length;
  const dense = layout.nodes.length > 14;
  const showEdgeLabels = layout.edges.length <= 8 && !dense;
  const nodeR = dense ? 16 : layout.nodes.length > 8 ? 18 : 22;
  const fontSize = dense ? 9 : 10;

  return (
    <div className="session-graph">
      <div className="session-graph__toolbar">
        <span className="session-graph__stat">
          显示 {layout.nodes.length} 节点
          {filter === 'attack' && nodeCount > layout.nodes.length && (
            <span className="muted"> / 共 {nodeCount}</span>
          )}
          {attackCount > 0 && (
            <span className="muted"> · 攻击 {attackCount}</span>
          )}
        </span>
        <div className="session-graph__filters">
          <button
            type="button"
            className={filter === 'attack' ? 'graph-filter graph-filter--active' : 'graph-filter'}
            onClick={() => setFilter('attack')}
            disabled={attackCount === 0}
          >
            攻击链
          </button>
          <button
            type="button"
            className={filter === 'all' ? 'graph-filter graph-filter--active' : 'graph-filter'}
            onClick={() => setFilter('all')}
          >
            全部
          </button>
        </div>
      </div>

      <div className="session-graph__scroll">
        <svg
          viewBox={layout.viewBox}
          className="session-graph__svg"
          preserveAspectRatio="xMidYMid meet"
        >
          <defs>
            <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
              <path d="M0,0 L6,3 L0,6 Z" fill="#5a7a9a" />
            </marker>
          </defs>

          {/* 主机列背景 */}
          {layout.hostColumns.map((col) => (
            <g key={col.host}>
              <rect
                x={col.x + 4}
                y={8}
                width={col.width - 8}
                height={layout.height - 16}
                rx={6}
                className="graph-host-col"
              />
              <text
                x={col.x + col.width / 2}
                y={26}
                textAnchor="middle"
                className="graph-host-col__label"
              >
                {col.host.length > 14 ? `${col.host.slice(0, 12)}…` : col.host}
              </text>
            </g>
          ))}

          {/* 边 */}
          {layout.edges.map((e) => {
            const s = nodeMap[e.source];
            const t = nodeMap[e.target];
            if (!s || !t) return null;
            const cls = [
              'graph-edge',
              e.confirmed ? 'graph-edge--confirmed' : '',
              e.contested ? 'graph-edge--contested' : '',
              e.pruned ? 'graph-edge--pruned' : '',
              e.oos ? 'graph-edge--oos' : '',
              dense ? 'graph-edge--dense' : '',
            ]
              .filter(Boolean)
              .join(' ');
            const midX = (s.x + t.x) / 2;
            const midY = (s.y + t.y) / 2;
            const sameCol = Math.abs(s.x - t.x) < 20;
            const pathD = sameCol
              ? `M ${s.x} ${s.y + nodeR} L ${t.x} ${t.y - nodeR}`
              : `M ${s.x} ${s.y} Q ${midX} ${midY - 20} ${t.x} ${t.y}`;

            return (
              <g key={e.id}>
                <path
                  d={pathD}
                  className={cls}
                  fill="none"
                  markerEnd="url(#arrow)"
                />
                {showEdgeLabels && e.label && e.label !== '→' && (
                  <text x={midX} y={midY - 4} textAnchor="middle" className="graph-edge__label">
                    {e.label}
                  </text>
                )}
              </g>
            );
          })}

          {/* 节点 */}
          {layout.nodes.map((n) => (
            <g key={n.id} transform={`translate(${n.x}, ${n.y})`} className="graph-node">
              <title>{n.label}</title>
              <circle
                r={nodeR}
                className={`graph-node__circle ${n.malicious ? 'graph-node__circle--malicious' : ''}`}
              />
              <text y={4} textAnchor="middle" className="graph-node__icon">
                {KIND_ICON[n.kind] ?? '•'}
              </text>
              <text
                y={nodeR + 14}
                textAnchor="middle"
                className="graph-node__label"
                style={{ fontSize }}
              >
                {n.shortLabel.length > 12 ? `${n.shortLabel.slice(0, 10)}…` : n.shortLabel}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}
