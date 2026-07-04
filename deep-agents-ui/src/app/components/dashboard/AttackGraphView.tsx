"use client";

import React, { useMemo } from "react";
import type { GraphRoundSnapshot } from "@/app/hooks/useLOCKState";

const TACTIC_COLORS: Record<string, string> = {
  "initial-access": "#ef4444",
  "credential-access": "#f97316",
  execution: "#eab308",
  persistence: "#14b8a6",
  "privilege-escalation": "#f59e0b",
  "defense-evasion": "#8b5cf6",
  collection: "#22c55e",
  exfiltration: "#a855f7",
  "lateral-movement": "#3b82f6",
  "command-and-control": "#ec4899",
  impact: "#dc2626",
};
const DEFAULT_NODE_COLOR = "#64748b";

const NODE_RADIUS = 10;
const LANE_HEIGHT = 64;
const COL_WIDTH = 72;
const LEFT_LABEL_WIDTH = 80;
const TOP_PADDING = 16;
const MIN_WIDTH = 320;

interface AttackGraphViewProps {
  snapshot: GraphRoundSnapshot;
}

interface LayoutResult {
  hosts: string[];
  allSorted: GraphRoundSnapshot["nodes"];
  nodePositions: Map<string, { x: number; y: number }>;
  validNodeIds: Set<string>;
  svgWidth: number;
  svgHeight: number;
}

function computeLayout(snapshot: GraphRoundSnapshot): LayoutResult {
  const { nodes } = snapshot;

  const hosts: string[] = [];
  const hostSet = new Set<string>();
  const nodesByHost = new Map<string, typeof nodes>();

  for (const node of nodes) {
    const host = node.host || "?";
    if (!hostSet.has(host)) {
      hostSet.add(host);
      hosts.push(host);
    }
    if (!nodesByHost.has(host)) {
      nodesByHost.set(host, []);
    }
    nodesByHost.get(host)!.push(node);
  }

  for (const [, hostNodes] of nodesByHost) {
    hostNodes.sort((a, b) => a.timestamp - b.timestamp);
  }

  const nodePositions = new Map<string, { x: number; y: number }>();
  const allSorted = [...nodes].sort((a, b) => a.timestamp - b.timestamp);
  const hostLaneIndex = new Map<string, number>();
  hosts.forEach((h, i) => hostLaneIndex.set(h, i));

  for (let i = 0; i < allSorted.length; i++) {
    const node = allSorted[i];
    const laneIdx = hostLaneIndex.get(node.host || "?") ?? 0;
    const x = LEFT_LABEL_WIDTH + i * COL_WIDTH + COL_WIDTH / 2;
    const y = TOP_PADDING + laneIdx * LANE_HEIGHT + LANE_HEIGHT / 2;
    nodePositions.set(node.id, { x, y });
  }

  const svgWidth = Math.max(
    MIN_WIDTH,
    LEFT_LABEL_WIDTH + allSorted.length * COL_WIDTH + 20
  );
  const svgHeight = Math.max(80, TOP_PADDING + hosts.length * LANE_HEIGHT + 8);
  const validNodeIds = new Set(nodes.map((n) => n.id));

  return { hosts, allSorted, nodePositions, validNodeIds, svgWidth, svgHeight };
}

function AttackGraphViewInner({ snapshot }: AttackGraphViewProps) {
  const { edges, newNodeIds, newEdgeIds } = snapshot;
  const layout = useMemo(() => computeLayout(snapshot), [snapshot]);
  const { hosts, allSorted, nodePositions, validNodeIds, svgWidth, svgHeight } = layout;

  return (
    <div className="overflow-x-auto">
      <svg
        width={svgWidth}
        height={svgHeight}
        className="block"
        role="img"
        aria-label="Attack graph visualization"
      >
        {/* Arrowhead marker */}
        <defs>
          <marker
            id="arrowhead"
            markerWidth="8"
            markerHeight="6"
            refX="8"
            refY="3"
            orient="auto"
          >
            <path d="M0,0 L8,3 L0,6" fill="#64748b" />
          </marker>
          <marker
            id="arrowhead-new"
            markerWidth="8"
            markerHeight="6"
            refX="8"
            refY="3"
            orient="auto"
          >
            <path d="M0,0 L8,3 L0,6" fill="#3b82f6" />
          </marker>
        </defs>

        {/* Host swimlane labels and lines */}
        {hosts.map((host, i) => {
          const y = TOP_PADDING + i * LANE_HEIGHT;
          return (
            <g key={host}>
              <line
                x1={0}
                y1={y}
                x2={svgWidth}
                y2={y}
                stroke="#334155"
                strokeWidth={0.5}
                strokeDasharray="4,4"
              />
              <text
                x={4}
                y={y + LANE_HEIGHT / 2 + 3}
                className="fill-muted-foreground"
                fontSize={9}
                fontFamily="monospace"
              >
                {host.length > 12 ? host.slice(0, 12) + "…" : host}
              </text>
            </g>
          );
        })}

        {/* Edges */}
        {edges.map((edge, i) => {
          if (!validNodeIds.has(edge.source) || !validNodeIds.has(edge.target)) {
            return null;
          }
          const src = nodePositions.get(edge.source);
          const tgt = nodePositions.get(edge.target);
          if (!src || !tgt) return null;

          const edgeKey = `${edge.source}->${edge.target}`;
          const isNew = newEdgeIds.has(edgeKey);
          const midX = (src.x + tgt.x) / 2;

          return (
            <path
              key={`e-${i}`}
              d={`M${src.x},${src.y} C${midX},${src.y} ${midX},${tgt.y} ${tgt.x},${tgt.y}`}
              fill="none"
              stroke={isNew ? "#3b82f6" : "#475569"}
              strokeWidth={isNew ? 2 : 1}
              markerEnd={isNew ? "url(#arrowhead-new)" : "url(#arrowhead)"}
              opacity={0.8}
            />
          );
        })}

        {/* Nodes */}
        {allSorted.map((node) => {
          const pos = nodePositions.get(node.id);
          if (!pos) return null;
          const color = TACTIC_COLORS[node.tactic] || DEFAULT_NODE_COLOR;
          const isNew = newNodeIds.has(node.id);
          const opacity = node.attributed ? 1 : 0.5;

          return (
            <g key={node.id} opacity={opacity}>
              {/* One-shot highlight ring for new nodes (no continuous repaint) */}
              {isNew && (
                <circle
                  cx={pos.x}
                  cy={pos.y}
                  r={NODE_RADIUS + 4}
                  fill="none"
                  stroke={color}
                  strokeWidth={2}
                  opacity={0.7}
                  style={{ animation: "graph-node-flash 0.6s ease-out forwards" }}
                />
              )}
              <circle
                cx={pos.x}
                cy={pos.y}
                r={NODE_RADIUS}
                fill={color}
                stroke={isNew ? "#fff" : "#1e293b"}
                strokeWidth={isNew ? 1.5 : 0.5}
              />
              <title>
                {node.technique} · {node.tactic} · {node.host} · {node.id}
              </title>
              <text
                x={pos.x}
                y={pos.y + NODE_RADIUS + 10}
                textAnchor="middle"
                fontSize={8}
                fontFamily="monospace"
                className="fill-muted-foreground"
              >
                {node.technique || "?"}
              </text>
            </g>
          );
        })}
      </svg>
      {/* One-shot flash animation (no continuous repaint like animate-pulse) */}
      <style>{`
        @keyframes graph-node-flash {
          0% { opacity: 0.9; r: ${NODE_RADIUS + 4}; }
          100% { opacity: 0; r: ${NODE_RADIUS + 10}; }
        }
      `}</style>
    </div>
  );
}

export const AttackGraphView = React.memo(AttackGraphViewInner);
