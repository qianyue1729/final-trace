import type { GraphEdge, GraphNode, GraphSnapshot } from '../types';

const TACTIC_ORDER = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
  'unknown',
];

export type GraphFilter = 'attack' | 'all';

export interface LayoutNode extends GraphNode {
  x: number;
  y: number;
  shortLabel: string;
}

export interface HostColumn {
  host: string;
  x: number;
  width: number;
}

export interface LayoutResult {
  nodes: LayoutNode[];
  edges: GraphEdge[];
  hostColumns: HostColumn[];
  viewBox: string;
  width: number;
  height: number;
  synthEdgeCount: number;
}

function tacticIndex(tactic: string): number {
  const i = TACTIC_ORDER.indexOf(tactic || 'unknown');
  return i >= 0 ? i : TACTIC_ORDER.length;
}

function shortLabel(node: GraphNode): string {
  if (node.technique) return node.technique;
  const parts = node.label.split(' · ');
  return parts[parts.length - 1] || node.label;
}

function filterNodes(nodes: GraphNode[], mode: GraphFilter): GraphNode[] {
  if (mode === 'all') return nodes;
  const attacks = nodes.filter((n) => n.malicious);
  return attacks.length > 0 ? attacks : nodes;
}

function filterEdges(edges: GraphEdge[], visibleIds: Set<string>): GraphEdge[] {
  return edges.filter((e) => visibleIds.has(e.source) && visibleIds.has(e.target));
}

/** 同主机内按战术+时间顺序补 kill-chain 连线（仅当真实边很少时） */
function synthesizeHostChainEdges(nodes: LayoutNode[]): GraphEdge[] {
  const byHost = new Map<string, LayoutNode[]>();
  for (const n of nodes) {
    const h = (n.host || 'unknown').toLowerCase();
    if (!byHost.has(h)) byHost.set(h, []);
    byHost.get(h)!.push(n);
  }
  const out: GraphEdge[] = [];
  let seq = 0;
  for (const group of byHost.values()) {
    if (group.length < 2) continue;
    const sorted = [...group].sort((a, b) => {
      const td = tacticIndex(a.tactic || '') - tacticIndex(b.tactic || '');
      if (td !== 0) return td;
      return (a.timestamp ?? 0) - (b.timestamp ?? 0);
    });
    for (let i = 0; i < sorted.length - 1; i += 1) {
      seq += 1;
      out.push({
        id: `synth-${seq}`,
        source: sorted[i].id,
        target: sorted[i + 1].id,
        label: '→',
        confirmed: true,
      });
    }
  }
  return out;
}

/** 主机列 × 战术行的网格布局 */
export function layoutGraphSnapshot(
  graph: GraphSnapshot,
  filter: GraphFilter,
): LayoutResult {
  const COL_W = 108;
  const ROW_H = 46;
  const HEADER_H = 32;
  const MARGIN_X = 48;
  const MARGIN_Y = 36;
  const BOTTOM = 24;

  const filtered = filterNodes(graph.nodes, filter);
  const hasMeta = filtered.some((n) => n.host || n.tactic);

  if (!hasMeta) {
    const nodes: LayoutNode[] = filtered.map((n) => ({
      ...n,
      shortLabel: shortLabel(n),
    }));
    const ids = new Set(nodes.map((n) => n.id));
    const edges = filterEdges(graph.edges, ids);
    const xs = nodes.map((n) => n.x);
    const ys = nodes.map((n) => n.y);
    const minX = Math.min(...xs, 0) - 40;
    const maxX = Math.max(...xs, 600) + 40;
    const minY = Math.min(...ys, 0) - 40;
    const maxY = Math.max(...ys, 320) + 40;
    return {
      nodes,
      edges,
      hostColumns: [],
      viewBox: `${minX} ${minY} ${maxX - minX} ${maxY - minY}`,
      width: maxX - minX,
      height: maxY - minY,
      synthEdgeCount: 0,
    };
  }

  const hosts = [...new Set(filtered.map((n) => n.host || 'unknown'))].sort((a, b) =>
    a.localeCompare(b, undefined, { sensitivity: 'base' }),
  );

  const byHost = new Map<string, GraphNode[]>();
  for (const n of filtered) {
    const h = n.host || 'unknown';
    if (!byHost.has(h)) byHost.set(h, []);
    byHost.get(h)!.push(n);
  }

  const layoutNodes: LayoutNode[] = [];
  const hostColumns: HostColumn[] = [];
  let maxRows = 0;

  hosts.forEach((host, col) => {
    const group = byHost.get(host) ?? [];
    group.sort((a, b) => {
      const td = tacticIndex(a.tactic || '') - tacticIndex(b.tactic || '');
      if (td !== 0) return td;
      return (a.timestamp ?? 0) - (b.timestamp ?? 0);
    });
    maxRows = Math.max(maxRows, group.length);
    const colX = MARGIN_X + col * COL_W;
    hostColumns.push({ host, x: colX, width: COL_W });

    group.forEach((node, row) => {
      layoutNodes.push({
        ...node,
        x: colX + COL_W / 2,
        y: MARGIN_Y + HEADER_H + row * ROW_H,
        shortLabel: shortLabel(node),
      });
    });
  });

  const visibleIds = new Set(layoutNodes.map((n) => n.id));
  let edges = filterEdges(graph.edges, visibleIds);
  let synthEdgeCount = 0;
  if (edges.length < Math.max(1, layoutNodes.length / 3)) {
    const synth = synthesizeHostChainEdges(layoutNodes);
    const existing = new Set(edges.map((e) => `${e.source}|${e.target}`));
    for (const e of synth) {
      const key = `${e.source}|${e.target}`;
      if (!existing.has(key)) {
        edges.push(e);
        existing.add(key);
        synthEdgeCount += 1;
      }
    }
  }

  const width = MARGIN_X * 2 + hosts.length * COL_W;
  const height = MARGIN_Y + HEADER_H + maxRows * ROW_H + BOTTOM;

  return {
    nodes: layoutNodes,
    edges,
    hostColumns,
    viewBox: `0 0 ${width} ${height}`,
    width,
    height,
    synthEdgeCount,
  };
}

export function defaultGraphFilter(graph: GraphSnapshot): GraphFilter {
  if (graph.meta?.defaultFilter === 'all') return 'all';
  if (graph.meta?.defaultFilter === 'attack') return 'attack';
  const total = graph.meta?.totalNodes ?? graph.nodes.length;
  const attacks = graph.meta?.attackNodes ?? graph.nodes.filter((n) => n.malicious).length;
  if (total > 18 && attacks >= 3) return 'attack';
  return 'all';
}
