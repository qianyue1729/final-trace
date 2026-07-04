"use client";

import { useMemo, useRef } from "react";
import type {
  LOCKPhaseEvent,
  KPhaseEventData,
  VetoPhaseEventData,
  CPhaseEventData,
  StopDecisionEventData,
  ExplanationSnapshot,
  BoundaryBeliefSnapshot,
  GraphNodeSnapshot,
  GraphEdgeSnapshot,
} from "@/app/types/types";

export interface GraphState {
  nodeCount: number;
  edgeCount: number;
  newNodes: number;
  newEdges: number;
  deltaPAtk: number | null;
}

export interface GraphRoundSnapshot {
  round: number;
  nodes: GraphNodeSnapshot[];
  edges: GraphEdgeSnapshot[];
  newNodeIds: Set<string>;
  newEdgeIds: Set<string>;
  truncated: boolean;
}

export interface DecisionState {
  explanations: ExplanationSnapshot[];
  contested: BoundaryBeliefSnapshot[];
  leading: string;
  margin: number;
  entropy: number;
  /** previous-round posteriors for trend arrows (eid -> posterior) */
  prevPosteriors: Record<string, number>;
}

export interface BetaAggregate {
  probeKey: string;
  hits: number;
  misses: number;
  alpha: number;
  beta: number;
}

export interface ObligationState {
  open: number;
  discharged: number;
  overdue: number;
  types: Record<string, number>;
}

export interface LOCKSnapshot {
  graphState: GraphState;
  decisionState: DecisionState | null;
  betaAggregates: BetaAggregate[];
  obligationState: ObligationState;
  stopDecision: StopDecisionEventData | null;
  graphHistory: GraphRoundSnapshot[];
}

export function useLOCKState(events: LOCKPhaseEvent[]): LOCKSnapshot {
  // Incremental fold: only process new events since last run
  const accRef = useRef<{
    graphState: GraphState;
    decisionState: DecisionState | null;
    betaMap: Map<string, BetaAggregate>;
    obligationState: ObligationState;
    stopDecision: StopDecisionEventData | null;
    graphHistory: GraphRoundSnapshot[];
    prevNodeIds: Set<string>;
    prevEdgeKeys: Set<string>;
    lastIndex: number;
    firstEventId: string | null; // detect thread reset
  }>({
    graphState: { nodeCount: 0, edgeCount: 0, newNodes: 0, newEdges: 0, deltaPAtk: null },
    decisionState: null,
    betaMap: new Map(),
    obligationState: { open: 0, discharged: 0, overdue: 0, types: {} },
    stopDecision: null,
    graphHistory: [],
    prevNodeIds: new Set(),
    prevEdgeKeys: new Set(),
    lastIndex: 0,
    firstEventId: null,
  });

  return useMemo(() => {
    const acc = accRef.current;

    // Detect thread reset: events array shorter or first event changed
    const firstId = events.length > 0
      ? `${(events[0] as any).phase}-${(events[0] as any).event_kind}-${(events[0] as any).round}`
      : null;
    if (events.length < acc.lastIndex || (acc.firstEventId && firstId !== acc.firstEventId)) {
      // Reset accumulator
      acc.graphState = { nodeCount: 0, edgeCount: 0, newNodes: 0, newEdges: 0, deltaPAtk: null };
      acc.decisionState = null;
      acc.betaMap = new Map();
      acc.obligationState = { open: 0, discharged: 0, overdue: 0, types: {} };
      acc.stopDecision = null;
      acc.graphHistory = [];
      acc.prevNodeIds = new Set();
      acc.prevEdgeKeys = new Set();
      acc.lastIndex = 0;
      acc.firstEventId = firstId;
    }
    if (events.length === 0) {
      acc.firstEventId = null;
    }

    // Incremental fold: only process events[acc.lastIndex..]
    for (let i = acc.lastIndex; i < events.length; i++) {
      const event = events[i];

      if (event.phase === "K" && event.event_kind === "phase_end") {
        const k = event as KPhaseEventData;
        acc.graphState.nodeCount = k.graph_node_count ?? acc.graphState.nodeCount;
        acc.graphState.edgeCount = k.graph_edge_count ?? acc.graphState.edgeCount;
        acc.graphState.newNodes = k.new_nodes ?? 0;
        acc.graphState.newEdges = k.new_edges ?? 0;

        const prevPosteriors: Record<string, number> = {};
        if (acc.decisionState) {
          for (const e of acc.decisionState.explanations) {
            prevPosteriors[e.eid] = e.posterior;
          }
        }
        acc.decisionState = {
          explanations: k.explanations ?? [],
          contested: k.contested_edges ?? [],
          leading: k.leading_explanation ?? "",
          margin: k.margin ?? 0,
          entropy: k.entropy ?? 0,
          prevPosteriors,
        };

        for (const u of k.beta_updates ?? []) {
          const existing = acc.betaMap.get(u.probe_key);
          if (existing) {
            if (u.hit) existing.hits++;
            else existing.misses++;
            existing.alpha = u.new_alpha;
            existing.beta = u.new_beta;
          } else {
            acc.betaMap.set(u.probe_key, {
              probeKey: u.probe_key,
              hits: u.hit ? 1 : 0,
              misses: u.hit ? 0 : 1,
              alpha: u.new_alpha,
              beta: u.new_beta,
            });
          }
        }

        acc.obligationState.open = k.obligations_open ?? 0;
        acc.obligationState.discharged = k.obligations_discharged ?? 0;
        acc.obligationState.overdue = k.obligations_overdue ?? 0;

        if (k.graph_nodes && k.graph_nodes.length > 0) {
          const nodes = k.graph_nodes;
          const edges = k.graph_edges ?? [];
          const currentNodeIds = new Set(nodes.map((n) => n.id));
          const currentEdgeKeys = new Set(
            edges.map((e) => `${e.source}->${e.target}`)
          );
          const newNodeIds = new Set(
            [...currentNodeIds].filter((id) => !acc.prevNodeIds.has(id))
          );
          const newEdgeIds = new Set(
            [...currentEdgeKeys].filter((key) => !acc.prevEdgeKeys.has(key))
          );
          const snapshot: GraphRoundSnapshot = {
            round: k.round ?? 0,
            nodes,
            edges,
            newNodeIds: acc.graphHistory.length === 0 ? currentNodeIds : newNodeIds,
            newEdgeIds: acc.graphHistory.length === 0 ? currentEdgeKeys : newEdgeIds,
            truncated: k.graph_truncated ?? false,
          };
          const existingIdx = acc.graphHistory.findIndex(
            (s) => s.round === snapshot.round
          );
          if (existingIdx >= 0) {
            acc.graphHistory[existingIdx] = snapshot;
          } else {
            acc.graphHistory.push(snapshot);
          }
          acc.prevNodeIds = currentNodeIds;
          acc.prevEdgeKeys = currentEdgeKeys;
        }
      }

      if (event.phase === "Veto" && event.event_kind === "phase_end") {
        const v = event as VetoPhaseEventData;
        acc.obligationState.types = v.obligation_types ?? acc.obligationState.types;
      }

      if (event.phase === "C" && event.event_kind === "phase_end") {
        const c = event as CPhaseEventData;
        if (c.delta_p_atk != null) acc.graphState.deltaPAtk = c.delta_p_atk;
      }

      if (event.event_kind === "stop_decision") {
        acc.stopDecision = event as StopDecisionEventData;
      }
    }

    acc.lastIndex = events.length;

    const betaAggregates = Array.from(acc.betaMap.values()).sort(
      (a, b) =>
        b.hits / Math.max(1, b.hits + b.misses) -
        a.hits / Math.max(1, a.hits + a.misses)
    );

    return {
      graphState: { ...acc.graphState },
      decisionState: acc.decisionState ? { ...acc.decisionState } : null,
      betaAggregates,
      obligationState: { ...acc.obligationState },
      stopDecision: acc.stopDecision,
      graphHistory: acc.graphHistory,
    };
  }, [events]);
}
