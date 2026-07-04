"use client";

import React, { useState } from "react";
import { cn } from "@/lib/utils";
import type { GraphState, GraphRoundSnapshot } from "@/app/hooks/useLOCKState";
import { AttackGraphView } from "./AttackGraphView";

interface GraphLedgerProps {
  state: GraphState;
  history: GraphRoundSnapshot[];
  hasData: boolean;
}

function GraphLedgerInner({ state, history, hasData }: GraphLedgerProps) {
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);

  if (!hasData) {
    return <Placeholder title="图账本" />;
  }

  const deltaDir =
    state.deltaPAtk != null
      ? state.deltaPAtk > 0
        ? "up"
        : state.deltaPAtk < 0
          ? "down"
          : "flat"
      : null;

  const latestIdx = history.length - 1;
  const activeIdx = selectedIdx ?? latestIdx;
  const activeSnapshot = history[activeIdx] ?? null;
  const isFollowing = selectedIdx === null;

  return (
    <div className="flex flex-col gap-3">
      <PanelTitle>图账本</PanelTitle>

      {/* Node / Edge counts */}
      <div className="grid grid-cols-2 gap-2">
        <MetricCard
          label="节点"
          value={state.nodeCount}
          delta={state.newNodes}
          flash={state.newNodes > 0}
        />
        <MetricCard
          label="边"
          value={state.edgeCount}
          delta={state.newEdges}
          flash={state.newEdges > 0}
        />
      </div>

      {/* P(attack) delta */}
      {deltaDir && (
        <div
          className={cn(
            "flex items-center justify-between rounded border px-3 py-2 text-xs",
            deltaDir === "up"
              ? "border-orange-500/40 bg-orange-500/5 text-orange-400"
              : deltaDir === "down"
                ? "border-green-500/40 bg-green-500/5 text-green-400"
                : "border-border text-muted-foreground"
          )}
        >
          <span className="font-mono text-[11px] uppercase tracking-wider">
            ΔP(atk)
          </span>
          <span className="font-mono font-semibold">
            {deltaDir === "up" ? "▲" : deltaDir === "down" ? "▼" : "—"}{" "}
            {Math.abs(state.deltaPAtk!).toFixed(4)}
          </span>
        </div>
      )}

      {/* Attack graph with scrubber */}
      {history.length > 0 && activeSnapshot && (
        <div className="max-h-[280px] overflow-auto rounded border border-border/40">
          {/* Scrubber controls */}
          <div className="flex items-center gap-2 px-2 py-1 border-b border-border/30 bg-muted/20">
            <button
              onClick={() =>
                setSelectedIdx(Math.max(0, activeIdx - 1))
              }
              disabled={activeIdx <= 0}
              className="text-[10px] font-mono text-muted-foreground hover:text-foreground disabled:opacity-30 px-1"
            >
              ◀
            </button>
            <input
              type="range"
              min={0}
              max={latestIdx}
              value={activeIdx}
              onChange={(e) => setSelectedIdx(Number(e.target.value))}
              className="flex-1 h-1 accent-primary"
            />
            <button
              onClick={() =>
                setSelectedIdx(Math.min(latestIdx, activeIdx + 1))
              }
              disabled={activeIdx >= latestIdx}
              className="text-[10px] font-mono text-muted-foreground hover:text-foreground disabled:opacity-30 px-1"
            >
              ▶
            </button>
            <span className="text-[10px] font-mono text-muted-foreground whitespace-nowrap">
              R{activeSnapshot.round}
              {history.length > 1 && ` / R${history[latestIdx].round}`}
            </span>
            {!isFollowing && (
              <button
                onClick={() => setSelectedIdx(null)}
                className="text-[9px] font-mono text-primary/80 hover:text-primary px-1"
              >
                跟随
              </button>
            )}
          </div>

          {/* SVG graph */}
          <AttackGraphView snapshot={activeSnapshot} />

          {/* Delta caption */}
          <div className="flex items-center gap-2 px-2 py-1 text-[10px] font-mono text-muted-foreground border-t border-border/20">
            <span>
              本轮新增 {activeSnapshot.newNodeIds.size} 节点 /{" "}
              {activeSnapshot.newEdgeIds.size} 边
            </span>
            {activeSnapshot.truncated && (
              <span className="text-red-400/80">（图已截断）</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export const GraphLedger = React.memo(GraphLedgerInner);

function Placeholder({ title }: { title: string }) {
  return (
    <div>
      <PanelTitle>{title}</PanelTitle>
      <p className="mt-2 text-xs text-muted-foreground">等待数据...</p>
    </div>
  );
}

function PanelTitle({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">
      {children}
    </h3>
  );
}

function MetricCard({
  label,
  value,
  delta = 0,
  flash = false,
}: {
  label: string;
  value: number;
  delta?: number;
  flash?: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded border px-3 py-2 transition-colors duration-700",
        flash
          ? "border-primary/60 bg-primary/10"
          : "border-border bg-background"
      )}
    >
      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-0.5 flex items-baseline gap-1">
        <span className="font-mono text-base font-semibold tabular-nums">
          {value}
        </span>
        {delta > 0 && (
          <span className="text-[10px] font-medium text-primary">
            +{delta}
          </span>
        )}
      </div>
    </div>
  );
}
