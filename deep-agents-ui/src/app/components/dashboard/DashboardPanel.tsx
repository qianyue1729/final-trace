"use client";

import React from "react";
import { cn } from "@/lib/utils";
import type { LOCKPhaseEvent, LOCKPhase } from "@/app/types/types";
import { useLOCKState } from "@/app/hooks/useLOCKState";
import { GraphLedger } from "./GraphLedger";
import { DecisionLedgerPanel } from "./DecisionLedgerPanel";
import { BetaLedgerPanel } from "./BetaLedgerPanel";
import { ObligationPanel } from "./ObligationPanel";

export interface DashboardPanelProps {
  events: LOCKPhaseEvent[];
  currentRound: number;
  currentPhase: LOCKPhase | null;
  isRunning: boolean;
}

export function DashboardPanel({
  events,
  currentRound,
  currentPhase,
  isRunning,
}: DashboardPanelProps) {
  const {
    graphState,
    decisionState,
    betaAggregates,
    obligationState,
    stopDecision,
    graphHistory,
  } = useLOCKState(events);

  const hasGraphData = graphState.nodeCount > 0 || graphState.edgeCount > 0;
  const hasObligationData =
    obligationState.open > 0 ||
    obligationState.discharged > 0 ||
    obligationState.overdue > 0 ||
    Object.keys(obligationState.types).length > 0;

  return (
    <div className="flex flex-col gap-3">
      {/* Status bar */}
      <StatusBar
        round={currentRound}
        phase={currentPhase}
        isRunning={isRunning}
        stopReason={stopDecision?.stop_reason}
      />

      {/* 2×2 grid — collapses to single column on small screens */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <PanelCard>
          <GraphLedger state={graphState} history={graphHistory} hasData={hasGraphData} />
        </PanelCard>
        <PanelCard>
          <DecisionLedgerPanel state={decisionState} />
        </PanelCard>
        <PanelCard>
          <BetaLedgerPanel aggregates={betaAggregates} />
        </PanelCard>
        <PanelCard>
          <ObligationPanel state={obligationState} hasData={hasObligationData} />
        </PanelCard>
      </div>
    </div>
  );
}

function StatusBar({
  round,
  phase,
  isRunning,
  stopReason,
}: {
  round: number;
  phase: LOCKPhase | null;
  isRunning: boolean;
  stopReason?: string;
}) {
  return (
    <div className="flex items-center gap-3 rounded border border-border bg-background px-3 py-2">
      {/* Running indicator */}
      <div className="flex items-center gap-1.5">
        <div
          className={cn(
            "h-2 w-2 rounded-full",
            isRunning
              ? "bg-green-500 animate-pulse"
              : stopReason
                ? "bg-muted-foreground"
                : "bg-muted-foreground/40"
          )}
        />
        <span className="text-[11px] font-medium text-muted-foreground">
          {isRunning ? "运行中" : stopReason ? "已停止" : "空闲"}
        </span>
      </div>

      <Divider />

      <span className="text-[11px] font-mono text-muted-foreground">
        R{round}
      </span>

      {phase && (
        <>
          <Divider />
          <span
            className={cn(
              "rounded px-1.5 py-0.5 text-[10px] font-semibold",
              "bg-primary/10 text-primary"
            )}
          >
            {phase} 拍
          </span>
        </>
      )}

      {stopReason && (
        <>
          <Divider />
          <span className="truncate text-[11px] text-muted-foreground">
            {stopReason}
          </span>
        </>
      )}
    </div>
  );
}

function Divider() {
  return <div className="h-3 w-px bg-border" />;
}

function PanelCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-border bg-background p-3">
      {children}
    </div>
  );
}
