"use client";

import React from "react";
import { cn } from "@/lib/utils";
import type { DecisionState } from "@/app/hooks/useLOCKState";

interface DecisionLedgerPanelProps {
  state: DecisionState | null;
}

function DecisionLedgerPanelInner({ state }: DecisionLedgerPanelProps) {
  if (!state) {
    return (
      <div>
        <PanelTitle>决策账本</PanelTitle>
        <p className="mt-2 text-xs text-muted-foreground">等待数据...</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <PanelTitle>决策账本</PanelTitle>

      {/* Margin + Entropy */}
      <div className="grid grid-cols-2 gap-2">
        <StatBox
          label="margin"
          value={state.margin.toFixed(4)}
          warn={state.margin < 0.15}
        />
        <StatBox label="entropy" value={state.entropy.toFixed(4)} />
      </div>

      {/* Explanations */}
      <div className="flex flex-col gap-1.5">
        {state.explanations.map((exp) => {
          const prev = state.prevPosteriors[exp.eid];
          const diff = prev != null ? exp.posterior - prev : null;
          const isLeading = exp.eid === state.leading;
          return (
            <div
              key={exp.eid}
              className={cn(
                "rounded border px-2.5 py-1.5",
                exp.is_null
                  ? "border-dashed border-border bg-muted/20"
                  : isLeading
                    ? "border-primary/60 bg-primary/5"
                    : "border-border"
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 min-w-0">
                  <span
                    className={cn(
                      "truncate text-xs font-medium",
                      isLeading && "text-primary font-semibold"
                    )}
                  >
                    {exp.label}
                  </span>
                  {exp.is_null && (
                    <span className="shrink-0 rounded border border-border px-1 text-[9px] text-muted-foreground">
                      null 锚
                    </span>
                  )}
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <span className="font-mono text-xs tabular-nums">
                    {(exp.posterior * 100).toFixed(1)}%
                  </span>
                  {diff != null && Math.abs(diff) > 0.001 && (
                    <span
                      className={cn(
                        "text-[10px] font-medium",
                        diff > 0 ? "text-green-500" : "text-red-400"
                      )}
                    >
                      {diff > 0 ? "▲" : "▼"}
                      {Math.abs(diff * 100).toFixed(1)}
                    </span>
                  )}
                </div>
              </div>
              {/* posterior bar */}
              <div className="mt-1 h-1 w-full overflow-hidden rounded bg-muted">
                <div
                  className={cn(
                    "h-full rounded transition-all duration-500",
                    isLeading ? "bg-primary" : "bg-muted-foreground/40"
                  )}
                  style={{ width: `${Math.min(100, exp.posterior * 100)}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>

      {/* Contested edges */}
      {state.contested.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <h4 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            边界信念
          </h4>
          {state.contested.map((edge) => (
            <div key={edge.edge_id} className="rounded border border-border px-2.5 py-1.5">
              <div className="mb-1 text-[10px] font-mono text-muted-foreground truncate">
                {edge.edge_id}
              </div>
              <TriBar
                pAttack={edge.p_in_attack}
                pBenign={edge.p_benign}
                pOos={edge.p_oos}
              />
            </div>
          ))}
        </div>
      )}
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

function StatBox({
  label,
  value,
  warn = false,
}: {
  label: string;
  value: string;
  warn?: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded border px-3 py-2",
        warn ? "border-red-500/50 bg-red-500/5" : "border-border"
      )}
    >
      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div
        className={cn(
          "mt-0.5 font-mono text-sm font-semibold tabular-nums",
          warn && "text-red-400"
        )}
      >
        {value}
      </div>
    </div>
  );
}

function TriBar({
  pAttack,
  pBenign,
  pOos,
}: {
  pAttack: number;
  pBenign: number;
  pOos: number;
}) {
  const total = pAttack + pBenign + pOos || 1;
  const wA = (pAttack / total) * 100;
  const wB = (pBenign / total) * 100;
  const wO = (pOos / total) * 100;
  return (
    <div className="flex h-1.5 w-full overflow-hidden rounded">
      <div className="bg-green-500" style={{ width: `${wA}%` }} />
      <div className="bg-gray-400" style={{ width: `${wB}%` }} />
      <div className="bg-orange-400" style={{ width: `${wO}%` }} />
    </div>
  );
}

export const DecisionLedgerPanel = React.memo(DecisionLedgerPanelInner);
