"use client";

import React from "react";
import { cn } from "@/lib/utils";
import type { ObligationState } from "@/app/hooks/useLOCKState";

interface ObligationPanelProps {
  state: ObligationState;
  hasData: boolean;
}

function ObligationPanelInner({ state, hasData }: ObligationPanelProps) {
  if (!hasData) {
    return (
      <div>
        <PanelTitle>义务台账</PanelTitle>
        <p className="mt-2 text-xs text-muted-foreground">等待数据...</p>
      </div>
    );
  }

  const typeEntries = Object.entries(state.types);

  return (
    <div className="flex flex-col gap-3">
      <PanelTitle>义务台账</PanelTitle>

      {/* Counts */}
      <div className="grid grid-cols-3 gap-2">
        <CountCard label="开放" value={state.open} />
        <CountCard label="已履行" value={state.discharged} success />
        <CountCard label="逾期" value={state.overdue} danger={state.overdue > 0} />
      </div>

      {/* Type distribution */}
      {typeEntries.length > 0 && (
        <div className="flex flex-col gap-1">
          <h4 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            义务类型
          </h4>
          {typeEntries.map(([type, count]) => (
            <div
              key={type}
              className="flex items-center justify-between rounded border border-border px-2.5 py-1"
            >
              <span className="truncate text-xs">{type}</span>
              <span className="shrink-0 font-mono text-xs tabular-nums font-semibold">
                {count}
              </span>
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

function CountCard({
  label,
  value,
  success = false,
  danger = false,
}: {
  label: string;
  value: number;
  success?: boolean;
  danger?: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded border px-2 py-2 text-center",
        danger
          ? "border-red-500/50 bg-red-500/10"
          : success
            ? "border-green-500/40 bg-green-500/5"
            : "border-border"
      )}
    >
      <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div
        className={cn(
          "mt-0.5 font-mono text-lg font-bold tabular-nums",
          danger ? "text-red-400" : success ? "text-green-500" : ""
        )}
      >
        {value}
      </div>
    </div>
  );
}

export const ObligationPanel = React.memo(ObligationPanelInner);
