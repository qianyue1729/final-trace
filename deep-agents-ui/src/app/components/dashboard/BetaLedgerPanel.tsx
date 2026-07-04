"use client";

import React from "react";
import { cn } from "@/lib/utils";
import type { BetaAggregate } from "@/app/hooks/useLOCKState";

interface BetaLedgerPanelProps {
  aggregates: BetaAggregate[];
}

function BetaLedgerPanelInner({ aggregates }: BetaLedgerPanelProps) {
  if (aggregates.length === 0) {
    return (
      <div>
        <PanelTitle>Beta 台账</PanelTitle>
        <p className="mt-2 text-xs text-muted-foreground">等待数据...</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <PanelTitle>Beta 台账</PanelTitle>

      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-border text-muted-foreground">
            <th className="pb-1 text-left font-semibold">探针</th>
            <th className="pb-1 text-right font-semibold w-10">命中</th>
            <th className="pb-1 text-right font-semibold w-10">未中</th>
            <th className="pb-1 text-right font-semibold w-20">命中率</th>
          </tr>
        </thead>
        <tbody>
          {aggregates.map((agg) => {
            const total = agg.hits + agg.misses;
            const rate = total > 0 ? agg.hits / total : 0;
            return (
              <tr key={agg.probeKey} className="border-b border-border/40">
                <td className="py-1.5 pr-2 font-mono text-[11px] truncate max-w-[100px]">
                  {agg.probeKey}
                </td>
                <td className="py-1.5 text-right font-mono tabular-nums">
                  {agg.hits}
                </td>
                <td className="py-1.5 text-right font-mono tabular-nums">
                  {agg.misses}
                </td>
                <td className="py-1.5 pl-2">
                  <div className="flex items-center gap-1.5">
                    <div className="h-1.5 flex-1 overflow-hidden rounded bg-muted">
                      <div
                        className={cn(
                          "h-full rounded transition-all duration-500",
                          rate >= 0.7
                            ? "bg-green-500"
                            : rate >= 0.4
                              ? "bg-yellow-500"
                              : "bg-red-400"
                        )}
                        style={{ width: `${rate * 100}%` }}
                      />
                    </div>
                    <span className="w-8 shrink-0 text-right font-mono text-[10px] tabular-nums">
                      {(rate * 100).toFixed(0)}%
                    </span>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
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

export const BetaLedgerPanel = React.memo(BetaLedgerPanelInner);
