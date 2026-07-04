/**
 * @deprecated 已被 LOCKPhaseStream.tsx 替代。保留仅为向后兼容，新代码请使用 LOCKPhaseStream。
 */
"use client";

import React, { useMemo } from "react";
import { CheckCircle2, Circle, Loader2 } from "lucide-react";
import type { LockProgressEvent } from "@/app/types/types";
import { cn } from "@/lib/utils";

const PHASES = ["L", "Veto", "O", "C", "K"] as const;

function parseReport(result?: string): Record<string, any> | null {
  if (!result) return null;
  try {
    const value = JSON.parse(result);
    return value && typeof value === "object" ? value : null;
  } catch {
    return null;
  }
}

function phaseText(event: LockProgressEvent): string {
  if (event.phase === "L") return `候选 ${event.candidate_count ?? "-"}`;
  if (event.phase === "Veto") return `保留 ${event.candidate_count ?? "-"}`;
  if (event.phase === "O")
    return (event.probes_selected ?? []).join(", ") || "无探针";
  if (event.phase === "C")
    return `事件 ${event.events ?? 0} · 入图 ${event.attached ?? 0}`;
  if (event.phase === "K") {
    const delta =
      typeof event.delta_p_atk === "number" ? `ΔP ${event.delta_p_atk}` : "";
    return (
      [delta, event.stop_reason_candidate].filter(Boolean).join(" · ") || "继续"
    );
  }
  return event.stage;
}

export function LockLoopPanel({
  progress,
  result,
}: {
  progress: LockProgressEvent[];
  result?: string;
}) {
  const report = useMemo(() => parseReport(result), [result]);
  const latestRound = Math.max(0, ...progress.map((item) => item.round ?? 0));
  const latestByPhase = new Map<string, LockProgressEvent>();
  progress
    .filter((item) => (item.round ?? 0) === latestRound && item.phase)
    .forEach((item) => latestByPhase.set(item.phase!, item));
  const model = report?.model_processing;
  const judgement = model?.judgement;
  const livePlanner = [...progress]
    .reverse()
    .find((item) => item.model_planner)?.model_planner;
  const liveJudgement = [...progress]
    .reverse()
    .find((item) => item.model_judgement)?.model_judgement;
  const hasLiveModel = Boolean(livePlanner || liveJudgement);
  const rounds = report?.lock_loop?.rounds ?? [];

  return (
    <div className="mt-4 space-y-3">
      <div className="rounded-md border border-border bg-background p-3">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              LOCK 调查循环
            </div>
            <div className="mt-1 text-sm font-medium">
              {report?.display_headline ??
                (latestRound ? `第 ${latestRound} 轮处理中` : "等待执行")}
            </div>
          </div>
          {!report && progress.length > 0 && (
            <Loader2 className="h-4 w-4 animate-spin" />
          )}
        </div>
        <div className="grid grid-cols-5 gap-2">
          {PHASES.map((phase) => {
            const event = latestByPhase.get(phase);
            const done =
              event?.status === "completed" || event?.status === "stopped";
            return (
              <div
                key={phase}
                className={cn(
                  "rounded border p-2",
                  event && "border-primary/40 bg-primary/5"
                )}
              >
                <div className="flex items-center gap-1 text-xs font-semibold">
                  {done ? (
                    <CheckCircle2 className="h-3 w-3 text-success" />
                  ) : (
                    <Circle className="h-3 w-3 text-muted-foreground" />
                  )}
                  {phase}
                </div>
                <div
                  className="mt-1 truncate text-[11px] text-muted-foreground"
                  title={event ? phaseText(event) : "等待"}
                >
                  {event ? phaseText(event) : "等待"}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {!report && hasLiveModel && (
        <details
          className="rounded-md border border-border bg-background p-3"
          open
        >
          <summary className="cursor-pointer text-sm font-semibold">
            模型处理中间结果
          </summary>
          <pre className="mt-3 max-h-56 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 text-[11px] leading-5">
            {JSON.stringify(
              { planner: livePlanner, judgement: liveJudgement },
              null,
              2
            )}
          </pre>
        </details>
      )}

      {report && (
        <>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Metric
              label="建链"
              value={report.chain_build_label}
            />
            <Metric
              label="归因"
              value={report.attribution_label}
            />
            <Metric
              label="轮次"
              value={report.lock_loop?.rounds_used}
            />
            <Metric
              label="停止原因"
              value={report.lock_loop?.final_stop_reason}
            />
          </div>

          {rounds.length > 0 && (
            <details
              className="rounded-md border border-border bg-background p-3"
              open
            >
              <summary className="cursor-pointer text-sm font-semibold">
                逐轮处理结果（{rounds.length}）
              </summary>
              <div className="mt-3 max-h-72 space-y-2 overflow-y-auto">
                {rounds.map((round: any) => (
                  <div
                    key={round.round}
                    className="rounded border border-border/70 p-2 text-xs"
                  >
                    <div className="font-semibold">
                      第 {round.round} 轮 · L → Veto → O → C → K
                    </div>
                    <div className="mt-1 text-muted-foreground">
                      探针 {(round.probes_selected ?? []).join(", ") || "无"} ·
                      新节点 {round.new_graph_nodes ?? 0} · 新边{" "}
                      {round.new_graph_edges ?? 0} · P(atk){" "}
                      {round.p_atk_before ?? "-"} → {round.p_atk_after ?? "-"}
                    </div>
                  </div>
                ))}
              </div>
            </details>
          )}

          <details
            className="rounded-md border border-border bg-background p-3"
            open
          >
            <summary className="cursor-pointer text-sm font-semibold">
              模型处理结果
            </summary>
            <div className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <Metric
                label="Judgement 模式"
                value={judgement?.mode ?? "off"}
              />
              <Metric
                label="模型调用"
                value={judgement?.l3_llm_calls ?? 0}
              />
              <Metric
                label="Provider 错误"
                value={judgement?.provider_errors ?? 0}
              />
              <Metric
                label="Planner 轮次"
                value={model?.planner?.length ?? 0}
              />
            </div>
            {(model?.planner?.length > 0 || judgement?.audit?.length > 0) && (
              <pre className="mt-3 max-h-64 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-2 text-[11px] leading-5">
                {JSON.stringify(
                  {
                    planner: model.planner,
                    judgement_audit: judgement.audit,
                    summary: judgement.shadow_summary,
                  },
                  null,
                  2
                )}
              </pre>
            )}
          </details>
        </>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: unknown }) {
  return (
    <div className="rounded-md border border-border bg-background p-2">
      <div className="text-[10px] uppercase tracking-wider text-muted-foreground">
        {label}
      </div>
      <div className="mt-1 break-words text-xs font-medium">
        {value == null || value === "" ? "-" : String(value)}
      </div>
    </div>
  );
}
