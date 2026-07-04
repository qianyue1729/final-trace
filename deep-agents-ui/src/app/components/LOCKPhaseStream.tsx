"use client";

import React, { useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type {
  LOCKPhaseEvent,
  LOCKPhase,
  LPhaseEventData,
  VetoPhaseEventData,
  OPhaseEventData,
  CPhaseEventData,
  KPhaseEventData,
  StopDecisionEventData,
} from "@/app/types/types";
import { cn } from "@/lib/utils";

const PHASES: LOCKPhase[] = ["L", "Veto", "O", "C", "K"];

const PHASE_LABELS: Record<LOCKPhase, string> = {
  L: "候选生成",
  Veto: "剪枝检验",
  O: "VOI 排序",
  C: "扇出取证",
  K: "决策更新",
};

export interface LOCKPhaseStreamProps {
  events: LOCKPhaseEvent[];
  currentRound: number;
  currentPhase: LOCKPhase | null;
  isRunning: boolean;
}

export function LOCKPhaseStream({
  events,
  currentRound,
  currentPhase,
  isRunning,
}: LOCKPhaseStreamProps) {
  const rounds = useMemo(
    () => Array.from(new Set(events.map((e) => e.round))).sort((a, b) => a - b),
    [events]
  );
  const [selectedRound, setSelectedRound] = useState<number | null>(null);
  const viewRound = selectedRound ?? currentRound;

  const roundEvents = useMemo(
    () => events.filter((e) => e.round === viewRound),
    [events, viewRound]
  );

  const phaseEventMap = useMemo(() => {
    const map = new Map<LOCKPhase, LOCKPhaseEvent>();
    for (const e of roundEvents) {
      if (e.event_kind === "phase_end" && PHASES.includes(e.phase as LOCKPhase)) {
        map.set(e.phase as LOCKPhase, e);
      }
    }
    return map;
  }, [roundEvents]);

  const stopDecision = useMemo(
    () =>
      events.find((e): e is StopDecisionEventData => e.event_kind === "stop_decision") ??
      null,
    [events]
  );

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const toggle = (key: string) =>
    setCollapsed((p) => ({ ...p, [key]: !p[key] }));

  // Auto-collapse non-current rounds to reduce DOM size
  const isHistoryRound = (r: number) => r !== currentRound;

  return (
    <div className="mt-3 space-y-3">
      {/* Phase indicator */}
      <div className="rounded-md border border-border bg-background p-3">
        <div className="flex items-center justify-between gap-1">
          {PHASES.map((phase, i) => {
            const isCurrent = phase === currentPhase && isRunning;
            const isDone = phaseEventMap.has(phase);
            return (
              <React.Fragment key={phase}>
                {i > 0 && (
                  <div
                    className={cn(
                      "h-px flex-1",
                      isDone ? "bg-primary/60" : "bg-border"
                    )}
                  />
                )}
                <div className="flex flex-col items-center gap-1">
                  <div
                    className={cn(
                      "flex h-6 w-6 items-center justify-center rounded-full text-[10px] font-bold",
                      isCurrent && "animate-pulse bg-primary text-primary-foreground",
                      isDone && !isCurrent && "bg-primary/80 text-primary-foreground",
                      !isDone && !isCurrent && "bg-muted text-muted-foreground"
                    )}
                  >
                    {phase[0]}
                  </div>
                  <span className="text-[9px] text-muted-foreground whitespace-nowrap">
                    {PHASE_LABELS[phase]}
                  </span>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Round selector */}
      {rounds.length > 1 && (
        <div className="flex gap-1 overflow-x-auto pb-1">
          {rounds.map((r) => (
            <button
              key={r}
              onClick={() => setSelectedRound(r === selectedRound ? null : r)}
              className={cn(
                "shrink-0 rounded px-2 py-0.5 text-[11px] font-medium transition-colors",
                r === viewRound
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/50 text-muted-foreground hover:bg-muted"
              )}
            >
              R{r}
            </button>
          ))}
        </div>
      )}

      {/* Phase detail cards */}
      <div className="space-y-2">
        {PHASES.map((phase) => {
          const evt = phaseEventMap.get(phase);
          if (!evt) return null;
          const key = `${viewRound}-${phase}`;
          const isCollapsed = collapsed[key] ?? isHistoryRound(viewRound);
          return (
            <div
              key={key}
              className="rounded-md border border-border bg-background overflow-hidden"
            >
              <button
                onClick={() => toggle(key)}
                className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/30 transition-colors"
              >
                {isCollapsed ? (
                  <ChevronRight size={12} className="text-muted-foreground shrink-0" />
                ) : (
                  <ChevronDown size={12} className="text-muted-foreground shrink-0" />
                )}
                <span className="text-[10px] font-bold uppercase tracking-wider text-primary/80">
                  [{phase}]
                </span>
                <span className="text-xs font-medium text-foreground">
                  {PHASE_LABELS[phase]}
                </span>
              </button>
              {!isCollapsed && (
                <div className="border-t border-border px-3 py-2">
                  <PhaseBody event={evt} />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Stop reasoning */}
      {stopDecision && (
        <div className="rounded-md border border-amber-500/40 bg-amber-500/5 p-3">
          <div className="text-[10px] font-bold uppercase tracking-wider text-amber-400">
            停止推理
          </div>
          <div className="mt-1 text-xs text-foreground">
            原因: <span className="font-mono font-semibold">{stopDecision.stop_reason}</span>
          </div>
          {stopDecision.reasoning && (
            <div className="mt-1 text-[11px] text-muted-foreground leading-relaxed">
              {stopDecision.reasoning}
            </div>
          )}
          <div className="mt-2 flex gap-3 text-[10px] text-muted-foreground font-mono">
            <span>max_voi={stopDecision.max_voi.toFixed(3)}</span>
            <span>robust={stopDecision.decision_robust ? "✓" : "✗"}</span>
            <span>obligations_open={stopDecision.hard_obligations_open}</span>
          </div>
        </div>
      )}
    </div>
  );
}

const PhaseBody = React.memo(function PhaseBody({ event }: { event: LOCKPhaseEvent }) {
  if (event.phase === "L") return <LBody e={event as LPhaseEventData} />;
  if (event.phase === "Veto") return <VetoBody e={event as VetoPhaseEventData} />;
  if (event.phase === "O") return <OBody e={event as OPhaseEventData} />;
  if (event.phase === "C") return <CBody e={event as CPhaseEventData} />;
  if (event.phase === "K") return <KBody e={event as KPhaseEventData} />;
  return null;
});

function LBody({ e }: { e: LPhaseEventData }) {
  return (
    <div className="space-y-1">
      <div className="text-xs">
        候选数: <span className="font-mono font-semibold">{e.candidates_count}</span>
      </div>
      {e.pool_summary && Object.keys(e.pool_summary).length > 0 && (
        <div className="text-[11px] text-muted-foreground font-mono">
          {Object.entries(e.pool_summary).map(([k, v]) => `${k}: ${v}`).join(" | ")}
        </div>
      )}
    </div>
  );
}

function VetoBody({ e }: { e: VetoPhaseEventData }) {
  return (
    <div className="space-y-1">
      <div className="text-xs">
        剪枝: <span className="font-mono text-red-400">{e.vetoed_count}</span>
        {" | "}存活: <span className="font-mono text-green-400">{e.surviving_count}</span>
      </div>
      {e.veto_reasons && Object.keys(e.veto_reasons).length > 0 && (
        <div className="text-[11px] text-muted-foreground font-mono">
          {Object.entries(e.veto_reasons).map(([k, v]) => `${k}:${v}`).join(", ")}
        </div>
      )}
      {e.mandated_count > 0 && (
        <div className="text-[11px] text-muted-foreground">
          义务: {e.mandated_count} (
          {Object.entries(e.obligation_types ?? {}).map(([k, v]) => `${k}×${v}`).join(", ")})
        </div>
      )}
    </div>
  );
}

function OBody({ e }: { e: OPhaseEventData }) {
  const top = (e.voi_ranking ?? []).slice(0, 5);
  return (
    <div className="space-y-1">
      <div className="text-[11px] text-muted-foreground mb-1">
        slots: {e.slots_filled}/{e.slots_total} (义务槽: {e.obligation_slots})
        {e.llm_gate_triggered && (
          <span className="ml-2 text-amber-400 font-semibold">⚡ LLM 图侦察已触发</span>
        )}
      </div>
      {top.length > 0 && (
        <div className="space-y-1">
          <div className="text-[10px] font-bold uppercase tracking-wider text-primary/60 mb-0.5">
            模型选择的 Wazuh 探针
          </div>
          <div className="font-mono text-[11px] space-y-0.5">
            {top.map((r, i) => (
              <div key={i} className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 truncate">
                  <span className="text-blue-400 font-semibold">{r.operator || r.source}</span>
                  {r.target && <span className="text-muted-foreground">→ {r.target}</span>}
                </div>
                <span
                  className={cn(
                    "shrink-0",
                    r.voi_score >= 0.6
                      ? "text-green-400"
                      : r.voi_score >= 0.3
                        ? "text-yellow-400"
                        : "text-red-400"
                  )}
                >
                  VOI={r.voi_score.toFixed(3)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CBody({ e }: { e: CPhaseEventData }) {
  const queries = e.wazuh_queries ?? [];
  const judgements = e.llm_judgements ?? [];
  const compiler = e.mcp_compiler_audit;
  return (
    <div className="space-y-2">
      {compiler && (
        <div className="text-[10px] font-mono text-muted-foreground">
          MCP {compiler.mode}: {compiler.accepted}/{compiler.proposed} accepted,
          {" "}{compiler.executed} executed,
          {" "}{compiler.fallback_probes} fallback
          {(compiler.plans ?? [])
            .filter((plan) => !plan.accepted)
            .slice(0, 2)
            .map((plan) => (
              <div key={plan.plan_id} className="truncate text-red-400/80">
                {plan.source_probe_id}: {plan.validator_reasons.join(", ")}
              </div>
            ))}
        </div>
      )}
      {/* Transport query results */}
      {queries && queries.length > 0 && (() => {
        // Group template queries by target for dedup summary
        const templateQueries = queries.filter(q => q.source !== "model_plan");
        const groupSize = templateQueries[0]?.query_group_size ?? 1;
        const sharedRecords = templateQueries[0]?.shared_records ?? 0;
        const totalMatched = queries.reduce((sum, q) => sum + (q.events_matched ?? 0), 0);
        return (
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-blue-400/80 mb-0.5">
              Evidence query results
              {groupSize > 1 && (
                <span className="ml-2 text-muted-foreground normal-case">
                  ({groupSize} probes → 1 deduplicated query, {sharedRecords} records fetched)
                </span>
              )}
            </div>
            <div className="font-mono text-[11px] space-y-0.5">
              {queries.slice(0, 8).map((q, i) => (
                <div key={i} className="flex items-center justify-between gap-2">
                  <span className="text-blue-400">
                    {q.mcp_tool || q.operator}
                  </span>
                  {q.query_preview && (
                    <span
                      className="max-w-48 truncate text-[10px] text-muted-foreground"
                      title={q.query_preview}
                    >
                      {q.query_preview}
                    </span>
                  )}
                  <span className="text-muted-foreground">→ {q.target}</span>
                  <span className="text-green-400">{q.events_matched ?? 0} matched</span>
                  <span className="text-muted-foreground">
                    {q.source === "model_plan" ? "model" : "template"}
                    {q.transport ? ` ${q.transport}` : ""}
                    {q.records_returned ? ` | ~${q.records_returned} recs` : ""}
                    {q.elapsed_ms > 0 ? ` ${q.elapsed_ms}ms` : ""}
                  </span>
                </div>
              ))}
            </div>
            {totalMatched > 0 && (
              <div className="text-[10px] font-mono text-green-400/80 mt-0.5">
                Total: {totalMatched} matched events → ingest pipeline
              </div>
            )}
          </div>
        );
      })()}
      {/* L0-L4 Triage Pipeline */}
      {e.triage_pipeline && (() => {
        const tp = e.triage_pipeline;
        const bucketColors: Record<string, string> = {
          ATTACH: "text-green-400", WEAK: "text-green-400/60",
          PARK: "text-yellow-400", DISCARD: "text-red-400", SPAWN: "text-blue-400",
        };
        return (
          <div>
            <div className="text-[10px] font-bold uppercase tracking-wider text-cyan-400/80 mb-1">
              Triage pipeline (L0–L4)
            </div>
            {/* Funnel summary */}
            <div className="flex items-center gap-1 text-[11px] font-mono mb-1">
              <span className="text-muted-foreground">raw {tp.raw_events}</span>
              <span className="text-muted-foreground/50">→</span>
              <span className="text-cyan-400">L0 {tp.l0_clean}</span>
              {tp.filtered > 0 && (
                <span className="text-red-400/60">(-{tp.filtered} noise)</span>
              )}
              <span className="text-muted-foreground/50">→</span>
              <span className="text-green-400">ATTACH {e.attached}</span>
              <span className="text-green-400/60">WEAK {e.weak_attached}</span>
              <span className="text-yellow-400">PARK {e.parked}</span>
              <span className="text-red-400">DISCARD {e.discarded}</span>
              <span className="text-blue-400">SPAWN {e.spawned}</span>
            </div>
            {/* Trust tier distribution */}
            {Object.keys(tp.trust_tier_distribution).length > 0 && (
              <div className="flex flex-wrap gap-x-2 text-[10px] font-mono text-muted-foreground mb-0.5">
                <span className="text-cyan-400/60">L2 trust:</span>
                {Object.entries(tp.trust_tier_distribution).map(([tier, count]) => (
                  <span key={tier}>{tier}×{count}</span>
                ))}
                <span className="mx-1 text-muted-foreground/30">|</span>
                <span className="text-cyan-400/60">L3 attr:</span>
                {Object.entries(tp.attribution_status_distribution).map(([st, count]) => (
                  <span key={st}>{st}×{count}</span>
                ))}
              </div>
            )}
            {/* Per-event detail table (expandable, max 10) */}
            {tp.events.length > 0 && (
              <details className="mt-1">
                <summary className="text-[10px] cursor-pointer text-muted-foreground/80 hover:text-muted-foreground">
                  Show {tp.events.length} triaged events
                </summary>
                <div className="mt-0.5 max-h-48 overflow-y-auto border border-border/30 rounded">
                  <table className="w-full text-[10px] font-mono">
                    <thead>
                      <tr className="text-muted-foreground/60 border-b border-border/20">
                        <th className="text-left px-1 py-0.5">technique</th>
                        <th className="text-left px-1">tactic</th>
                        <th className="text-left px-1">host</th>
                        <th className="text-left px-1">bucket</th>
                        <th className="text-left px-1">trust</th>
                        <th className="text-left px-1">attr</th>
                      </tr>
                    </thead>
                    <tbody>
                      {tp.events.slice(0, 20).map((ev, i) => (
                        <tr key={i} className="border-b border-border/10 hover:bg-muted/20">
                          <td className="px-1 py-0.5 text-cyan-300">{ev.technique || "-"}</td>
                          <td className="px-1">{ev.tactic || "-"}</td>
                          <td className="px-1 text-muted-foreground">{ev.host || "-"}</td>
                          <td className={cn("px-1 font-semibold", bucketColors[ev.bucket] || "text-muted-foreground")}>
                            {ev.bucket || "?"}
                          </td>
                          <td className="px-1">
                            {ev.trust_tier}
                            {ev.integrity > 0 && (
                              <span className="text-muted-foreground/50">({ev.integrity})</span>
                            )}
                          </td>
                          <td className={cn("px-1",
                            ev.attribution_status === "CONFIRMED" ? "text-green-400" :
                            ev.attribution_status === "CONTESTED" ? "text-yellow-400" :
                            "text-muted-foreground/50"
                          )}>
                            {ev.attribution_status || "-"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            )}
          </div>
        );
      })()}
      {/* LLM 研判 */}
      {judgements && judgements.length > 0 && (
        <div>
          <div className="text-[10px] font-bold uppercase tracking-wider text-purple-400/80 mb-0.5">
            LLM 研判 (L4)
          </div>
          <div className="text-[11px] space-y-0.5">
            {judgements.slice(0, 5).map((j, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className={cn(
                  "font-mono font-semibold",
                  j.verdict === "attach" ? "text-green-400" :
                  j.verdict === "park" ? "text-yellow-400" :
                  j.verdict === "discard" ? "text-red-400" :
                  j.verdict === "spawn" ? "text-blue-400" : "text-muted-foreground"
                )}>
                  {j.verdict}
                </span>
                <span className="text-muted-foreground truncate">{j.event_ref}</span>
                {j.reasoning && (
                  <span className="text-[10px] text-muted-foreground italic truncate">{j.reasoning}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
      {e.delta_p_atk != null && (
        <div className="text-[11px] font-mono text-muted-foreground">
          ΔP(atk): {e.delta_p_atk > 0 ? "↑" : "↓"} {Math.abs(e.delta_p_atk).toFixed(3)}
        </div>
      )}
    </div>
  );
}

function KBody({ e }: { e: KPhaseEventData }) {
  return (
    <div className="space-y-1">
      <div className="text-xs">
        领先:{" "}
        <span className="font-semibold">{e.leading_explanation ?? "-"}</span>
        {e.margin != null && (
          <span className="ml-1 text-muted-foreground">
            ({(e.margin * 100).toFixed(1)}%)
          </span>
        )}
      </div>
      <div className="text-[11px] font-mono text-muted-foreground">
        熵: {e.entropy?.toFixed(3) ?? "-"} | 新增节点: +{e.new_nodes ?? 0} | 新增边: +{e.new_edges ?? 0}
      </div>
    </div>
  );
}
