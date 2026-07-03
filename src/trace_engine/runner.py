"""调查会话运行器 — 告警入参 → LOCK 单环 → 结构化报告。

backend:
- "scenario"  验收态：LocalScenarioTransport + 场景 GT 对账
- "soar_mcp"  生产态：McpHttpTransport 连真实 SOAR MCP
两态共用 SoarMcpProbeExecutor 与同一 LOCK 内核，行为一致。
"""
from __future__ import annotations

import json
import os
import time
import traceback
from pathlib import Path
from typing import Any, Optional

from dataclasses import replace

from trace_agent.agents.orchestrator import BudgetState, DecisionOrchestrator
from trace_agent.data_loader import load_prior_bundle
from trace_agent.decision.belief import DecisionLedger
from trace_agent.decision.calibrator import ArtifactCalibrator
from trace_agent.decision.types import AlertEvent
from trace_agent.prior_v2 import PriorManager

from .decision_guardrails import apply_decision_guardrails
from .config import EngineConfig, resolve_wazuh_attacks_only
from .normalizer import EventNormalizer
from .soar_executor import SoarMcpProbeExecutor
from .transports import LocalScenarioTransport, McpHttpTransport, build_mcp_transport
from .alert_enricher import AlertEnricher, EnrichmentResult, create_model_enricher

_TECHNIQUE_TACTIC: dict[str, str] = {}


def _technique_tactic(technique: str) -> str:
    global _TECHNIQUE_TACTIC
    if not _TECHNIQUE_TACTIC:
        from trace_agent.loop.scenario_executor import TECHNIQUE_TACTIC_MAP
        _TECHNIQUE_TACTIC = TECHNIQUE_TACTIC_MAP
    base = technique.split(".")[0]
    return _TECHNIQUE_TACTIC.get(technique) or _TECHNIQUE_TACTIC.get(base, "execution")


def build_alert(payload: dict[str, Any], enrichment: Optional[EnrichmentResult] = None) -> AlertEvent:
    """归一化告警入参 → AlertEvent。

    当 technique 缺省时，从 EnrichmentResult 取候选；
    如果无候选（弃权），使用 T0000 并标记 unknown_technique=True。
    多候选时，attributes 里记录 alternates 供 seeding 保留不确定性。
    """
    # Determine technique: explicit > enrichment primary > T0000
    technique = payload.get("technique") or payload.get("technique_id")
    if not technique and enrichment and enrichment.primary_technique:
        technique = enrichment.primary_technique
    if not technique:
        technique = "T0000"

    asset = payload.get("asset") or payload.get("asset_id") or ""
    tactic = payload.get("tactic") or _technique_tactic(technique)

    # Platform: explicit > enrichment > None
    platform = payload.get("platform")
    if not platform and enrichment and enrichment.platform:
        platform = enrichment.platform

    # Log source: explicit > enrichment > default
    log_source = payload.get("log_source") or (
        enrichment.log_source if enrichment else None
    ) or "alert"

    ts_raw = payload.get("timestamp")
    timestamp: Optional[str] = None
    if ts_raw is not None:
        if isinstance(ts_raw, (int, float)):
            timestamp = str(float(ts_raw))
        else:
            from trace_agent.loop.scenario_executor import ScenarioExecutor
            parsed = ScenarioExecutor._parse_ts(str(ts_raw))
            timestamp = str(parsed) if parsed else str(ts_raw)

    attributes = dict(payload.get("attributes") or {})

    # Preserve enrichment ambiguity in attributes for seeding (Step 4)
    if enrichment:
        # Record alternate candidates so seed can create competing explanations
        alternates = [
            {"technique": c.technique, "tactics": c.tactics, "source": c.source}
            for c in enrichment.candidates[1:]  # skip primary (already in technique_id)
        ]
        if alternates:
            attributes["enrichment_alternates"] = alternates
        # Mark unknown technique explicitly — T0000 must not masquerade as real
        if technique == "T0000":
            attributes["unknown_technique"] = True
            # Use a neutral tactic instead of defaulting to 'execution'
            tactic = "unknown"
        attributes["enrichment_provenance"] = {
            "mode": enrichment.mode,
            "abstained": enrichment.abstained,
            "candidate_count": len(enrichment.candidates),
            "platform_source": enrichment.platform_source,
            "model_invoked": enrichment.model_invoked,
        }

    # Copy bounded process/cloud context into attributes
    for key in ("process_name", "command_line", "parent_process_name",
                "vendor_rule_id", "vendor_rule_title", "cloud_action", "network_direction"):
        val = payload.get(key)
        if val:
            attributes[key] = val

    return AlertEvent(
        technique_id=technique,
        tactic=tactic,
        platform=platform,
        log_source=log_source,
        asset_id=asset,
        timestamp=timestamp,
        anomaly_score=float(payload.get("anomaly_score", 0.5)),
        attributes=attributes,
    )


class InvestigationRunner:
    """按配置组装执行器并运行一次完整调查。线程安全（每次调用独立会话对象）。"""

    def __init__(self, config: EngineConfig):
        config._sanitize_production_flags()
        self.config = config
        self._prior_bundle = None
        self._decision_calibrator = ArtifactCalibrator.load(
            config.calibration.artifact_path,
            max_age_days=config.calibration.max_age_days,
        )
        self._ingest_factory = self._build_ingest_factory()
        self._alert_enricher = self._build_alert_enricher()

    def _build_alert_enricher(self) -> Optional[AlertEnricher]:
        """Build alert enricher if mode is not off."""
        cfg = self.config.alert_enricher
        if cfg.mode == "off":
            return None
        model_enricher = create_model_enricher(cfg)
        return AlertEnricher(
            config=cfg,
            model_enricher=model_enricher,
        )

    def _build_ingest_factory(self):
        settings = self.config.model_judgement
        if settings.mode == "off":
            return None

        def factory(trust, graph, ledger):
            from trace_agent.llm.client import DeepSeekClient
            from trace_agent.loop.llm_ingest import LLMIngestPipeline

            api_key = os.environ.get(settings.credential_env, "")
            client = None
            if settings.provider == "deepseek" and api_key:
                client = DeepSeekClient(
                    base_url=settings.endpoint,
                    api_key=api_key,
                    model=settings.model,
                    connect_timeout=settings.connect_timeout_seconds,
                    read_timeout=settings.read_timeout_seconds,
                    max_retries=settings.max_retries,
                    verify_tls=settings.verify_tls,
                    ca_bundle=settings.ca_bundle or None,
                )
            return LLMIngestPipeline(
                trust,
                graph,
                ledger,
                llm_client=client,
                mode=settings.mode,
                max_llm_per_round=settings.max_calls_per_round,
                max_llm_per_case=settings.max_calls_per_case,
                max_tokens_per_case=settings.max_tokens_per_case,
                max_graph_nodes=settings.max_context_nodes,
                ambiguity_margin=settings.ambiguity_margin,
            )

        return factory

    def _prior_manager(self) -> Optional[PriorManager]:
        if self._prior_bundle is None:
            self._prior_bundle = load_prior_bundle()
        return PriorManager(self._prior_bundle)

    # ── 执行器工厂 ──
    def _build_executor(
        self, scenario_id: Optional[str],
    ) -> tuple[SoarMcpProbeExecutor, Optional[dict]]:
        """返回 (executor, scenario_data)。

        backend=scenario  → 本地 soar_mcp_env 回放（验收）
        backend=soar_mcp  → 真实 MCP；scenario_id 仅作 case/incident 查询范围，不读本地 JSON
        """
        normalizer = EventNormalizer(self.config.normalizer)

        if self.config.backend == "scenario":
            sid = scenario_id or "pipeline_18"
            scenario_data, _spec = self._load_scenario(sid)
            transport = LocalScenarioTransport(scenario_data)
            hosts = sorted(
                (h for h in (transport.meta.get("cmdb") or {}).keys()),
            ) or None
            executor = SoarMcpProbeExecutor(
                transport=transport,
                config=self.config.soar_mcp,
                normalizer=normalizer,
                known_hosts=hosts,
            )
            return executor, scenario_data

        # Production: scenario_id may map to registry Wazuh scope (incident_id + is_attack).
        from .scenario_registry import resolve_wazuh_scope

        soar_cfg = self.config.soar_mcp
        if scenario_id:
            scope = resolve_wazuh_scope(scenario_id)
            if scope is not None:
                attacks_only = resolve_wazuh_attacks_only(
                    scope.attacks_only,
                    backend=self.config.backend,
                    scenario_indexed_attack_chain=scope.indexed_attack_chain,
                )
                soar_cfg = replace(
                    soar_cfg,
                    wazuh_incident_prefix=scope.incident_prefix,
                    wazuh_scope_field=scope.scope_field,
                    wazuh_attacks_only=attacks_only,
                    wazuh_scenario_slug=scope.scenario_slug,
                )
            else:
                soar_cfg = replace(
                    soar_cfg,
                    wazuh_incident_prefix=scenario_id,
                )
        transport = build_mcp_transport(soar_cfg)
        executor = SoarMcpProbeExecutor(
            transport=transport,
            config=soar_cfg,
            normalizer=normalizer,
        )
        return executor, None

    def _load_scenario(self, scenario_id: str) -> tuple[dict, dict]:
        env_dir = Path(self.config.scenario_env_dir)
        registry = json.loads(
            (env_dir / "registry.json").read_text(encoding="utf-8")
        )
        spec = registry.get("scenarios", {}).get(scenario_id)
        if spec is None:
            raise KeyError(f"unknown scenario: {scenario_id}")
        data = json.loads(
            (env_dir / spec["file"]).read_text(encoding="utf-8")
        )
        return data, spec

    def list_scenarios(self) -> list[dict]:
        env_dir = Path(self.config.scenario_env_dir)
        registry = json.loads(
            (env_dir / "registry.json").read_text(encoding="utf-8")
        )
        return [
            {
                "id": sid,
                "name": spec.get("name", sid),
                "description": spec.get("description", ""),
                "tags": spec.get("tags", []),
            }
            for sid, spec in registry.get("scenarios", {}).items()
        ]

    # ── 主入口 ──
    def run(
        self,
        alert_payload: dict[str, Any],
        scenario_id: Optional[str] = None,
        max_rounds: Optional[int] = None,
        progress_cb=None,
    ) -> dict[str, Any]:
        """运行完整调查，返回可 JSON 序列化的报告 dict。异常包装为 error 报告。"""
        t0 = time.time()
        try:
            return self._run_inner(alert_payload, scenario_id, max_rounds, progress_cb)
        except Exception as e:  # noqa: BLE001 — 服务边界：错误进报告而非炸线程
            return {
                "status": "error",
                "error": f"{type(e).__name__}: {e}",
                "traceback": traceback.format_exc(),
                "elapsed_seconds": round(time.time() - t0, 2),
            }

    def _run_inner(
        self,
        alert_payload: dict[str, Any],
        scenario_id: Optional[str],
        max_rounds: Optional[int],
        progress_cb,
    ) -> dict[str, Any]:
        t0 = time.time()

        # ── Alert enrichment (Plan 008) ──
        enrichment: Optional[EnrichmentResult] = None
        if self._alert_enricher is not None:
            enrichment = self._alert_enricher.enrich(alert_payload)
        elif not alert_payload.get("technique") and not alert_payload.get("technique_id"):
            # Even without enricher, run deterministic enrichment for basic inference
            from .alert_enricher import AlertEnricher as _AE
            fallback = _AE(technique_tactic_map=_TECHNIQUE_TACTIC)
            enrichment = fallback.enrich(alert_payload)

        alert = build_alert(alert_payload, enrichment=enrichment)

        executor, scenario_data = self._build_executor(scenario_id)

        if self.config.demo_profile.enabled and self.config.backend == "soar_mcp":
            from trace_engine.attack_chain_materializer import DiversityCaps

            demo = self.config.demo_profile
            executor._production_diversity_caps = DiversityCaps(
                per_rule_id=demo.diversity_per_rule_id_cap,
            )
            executor._production_candidate_top_k = demo.candidate_top_k

        if not executor.available():
            transport_error = getattr(
                executor.transport, "last_error_code", None
            )
            raise ConnectionError(
                f"SOAR backend unavailable (backend={self.config.backend}, "
                f"endpoint={self.config.soar_mcp.endpoint}, "
                f"reason={transport_error or 'unknown'})"
            )

        alert_ts = float(alert.timestamp or 0)
        if alert_ts > 0:
            executor.align_to_alert(alert_ts)

        bootstrap_stats: dict = {}
        if self.config.backend == "soar_mcp":
            bootstrap_stats = executor.bootstrap_investigation(alert_payload)

        prior_manager = self._prior_manager()
        dl = DecisionLedger(prior_manager)
        seed = dl.seed(alert)

        b = self.config.budget
        budget = BudgetState(
            total_rounds=max_rounds or b.total_rounds,
            total_probes=b.total_probes,
            fanout_per_round=b.fanout_per_round,
            min_rounds_before_robust=b.min_rounds_before_robust,
            min_rounds_after_root=b.min_rounds_after_root,
        )
        orch = DecisionOrchestrator(
            alert=alert,
            executor=executor,
            prior_manager=prior_manager,
            budget=budget,
            seed=seed,
            decision_calibrator=self._decision_calibrator,
            automation_policy={
                "min_slice_support": self.config.calibration.min_slice_support,
                "min_precision": self.config.calibration.min_precision,
                "min_recall": self.config.calibration.min_recall,
                "contain_threshold": self.config.calibration.contain_threshold,
                "dismiss_threshold": self.config.calibration.dismiss_threshold,
            },
            planner_mode=self.config.model_planner.mode,
            planner_max_intents=self.config.model_planner.max_intents_per_round,
            planner_cost_budget=self.config.model_planner.cost_budget_per_round,
            planner_max_graph_nodes=self.config.model_planner.max_graph_nodes,
            ingest_factory=self._ingest_factory,
            demo_profile_enabled=self.config.demo_profile.enabled,
            demo_plateau_rounds=self.config.demo_profile.plateau_rounds,
            demo_min_graph_nodes=self.config.demo_profile.min_graph_nodes,
            demo_min_graph_edges=self.config.demo_profile.min_graph_edges,
        )

        if progress_cb:
            progress_cb({"stage": "running", "round": 0})

        try:
            result = orch.run()
            elapsed = time.time() - t0

            report = self._build_report(orch, result, executor, alert, elapsed)
            if enrichment is not None:
                report["alert_enrichment"] = enrichment.to_dict()
            if bootstrap_stats:
                report["trace_coverage"] = self._trace_coverage(
                    orch, executor, bootstrap_stats,
                )
            if self.config.demo_profile.enabled:
                report["demo_profile"] = {
                    "enabled": True,
                    "plateau_rounds": self.config.demo_profile.plateau_rounds,
                    "guardrail_downgrade": self.config.demo_profile.guardrail_downgrade,
                }
            if scenario_data is not None:
                report["ground_truth_eval"] = self._eval_ground_truth(
                    orch, scenario_data
                )
            return report
        finally:
            orch.close()

    # ── 报告组装 ──
    def _build_report(self, orch, result, executor, alert, elapsed) -> dict[str, Any]:
        confidence = result.decision_confidence.to_dict()
        graph_nodes = []
        for nid, node in orch.graph._nodes.items():
            attrs = node.attributes or {}
            graph_nodes.append({
                "id": str(nid),
                "technique": node.technique or "",
                "tactic": node.tactic or "",
                "host": str(
                    attrs.get("host_uid") or attrs.get("asset_id")
                    or attrs.get("target") or ""
                ),
                "timestamp": float(node.timestamp or 0),
                "attributed": bool(node.explanation_ids),
            })
        graph_edges = [
            {"source": str(e.src), "target": str(e.dst), "relation": e.relation}
            for e in orch.graph._edges.values()
        ]

        report = {
            "status": "completed",
            "alert": alert.to_dict(),
            "decision": {
                "action": result.decision,
                # Compatibility field: nullable unless calibration is stable.
                "confidence": (
                    round(result.confidence, 4)
                    if result.confidence is not None
                    else None
                ),
                **confidence,
                "stop_reason": result.stop_reason,
                "leading_explanation": result.leading_explanation,
                "alternatives": result.alternatives,
                "boundary_decisions": result.boundary_decisions,
                "incomplete": result.incomplete,
                "unresolved_obligations": result.unresolved_obligations,
            },
            "usage": {
                "rounds": result.rounds_used,
                "events_processed": result.total_events_processed,
                "probes_used": orch.budget.probes_used,
                "soar_fetch": getattr(executor, "fetch_stats", {}),
                "voi_audit": result.voi_audit,
                "model_planner": result.planner_audit,
                "model_judgement": getattr(
                    orch.ingest, "llm_stats", {"mode": "off"}
                ),
                "round_diagnostics": list(result.round_diagnostics),
                "elapsed_seconds": round(elapsed, 2),
            },
            "graph": {
                "nodes": graph_nodes,
                "edges": graph_edges,
                "attributed_node_count": sum(
                    1 for node in graph_nodes if node["attributed"]
                ),
            },
        }
        report = apply_decision_guardrails(
            report,
            demo_profile=(
                self.config.demo_profile.enabled
                and self.config.demo_profile.guardrail_downgrade
            ),
        )
        return report

    @staticmethod
    def _trace_coverage(orch, executor, bootstrap_stats: dict) -> dict[str, Any]:
        """生产态溯源覆盖指标（不依赖 GT）。"""
        from trace_agent.loop.scenario_executor import ScenarioExecutor

        hosts: set[str] = set()
        tactics: set[str] = set()
        for ev in getattr(executor, "_events", []):
            host = ScenarioExecutor._extract_host(ev)
            if host:
                hosts.add(str(host))
            tac = ev.get("_normalized_tactic") or ev.get("tactic")
            if tac:
                tactics.add(str(tac))
        graph_hosts: set[str] = set()
        for node in orch.graph._nodes.values():
            attrs = node.attributes or {}
            for key in ("host_uid", "asset_id", "host", "target"):
                val = attrs.get(key)
                if val:
                    graph_hosts.add(str(val))
        coverage = {
            "bootstrap": bootstrap_stats,
            "events_cached": len(getattr(executor, "_events", [])),
            "discovered_hosts": sorted(hosts),
            "hosts_in_graph": sorted(graph_hosts),
            "tactics_in_cache": sorted(tactics),
            "tactics_in_graph": orch.graph.stats().get("tactics_seen", []),
            "soar_fetch": getattr(executor, "fetch_stats", {}),
        }
        chain_diag = getattr(executor, "_candidate_chain_diagnostics", None)
        if isinstance(chain_diag, dict):
            coverage["candidate_chain"] = dict(chain_diag)
        return coverage

    @staticmethod
    def _eval_ground_truth(orch, scenario_data: dict) -> dict[str, Any]:
        gt_refs = set(
            scenario_data.get("ground_truth", {}).get("attack_edge_refs", [])
        )
        hits: set[str] = set()
        for node in orch.graph._nodes.values():
            attrs = node.attributes or {}
            ref = str(attrs.get("raw_log_ref") or node.id or "")
            if ref in gt_refs or str(node.id) in gt_refs:
                hits.add(ref if ref in gt_refs else str(node.id))
        total = len(gt_refs)
        return {
            "gt_total": total,
            "gt_hits": len(hits),
            "recall": round(len(hits) / total, 4) if total else None,
            "missed_refs": sorted(gt_refs - hits)[:20],
        }
