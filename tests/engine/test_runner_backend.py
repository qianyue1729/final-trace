"""InvestigationRunner 生产/验收 backend 分流。"""
import copy
from dataclasses import replace

from trace_agent.eval.soar_integration_runner import (
    build_alert_event,
    find_entry_event,
    load_scenario,
)
from trace_engine.config import EngineConfig
from trace_engine.runner import InvestigationRunner
from trace_engine.transports import LocalScenarioTransport, WazuhMcpTransport
from trace_agent.loop.session_graph import SessionGraph


def test_scenario_id_on_soar_mcp_uses_registry_wazuh_scope(monkeypatch):
    monkeypatch.delenv("TRACE_ENGINE_EVAL_ATTACKS_ONLY", raising=False)
    cfg = EngineConfig.load()
    cfg = replace(
        cfg,
        backend="soar_mcp",
        soar_mcp=replace(cfg.soar_mcp, tool_profile="wazuh"),
    )
    runner = InvestigationRunner(cfg)
    executor, scenario_data = runner._build_executor("pipeline_18")
    assert scenario_data is None
    assert not isinstance(executor.transport, LocalScenarioTransport)
    assert getattr(executor.transport, "incident_prefix", "") == "INC-PIPELINE_18"
    assert getattr(executor.transport, "scope_field", "") == "incident"
    assert getattr(executor.transport, "attacks_only", False) is True
    assert getattr(executor.transport, "scenario_slug", "") == "pipeline_18"


def test_scenario_id_without_registry_keeps_scenario_prefix(monkeypatch):
    monkeypatch.delenv("TRACE_ENGINE_EVAL_ATTACKS_ONLY", raising=False)
    cfg = replace(
        EngineConfig.load(),
        backend="soar_mcp",
        soar_mcp=replace(
            EngineConfig.load().soar_mcp,
            tool_profile="wazuh",
            wazuh_attacks_only=False,
        ),
    )
    runner = InvestigationRunner(cfg)
    executor, _ = runner._build_executor("unknown_scenario_xyz")
    assert isinstance(executor.transport, WazuhMcpTransport)
    assert executor.transport.incident_prefix == "unknown_scenario_xyz"
    assert executor.transport.attacks_only is False


def test_scenario_id_does_not_auto_enable_attacks_only_without_registry(monkeypatch):
    monkeypatch.delenv("TRACE_ENGINE_EVAL_ATTACKS_ONLY", raising=False)
    cfg = replace(
        EngineConfig.load(),
        backend="soar_mcp",
        soar_mcp=replace(
            EngineConfig.load().soar_mcp,
            tool_profile="wazuh",
            wazuh_attacks_only=False,
        ),
    )
    runner = InvestigationRunner(cfg)
    executor, _ = runner._build_executor("unknown_scenario_xyz")
    assert isinstance(executor.transport, WazuhMcpTransport)
    assert executor.transport.attacks_only is False


def test_eval_flag_allows_attacks_only_on_soar_mcp(monkeypatch):
    monkeypatch.setenv("TRACE_ENGINE_EVAL_ATTACKS_ONLY", "1")
    cfg = replace(
        EngineConfig.load(),
        backend="soar_mcp",
        soar_mcp=replace(
            EngineConfig.load().soar_mcp,
            tool_profile="wazuh",
            wazuh_attacks_only=True,
        ),
    )
    runner = InvestigationRunner(cfg)
    executor, _ = runner._build_executor("pipeline_18")
    assert executor.transport.attacks_only is True


def test_scenario_backend_uses_local_transport():
    cfg = EngineConfig.load()
    cfg = replace(cfg, backend="scenario")
    runner = InvestigationRunner(cfg)
    executor, scenario_data = runner._build_executor("pipeline_18")
    assert scenario_data is not None
    assert isinstance(executor.transport, LocalScenarioTransport)


def test_ground_truth_changes_metrics_only(monkeypatch):
    scenario, spec = load_scenario("pipeline_18")
    entry = build_alert_event(find_entry_event(scenario, spec))
    alert = {
        "technique": entry.technique_id,
        "asset": entry.asset_id,
        "tactic": entry.tactic,
        "timestamp": entry.timestamp,
        "log_source": entry.log_source,
        "anomaly_score": entry.anomaly_score,
        "attributes": entry.attributes,
    }
    cfg = replace(
        EngineConfig.load(),
        backend="scenario",
        budget=replace(
            EngineConfig.load().budget,
            min_rounds_before_robust=1,
            min_rounds_after_root=1,
        ),
    )
    runner = InvestigationRunner(cfg)

    def run_with_refs(refs):
        changed = copy.deepcopy(scenario)
        changed["ground_truth"] = {"attack_edge_refs": refs}
        monkeypatch.setattr(
            runner,
            "_load_scenario",
            lambda _scenario_id: (copy.deepcopy(changed), spec),
        )
        report = runner.run(alert, "pipeline_18", max_rounds=1)
        assert report["status"] == "completed"
        runtime = copy.deepcopy(report)
        metrics = runtime.pop("ground_truth_eval")
        runtime["usage"].pop("elapsed_seconds")
        return runtime, metrics

    baseline_runtime, baseline_metrics = run_with_refs(
        scenario["ground_truth"]["attack_edge_refs"]
    )
    changed_runtime, changed_metrics = run_with_refs(["not-present"])

    assert changed_runtime == baseline_runtime
    assert changed_metrics != baseline_metrics


def test_runner_configures_off_shadow_and_assist_ingest(monkeypatch):
    monkeypatch.delenv("TRACE_TEST_MISSING_MODEL_KEY", raising=False)
    base = EngineConfig.load()
    for mode in ("off", "shadow", "assist"):
        cfg = replace(
            base,
            model_judgement=replace(
                base.model_judgement,
                mode=mode,
                credential_env="TRACE_TEST_MISSING_MODEL_KEY",
            ),
        )
        runner = InvestigationRunner(cfg)
        if mode == "off":
            assert runner._ingest_factory is None
            continue
        pipeline = runner._ingest_factory(object(), SessionGraph(), None)
        assert pipeline.llm_stats["mode"] == mode
        assert pipeline.llm_stats["client_stats"] == {}
