from types import SimpleNamespace

from trace_agent.loop.probe import Probe
from trace_engine.model_mcp_runtime import (
    McpCallPlanValidator,
    ModelMcpRuntime,
    StructuredModelMcpCompiler,
)
from trace_engine.soar_executor import SoarMcpProbeExecutor
from trace_engine.transports import WAZUH_MCP_CAPABILITIES


def _probe(probe_id: str, target: str) -> Probe:
    return Probe(
        id=probe_id,
        target=target,
        target_type="host",
        operator="auth_log",
        tactic="credential_access",
        source="test",
        explanation_ids=["H1"],
    )


def _raw_plan(probe: Probe, **argument_overrides):
    arguments = {
        "host": probe.target,
        "filters": [{"field": "rule.groups", "value": "authentication"}],
        "time_range": "7d",
        "limit": 25,
        "compact": False,
        **argument_overrides,
    }
    return {
        "plan_id": f"mp_{probe.id}",
        "source_probe_id": probe.id,
        "mcp_tool": "search_security_events",
        "arguments": arguments,
        "intent_summary": "Corroborate authentication activity",
        "evidence_refs": [],
        "reason_codes": ["AUTH_CORROBORATION"],
    }


def _validator() -> McpCallPlanValidator:
    return McpCallPlanValidator(
        page_limit=50,
        max_time_range_days=30,
        max_filters=4,
    )


def test_validator_injects_scope_and_rejects_raw_query():
    probe = _probe("p1", "DB-PROD-01")
    common = {
        "probes": {probe.id: probe},
        "known_hosts": {"db-prod-01"},
        "evidence_refs": set(),
        "scope": {
            "incident_prefix": "INC-PIPELINE_18",
            "scope_field": "incident",
            "attacks_only": True,
            "scenario_slug": "",
        },
        "recent_call_keys": set(),
        "accepted_probe_ids": set(),
        "calls_remaining": 3,
    }

    accepted = _validator().validate(_raw_plan(probe), **common)
    assert accepted.accepted
    query = accepted.plan.arguments["query"]
    assert 'data.incident_id:"INC-PIPELINE_18"' in query
    assert "data.is_attack:true" in query
    assert 'agent.name:"DB-PROD-01"' in query
    assert 'rule.groups:"authentication"' in query

    rejected = _validator().validate(
        _raw_plan(probe, query="*"),
        **common,
    )
    assert not rejected.accepted
    assert "QUERY_TOO_BROAD" in rejected.reason_codes


class _Provider:
    def __init__(self, plans):
        self.plans = plans
        self.stats = {"total_tokens": 12}
        self.closed = False

    def compile_mcp_plans(self, context):
        return {"plans": self.plans, "abstained": not self.plans}

    def close(self):
        self.closed = True


class _FailingProvider:
    stats = {"total_tokens": 0}

    def compile_mcp_plans(self, context):
        raise TimeoutError("provider timeout")


class _Executor:
    def __init__(self):
        self.mcp_config = SimpleNamespace(
            page_limit=50,
            wazuh_incident_prefix="INC-CASE-01",
            wazuh_scenario_slug="",
            wazuh_scope_field="incident",
            wazuh_attacks_only=False,
        )
        self.template_calls = []
        self.direct_calls = []

    def execute_fanout(self, probes):
        self.template_calls.append([probe.id for probe in probes])
        return [
            {"id": f"template-{probe.id}", "probe_id": probe.id}
            for probe in probes
        ]

    def execute_mcp_plans(self, plans, probes_by_id):
        self.direct_calls.append(plans)
        return {
            "events": [
                {
                    "id": f"direct-{plan['source_probe_id']}",
                    "probe_id": plan["source_probe_id"],
                }
                for plan in plans
            ],
            "executions": [
                {
                    "source_probe_id": plan["source_probe_id"],
                    "status": "ok",
                    "hits": 1,
                    "latency_ms": 2.5,
                }
                for plan in plans
            ],
            "failed_probe_ids": [],
        }


def _runtime(mode, provider):
    return ModelMcpRuntime(
        mode=mode,
        compiler=StructuredModelMcpCompiler(
            provider,
            model_version="test-model",
        ),
        page_limit=50,
        max_plans_per_round=4,
        max_calls_per_round=3,
        max_calls_per_case=30,
        max_tokens_per_case=20_000,
        max_context_nodes=20,
        max_time_range_days=30,
        max_filters=4,
        fallback_to_template=True,
    )


def _session(executor, hosts):
    return SimpleNamespace(
        round=2,
        executor=executor,
        graph=None,
        ledger=None,
        obligations=None,
        _scenario_hosts=hosts,
    )


def test_shadow_audits_plan_but_only_executes_template():
    probe = _probe("p1", "DB-PROD-01")
    executor = _Executor()
    runtime = _runtime("shadow", _Provider([_raw_plan(probe)]))

    events = runtime.execute(_session(executor, [probe.target]), [probe])

    assert events[0]["id"] == "template-p1"
    assert executor.template_calls == [["p1"]]
    assert executor.direct_calls == []
    assert runtime.audit[-1]["accepted"] == 1
    assert runtime.audit[-1]["executed"] == 0


def test_assist_executes_accepted_plan_and_falls_back_missing_probe():
    planned = _probe("p1", "DB-PROD-01")
    unplanned = _probe("p2", "APP-PROD-01")
    executor = _Executor()
    runtime = _runtime("assist", _Provider([_raw_plan(planned)]))

    events = runtime.execute(
        _session(executor, [planned.target, unplanned.target]),
        [planned, unplanned],
    )

    assert [plan["source_probe_id"] for plan in executor.direct_calls[0]] == [
        "p1"
    ]
    assert executor.template_calls == [["p2"]]
    assert {event["id"] for event in events} == {
        "direct-p1",
        "template-p2",
    }
    assert runtime.audit[-1]["executed"] == 1
    assert runtime.audit[-1]["fallback_probes"] == 1


def test_assist_rejected_plan_falls_back_to_template():
    probe = _probe("p1", "DB-PROD-01")
    executor = _Executor()
    runtime = _runtime(
        "assist",
        _Provider([_raw_plan(probe, query="*")]),
    )

    events = runtime.execute(_session(executor, [probe.target]), [probe])

    assert events[0]["id"] == "template-p1"
    assert executor.direct_calls == []
    reasons = runtime.audit[-1]["plans"][0]["validator_reasons"]
    assert "QUERY_TOO_BROAD" in reasons


def test_assist_provider_error_falls_back_to_template():
    probe = _probe("p1", "DB-PROD-01")
    executor = _Executor()
    runtime = _runtime("assist", _FailingProvider())

    events = runtime.execute(_session(executor, [probe.target]), [probe])

    assert events[0]["id"] == "template-p1"
    assert executor.direct_calls == []
    assert runtime.audit[-1]["provider_status"] == "error"


def test_assist_mcp_error_falls_back_to_template():
    probe = _probe("p1", "DB-PROD-01")
    executor = _Executor()

    def fail_direct(plans, probes_by_id):
        return {
            "events": [],
            "executions": [{
                "source_probe_id": "p1",
                "status": "failed",
                "hits": 0,
                "latency_ms": 3.0,
                "error": "ConnectionError: upstream failed",
            }],
            "failed_probe_ids": ["p1"],
        }

    executor.execute_mcp_plans = fail_direct
    runtime = _runtime("assist", _Provider([_raw_plan(probe)]))

    events = runtime.execute(_session(executor, [probe.target]), [probe])

    assert events[0]["id"] == "template-p1"
    assert executor.template_calls == [["p1"]]
    assert runtime.audit[-1]["executed"] == 0
    assert runtime.audit[-1]["plans"][0]["execution_status"] == "failed"


class _RemoteToolTransport:
    capabilities = WAZUH_MCP_CAPABILITIES

    def __init__(self):
        self.calls = []

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        return {
            "structuredContent": {
                "records": [{
                    "raw_log_ref": "wazuh:evt-1",
                    "ts": "100",
                    "technique": "T1078",
                    "tactic": "credential-access",
                    "action": "AUTH",
                    "anomaly_score": 0.8,
                    "src_entity": {
                        "type": "host",
                        "id": "DB-PROD-01",
                        "attrs": {"host_uid": "DB-PROD-01"},
                    },
                    "dst_entity": {
                        "type": "host",
                        "id": "DB-PROD-01",
                        "attrs": {"host_uid": "DB-PROD-01"},
                    },
                }],
            },
        }

    @staticmethod
    def _extract_records(result):
        return result["structuredContent"]["records"]

    def ping(self):
        return True


def test_soar_executor_calls_sanitized_mcp_plan():
    transport = _RemoteToolTransport()
    executor = SoarMcpProbeExecutor(transport=transport)
    executor.align_to_alert(100)
    probe = _probe("p1", "DB-PROD-01")
    probe.tactic = "credential-access"
    plan = {
        "plan_id": "mp_p1",
        "source_probe_id": "p1",
        "mcp_tool": "search_security_events",
        "arguments": {
            "query": 'data.incident_id:"INC-1" AND agent.name:"DB-PROD-01"',
            "time_range": "7d",
            "limit": 25,
            "compact": False,
        },
    }

    result = executor.execute_mcp_plans([plan], {"p1": probe})

    assert transport.calls == [
        ("search_security_events", plan["arguments"])
    ]
    assert result["failed_probe_ids"] == []
    assert result["executions"][0]["hits"] == 1
    assert result["events"][0]["probe_id"] == "p1"
