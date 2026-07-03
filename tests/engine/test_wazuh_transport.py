"""Wazuh MCP transport 单元测试。"""
from trace_engine.transports import (
    McpHttpTransport,
    WAZUH_MCP_CAPABILITIES,
    WazuhMcpTransport,
    _extract_mcp_records,
    _parse_wazuh_security_events_text,
)
from scripts.validate_wazuh_runtime import _error_code


def test_wazuh_declares_search_after_pagination():
    assert WazuhMcpTransport.capabilities == WAZUH_MCP_CAPABILITIES
    assert WazuhMcpTransport.capabilities.exact_time_bounds is False
    assert WazuhMcpTransport.capabilities.cursor_pagination is True


def test_http_5xx_is_classified_as_upstream_server_error():
    transport = McpHttpTransport(endpoint="https://example.invalid/mcp")
    transport._ensure_initialized = lambda: (_ for _ in ()).throw(
        ConnectionError("500 Internal Server Error")
    )
    try:
        assert transport.ping() is False
        assert transport.last_error_code == "upstream_server_error"
        assert _error_code(RuntimeError("503 Service Unavailable")) == (
            "upstream_server_error"
        )
    finally:
        transport.close()


def test_wazuh_query_translation():
    q = WazuhMcpTransport._to_wazuh_query("host:WS-USER-01 source:SIEM")
    assert 'data.hostname:"WS-USER-01"' in q
    assert "source:SIEM" not in q


def test_synthetic_wazuh_ref_queries_native_alert_id():
    q = WazuhMcpTransport._to_wazuh_query("ref:wazuh:alert-1")
    assert 'id:"alert-1"' in q
    assert 'data.raw_log_ref:"wazuh:alert-1"' in q


def test_attacks_only_appends_is_attack_filter():
    t = WazuhMcpTransport(
        endpoint="http://x/mcp",
        incident_prefix="pipeline_18",
        attacks_only=True,
    )
    t._ensure_initialized = lambda: None  # type: ignore[method-assign]
    captured: dict = {}

    def fake_rpc(_method, payload):
        captured.update(payload)
        return {"events": []}

    t._rpc = fake_rpc  # type: ignore[method-assign]
    t.query(query="*", from_ms=0, to_ms=0, limit=1)
    assert 'data.scenario:"pipeline_18"' in captured["arguments"]["query"]
    assert "data.is_attack:true" in captured["arguments"]["query"]


def test_incident_prefix_scenario_vs_inc():
    t = WazuhMcpTransport(endpoint="http://x/mcp", incident_prefix="pipeline_18")
    t._ensure_initialized = lambda: None  # type: ignore[method-assign]
    captured: dict = {}

    def fake_rpc(_method, payload):
        captured.update(payload)
        return {"events": []}

    t._rpc = fake_rpc  # type: ignore[method-assign]
    t.query(query="host:WS-USER-01", from_ms=0, to_ms=0, limit=1)
    assert 'data.scenario:"pipeline_18"' in captured["arguments"]["query"]

    t2 = WazuhMcpTransport(endpoint="http://x/mcp", incident_prefix="INC-PIPELINE-18-001")
    t2._ensure_initialized = lambda: None  # type: ignore[method-assign]
    t2._rpc = fake_rpc  # type: ignore[method-assign]
    captured.clear()
    t2.query(query="*", from_ms=0, to_ms=0, limit=1)
    assert captured["arguments"]["query"] == (
        'data.incident_id:"INC-PIPELINE-18-001"'
    )

    t3 = WazuhMcpTransport(
        endpoint="http://x/mcp",
        incident_prefix="case-123",
        scope_field="incident",
    )
    t3._ensure_initialized = lambda: None  # type: ignore[method-assign]
    t3._rpc = fake_rpc  # type: ignore[method-assign]
    captured.clear()
    t3.query(query="*", from_ms=0, to_ms=0, limit=1)
    assert captured["arguments"]["query"] == 'data.incident_id:"case-123"'


def test_incident_attacks_only_compose():
    t = WazuhMcpTransport(
        endpoint="http://x/mcp",
        incident_prefix="INC-PIPELINE_18",
        scope_field="incident",
        attacks_only=True,
    )
    q = t._compose_wazuh_query("host:DB-PROD-01")
    assert 'data.incident_id:"INC-PIPELINE_18"' in q
    assert "data.is_attack:true" in q
    assert "data.scenario:" not in q


def test_ref_query_adds_scenario_slug_when_no_incident_prefix():
    t = WazuhMcpTransport(
        endpoint="http://x/mcp",
        scenario_slug="pipeline_18",
    )
    q = t._compose_wazuh_query("ref:attack:idx_stress:evt_018")
    assert 'data.scenario:"pipeline_18"' in q
    assert 'data.raw_log_ref:"attack:idx_stress:evt_018"' in q


def test_seed_ref_uses_incident_disambiguation():
    t = WazuhMcpTransport(
        endpoint="http://x/mcp",
        incident_prefix="INC-PIPELINE_18",
        scope_field="incident",
        attacks_only=True,
    )
    q = t._compose_wazuh_query("ref:attack:idx_stress:evt_018")
    assert 'data.incident_id:"INC-PIPELINE_18"' in q
    assert 'data.raw_log_ref:"attack:idx_stress:evt_018"' in q
    assert "data.is_attack:true" in q


def test_query_terms_are_quoted_against_lucene_injection():
    query = WazuhMcpTransport._to_wazuh_query(
        'host:host-A")OR(data.level:*)'
    )
    assert 'data.hostname:"host-A\\")OR(data.level:*' in query


def test_extract_wazuh_security_events_text():
    sample = (
        'Security Events:\n'
        '{"data": {"affected_items": [{"timestamp": "2026-07-02T09:21:32.606+0000", '
        '"agent": {"id": "000", "name": "wazuh.manager"}, '
        '"full_log": "{\\"raw_log_ref\\":\\"attack:idx_stress:evt_018\\",'
        '\\"hostname\\":\\"DB-PROD-01\\",\\"mitre_technique\\":\\"T1041\\",'
        '\\"action\\":\\"CONNECT\\",\\"anomaly_score\\":\\"0.92\\"}"}]}}'
    )
    recs = _parse_wazuh_security_events_text(sample)
    assert len(recs) == 1
    assert recs[0]["raw_log_ref"] == "attack:idx_stress:evt_018"
    assert recs[0]["host"] == "DB-PROD-01"
    assert recs[0]["technique"] == "T1041"


def test_extract_wazuh_events_shape():
    payload = {"events": [{"id": "1", "agent": {"name": "h1"}}]}
    recs = _extract_mcp_records(payload)
    assert len(recs) == 1
    assert recs[0]["id"] == "1"


def test_flatten_real_wazuh_nested_rule_and_agent_shape():
    sample = (
        'Security Events:\n'
        '{"data":{"affected_items":[{'
        '"id":"alert-1","timestamp":"2026-07-03T08:00:00Z",'
        '"agent":{"id":"007","name":"prod-db-01"},'
        '"rule":{"id":"92001","level":12,"description":"Suspicious process",'
        '"groups":["syslog","authentication_failed"],'
        '"mitre":{"id":["T1059.001"],"tactic":["Execution"]}},'
        '"data":{"srcip":"10.0.0.5","dstuser":"alice",'
        '"win":{"system":{"eventID":"4625"},'
        '"eventdata":{"image":"C:\\\\\\\\Windows\\\\\\\\powershell.exe"}}}'
        '}]}}'
    )
    records = _parse_wazuh_security_events_text(sample)
    assert records[0]["raw_log_ref"] == "wazuh:alert-1"
    assert records[0]["host"] == "prod-db-01"
    assert records[0]["mitre_technique"] == "T1059.001"
    assert records[0]["mitre_tactic"] == "Execution"
    assert records[0]["src_process"].endswith("powershell.exe")
    assert records[0]["source"] == "syslog"
    assert records[0]["action"] == "AUTH"
    assert records[0]["ocsf_class_uid"] == 5002
    assert records[0]["anomaly_score"] == 0.8
    assert records[0]["auth_outcome"] == "failure"
    assert records[0]["src_ip"] == "10.0.0.5"
    assert records[0]["user"] == "alice"
    assert records[0]["event_code"] == "4625"


def test_parse_wazuh_search_payload_with_pagination():
    from trace_engine.transports import _parse_wazuh_search_blob

    sample = (
        'Security Events:\n'
        '{"data": {"affected_items": [{"id": "1", "agent": {"name": "h1"}}], '
        '"pagination": {"limit": 1, "returned": 1, "has_more": true, '
        '"mode": "search_after", "next_search_after": ["2026-07-02T10:00:00Z", "abc"]}}}'
    )
    records, pagination = _parse_wazuh_search_blob(sample)
    assert len(records) == 1
    assert pagination["has_more"] is True
    assert pagination["mode"] == "search_after"
    assert pagination["next_search_after"] == ["2026-07-02T10:00:00Z", "abc"]


def test_query_pages_uses_search_after_then_stops():
    t = WazuhMcpTransport(endpoint="https://x/mcp", verify_tls=False)
    t._ensure_initialized = lambda: None  # type: ignore[method-assign]
    pages = [
        (
            {"content": [{"type": "text", "text": (
                'Security Events:\n{"data":{"affected_items":[{"id":"1","agent":{"name":"h1"}}],'
                '"pagination":{"has_more":true,"mode":"search_after",'
                '"next_search_after":["t1","id1"]}}}'
            )}]},
            1,
        ),
        (
            {"content": [{"type": "text", "text": (
                'Security Events:\n{"data":{"affected_items":[{"id":"2","agent":{"name":"h2"}}],'
                '"pagination":{"has_more":false,"mode":"search_after"}}}'
            )}]},
            2,
        ),
    ]

    def fake_rpc(_method, payload):
        arguments = payload["arguments"]
        if "search_after" in arguments:
            return pages[1][0]
        return pages[0][0]

    t._rpc = fake_rpc  # type: ignore[method-assign]
    collected = list(
        t.query_pages(query="*", from_ms=0, to_ms=0, limit=1, max_pages=5)
    )
    assert len(collected) == 2
    assert len(collected[0].records) == 1
    assert collected[0].pagination["has_more"] is True
    assert collected[1].pagination["has_more"] is False


def test_window_to_time_range():
    assert WazuhMcpTransport._window_to_time_range(0, 0, "30d") == "30d"
    assert WazuhMcpTransport._window_to_time_range(0, 86400000 * 3, "30d") == "7d"
    assert WazuhMcpTransport._window_to_time_range(0, 86400000 * 90, "30d") == "30d"
