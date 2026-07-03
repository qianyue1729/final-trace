"""资产清单发现单元测试。"""
import json

from trace_engine.asset_inventory import (
    _extract_items_from_mcp_result,
    _hostnames_from_records,
    fetch_cmdb_hosts,
)
from trace_engine.config import AssetInventoryConfig, CmdbConfig


def test_extract_wazuh_agents_from_mcp_text():
    payload = {
        "content": [{
            "type": "text",
            "text": (
                'Wazuh Agents:\n'
                '{"data": {"affected_items": ['
                '{"id": "001", "name": "SRV-MAIL-01", "status": "active"},'
                '{"id": "002", "name": "WS-USER-01", "status": "active"}'
                "]}}"
            ),
        }],
    }
    items = _extract_items_from_mcp_result(payload)
    hosts = _hostnames_from_records(items, "name")
    assert hosts == ["SRV-MAIL-01", "WS-USER-01"]


def test_cmdb_hosts_json_path(monkeypatch):
    cfg = AssetInventoryConfig(
        cmdb=CmdbConfig(
            enabled=True,
            url="http://cmdb.internal/api/hosts",
            hosts_json_path="data.items",
            hostname_field="hostname",
        ),
    )

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "data": {
                    "items": [
                        {"hostname": "DC01", "role": "dc"},
                        {"hostname": "SRV-WEB-03"},
                    ],
                },
            }

    class FakeClient:
        @staticmethod
        def request(*_a, **_k):
            return FakeResp()

    monkeypatch.setattr("httpx.request", FakeClient.request)
    hosts, meta = fetch_cmdb_hosts(cfg)
    assert meta["count"] == 2
    assert "DC01" in hosts and "SRV-WEB-03" in hosts
