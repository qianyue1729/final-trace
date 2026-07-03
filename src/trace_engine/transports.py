"""SOAR 查询传输层 — 生产 MCP HTTP 与本地场景两种实现，同一接口。

执行器只依赖 SoarQueryTransport 协议；换 SOAR 平台 = 换 transport，不动引擎。
"""
from __future__ import annotations

import itertools
import json
import ssl
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Protocol, runtime_checkable


@dataclass(frozen=True)
class QueryPage:
    """Single MCP search page + server pagination metadata."""

    records: list[dict]
    pagination: dict[str, Any]


@dataclass(frozen=True)
class TransportCapabilities:
    """Query guarantees used by capability-aware pagination."""

    exact_time_bounds: bool
    stable_ascending_sort: bool
    cursor_pagination: bool
    supported_query_dimensions: frozenset[str]


GENERIC_MCP_CAPABILITIES = TransportCapabilities(
    exact_time_bounds=True,
    stable_ascending_sort=True,
    cursor_pagination=True,
    supported_query_dimensions=frozenset(
        {"host", "datasource", "operator", "tactic", "ref"}
    ),
)
WAZUH_MCP_CAPABILITIES = TransportCapabilities(
    exact_time_bounds=False,
    stable_ascending_sort=True,
    cursor_pagination=True,
    supported_query_dimensions=frozenset({"host", "ref", "incident"}),
)
LOCAL_SCENARIO_CAPABILITIES = TransportCapabilities(
    exact_time_bounds=True,
    stable_ascending_sort=True,
    cursor_pagination=True,
    supported_query_dimensions=frozenset(
        {"host", "datasource", "operator", "tactic", "ref"}
    ),
)


@runtime_checkable
class SoarQueryTransport(Protocol):
    """单 SOAR MCP 统一查询接口（内部多数据源分片路由由 SOAR 侧完成）。"""

    def query(self, *, query: str, from_ms: int, to_ms: int, limit: int) -> list[dict]:
        """按查询串 + 时间窗返回原始记录列表。"""
        ...

    def ping(self) -> bool:
        """连通性检查。"""
        ...

    @property
    def capabilities(self) -> TransportCapabilities:
        """Declare time, ordering, pagination, and query guarantees."""
        ...


class McpHttpTransport:
    """生产态：MCP streamable-HTTP JSON-RPC 客户端（initialize + tools/call）。

    兼容标准 MCP 服务端；工具入参约定为
    {query, from_ms, to_ms, limit}，返回 content[0].text 为 JSON 数组。
    """

    capabilities = GENERIC_MCP_CAPABILITIES

    def __init__(
        self,
        endpoint: str,
        tool_name: str = "soar_query",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        max_retries: int = 2,
        verify_tls: bool = True,
        ca_bundle: str | None = None,
    ):
        import httpx

        self.endpoint = endpoint
        self.tool_name = tool_name
        self.timeout = timeout
        self.max_retries = max_retries
        self.last_error_code: str | None = None
        self._id_counter = itertools.count(1)
        self._lock = threading.Lock()
        self._session_id: str | None = None
        base_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            **(headers or {}),
        }
        if not verify_tls:
            tls_verify: ssl.SSLContext | bool = False
        elif ca_bundle:
            tls_verify = ssl.create_default_context(cafile=ca_bundle)
        else:
            tls_verify = True
        self._client = httpx.Client(
            timeout=timeout,
            headers=base_headers,
            verify=tls_verify,
        )

    # ── MCP 协议 ──
    def _rpc(self, method: str, params: dict | None = None) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": next(self._id_counter),
            "method": method,
            "params": params or {},
        }
        headers = {}
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        last_err: Exception | None = None
        for _ in range(self.max_retries + 1):
            try:
                resp = self._client.post(self.endpoint, json=payload, headers=headers)
                resp.raise_for_status()
                if sid := resp.headers.get("Mcp-Session-Id"):
                    self._session_id = sid
                body = self._parse_body(resp)
                if "error" in body:
                    raise RuntimeError(f"MCP error: {body['error']}")
                return body.get("result")
            except Exception as e:  # noqa: BLE001 — 重试后上抛
                last_err = e
        raise ConnectionError(f"MCP RPC failed after retries: {last_err}") from last_err

    @staticmethod
    def _parse_body(resp) -> dict:
        ctype = resp.headers.get("Content-Type", "")
        if "text/event-stream" in ctype:
            # SSE：取最后一条 data 帧
            data_lines = [
                line[len("data:"):].strip()
                for line in resp.text.splitlines()
                if line.startswith("data:")
            ]
            return json.loads(data_lines[-1]) if data_lines else {}
        return resp.json()

    def _ensure_initialized(self) -> None:
        with self._lock:
            if self._session_id is not None:
                return
            self._rpc("initialize", {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "trace-engine", "version": "1.0.0"},
            })
            # notifications/initialized 为 fire-and-forget；失败不阻断
            try:
                self._client.post(
                    self.endpoint,
                    json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                    headers={"Mcp-Session-Id": self._session_id or ""},
                )
            except Exception:  # noqa: BLE001
                pass

    # ── SoarQueryTransport ──
    def query(self, *, query: str, from_ms: int, to_ms: int, limit: int) -> list[dict]:
        self._ensure_initialized()
        result = self._rpc("tools/call", {
            "name": self.tool_name,
            "arguments": {
                "query": query, "from_ms": from_ms, "to_ms": to_ms, "limit": limit,
            },
        })
        return _extract_mcp_records(result)

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """调用任意 MCP 工具（如 get_wazuh_agents）。"""
        self._ensure_initialized()
        return self._rpc("tools/call", {
            "name": name,
            "arguments": arguments or {},
        })

    @staticmethod
    def _extract_records(result: Any) -> list[dict]:
        return _extract_mcp_records(result)

    def ping(self) -> bool:
        try:
            self._ensure_initialized()
            self.last_error_code = None
            return True
        except Exception as exc:  # noqa: BLE001
            message = str(exc).lower()
            if "401" in message or "unauthorized" in message:
                self.last_error_code = "auth_unauthorized"
            elif "403" in message or "forbidden" in message:
                self.last_error_code = "auth_forbidden"
            elif "certificate_verify_failed" in message:
                self.last_error_code = "tls_ca_untrusted"
            elif "timeout" in message:
                self.last_error_code = "connection_timeout"
            elif any(f"{code}" in message for code in range(500, 600)):
                self.last_error_code = "upstream_server_error"
            else:
                self.last_error_code = "connection_failed"
            return False

    def close(self) -> None:
        self._client.close()


def _flatten_wazuh_alert(item: dict) -> dict:
    """Wazuh alert 行 + full_log 内嵌 SOAR JSON → 单条扁平记录。"""
    out = {k: v for k, v in item.items() if k != "full_log"}
    full_log = item.get("full_log")
    if isinstance(full_log, str) and full_log.strip():
        try:
            parsed = json.loads(full_log)
            if isinstance(parsed, dict):
                out.update(parsed)
        except json.JSONDecodeError:
            out["_full_log_parse_error"] = True
    if out.get("hostname") and not out.get("host"):
        out["host"] = out["hostname"]
    if out.get("mitre_technique") and not out.get("technique"):
        out["technique"] = out["mitre_technique"]
    if not out.get("timestamp") and item.get("timestamp"):
        out["timestamp"] = item["timestamp"]
    agent = item.get("agent")
    if isinstance(agent, dict):
        out.setdefault("agent_name", agent.get("name"))
        out.setdefault("agent_id", agent.get("id"))
        out.setdefault("host", agent.get("name"))
    rule = item.get("rule")
    if isinstance(rule, dict):
        out.setdefault("rule_id", rule.get("id"))
        out.setdefault("rule_level", rule.get("level"))
        out.setdefault("rule_description", rule.get("description"))
        try:
            level = float(rule.get("level"))
        except (TypeError, ValueError):
            level = None
        if level is not None:
            out.setdefault("anomaly_score", max(0.0, min(1.0, level / 15.0)))
        raw_groups = rule.get("groups") or []
        if isinstance(raw_groups, str):
            raw_groups = [raw_groups]
        groups = {
            str(group).strip().lower()
            for group in raw_groups
            if str(group).strip()
        }
        decoder = item.get("decoder")
        decoder_name = (
            str(decoder.get("name") or "").strip().lower()
            if isinstance(decoder, dict) else ""
        )
        location = str(item.get("location") or "").strip().lower()
        if not out.get("source"):
            if "sysmon" in groups or decoder_name == "sysmon":
                out["source"] = "sysmon"
            elif "auditd" in groups or decoder_name == "auditd":
                out["source"] = "auditd"
            elif "powershell" in groups:
                out["source"] = "windows_event_log_powershell"
            elif groups & {"windows", "windows_security", "eventchannel"}:
                out["source"] = "windows_event_log_security"
            elif "syslog" in groups or location in {"journald", "syslog"}:
                out["source"] = "syslog"
        if not out.get("action"):
            if groups & {
                "authentication_failed",
                "authentication_failures",
                "authentication_success",
                "sshd",
                "pam",
            }:
                out["action"] = "AUTH"
                out.setdefault("ocsf_class_uid", 5002)
            elif "sysmon_event1" in groups or "process_creation" in groups:
                out["action"] = "EXEC"
                out.setdefault("ocsf_class_uid", 2001)
        if groups & {"authentication_failed", "authentication_failures"}:
            out.setdefault("auth_outcome", "failure")
        elif "authentication_success" in groups:
            out.setdefault("auth_outcome", "success")
        if groups:
            out.setdefault("rule_groups", sorted(groups))
        mitre = rule.get("mitre")
        if isinstance(mitre, dict):
            technique_ids = mitre.get("id") or mitre.get("technique") or []
            tactics = mitre.get("tactic") or []
            if isinstance(technique_ids, str):
                technique_ids = [technique_ids]
            if isinstance(tactics, str):
                tactics = [tactics]
            if technique_ids:
                out.setdefault("mitre_technique", technique_ids[0])
                out.setdefault("mitre_techniques", technique_ids)
            if tactics:
                out.setdefault("mitre_tactic", tactics[0])
                out.setdefault("mitre_tactics", tactics)
    data = item.get("data")
    if isinstance(data, dict):
        if data.get("action") and not out.get("action"):
            out["action"] = data["action"]
        win = data.get("win")
        system_data = win.get("system", {}) if isinstance(win, dict) else {}
        if isinstance(system_data, dict):
            event_id = (
                system_data.get("eventID")
                or system_data.get("eventId")
                or system_data.get("event_id")
            )
            if event_id not in (None, ""):
                out.setdefault("event_code", str(event_id))
        event_data = win.get("eventdata", {}) if isinstance(win, dict) else {}
        if isinstance(event_data, dict):
            process_name = (
                event_data.get("image")
                or event_data.get("processName")
                or event_data.get("parentImage")
            )
            if process_name and not out.get("src_process"):
                out["src_process"] = process_name
            action = event_data.get("action") or event_data.get("eventType")
            if action and not out.get("action"):
                out["action"] = action
            aliases = {
                "src_ip": ("ipAddress", "sourceIp", "srcIp"),
                "dst_ip": ("destinationIp", "destIp", "dstIp"),
                "user": ("targetUserName", "subjectUserName", "user"),
                "logon_type": ("logonType",),
                "status": ("status", "subStatus"),
                "auth_package": ("authenticationPackageName",),
            }
            for target, source_names in aliases.items():
                for source_name in source_names:
                    value = event_data.get(source_name)
                    if value not in (None, ""):
                        out.setdefault(target, value)
                        break
        for field in ("srcip", "dstip", "srcport", "dstport", "srcuser", "dstuser"):
            if data.get(field) not in (None, ""):
                out.setdefault(field, data[field])
        for field in (
            "src_process",
            "dst_process",
            "trace_step",
            "incident_id",
            "scenario",
            "is_attack",
            "src_entity_type",
            "dst_entity_type",
            "mitre_technique",
            "mitre_tactic",
            "raw_log_ref",
        ):
            if data.get(field) not in (None, ""):
                out.setdefault(field, data[field])
        out.setdefault("src_ip", out.get("srcip"))
        out.setdefault("dst_ip", out.get("dstip"))
        out.setdefault("src_port", out.get("srcport"))
        out.setdefault("dst_port", out.get("dstport"))
        out.setdefault("user", out.get("dstuser") or out.get("srcuser"))
    if not out.get("raw_log_ref"):
        stable_id = item.get("id") or item.get("_id")
        if stable_id:
            out["raw_log_ref"] = f"wazuh:{stable_id}"
    return out


def _parse_wazuh_search_payload(parsed: dict) -> tuple[list[dict], dict[str, Any]]:
    data = parsed.get("data", parsed)
    items = data.get("affected_items") if isinstance(data, dict) else None
    pagination = data.get("pagination") if isinstance(data, dict) else None
    if not isinstance(items, list):
        items = []
    if not isinstance(pagination, dict):
        pagination = {}
    records = [_flatten_wazuh_alert(item) for item in items if isinstance(item, dict)]
    return records, pagination


def _parse_wazuh_search_blob(text: str) -> tuple[list[dict], dict[str, Any]]:
    blob = text.strip()
    if blob.startswith("Security Events"):
        blob = blob.split("\n", 1)[-1].strip()
    if not blob:
        return [], {}
    try:
        parsed = json.loads(blob)
    except json.JSONDecodeError:
        return [], {}
    if not isinstance(parsed, dict):
        return [], {}
    return _parse_wazuh_search_payload(parsed)


def _parse_wazuh_mcp_search_result(result: Any) -> tuple[list[dict], dict[str, Any]]:
    if isinstance(result, dict):
        for item in result.get("content", []):
            if item.get("type") != "text":
                continue
            text = item.get("text", "")
            if text.strip().startswith("Security Events"):
                return _parse_wazuh_search_blob(text)
    return _extract_mcp_records(result), {}


def _parse_wazuh_security_events_text(text: str) -> list[dict]:
    """search_security_events 返回的 Security Events 文本块（仅记录，兼容旧调用）。"""
    records, _pagination = _parse_wazuh_search_blob(text)
    return records


def _extract_mcp_records(result: Any) -> list[dict]:
    """MCP tool 结果 → 记录列表。支持 generic / Wazuh 多种 JSON 形态。"""
    if result is None:
        return []
    if isinstance(result, list):
        return [r for r in result if isinstance(r, dict)]

    structured = result.get("structuredContent") if isinstance(result, dict) else None
    if isinstance(structured, dict):
        for key in ("records", "events", "alerts", "hits", "results", "data"):
            chunk = structured.get(key)
            if isinstance(chunk, list):
                return [r for r in chunk if isinstance(r, dict)]
            if isinstance(chunk, dict) and isinstance(chunk.get("hits"), list):
                return [r for r in chunk["hits"] if isinstance(r, dict)]
    if isinstance(structured, list):
        return [r for r in structured if isinstance(r, dict)]

    records: list[dict] = []
    if isinstance(result, dict):
        for item in result.get("content", []):
            if item.get("type") != "text":
                continue
            text = item.get("text", "")
            if text.strip().startswith("Security Events"):
                records.extend(_parse_wazuh_security_events_text(text))
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            records.extend(_extract_mcp_records(parsed))
        if records:
            return records
        for key in ("records", "events", "alerts", "hits", "results"):
            chunk = result.get(key)
            if isinstance(chunk, list):
                return [r for r in chunk if isinstance(r, dict)]
    return records


class WazuhMcpTransport(McpHttpTransport):
    """Wazuh MCP：主查询工具 search_security_events（无 soar_query）。"""

    capabilities = WAZUH_MCP_CAPABILITIES

    def __init__(
        self,
        endpoint: str,
        tool_name: str = "search_security_events",
        headers: dict[str, str] | None = None,
        timeout: float = 45.0,
        max_retries: int = 3,
        verify_tls: bool = True,
        ca_bundle: str | None = None,
        default_time_range: str = "30d",
        compact: bool = True,
        incident_prefix: str = "",
        attacks_only: bool = False,
        scope_field: str = "auto",
        scenario_slug: str = "",
    ):
        super().__init__(
            endpoint=endpoint,
            tool_name=tool_name,
            headers=headers,
            timeout=timeout,
            max_retries=max_retries,
            verify_tls=verify_tls,
            ca_bundle=ca_bundle,
        )
        self.default_time_range = default_time_range
        self.compact = compact
        self.incident_prefix = incident_prefix.strip()
        self.attacks_only = attacks_only
        self.scenario_slug = scenario_slug.strip()
        self.scope_field = (
            scope_field
            if scope_field in ("auto", "scenario", "incident")
            else "auto"
        )

    @staticmethod
    def _quote_term(value: str) -> str:
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    @staticmethod
    def _to_wazuh_query(query: str) -> str:
        """LOCK 探针查询串 → Wazuh Lucene 语法（扁平 SOAR 字段在 Indexer 中为 data.*）。"""
        clauses: list[str] = []
        for token in query.split():
            low = token.lower()
            if low.startswith("host:"):
                host = token.split(":", 1)[1].strip()
                if host:
                    host_term = WazuhMcpTransport._quote_term(host)
                    clauses.append(
                        f"(data.hostname:{host_term} OR data.host:{host_term} OR "
                        f"agent.name:{host_term})"
                    )
            elif low.startswith("ref:"):
                ref = token.split(":", 1)[1].strip()
                if ref:
                    ref_term = WazuhMcpTransport._quote_term(ref)
                    if ref.lower().startswith("wazuh:"):
                        wazuh_id = ref.split(":", 1)[1]
                        clauses.append(
                            f"(id:{WazuhMcpTransport._quote_term(wazuh_id)} "
                            f"OR data.raw_log_ref:{ref_term})"
                        )
                    else:
                        clauses.append(f"data.raw_log_ref:{ref_term}")
            elif low.startswith("source:"):
                continue
            elif token.strip():
                clauses.append(token)
        return " AND ".join(clauses) if clauses else "*"

    @staticmethod
    def _window_to_time_range(from_ms: int, to_ms: int, fallback: str) -> str:
        if from_ms <= 0 and to_ms <= 0:
            return fallback
        span_ms = max(0, to_ms - from_ms)
        span_days = max(1, int(span_ms / 86400000) + 1)
        if span_days <= 1:
            return "1d"
        if span_days <= 7:
            return "7d"
        # Wazuh MCP search_security_events 实测 >30d（如 90d）返回空结果
        return "30d"

    def _build_search_arguments(
        self,
        wazuh_query: str,
        *,
        from_ms: int,
        to_ms: int,
        limit: int,
        search_after: list[Any] | None = None,
        offset: int | None = None,
    ) -> dict[str, Any]:
        arguments: dict[str, Any] = {
            "query": wazuh_query,
            "time_range": self._window_to_time_range(
                from_ms, to_ms, self.default_time_range
            ),
            "limit": limit,
            "compact": self.compact,
        }
        if search_after:
            arguments["search_after"] = search_after
        elif offset is not None and offset > 0:
            arguments["offset"] = offset
        return arguments

    def _compose_wazuh_query(self, query: str) -> str:
        wazuh_query = self._to_wazuh_query(query)
        if self.incident_prefix:
            prefix = self.incident_prefix.strip()
            prefix_term = self._quote_term(prefix)
            if self.scope_field == "incident" or (
                self.scope_field == "auto"
                and prefix.upper().startswith("INC-")
            ):
                tag = f"data.incident_id:{prefix_term}"
            else:
                tag = f"data.scenario:{prefix_term}"
            if self.attacks_only:
                tag = f"{tag} AND data.is_attack:true"
            wazuh_query = f"{tag} AND ({wazuh_query})" if wazuh_query != "*" else tag
        elif (
            self.scenario_slug
            and "data.raw_log_ref:" in wazuh_query
            and "data.scenario:" not in wazuh_query
        ):
            slug_term = self._quote_term(self.scenario_slug)
            wazuh_query = f'data.scenario:{slug_term} AND ({wazuh_query})'
        return wazuh_query

    def query_pages(
        self,
        *,
        query: str,
        from_ms: int,
        to_ms: int,
        limit: int,
        max_pages: int = 20,
    ) -> Iterator[QueryPage]:
        """Yield MCP pages using search_after (preferred) or offset fallback."""
        self._ensure_initialized()
        wazuh_query = self._compose_wazuh_query(query)
        search_after: list[Any] | None = None
        offset: int | None = None
        seen_cursors: set[str] = set()

        for _page in range(max(1, max_pages)):
            arguments = self._build_search_arguments(
                wazuh_query,
                from_ms=from_ms,
                to_ms=to_ms,
                limit=limit,
                search_after=search_after,
                offset=offset,
            )
            result = self._rpc("tools/call", {
                "name": self.tool_name,
                "arguments": arguments,
            })
            records, pagination = _parse_wazuh_mcp_search_result(result)
            yield QueryPage(records=records, pagination=pagination)

            if not pagination.get("has_more"):
                break

            mode = str(pagination.get("mode") or "").lower()
            next_search_after = pagination.get("next_search_after")
            if mode == "search_after" and isinstance(next_search_after, list):
                cursor_key = json.dumps(next_search_after, sort_keys=True, default=str)
                if cursor_key in seen_cursors:
                    break
                seen_cursors.add(cursor_key)
                search_after = next_search_after
                offset = None
                continue

            next_offset = pagination.get("next_offset")
            if next_offset is not None:
                try:
                    next_offset_int = int(next_offset)
                except (TypeError, ValueError):
                    break
                cursor_key = f"offset:{next_offset_int}"
                if cursor_key in seen_cursors:
                    break
                seen_cursors.add(cursor_key)
                offset = next_offset_int
                search_after = None
                continue
            break

    def query(self, *, query: str, from_ms: int, to_ms: int, limit: int) -> list[dict]:
        self._ensure_initialized()
        wazuh_query = self._compose_wazuh_query(query)
        result = self._rpc("tools/call", {
            "name": self.tool_name,
            "arguments": self._build_search_arguments(
                wazuh_query,
                from_ms=from_ms,
                to_ms=to_ms,
                limit=limit,
            ),
        })
        records, _pagination = _parse_wazuh_mcp_search_result(result)
        return records

    @staticmethod
    def _extract_records(result: Any) -> list[dict]:
        return _extract_mcp_records(result)


def build_mcp_transport(cfg) -> McpHttpTransport | WazuhMcpTransport:
    """按 tool_profile 构造 MCP 传输层。"""
    common = dict(
        endpoint=cfg.endpoint,
        tool_name=cfg.tool_name,
        headers=cfg.headers,
        timeout=cfg.timeout_seconds,
        max_retries=cfg.max_retries,
        verify_tls=getattr(cfg, "verify_tls", True),
        ca_bundle=getattr(cfg, "ca_bundle", "") or None,
    )
    if getattr(cfg, "tool_profile", "generic") == "wazuh":
        return WazuhMcpTransport(
            **common,
            default_time_range=getattr(cfg, "wazuh_time_range", "30d"),
            compact=getattr(cfg, "wazuh_compact", True),
            incident_prefix=getattr(cfg, "wazuh_incident_prefix", ""),
            attacks_only=getattr(cfg, "wazuh_attacks_only", False),
            scope_field=getattr(cfg, "wazuh_scope_field", "auto"),
            scenario_slug=getattr(cfg, "wazuh_scenario_slug", ""),
        )
    return McpHttpTransport(**common)


class LocalScenarioTransport:
    """验收态：直接读 soar_mcp_env 场景 JSON，按查询串 + 时间窗过滤。

    行为与生产 SOAR 查询语义一致（host / source 过滤 + 时间窗 + limit），
    用于无外部依赖的 E2E 验收与 CI。
    """

    capabilities = LOCAL_SCENARIO_CAPABILITIES

    def __init__(self, scenario_path_or_data: str | Path | dict):
        if isinstance(scenario_path_or_data, dict):
            data = scenario_path_or_data
        else:
            data = json.loads(Path(scenario_path_or_data).read_text(encoding="utf-8"))
        self._events: list[dict] = data.get("events", [])
        self._meta: dict = data.get("meta", {})

    @property
    def meta(self) -> dict:
        return self._meta

    def query(self, *, query: str, from_ms: int, to_ms: int, limit: int) -> list[dict]:
        from trace_agent.loop.scenario_executor import ScenarioExecutor

        host_filter = ""
        for token in query.split():
            if token.lower().startswith("host:"):
                host_filter = token.split(":", 1)[1].strip().lower()

        matched: list[tuple[float, dict]] = []
        for ev in self._events:
            ts_ms = ScenarioExecutor._parse_ts(ev.get("ts", "")) * 1000
            if not (from_ms <= ts_ms <= to_ms):
                continue
            if host_filter:
                src_host = (
                    ev.get("src_entity", {}).get("attrs", {}).get("host_uid") or ""
                ).lower()
                dst_host = (
                    ev.get("dst_entity", {}).get("attrs", {}).get("host_uid") or ""
                ).lower()
                if host_filter not in (src_host, dst_host):
                    continue
            matched.append((ts_ms, ev))

        # 与真实 SIEM/SOAR 语义一致：按时间升序返回前 limit 条（可时间分页）
        matched.sort(key=lambda x: x[0])
        return [ev for _, ev in matched[:limit]]

    def ping(self) -> bool:
        return len(self._events) > 0
