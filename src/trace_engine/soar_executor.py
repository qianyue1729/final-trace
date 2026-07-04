"""SoarMcpProbeExecutor — 生产态 C 拍执行器（单 SOAR MCP 多数据源）。

设计：
- 每轮扇出前按探针增量拉取 SOAR 记录（时间窗游标前进），归一化后
  注入本地事件缓存；
- 匹配/评分/证据生命周期完全复用 ScenarioExecutor 内核（Ranking v2 +
  commit-on-confirm），保证生产与验收行为一致；
- 换 SOAR 平台只需换 transport + 归一化字段映射，引擎与内核不动。
"""
from __future__ import annotations

import time
from typing import Any, Optional

from trace_agent.loop.probe import Probe
from trace_agent.loop.scenario_executor import ScenarioExecutor

from .config import SoarMcpConfig
from .normalizer import EventNormalizer
from .transports import SoarQueryTransport, TransportCapabilities


class SoarMcpProbeExecutor(ScenarioExecutor):
    """从单 SOAR MCP 统一查询接口动态取证的 ProbeExecutor。"""

    def __init__(
        self,
        transport: SoarQueryTransport,
        config: Optional[SoarMcpConfig] = None,
        normalizer: Optional[EventNormalizer] = None,
        known_hosts: Optional[list[str]] = None,
        seed: int | None = 42,
    ):
        self.transport = transport
        self.mcp_config = config or SoarMcpConfig()
        self.normalizer = normalizer or EventNormalizer()
        self._static_hosts = list(known_hosts or [])
        self._seen_refs: set[str] = set()
        self._fetch_stats: dict[str, Any] = {
            "queries": 0,
            "logical_queries": 0,
            "deduplicated_queries": 0,
            "records": 0,
            "errors": 0,
            "coverage_truncated": False,
            "truncations": [],
            "query_diagnostics": [],
        }
        self._bootstrap_stats: dict = {}
        # 空场景起步；事件随查询增量注入（生产态 bootstrap 后才有主机清单）
        super().__init__({"events": [], "meta": {}}, seed=seed)

    # ── 时间窗 ──
    def align_to_alert(self, alert_ts: float) -> None:
        """时间窗对齐到告警时刻（等价验收 harness 的 _align_executor_to_alert）。"""
        if alert_ts > 0:
            self._time_cursor = alert_ts

    def _window_ms(self) -> tuple[int, int]:
        now = time.time()
        cursor = self._time_cursor or now

        if not self._is_remote_mcp():
            from trace_agent.loop.scenario_executor import TIME_WINDOW_STEP

            return (
                int((cursor - self.mcp_config.lookback_seconds) * 1000),
                int((cursor + TIME_WINDOW_STEP) * 1000),
            )

        latest_allowed = now + max(
            0, self.mcp_config.allowed_clock_skew_seconds
        )
        anchor = min(cursor, latest_allowed)
        to_s = min(
            anchor + max(0, self.mcp_config.lookahead_seconds),
            latest_allowed,
        )
        from_s = anchor - max(0, self.mcp_config.lookback_seconds)
        return int(from_s * 1000), int(to_s * 1000)

    # ── 增量事件注入 ──
    def _ingest_events(self, events: list[dict]) -> int:
        """归一化事件注入缓存 + 增量建索引（去重按 raw_log_ref）。"""
        added = 0
        for ev in events:
            ref = ev.get("raw_log_ref", "")
            if ref and ref in self._seen_refs:
                continue
            if ref:
                self._seen_refs.add(ref)
            idx = len(self._events)
            self._events.append(ev)
            self._index_one(idx, ev)
            added += 1
        return added

    def _index_one(self, idx: int, event: dict) -> None:
        """单事件标准化 + 索引（与 _build_indexes 同逻辑的增量版）。"""
        self._normalize_event(event)
        host = self._extract_host(event)
        if host:
            self._index_by_host[host].append(idx)
        technique = event.get("technique")
        if technique:
            self._index_by_technique[technique].append(idx)
            base = technique.split(".")[0]
            if base != technique:
                self._index_by_technique[base].append(idx)
        tactic = event.get("_normalized_tactic", "") or self._infer_tactic(event)
        if tactic:
            self._index_by_tactic[tactic].append(idx)
        action = event.get("action")
        if action:
            self._index_by_action[action].append(idx)
        ts = self._parse_ts(event.get("ts", ""))
        if ts:
            self._all_timestamps.append(ts)

    # ── 生产态冷启动：按 incident/case 从 MCP 拉关联攻击链，发现主机清单 ──
    def bootstrap_investigation(self, alert_payload: dict | None = None) -> dict:
        """真实 SOC 流程：告警入案 → 先拉 case 内关联事件 → 再 fan-out 探针。

        不读本地 soar_mcp_env；主机清单来自 MCP 返回事件的 hostname 字段。
        """
        stats: dict = {
            "case_prefetch_events": 0,
            "entry_prefetch_events": 0,
            "asset_inventory": {},
            "discovered_hosts": [],
        }
        if not self._is_remote_mcp():
            self._bootstrap_stats = stats
            return stats

        strategy = str(
            getattr(self.mcp_config, "bootstrap_strategy", "full_case")
            or "full_case"
        ).strip().lower()
        stats["bootstrap_strategy"] = strategy

        prefix = getattr(self.transport, "incident_prefix", "") or ""
        ref = ""
        srcip = ""
        dst_ip = ""
        technique = ""
        if alert_payload:
            attrs = alert_payload.get("attributes") or {}
            ref = str(attrs.get("raw_log_ref") or alert_payload.get("raw_log_ref") or "")
            srcip = str(attrs.get("srcip") or attrs.get("src_ip") or "").strip()
            dst_ip = str(attrs.get("dst_ip") or attrs.get("dstip") or "").strip()
            technique = str(
                alert_payload.get("technique")
                or attrs.get("technique")
                or attrs.get("mitre_technique")
                or attrs.get("rule_mitre_id")
                or ""
            ).strip()

        if strategy == "seed_only":
            # 种子只锁 1 条：按 pivot 字段优先级 dst_ip → srcip → ref 构造最窄查询。
            # real_trace_01 v2 种子为外传告警 (T1048 + dst_ip)。
            seed_pivots: list[tuple[str, str]] = []
            if dst_ip:
                seed_pivots.append(("data.dst_ip", dst_ip))
            if srcip:
                seed_pivots.append(("data.srcip", srcip))
            if technique and seed_pivots:
                field, value = seed_pivots[0]
                seed_q = f'rule.mitre.id:{technique} AND {field}:"{value}"'
                stats["bootstrap_query"] = seed_q
                stats["bootstrap_pivot"] = field
                stats["case_prefetch_events"] = self._fetch_paginated(
                    seed_q,
                    limit_override=2,
                )
            elif technique:
                # 无 IP pivot 时回退到 technique-only 查询
                seed_q = f"rule.mitre.id:{technique}"
                stats["bootstrap_query"] = seed_q
                stats["bootstrap_pivot"] = "technique"
                stats["case_prefetch_events"] = self._fetch_paginated(
                    seed_q,
                    limit_override=2,
                )
            elif ref:
                seed_q = f"ref:{ref}"
                stats["bootstrap_query"] = seed_q
                stats["entry_prefetch_events"] = self._fetch_paginated(
                    seed_q,
                    limit_override=2,
                )
        else:
            if prefix:
                stats["case_prefetch_events"] = self._fetch_paginated("*")
            if ref and stats["case_prefetch_events"] == 0:
                stats["entry_prefetch_events"] = self._fetch_paginated(f"ref:{ref}")
            elif not prefix and srcip and stats["case_prefetch_events"] == 0:
                group = "real_trace"
                if alert_payload:
                    group = str(
                        (alert_payload.get("attributes") or {}).get("rule_group")
                        or group
                    ).strip() or group
                bootstrap_q = f"rule.groups:{group} AND data.srcip:{srcip}"
                stats["bootstrap_query"] = bootstrap_q
                stats["case_prefetch_events"] = self._fetch_paginated(bootstrap_q)

        from .asset_inventory import discover_asset_hosts

        inv_cfg = self.mcp_config.asset_inventory
        if inv_cfg.wazuh_agents_enabled or inv_cfg.cmdb.enabled:
            inv_hosts, inv_report = discover_asset_hosts(self.transport, inv_cfg)
            stats["asset_inventory"] = inv_report
            if inv_hosts:
                self._static_hosts = sorted(set(self._static_hosts) | set(inv_hosts))

        stats["discovered_hosts"] = self.known_hosts()
        stats["attack_chain_events"] = sum(
            1 for event in self._events if str(event.get("raw_log_ref", "")).startswith("attack:")
        )
        if stats["attack_chain_events"] == 0 and stats["case_prefetch_events"]:
            stats["attack_chain_events"] = stats["case_prefetch_events"]

        # ── 关键修复：推进时间游标到缓存事件的最大时间戳 ──
        # Wazuh remote MCP 路径 advance_time=False，时间游标停在告警时刻，
        # 导致 _execute_single_probe 的 ts<=cursor 过滤只暴露告警前的事件。
        # 对于生产态 bootstrap（所有事件已一次性加载），需将游标推进到
        # 最大事件时间戳，使 LOCK 循环能发现全部攻击链事件。
        if self._all_timestamps:
            max_ts = max(self._all_timestamps)
            if max_ts > self._time_cursor:
                self._time_cursor = max_ts
                stats["time_cursor_advanced_to"] = max_ts

        self._bootstrap_stats = stats
        return stats

    def _is_remote_mcp(self) -> bool:
        from .transports import LocalScenarioTransport

        return not isinstance(self.transport, LocalScenarioTransport)

    def _transport_capabilities(self) -> TransportCapabilities:
        capabilities = getattr(self.transport, "capabilities", None)
        if isinstance(capabilities, TransportCapabilities):
            return capabilities
        return TransportCapabilities(
            exact_time_bounds=False,
            stable_ascending_sort=False,
            cursor_pagination=False,
            supported_query_dimensions=frozenset(),
        )

    def _fetch_paginated(
        self,
        query: str,
        *,
        window: tuple[int, int] | None = None,
        context: dict[str, Any] | None = None,
        limit_override: int | None = None,
    ) -> int:
        """Fetch records according to declared transport capabilities."""
        cfg = self.mcp_config
        effective_limit = (
            cfg.page_limit if limit_override is None else max(1, int(limit_override))
        )
        requested_from_ms, requested_to_ms = window or self._window_ms()
        from_ms = requested_from_ms
        to_ms = requested_to_ms
        capabilities = self._transport_capabilities()
        ingested = 0
        observed_timestamps: list[int] = []
        seen_cursors = {from_ms}
        diagnostic: dict[str, Any] = {
            "query": query,
            "operator": (context or {}).get("operator", ""),
            "datasource": (context or {}).get("datasource", ""),
            "operators": list((context or {}).get("operators", [])),
            "datasources": list((context or {}).get("datasources", [])),
            "probe_ids": list((context or {}).get("probe_ids", [])),
            "requested_from_ms": requested_from_ms,
            "requested_to_ms": requested_to_ms,
            "observed_from_ms": None,
            "observed_to_ms": None,
            "pages": 0,
            "records": 0,
            "limit": effective_limit,
            "exact_time_bounds": capabilities.exact_time_bounds,
            "coverage_truncated": False,
            "truncation_reason": None,
            "out_of_order": False,
            "error": None,
        }
        self._fetch_stats["logical_queries"] += 1
        page_count = (
            1
            if limit_override is not None
            else cfg.max_pages if capabilities.cursor_pagination else 1
        )
        query_pages = getattr(self.transport, "query_pages", None)

        if callable(query_pages) and capabilities.cursor_pagination:
            try:
                for page in query_pages(
                    query=query,
                    from_ms=requested_from_ms,
                    to_ms=requested_to_ms,
                    limit=effective_limit,
                    max_pages=page_count,
                ):
                    self._fetch_stats["queries"] += 1
                    diagnostic["pages"] += 1
                    records = page.records
                    self._fetch_stats["records"] += len(records)
                    diagnostic["records"] += len(records)
                    pagination = page.pagination or {}
                    if pagination.get("mode"):
                        diagnostic["pagination_mode"] = pagination.get("mode")

                    events = self.normalizer.normalize_batch(records)
                    timestamps = [
                        int(self._parse_ts(event.get("ts", "")) * 1000)
                        for event in events
                    ]
                    valid_timestamps = [
                        timestamp for timestamp in timestamps if timestamp > 0
                    ]
                    observed_timestamps.extend(valid_timestamps)
                    if valid_timestamps != sorted(valid_timestamps):
                        diagnostic["out_of_order"] = True
                        events.sort(
                            key=lambda event: self._parse_ts(event.get("ts", ""))
                        )
                    ingested += self._ingest_events(events)

                    if not pagination.get("has_more"):
                        break
                else:
                    if (
                        diagnostic["pages"] >= page_count
                        and diagnostic["records"] >= effective_limit
                    ):
                        diagnostic["coverage_truncated"] = True
                        diagnostic["truncation_reason"] = "max_pages_reached"
            except Exception as exc:  # noqa: BLE001
                self._fetch_stats["errors"] += 1
                diagnostic["error"] = f"{type(exc).__name__}: {exc}"
        else:
            for page_index in range(page_count):
                try:
                    records = self.transport.query(
                        query=query,
                        from_ms=from_ms,
                        to_ms=to_ms,
                        limit=effective_limit,
                    )
                    self._fetch_stats["queries"] += 1
                    self._fetch_stats["records"] += len(records)
                    diagnostic["pages"] += 1
                    diagnostic["records"] += len(records)
                except Exception as exc:  # noqa: BLE001
                    self._fetch_stats["errors"] += 1
                    diagnostic["error"] = f"{type(exc).__name__}: {exc}"
                    break

                events = self.normalizer.normalize_batch(records)
                timestamps = [
                    int(self._parse_ts(event.get("ts", "")) * 1000)
                    for event in events
                ]
                valid_timestamps = [
                    timestamp for timestamp in timestamps if timestamp > 0
                ]
                observed_timestamps.extend(valid_timestamps)
                if valid_timestamps != sorted(valid_timestamps):
                    diagnostic["out_of_order"] = True
                    events.sort(
                        key=lambda event: self._parse_ts(event.get("ts", ""))
                    )
                ingested += self._ingest_events(events)

                if len(records) < effective_limit:
                    break
                if not capabilities.cursor_pagination:
                    diagnostic["coverage_truncated"] = True
                    diagnostic["truncation_reason"] = "full_page_without_cursor"
                    break

                max_ts_ms = max(valid_timestamps, default=0)
                next_from = max_ts_ms + 1
                if next_from <= from_ms or next_from in seen_cursors:
                    diagnostic["coverage_truncated"] = True
                    diagnostic["truncation_reason"] = "repeated_or_missing_cursor"
                    break
                seen_cursors.add(next_from)
                from_ms = next_from
                if page_index == page_count - 1:
                    diagnostic["coverage_truncated"] = True
                    diagnostic["truncation_reason"] = "max_pages_reached"

        if observed_timestamps:
            diagnostic["observed_from_ms"] = min(observed_timestamps)
            diagnostic["observed_to_ms"] = max(observed_timestamps)
        if diagnostic["coverage_truncated"]:
            self._fetch_stats["coverage_truncated"] = True
            self._fetch_stats["truncations"].append({
                "query": query,
                "reason": diagnostic["truncation_reason"],
                "requested_from_ms": requested_from_ms,
                "requested_to_ms": requested_to_ms,
            })
        self._fetch_stats["query_diagnostics"].append(diagnostic)
        return ingested

    def _query_for_probe(
        self,
        probe: Probe,
        window: tuple[int, int],
    ) -> tuple[tuple[Any, ...], str, str]:
        cfg = self.mcp_config
        datasource = cfg.operator_datasource_map.get(probe.operator, "SIEM")

        # 显式查询覆盖：clue_pivot / model_mcp 探针携带完整 Lucene。
        explicit_query = str((probe.metadata or {}).get("mcp_query") or "").strip()
        if explicit_query:
            key = (
                "mcp_query",
                explicit_query.lower(),
                window[0],
                window[1],
            )
            return key, explicit_query, datasource

        # pivot 路由：按 operator 选 pivot 字段与模板（real_trace v2）。
        pivot_field = (cfg.pivot_field_map or {}).get(probe.operator, "")
        if pivot_field:
            template = (cfg.query_template_by_pivot or {}).get(
                pivot_field, "host:{value}"
            )
            query = template.format(value=probe.target)
            key_parts: list[Any] = [
                pivot_field,
                probe.target.strip().lower(),
                window[0],
                window[1],
            ]
            return tuple(key_parts), query, datasource

        query = cfg.query_template.format(
            host=probe.target,
            datasource=datasource,
            operator=probe.operator,
            tactic=probe.tactic,
        )
        dimensions = self._transport_capabilities().supported_query_dimensions
        key_parts: list[Any] = [
            probe.target.strip().lower(),
            window[0],
            window[1],
        ]
        if "datasource" in dimensions:
            key_parts.append(datasource.strip().lower())
        if "operator" in dimensions:
            key_parts.append(probe.operator.strip().lower())
        if "tactic" in dimensions:
            key_parts.append(probe.tactic.strip().lower())
        return tuple(key_parts), query, datasource

    def execute_fanout(self, probes: list[Probe]) -> list[dict]:
        window = self._window_ms()
        query_groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        for probe in probes:
            key, query, datasource = self._query_for_probe(probe, window)
            group = query_groups.setdefault(key, {
                "query": query,
                "operator": probe.operator,
                "datasource": datasource,
                "operators": [],
                "datasources": [],
                "probe_ids": [],
            })
            group["probe_ids"].append(probe.id)
            if probe.operator not in group["operators"]:
                group["operators"].append(probe.operator)
            if datasource not in group["datasources"]:
                group["datasources"].append(datasource)

        self._fetch_stats["deduplicated_queries"] += (
            len(probes) - len(query_groups)
        )
        for group in query_groups.values():
            self._fetch_paginated(
                group["query"],
                window=window,
                context=group,
            )

        # ── 关键修复：remote MCP 路径推进时间游标到缓存最大时间戳 ──
        # execute_fanout 对 remote MCP 使用 advance_time=False（不逐轮推进），
        # 但如果 _fetch_paginated 注入了新事件且游标仍停留在 0 / alert 时刻，
        # _execute_single_probe 的 ts<=cursor 过滤会丢弃全部新事件。
        # 此处与 bootstrap_investigation 对齐：游标至少推进到缓存最大时间戳。
        if self._is_remote_mcp() and self._all_timestamps:
            max_ts = max(self._all_timestamps)
            if max_ts > self._time_cursor:
                self._time_cursor = max_ts

        return self._execute_cached_fanout(
            probes,
            advance_time=not self._is_remote_mcp(),
        )

    def execute_mcp_plans(
        self,
        plans: list[dict[str, Any]],
        probes_by_id: dict[str, Probe],
    ) -> dict[str, Any]:
        """Execute validator-sanitized MCP calls and map results to source probes."""
        call_tool = getattr(self.transport, "call_tool", None)
        if not callable(call_tool) or not self._is_remote_mcp():
            return {
                "events": [],
                "executions": [],
                "failed_probe_ids": [
                    str(plan.get("source_probe_id") or "") for plan in plans
                ],
            }

        successful_probes: list[Probe] = []
        failed_probe_ids: list[str] = []
        executions: list[dict[str, Any]] = []
        for plan in plans:
            probe_id = str(plan.get("source_probe_id") or "")
            probe = probes_by_id.get(probe_id)
            started = time.perf_counter()
            execution: dict[str, Any] = {
                "plan_id": str(plan.get("plan_id") or ""),
                "source_probe_id": probe_id,
                "mcp_tool": str(plan.get("mcp_tool") or ""),
                "status": "failed",
                "hits": 0,
                "latency_ms": 0.0,
                "error": None,
            }
            try:
                result = call_tool(
                    execution["mcp_tool"],
                    dict(plan.get("arguments") or {}),
                )
                extract = getattr(self.transport, "_extract_records", None)
                records = extract(result) if callable(extract) else []
                events = self.normalizer.normalize_batch(records)
                self._ingest_events(events)
                self._fetch_stats["queries"] += 1
                self._fetch_stats["logical_queries"] += 1
                self._fetch_stats["records"] += len(records)
                self._fetch_stats["query_diagnostics"].append({
                    "query": str(
                        (plan.get("arguments") or {}).get("query") or ""
                    ),
                    "probe_ids": [probe_id],
                    "records": len(records),
                    "pages": 1,
                    "source": "model_mcp_compiler",
                    "mcp_tool": execution["mcp_tool"],
                    "error": None,
                })
                execution["status"] = "ok"
                execution["hits"] = len(records)
                if probe is not None:
                    successful_probes.append(probe)
            except Exception as exc:  # noqa: BLE001
                self._fetch_stats["errors"] += 1
                failed_probe_ids.append(probe_id)
                execution["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                execution["latency_ms"] = round(
                    (time.perf_counter() - started) * 1000, 1
                )
                executions.append(execution)

        # 推进时间游标（与 execute_fanout / bootstrap 对齐）
        if self._is_remote_mcp() and self._all_timestamps:
            max_ts = max(self._all_timestamps)
            if max_ts > self._time_cursor:
                self._time_cursor = max_ts

        events = self._execute_cached_fanout(
            successful_probes,
            advance_time=False,
        )
        return {
            "events": events,
            "executions": executions,
            "failed_probe_ids": failed_probe_ids,
        }

    def known_hosts(self) -> list[str]:
        hosts = set(self._static_hosts)
        hosts.update(super().known_hosts())
        return sorted(hosts)

    def available(self) -> bool:
        try:
            return self.transport.ping()
        except Exception:  # noqa: BLE001
            return False

    @property
    def fetch_stats(self) -> dict:
        out = dict(self._fetch_stats)
        out["truncations"] = list(self._fetch_stats["truncations"])
        out["query_diagnostics"] = [
            dict(item) for item in self._fetch_stats["query_diagnostics"]
        ]
        if self._bootstrap_stats:
            out["bootstrap"] = dict(self._bootstrap_stats)
        return out
