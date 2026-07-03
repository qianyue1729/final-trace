"""引擎配置 — YAML/JSON 文件 + 环境变量覆盖。

单一配置对象贯穿服务、执行器与归一化器，保证生产/验收两态只差一个 backend 字段。
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def eval_attacks_only_allowed() -> bool:
    """Explicit eval/debug opt-in for Wazuh `data.is_attack:true` query filter."""
    return os.environ.get("TRACE_ENGINE_EVAL_ATTACKS_ONLY", "").lower() in (
        "1",
        "true",
        "yes",
    )


def demo_profile_enabled() -> bool:
    """Explicit opt-in for Wazuh production demo profile (guardrail downgrade, etc.)."""
    return os.environ.get("TRACE_ENGINE_DEMO_PROFILE", "").lower() in (
        "1",
        "true",
        "yes",
    )


def resolve_wazuh_attacks_only(
    requested: bool,
    *,
    backend: str,
    scenario_indexed_attack_chain: bool = False,
) -> bool:
    """Production soar_mcp must not use eval GT filter unless explicitly opted in."""
    if not requested:
        return False
    if backend == "soar_mcp" and not (
        eval_attacks_only_allowed() or scenario_indexed_attack_chain
    ):
        return False
    return True


def _bootstrap_host_client_env() -> None:
    """从项目根 host-client.env 注入凭据（不覆盖已有环境变量）。"""
    env_path = _PROJECT_ROOT / "host-client.env"
    if not env_path.is_file():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if key and key not in os.environ:
            os.environ[key] = value


@dataclass
class CmdbConfig:
    """外部 CMDB HTTP 接口（资产台账）。"""
    enabled: bool = False
    url: str = ""
    method: str = "GET"
    headers: dict[str, str] = field(default_factory=dict)
    # 响应 JSON 中主机数组的点分路径，如 data.items 或 hosts
    hosts_json_path: str = "hosts"
    hostname_field: str = "hostname"
    timeout_seconds: float = 15.0


@dataclass
class AssetInventoryConfig:
    """bootstrap 阶段资产发现：Wazuh Agent 列表 + CMDB API。"""
    wazuh_agents_enabled: bool = False
    wazuh_agents_tool: str = "get_wazuh_agents"   # 或 get_wazuh_running_agents
    wazuh_agents_status: str = ""                 # 空=全部；可选 active / disconnected
    wazuh_agents_limit: int = 500
    wazuh_agent_name_field: str = "name"          # Wazuh agent 对象里的主机名字段
    cmdb: CmdbConfig = field(default_factory=CmdbConfig)


@dataclass
class SoarMcpConfig:
    """单 SOAR MCP 接入配置。"""
    endpoint: str = "http://localhost:9100/mcp"
    tool_name: str = "soar_query"           # MCP tools/call 的工具名
    # 探针 operator → 数据源提示（进查询串，SOAR 侧内部分片路由）
    operator_datasource_map: dict[str, str] = field(default_factory=lambda: {
        "process_tree": "EDR",
        "script_execution": "EDR",
        "credential_access_check": "EDR",
        "persistence_scan": "EDR",
        "registry_query": "EDR",
        "network_flow": "NDR",
        "dns_query": "NDR",
        "lateral_movement_check": "SIEM",
        "auth_log": "SIEM",
        "file_hash_lookup": "EDR",
    })
    query_template: str = "host:{host} source:{datasource}"
    page_limit: int = 200
    max_pages: int = 20              # 时间游标分页上限（单探针单轮）
    timeout_seconds: float = 30.0
    max_retries: int = 2
    headers: dict[str, str] = field(default_factory=dict)   # 认证头等
    verify_tls: bool = True
    ca_bundle: str = ""
    lookback_seconds: int = 30 * 86400   # 每次查询的回看窗口
    lookahead_seconds: int = 0            # 实时调查默认不查询告警之后
    allowed_clock_skew_seconds: int = 300 # 未来时间戳最大容忍偏移
    # tool_profile: generic = soar_query(from_ms/to_ms)；wazuh = search_security_events
    tool_profile: str = "generic"
    wazuh_time_range: str = "30d"        # search_security_events 默认 time_range
    wazuh_compact: bool = True
    wazuh_incident_prefix: str = ""      # 场景 ID → data.scenario:；INC- 前缀 → data.incident_id:
    wazuh_scope_field: str = "auto"      # auto | scenario | incident
    wazuh_attacks_only: bool = False     # 为 true 时追加 data.is_attack:true
    wazuh_scenario_slug: str = ""        # ref 查询跨场景消歧（data.scenario）
    asset_inventory: AssetInventoryConfig = field(default_factory=AssetInventoryConfig)


@dataclass
class NormalizerConfig:
    """SOAR 原始记录 → LOCK 场景事件的字段映射（点分路径）。

    默认适配 soar_mcp_env 的 EntityEvent 结构；接第三方 SOAR 时只改这里。
    """
    field_map: dict[str, str] = field(default_factory=lambda: {
        "ref": "raw_log_ref",
        "timestamp": "ts",
        "technique": "technique",
        "tactic": "tactic",
        "action": "action",
        "anomaly_score": "anomaly_score",
        "host": "src_entity.attrs.host_uid",
        "host_fallback": "dst_entity.attrs.host_uid",
        "process_name": "src_entity.attrs.name",
        "ocsf_class_uid": "ocsf_class_uid",
    })


@dataclass
class BudgetConfig:
    total_rounds: int = 50
    total_probes: int = 400
    fanout_per_round: int = 8
    min_rounds_before_robust: int = 4
    min_rounds_after_root: int = 8


@dataclass
class ServiceConfig:
    host: str = "0.0.0.0"
    port: int = 8100
    api_keys: list[str] = field(default_factory=list)   # 空 = 不鉴权（仅限内网/开发）
    db_path: str = str(_PROJECT_ROOT / "data" / "trace_engine.db")
    audit_log_path: str = str(_PROJECT_ROOT / "data" / "audit.log")
    max_workers: int = 4          # 并发调查会话数
    retention_days: int = 90      # 会话记录保留期


@dataclass
class CalibrationConfig:
    artifact_path: str = ""
    max_age_days: int = 90
    min_slice_support: int = 80
    min_precision: float = 0.90
    min_recall: float = 0.80
    contain_threshold: float = 0.70
    dismiss_threshold: float = 0.30


@dataclass
class AlertEnricherConfig:
    """Alert enrichment settings — Plan 008."""
    mode: str = "off"  # off | shadow | assist
    provider: str = "deepseek"
    model: str = "deepseek-v4-flash"
    endpoint: str = "https://api.deepseek.com/v1"
    credential_env: str = "DEEPSEEK_API_KEY"
    ca_bundle: str = ""
    verify_tls: bool = True
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 30.0
    max_retries: int = 2
    max_candidates: int = 5
    # Privacy: redact sensitive fields before model calls
    redact_patterns: list[str] = field(default_factory=lambda: [
        r"(?i)password",
        r"(?i)token",
        r"(?i)secret",
        r"(?i)api[._-]?key",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}",  # email
    ])
    redact_placeholder: str = "<redacted>"
    max_command_line_length: int = 500
    max_raw_attribute_bytes: int = 4096


@dataclass
class ModelPlannerConfig:
    mode: str = "shadow"  # off | shadow | assist; assist remains default-off
    max_intents_per_round: int = 4
    cost_budget_per_round: float = 1.0
    max_graph_nodes: int = 40


@dataclass
class DemoProfileConfig:
    """Production demo profile — must be explicitly enabled; never default-on."""
    enabled: bool = False
    plateau_rounds: int = 5
    min_graph_nodes: int = 8
    min_graph_edges: int = 6
    diversity_per_rule_id_cap: int = 20
    candidate_top_k: int = 50
    guardrail_downgrade: bool = True


@dataclass
class ModelJudgementConfig:
    mode: str = "off"  # off | shadow | assist
    provider: str = "deepseek"
    model: str = "deepseek-v4-flash"
    endpoint: str = "https://api.deepseek.com/v1"
    credential_env: str = "DEEPSEEK_API_KEY"
    ca_bundle: str = ""
    verify_tls: bool = True
    connect_timeout_seconds: float = 10.0
    read_timeout_seconds: float = 60.0
    max_retries: int = 2
    max_calls_per_round: int = 3
    max_calls_per_case: int = 20
    max_tokens_per_case: int = 20_000
    max_context_nodes: int = 40
    ambiguity_margin: float = 0.35
    deterministic_fallback: bool = True


@dataclass
class EngineConfig:
    # "scenario" = soar_mcp_env 场景验收态；"soar_mcp" = 生产态（真实 MCP）
    backend: str = "scenario"
    scenario_env_dir: str = str(_PROJECT_ROOT / "soar_mcp_env")
    soar_mcp: SoarMcpConfig = field(default_factory=SoarMcpConfig)
    normalizer: NormalizerConfig = field(default_factory=NormalizerConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    calibration: CalibrationConfig = field(default_factory=CalibrationConfig)
    alert_enricher: AlertEnricherConfig = field(default_factory=AlertEnricherConfig)
    model_planner: ModelPlannerConfig = field(default_factory=ModelPlannerConfig)
    model_judgement: ModelJudgementConfig = field(
        default_factory=ModelJudgementConfig
    )
    demo_profile: DemoProfileConfig = field(default_factory=DemoProfileConfig)
    service: ServiceConfig = field(default_factory=ServiceConfig)

    # ── 加载 ──
    @classmethod
    def load(cls, path: str | Path | None = None) -> "EngineConfig":
        """优先级：显式 path > TRACE_ENGINE_CONFIG 环境变量 > 全默认。"""
        _bootstrap_host_client_env()
        cfg_path = path or os.environ.get("TRACE_ENGINE_CONFIG")
        cfg = cls() if cfg_path is None else cls._from_file(Path(cfg_path))
        cfg._apply_env_overrides()
        cfg._sanitize_production_flags()
        cfg._resolve_ca_bundle_path()
        return cfg

    def _sanitize_production_flags(self) -> None:
        """Block eval-only shortcuts from silently affecting production MCP queries."""
        self.soar_mcp.wazuh_attacks_only = resolve_wazuh_attacks_only(
            self.soar_mcp.wazuh_attacks_only,
            backend=self.backend,
        )

    def _resolve_ca_bundle_path(self) -> None:
        """Resolve CA bundle; Windows 上 host-client.env 可能仍指向 Linux 路径。

        当 verify_tls=False 时跳过解析——代理环境注入自签名证书，
        CA bundle 无效且会导致 httpx 验证失败。
        """
        if not self.soar_mcp.verify_tls:
            self.soar_mcp.ca_bundle = ""
            return
        candidates: list[str] = []
        if self.soar_mcp.ca_bundle:
            candidates.append(self.soar_mcp.ca_bundle)
        candidates.append(str(_PROJECT_ROOT / "mcp-ca.crt"))

        for raw in candidates:
            if not raw:
                continue
            path = Path(raw)
            if not path.is_absolute():
                path = _PROJECT_ROOT / path
            if path.is_file():
                self.soar_mcp.ca_bundle = str(path.resolve())
                return

        if self.soar_mcp.ca_bundle:
            path = Path(self.soar_mcp.ca_bundle)
            if not path.is_absolute():
                path = _PROJECT_ROOT / path
            self.soar_mcp.ca_bundle = str(path.resolve())

    @classmethod
    def _from_file(cls, path: Path) -> "EngineConfig":
        text = path.read_text(encoding="utf-8")
        if path.suffix.lower() in (".yaml", ".yml"):
            import yaml
            raw = yaml.safe_load(text) or {}
        else:
            raw = json.loads(text)
        return cls._from_dict(raw)

    @classmethod
    def _from_dict(cls, raw: dict[str, Any]) -> "EngineConfig":
        def merge(dc_obj, data: dict[str, Any]):
            for k, v in (data or {}).items():
                if not hasattr(dc_obj, k):
                    continue
                cur = getattr(dc_obj, k)
                if isinstance(v, dict) and hasattr(cur, "__dataclass_fields__"):
                    merge(cur, v)
                else:
                    setattr(dc_obj, k, v)
        cfg = cls()
        merge(cfg, raw)
        return cfg

    def _apply_env_overrides(self) -> None:
        env = os.environ
        if env.get("TRACE_ENGINE_BACKEND"):
            self.backend = env["TRACE_ENGINE_BACKEND"]
        if env.get("TRACE_ENGINE_MCP_ENDPOINT"):
            self.soar_mcp.endpoint = env["TRACE_ENGINE_MCP_ENDPOINT"]
        if env.get("TRACE_ENGINE_API_KEYS"):
            self.service.api_keys = [
                k.strip() for k in env["TRACE_ENGINE_API_KEYS"].split(",") if k.strip()
            ]
        if env.get("TRACE_ENGINE_DB_PATH"):
            self.service.db_path = env["TRACE_ENGINE_DB_PATH"]
        if env.get("TRACE_ENGINE_PORT"):
            self.service.port = int(env["TRACE_ENGINE_PORT"])
        token = env.get("WAZUH_MCP_TOKEN") or env.get("TRACE_ENGINE_MCP_TOKEN")
        if token:
            self.soar_mcp.headers = {
                **self.soar_mcp.headers,
                "Authorization": f"Bearer {token}",
            }
        if env.get("TRACE_ENGINE_WAZUH_AGENTS", "").lower() in ("1", "true", "yes"):
            self.soar_mcp.asset_inventory.wazuh_agents_enabled = True
        if env.get("TRACE_ENGINE_CMDB_URL"):
            self.soar_mcp.asset_inventory.cmdb.enabled = True
            self.soar_mcp.asset_inventory.cmdb.url = env["TRACE_ENGINE_CMDB_URL"]
        if env.get("WAZUH_MCP_CA_BUNDLE"):
            self.soar_mcp.ca_bundle = env["WAZUH_MCP_CA_BUNDLE"]
        if env.get("WAZUH_MCP_VERIFY_TLS", "").lower() in ("0", "false", "no"):
            self.soar_mcp.verify_tls = False
            self.soar_mcp.ca_bundle = ""
        if demo_profile_enabled():
            self.demo_profile.enabled = True
        if env.get("TRACE_ENGINE_DEMO_PLATEAU_ROUNDS"):
            self.demo_profile.plateau_rounds = int(env["TRACE_ENGINE_DEMO_PLATEAU_ROUNDS"])
