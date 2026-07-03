"""PriorManager — runtime query API over L1–L4 prior products."""
from __future__ import annotations

from typing import Any, Literal

from .data_loader import (
    DEFAULT_SCORE_V3_WEIGHTS,
    PriorDataBundle,
    load_prior_bundle,
)

Direction = Literal["incoming", "outgoing", "both"]

TACTIC_SHORT_TO_ID: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}

TACTIC_ID_TO_SHORT: dict[str, str] = {v: k for k, v in TACTIC_SHORT_TO_ID.items()}

DEFAULT_BOUNDARY_PRIOR = {"p_in_attack": 0.34, "p_benign": 0.33, "p_oos": 0.33}

# Map env_config display names → canonical log source keys
ENV_LOG_ALIASES: dict[str, list[str]] = {
    "sysmon": ["process_creation", "network_connection", "dns_query", "registry", "module_load"],
    "windows security": ["authentication", "windows_event_log_security"],
    "windows powershell": ["script_execution", "windows_event_log_powershell"],
    "microsoft-windows-dns-client": ["dns_query"],
    "auditd": ["auditd", "process_creation"],
    "syslog": ["syslog"],
    "auth.log": ["authentication", "syslog"],
    "osquery": ["process_creation"],
    "cloudtrail": ["cloud_api_call"],
}

TRUST_KEY_FOR_CANONICAL: dict[str, str] = {
    "process_creation": "sysmon",
    "script_execution": "windows_event_log_powershell",
    "network_connection": "edr_kernel_process_event",
    "dns_query": "sysmon",
    "file_system": "edr_kernel_process_event",
    "registry": "sysmon",
    "module_load": "sysmon",
    "auditd": "auditd",
    "syslog": "syslog",
    "authentication": "windows_event_log_security",
}

_manager: "PriorManager | None" = None


def reset_prior_manager() -> None:
    global _manager
    _manager = None


def get_prior_manager(bundle: PriorDataBundle | None = None) -> "PriorManager":
    global _manager
    if bundle is not None:
        return PriorManager(bundle)
    if _manager is None:
        _manager = PriorManager()
    return _manager


class PriorManager:
    def __init__(self, bundle: PriorDataBundle | None = None):
        self.bundle = bundle or load_prior_bundle()
        self._nodes = self._extract_nodes(self.bundle.causal_graph)
        self._edges = self._extract_edges(self.bundle.causal_graph)
        self._incoming_edges, self._outgoing_edges = self._index_edges(self._edges)
        self._source_weights = self.bundle.attack_matrix.get("metadata", {}).get("source_weights", {})

    @staticmethod
    def _extract_nodes(graph: dict[str, Any]) -> dict[str, dict[str, Any]]:
        raw = graph.get("nodes") or graph.get("techniques") or {}
        if isinstance(raw, list):
            return {n["id"]: n for n in raw if isinstance(n, dict) and n.get("id")}
        return dict(raw)

    @staticmethod
    def _extract_edges(graph: dict[str, Any]) -> list[dict[str, Any]]:
        edges = graph.get("edges") or graph.get("links") or []
        return list(edges) if isinstance(edges, list) else []

    @staticmethod
    def _index_edges(edges: list[dict[str, Any]]) -> tuple[dict[str, list], dict[str, list]]:
        incoming: dict[str, list] = {}
        outgoing: dict[str, list] = {}
        for e in edges:
            src, dst = e.get("src"), e.get("dst")
            if not src or not dst:
                continue
            outgoing.setdefault(src, []).append(e)
            incoming.setdefault(dst, []).append(e)
        return incoming, outgoing

    def resolve_tactic_id(self, tactic: str | None) -> str | None:
        if not tactic:
            return None
        if tactic.startswith("TA") and tactic in TACTIC_ID_TO_SHORT:
            return tactic
        return TACTIC_SHORT_TO_ID.get(tactic.lower().replace("_", "-"))

    def _iter_l1_rows(self) -> list[dict[str, Any]]:
        matrix = self.bundle.attack_matrix.get("matrix")
        if isinstance(matrix, dict):
            rows: list[dict[str, Any]] = []
            for current_id, predecessors in matrix.items():
                if not isinstance(predecessors, dict):
                    continue
                for prev_id, val in predecessors.items():
                    if isinstance(val, dict):
                        prob = float(val.get("probability", 0))
                        support = val.get("support") or {}
                    else:
                        prob = float(val)
                        support = {}
                    rows.append(
                        {
                            "current_tactic": current_id,
                            "current_tactic_short": TACTIC_ID_TO_SHORT.get(current_id, current_id),
                            "prev_tactic": prev_id,
                            "prev_tactic_short": TACTIC_ID_TO_SHORT.get(prev_id, prev_id),
                            "probability": prob,
                            "support": support,
                            "confidence": val.get("confidence") if isinstance(val, dict) else None,
                        }
                    )
            return rows
        for key in ("rows", "transitions"):
            items = self.bundle.attack_matrix.get(key)
            if isinstance(items, list):
                return list(items)
        return []

    def predecessor_tactics(
        self,
        current_tactic: str | None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        current_id = self.resolve_tactic_id(current_tactic)
        if not current_id:
            node_tactic = None
        else:
            node_tactic = current_id

        rows = []
        for row in self._iter_l1_rows():
            if node_tactic and row["current_tactic"] != node_tactic:
                continue
            support = row.get("support") or {}
            rows.append(
                {
                    "prev_tactic": row["prev_tactic_short"],
                    "prev_tactic_id": row["prev_tactic"],
                    "current_tactic": row["current_tactic_short"],
                    "current_tactic_id": row["current_tactic"],
                    "probability": row["probability"],
                    "support": support,
                    "source_weights": self._source_weights,
                    "confidence": row.get("confidence"),
                }
            )
        rows.sort(key=lambda r: r["probability"], reverse=True)
        return rows[:top_k]

    def technique_node(self, technique_id: str) -> dict[str, Any] | None:
        node = self._nodes.get(technique_id)
        if node:
            return dict(node)
        base = technique_id.split(".")[0]
        return dict(self._nodes[base]) if base in self._nodes else None

    def _platform_match(self, node: dict[str, Any] | None, platform: str | None) -> bool:
        if not platform or not node:
            return True
        plats = [p.lower() for p in node.get("platforms") or []]
        p = platform.lower()
        if p in plats:
            return True
        if p == "windows" and any("windows" in x for x in plats):
            return True
        if p == "linux" and any("linux" in x for x in plats):
            return True
        return not plats

    def _edge_rank(self, edge: dict[str, Any], direction: str) -> float:
        prob = float(edge.get("probability") or 0)
        conf = float(edge.get("confidence") or 0)
        support = edge.get("support") or {}
        flow = 1.0 if support.get("attack_flow", 0) > 0 else 0.0
        bp = edge.get("boundary_prior") or {}
        has_bp = 1.0 if bp else 0.0
        return 0.45 * prob + 0.30 * conf + 0.15 * flow + 0.10 * has_bp

    def technique_neighbors(
        self,
        technique_id: str,
        direction: Direction = "both",
        top_k: int = 10,
        platform: str | None = None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []

        def add_edge(edge: dict[str, Any], dir_label: str) -> None:
            other_id = edge["dst"] if dir_label == "outgoing" else edge["src"]
            other_node = self.technique_node(other_id)
            if not self._platform_match(other_node, platform):
                return
            results.append(
                {
                    **edge,
                    "direction": dir_label,
                    "src_node": self.technique_node(edge["src"]),
                    "dst_node": self.technique_node(edge["dst"]),
                    "_rank": self._edge_rank(edge, dir_label),
                }
            )

        if direction in ("outgoing", "both"):
            for e in self._outgoing_edges.get(technique_id, []):
                add_edge(e, "outgoing")
        if direction in ("incoming", "both"):
            for e in self._incoming_edges.get(technique_id, []):
                add_edge(e, "incoming")

        results.sort(key=lambda x: x["_rank"], reverse=True)
        for r in results:
            r.pop("_rank", None)
        return results[:top_k]

    def boundary_prior_for_edge(self, src: str, dst: str) -> dict[str, float]:
        for e in self._edges:
            if e.get("src") == src and e.get("dst") == dst:
                bp = e.get("boundary_prior")
                if bp:
                    return {
                        "p_in_attack": float(bp.get("p_in_attack", 0.34)),
                        "p_benign": float(bp.get("p_benign", 0.33)),
                        "p_oos": float(bp.get("p_oos", 0.33)),
                    }
        return dict(DEFAULT_BOUNDARY_PRIOR)

    def _env_available_canonical(self) -> set[str]:
        available: set[str] = set()
        raw_sources = self.bundle.env_config.get("available_log_sources") or []
        for src in raw_sources:
            key = str(src).lower()
            available.add(key)
            for alias in ENV_LOG_ALIASES.get(key, []):
                available.add(alias.lower())
        return available

    def recommended_log_sources(
        self,
        technique_id: str,
        platform: str | None = None,
    ) -> list[dict[str, Any]]:
        node = self.technique_node(technique_id) or {}
        candidates = set(node.get("log_sources") or [])
        if node.get("sigma_rules"):
            candidates.update(node.get("log_sources") or [])

        env_avail = self._env_available_canonical()
        trust_reg = {
            k: v
            for k, v in self.bundle.log_source_trust.items()
            if not str(k).startswith("_") and isinstance(v, dict)
        }
        sigma_map = (self.bundle.log_source_trust.get("_sigma_mapping") or {}).get(
            "trust_registry_coverage", {}
        )

        out: list[dict[str, Any]] = []
        for canonical in sorted(candidates):
            trust_key = TRUST_KEY_FOR_CANONICAL.get(canonical, canonical)
            entry = trust_reg.get(trust_key, {})
            integrity = float(entry.get("integrity", 0.5))
            tier = entry.get("tier", "medium")
            hard_veto = bool(entry.get("hard_veto_allowed", False))
            sigma_count = int(sigma_map.get(trust_key, 0) or entry.get("sigma_technique_coverage", 0))

            available = (
                canonical.lower() in env_avail
                or trust_key.lower() in env_avail
                or any(a in env_avail for a in ENV_LOG_ALIASES.get(canonical, []))
            )

            out.append(
                {
                    "log_source": canonical,
                    "available": available,
                    "trust": integrity,
                    "tier": tier,
                    "hard_veto_allowed": hard_veto,
                    "source": "sigma" if node.get("sigma_rules") else "node",
                    "sigma_rule_count": sigma_count if node.get("sigma_rules") else len(node.get("sigma_rules") or []),
                }
            )

        out.sort(key=lambda x: (x["available"], x["trust"], x.get("sigma_rule_count", 0)), reverse=True)
        return out

    def _technique_matches(self, technique_id: str, pattern: str) -> bool:
        if technique_id == pattern:
            return True
        if "." not in pattern and technique_id.startswith(pattern + "."):
            return True
        return False

    def lifecycle_candidates(
        self,
        technique_id: str,
        tactic: str | None = None,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        tactic_short = None
        tactic_id = self.resolve_tactic_id(tactic)
        if tactic_id:
            tactic_short = TACTIC_ID_TO_SHORT.get(tactic_id)
        elif tactic:
            tactic_short = tactic.lower().replace("_", "-")

        matches: list[dict[str, Any]] = []
        templates = self.bundle.lifecycle_templates.get("templates") or []
        for tmpl in templates:
            if not isinstance(tmpl, dict):
                continue
            for stage in tmpl.get("stages") or []:
                if not isinstance(stage, dict):
                    continue
                score = 0.0
                reason = ""
                exp_techs = stage.get("expected_techniques") or []
                exp_tactics = stage.get("expected_tactics") or []
                for pat in exp_techs:
                    if self._technique_matches(technique_id, pat):
                        score = max(score, 0.9)
                        reason = "technique_id matched expected_techniques"
                        break
                if score < 0.9 and tactic_short and tactic_short in exp_tactics:
                    score = max(score, 0.6)
                    reason = reason or "tactic matched expected_tactics"
                if score <= 0:
                    continue
                matches.append(
                    {
                        "template_id": tmpl.get("template_id"),
                        "family": tmpl.get("family"),
                        "matched_stage": stage.get("stage"),
                        "match_reason": reason,
                        "required": stage.get("required"),
                        "debt_policy": stage.get("debt_policy"),
                        "score": score,
                    }
                )
        matches.sort(key=lambda m: m["score"], reverse=True)
        dedup: dict[str, dict] = {}
        for m in matches:
            key = f"{m['template_id']}:{m['matched_stage']}"
            if key not in dedup or m["score"] > dedup[key]["score"]:
                dedup[key] = m
        return list(dedup.values())[:top_k]

    def score_weights(self) -> dict[str, float]:
        w = self.bundle.score_v3_weights.get("weights") or DEFAULT_SCORE_V3_WEIGHTS["weights"]
        return {k: float(v) for k, v in w.items()}

    def score_temperature(self) -> float:
        return float(self.bundle.score_v3_weights.get("temperature", 2.0))

    def loss_baseline(self) -> dict[str, float]:
        lb = self.bundle.loss_baseline
        return {
            "LAMBDA_MISS": float(lb.get("LAMBDA_MISS", lb.get("lambda_miss", 10.0))),
            "LAMBDA_OVER": float(lb.get("LAMBDA_OVER", lb.get("lambda_over", 2.0))),
            "LAMBDA_OOS": float(lb.get("LAMBDA_OOS", lb.get("lambda_oos", 4.0))),
        }

    def manifest(self) -> dict[str, Any] | None:
        return self.bundle.prior_manifest

    def evidence_trust_defaults(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, val in self.bundle.log_source_trust.items():
            if str(key).startswith("_") or not isinstance(val, dict):
                continue
            out[key] = {
                "integrity": val.get("integrity"),
                "tier": val.get("tier"),
                "hard_veto_allowed": val.get("hard_veto_allowed"),
                "platforms": val.get("platforms"),
            }
        return out
