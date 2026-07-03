"""GenCalibration — RFC-004-02 §9 生成器标定

Per-source reliability tracking and probe cost estimation.
K 拍记录 source 表现，O 拍读成本估计。

职责（§6.1 一致性契约）：
- 标定"这类来源生成的候选历史准不准"
- 提供 cost(probe) 给 VOI: voi = risk_reduction - cost
- 记录决策结果供 Brier/ECE 评估（消费端：eval/calibration.py）
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


# Operator complexity tiers (higher = more expensive)
OPERATOR_COST_TABLE: dict[str, float] = {
    # Cheap queries (automated, fast)
    "process_tree": 0.05,
    "auth_log": 0.05,
    "dns_query": 0.03,
    "file_hash_lookup": 0.02,
    "registry_query": 0.04,
    # Medium queries
    "network_flow": 0.10,
    "lateral_movement_check": 0.12,
    "credential_access_check": 0.10,
    "persistence_scan": 0.08,
    # Expensive queries
    "memory_forensics": 0.25,
    "disk_image_analysis": 0.30,
    "malware_sandbox": 0.35,
    "llm_analysis": 0.50,
}

DEFAULT_OPERATOR_COST: float = 0.10
COST_MODEL_VERSION = "probe-cost-v1"


@dataclass
class CalibrationRecord:
    """Decision outcome record for Brier/ECE calculation."""

    predicted_dist: dict[str, float]  # {outcome: probability}
    actual: str  # actual outcome
    round_num: int = 0


@dataclass
class CostStats:
    samples: int = 0
    latency_ms: float = 0.0
    query_count: int = 0
    records_scanned: int = 0
    provider_cost: float = 0.0
    failures: int = 0


class GenCalibration:
    """Per-source generator calibration + probe cost estimation.

    Maintains:
    - Per-source hit/total counters with ε-floor smoothing
    - Operator complexity cost table
    - Decision outcome records for calibration evaluation
    """

    def __init__(
        self,
        eps_floor: float = 0.05,
        *,
        tenant_id: str = "global",
        schema_version: str = "v1",
        min_cost_samples: int = 10,
    ):
        """
        Args:
            eps_floor: Minimum reliability floor (prevents zero-cost exploitation)
        """
        self._eps_floor = eps_floor
        self._source_stats: dict[str, tuple[int, int]] = {}  # source → (hits, total)
        self._decision_records: list[CalibrationRecord] = []
        self._cost_stats: dict[str, CostStats] = {}
        self._round: int = 0
        self.tenant_id = tenant_id
        self.schema_version = schema_version
        self.min_cost_samples = min_cost_samples

    def record(self, source: str, hit: bool) -> None:
        """K 拍记录生成器表现.

        Args:
            source: Generator source name (e.g., "prior", "rule_gap", "obligation")
            hit: Whether the generated probe yielded attributable evidence
        """
        hits, total = self._source_stats.get(source, (0, 0))
        self._source_stats[source] = (hits + int(hit), total + 1)

    def reliability(self, source: str) -> float:
        """该 source 历史命中率 (with ε-floor smoothing).

        Returns max(hits/total, eps_floor) for seen sources.
        Returns eps_floor for unseen sources.
        """
        if source not in self._source_stats:
            return self._eps_floor
        hits, total = self._source_stats[source]
        if total == 0:
            return self._eps_floor
        return max(hits / total, self._eps_floor)

    def cost(self, probe: Any) -> float:
        """Bounded measured cost with shrinkage to an operator global prior."""
        operator = (
            str(probe.get("operator", ""))
            if isinstance(probe, dict)
            else str(getattr(probe, "operator", ""))
        )
        target_type = (
            str(probe.get("target_type", ""))
            if isinstance(probe, dict)
            else str(getattr(probe, "target_type", ""))
        )
        base_cost = OPERATOR_COST_TABLE.get(operator, DEFAULT_OPERATOR_COST)
        stats = self._cost_stats.get(self._cost_key(operator, target_type))
        if stats is None or stats.samples <= 0:
            return base_cost
        observed = (
            stats.latency_ms / max(stats.samples, 1) / 60_000 * 0.05
            + stats.query_count / max(stats.samples, 1) * 0.01
            + stats.records_scanned / max(stats.samples, 1) / 10_000 * 0.02
            + stats.provider_cost / max(stats.samples, 1)
            + stats.failures / max(stats.samples, 1) * 0.10
        )
        prior_weight = max(0, self.min_cost_samples - stats.samples)
        shrunk = (
            base_cost * prior_weight + observed * stats.samples
        ) / max(prior_weight + stats.samples, 1)
        return max(0.005, min(2.0, shrunk))

    @staticmethod
    def _cost_key(operator: str, target_type: str) -> str:
        return f"{operator.strip().lower()}|{target_type.strip().lower()}"

    def record_probe_cost(
        self,
        probe: Any,
        *,
        latency_ms: float = 0.0,
        query_count: int = 0,
        records_scanned: int = 0,
        provider_cost: float = 0.0,
        failed: bool = False,
    ) -> None:
        operator = (
            str(probe.get("operator", ""))
            if isinstance(probe, dict)
            else str(getattr(probe, "operator", ""))
        )
        target_type = (
            str(probe.get("target_type", ""))
            if isinstance(probe, dict)
            else str(getattr(probe, "target_type", ""))
        )
        key = self._cost_key(operator, target_type)
        stats = self._cost_stats.setdefault(key, CostStats())
        stats.samples += 1
        stats.latency_ms += max(0.0, float(latency_ms))
        stats.query_count += max(0, int(query_count))
        stats.records_scanned += max(0, int(records_scanned))
        stats.provider_cost += max(0.0, float(provider_cost))
        stats.failures += int(failed)

    def record_decision_outcome(self, predicted_dist: dict, actual: str) -> None:
        """决策校准记录.

        Used by eval/calibration.py for Brier score and ECE computation.

        Args:
            predicted_dist: Predicted probability distribution {outcome: prob}
            actual: The actual observed outcome
        """
        self._decision_records.append(
            CalibrationRecord(
                predicted_dist=dict(predicted_dist),
                actual=actual,
                round_num=self._round,
            )
        )

    def advance_round(self) -> None:
        """Advance internal round counter."""
        self._round += 1

    def get_records(self) -> list[CalibrationRecord]:
        """Get all decision outcome records (for eval consumption)."""
        return list(self._decision_records)

    def source_stats(self) -> dict[str, dict]:
        """Get all source statistics. Returns {source: {hits, total, reliability}}"""
        result: dict[str, dict] = {}
        for source, (hits, total) in self._source_stats.items():
            result[source] = {
                "hits": hits,
                "total": total,
                "reliability": self.reliability(source),
            }
        return result

    def to_dict(self) -> dict:
        """Serialize for persistence."""
        return {
            "cost_model_version": COST_MODEL_VERSION,
            "tenant_id": self.tenant_id,
            "schema_version": self.schema_version,
            "min_cost_samples": self.min_cost_samples,
            "eps_floor": self._eps_floor,
            "source_stats": {
                src: {"hits": h, "total": t}
                for src, (h, t) in self._source_stats.items()
            },
            "decision_records": [
                {
                    "predicted_dist": r.predicted_dist,
                    "actual": r.actual,
                    "round_num": r.round_num,
                }
                for r in self._decision_records
            ],
            "round": self._round,
            "cost_stats": {
                key: {
                    "samples": stats.samples,
                    "latency_ms": stats.latency_ms,
                    "query_count": stats.query_count,
                    "records_scanned": stats.records_scanned,
                    "provider_cost": stats.provider_cost,
                    "failures": stats.failures,
                }
                for key, stats in self._cost_stats.items()
            },
        }

    @classmethod
    def from_dict(
        cls,
        data: dict,
        *,
        expected_tenant_id: Optional[str] = None,
        expected_schema_version: Optional[str] = None,
    ) -> "GenCalibration":
        """Restore from serialized."""
        tenant_id = data.get("tenant_id", "global")
        schema_version = data.get("schema_version", "v1")
        if (
            (expected_tenant_id is not None and tenant_id != expected_tenant_id)
            or (
                expected_schema_version is not None
                and schema_version != expected_schema_version
            )
            or data.get("cost_model_version", COST_MODEL_VERSION)
            != COST_MODEL_VERSION
        ):
            return cls(
                tenant_id=expected_tenant_id or tenant_id,
                schema_version=expected_schema_version or schema_version,
            )
        obj = cls(
            eps_floor=data.get("eps_floor", 0.05),
            tenant_id=tenant_id,
            schema_version=schema_version,
            min_cost_samples=data.get("min_cost_samples", 10),
        )
        for src, stats in data.get("source_stats", {}).items():
            obj._source_stats[src] = (stats["hits"], stats["total"])
        for rec in data.get("decision_records", []):
            obj._decision_records.append(
                CalibrationRecord(
                    predicted_dist=rec["predicted_dist"],
                    actual=rec["actual"],
                    round_num=rec.get("round_num", 0),
                )
            )
        obj._round = data.get("round", 0)
        for key, stats in data.get("cost_stats", {}).items():
            obj._cost_stats[key] = CostStats(**stats)
        return obj
