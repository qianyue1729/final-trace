"""Read-only, versioned decision calibration artifact support."""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .runtime_types import ConfidenceStatus


RUNTIME_FEATURES = (
    "investigation_score",
    "ledger_margin",
    "entropy",
    "risk",
)


def artifact_checksum(payload: Mapping[str, Any]) -> str:
    body = {key: value for key, value in payload.items() if key != "checksum"}
    encoded = json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CalibratedEstimate:
    probability: float | None
    status: ConfidenceStatus
    version: str | None = None
    sample_count: int = 0
    slice_key: str = "global"
    interval: tuple[float, float] | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    reason_codes: tuple[str, ...] = ()


class ArtifactCalibrator:
    """Loads a simple logistic calibrator without mutating its artifact."""

    def __init__(
        self,
        artifact: dict[str, Any] | None = None,
        *,
        status: ConfidenceStatus = ConfidenceStatus.UNAVAILABLE,
        reason_codes: tuple[str, ...] = ("calibrator_missing",),
    ):
        self._artifact = artifact
        self.status = status
        self.reason_codes = reason_codes

    @classmethod
    def load(
        cls,
        path: str | Path | None,
        *,
        max_age_days: int = 90,
        expected_features: tuple[str, ...] = RUNTIME_FEATURES,
        now: datetime | None = None,
    ) -> "ArtifactCalibrator":
        if not path:
            return cls()
        artifact_path = Path(path)
        if not artifact_path.is_file():
            return cls(reason_codes=("calibrator_missing",))
        try:
            artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            return cls(reason_codes=("calibrator_corrupt",))
        if not isinstance(artifact, dict):
            return cls(reason_codes=("calibrator_corrupt",))
        if artifact.get("checksum") != artifact_checksum(artifact):
            return cls(reason_codes=("calibrator_checksum_invalid",))
        if tuple(artifact.get("feature_names") or ()) != expected_features:
            return cls(reason_codes=("calibrator_feature_mismatch",))
        required = (
            "version",
            "training_cutoff",
            "label_source",
            "sample_count",
            "slices",
            "model",
        )
        if any(key not in artifact for key in required):
            return cls(reason_codes=("calibrator_schema_invalid",))
        try:
            cutoff = datetime.fromisoformat(
                str(artifact["training_cutoff"]).replace("Z", "+00:00")
            )
            if cutoff.tzinfo is None:
                cutoff = cutoff.replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            return cls(reason_codes=("calibrator_schema_invalid",))
        current = now or datetime.now(timezone.utc)
        if (current - cutoff).days > max_age_days:
            return cls(
                artifact,
                status=ConfidenceStatus.STALE,
                reason_codes=("calibrator_stale",),
            )
        declared = str(artifact.get("status") or "experimental")
        status = (
            ConfidenceStatus.STABLE
            if declared == ConfidenceStatus.STABLE.value
            else ConfidenceStatus.EXPERIMENTAL
        )
        return cls(artifact, status=status, reason_codes=())

    def calibrate(
        self,
        features: Mapping[str, float],
        *,
        slice_key: str = "global",
    ) -> CalibratedEstimate:
        artifact = self._artifact
        if artifact is None or self.status in (
            ConfidenceStatus.UNAVAILABLE,
            ConfidenceStatus.STALE,
        ):
            return CalibratedEstimate(
                probability=None,
                status=self.status,
                version=(artifact or {}).get("version"),
                slice_key=slice_key,
                reason_codes=self.reason_codes,
            )
        if tuple(features.keys()) != tuple(artifact["feature_names"]):
            return CalibratedEstimate(
                probability=None,
                status=ConfidenceStatus.UNAVAILABLE,
                version=artifact.get("version"),
                slice_key=slice_key,
                reason_codes=("runtime_feature_mismatch",),
            )
        model = artifact.get("model") or {}
        weights = model.get("weights") or {}
        try:
            logit = float(model.get("intercept", 0.0))
            for name in artifact["feature_names"]:
                logit += float(weights[name]) * float(features[name])
        except (KeyError, TypeError, ValueError):
            return CalibratedEstimate(
                probability=None,
                status=ConfidenceStatus.UNAVAILABLE,
                version=artifact.get("version"),
                slice_key=slice_key,
                reason_codes=("calibrator_model_invalid",),
            )
        probability = 1.0 / (1.0 + math.exp(-max(-60.0, min(60.0, logit))))
        slice_meta = (artifact.get("slices") or {}).get(slice_key)
        if not isinstance(slice_meta, dict):
            slice_meta = (artifact.get("slices") or {}).get("global", {})
            slice_key = "global"
        half_width = slice_meta.get("interval_half_width")
        interval = None
        if half_width is not None:
            width = max(0.0, float(half_width))
            interval = (
                max(0.0, probability - width),
                min(1.0, probability + width),
            )
        return CalibratedEstimate(
            probability=probability,
            status=self.status,
            version=str(artifact.get("version")),
            sample_count=int(slice_meta.get("sample_count", 0)),
            slice_key=slice_key,
            interval=interval,
            metrics={
                "precision": slice_meta.get("precision"),
                "recall": slice_meta.get("recall"),
                "ece": slice_meta.get("ece"),
                "training_cutoff": artifact.get("training_cutoff"),
                "label_source": artifact.get("label_source"),
                "artifact_checksum": artifact.get("checksum"),
            },
        )
