from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from trace_agent.decision.calibrator import (
    RUNTIME_FEATURES,
    ArtifactCalibrator,
    artifact_checksum,
)
from trace_agent.decision.runtime_types import (
    ConfidenceStatus,
    DecisionConfidence,
)


def _artifact(*, cutoff="2026-07-01T00:00:00Z", features=RUNTIME_FEATURES):
    artifact = {
        "version": "decision-cal-v1",
        "status": "stable",
        "training_cutoff": cutoff,
        "label_source": "independent_analyst_verdicts",
        "sample_count": 120,
        "feature_names": list(features),
        "slices": {
            "global": {
                "sample_count": 120,
                "precision": 0.95,
                "recall": 0.91,
                "ece": 0.03,
                "interval_half_width": 0.05,
            }
        },
        "model": {
            "intercept": 0.0,
            "weights": {name: 1.0 for name in features},
        },
    }
    artifact["checksum"] = artifact_checksum(artifact)
    return artifact


def _write(tmp_path, artifact):
    path = tmp_path / "calibrator.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    return path


def _features():
    return dict(zip(RUNTIME_FEATURES, (0.8, 0.4, 0.2, 0.1)))


def test_valid_artifact_returns_versioned_probability(tmp_path):
    calibrator = ArtifactCalibrator.load(
        _write(tmp_path, _artifact()),
        now=datetime(2026, 7, 3, tzinfo=timezone.utc),
    )
    estimate = calibrator.calibrate(_features())
    assert estimate.status == ConfidenceStatus.STABLE
    assert 0.0 < estimate.probability < 1.0
    assert estimate.version == "decision-cal-v1"
    assert estimate.sample_count == 120
    assert estimate.interval is not None
    assert estimate.metrics["label_source"] == "independent_analyst_verdicts"


@pytest.mark.parametrize(
    ("kind", "reason"),
    [
        ("missing", "calibrator_missing"),
        ("corrupt", "calibrator_corrupt"),
        ("checksum", "calibrator_checksum_invalid"),
        ("features", "calibrator_feature_mismatch"),
    ],
)
def test_invalid_artifacts_fail_closed(tmp_path, kind, reason):
    path = tmp_path / "calibrator.json"
    if kind == "corrupt":
        path.write_text("{", encoding="utf-8")
    elif kind == "checksum":
        artifact = _artifact()
        artifact["checksum"] = "wrong"
        path = _write(tmp_path, artifact)
    elif kind == "features":
        path = _write(tmp_path, _artifact(features=("unexpected",)))
    estimate = ArtifactCalibrator.load(
        None if kind == "missing" else path,
        now=datetime(2026, 7, 3, tzinfo=timezone.utc),
    ).calibrate(_features())
    assert estimate.status == ConfidenceStatus.UNAVAILABLE
    assert estimate.probability is None
    assert reason in estimate.reason_codes


def test_stale_artifact_has_no_probability(tmp_path):
    calibrator = ArtifactCalibrator.load(
        _write(tmp_path, _artifact(cutoff="2025-01-01T00:00:00Z")),
        max_age_days=90,
        now=datetime(2026, 7, 3, tzinfo=timezone.utc),
    )
    estimate = calibrator.calibrate(_features())
    assert estimate.status == ConfidenceStatus.STALE
    assert estimate.probability is None
    assert "calibrator_stale" in estimate.reason_codes


def test_unavailable_contract_rejects_numeric_probability():
    with pytest.raises(ValueError):
        DecisionConfidence(
            investigation_score=0.4,
            calibrated_probability=0.8,
            confidence_status=ConfidenceStatus.UNAVAILABLE,
        )
