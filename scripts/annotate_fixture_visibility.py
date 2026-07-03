#!/usr/bin/env python3
"""One-shot: add expected_log_sources / gap fields to replay fixtures."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trace_agent.prior_v2 import PriorManager  # noqa: E402

FIX = ROOT / "tests" / "replay" / "fixtures"
GAP_OVERRIDES = {
    "gap_no_script_log": {
        "available_log_sources": ["process_creation"],
        "missing_expected_log_sources": ["script_execution"],
    },
    "gap_no_network_telemetry": {
        "available_log_sources": ["process_creation"],
        "missing_expected_log_sources": ["network_connection"],
    },
    "gap_single_edr_gap": {
        "available_log_sources": ["process_creation"],
        "missing_expected_log_sources": ["network_connection", "script_execution"],
    },
    "gap_auth_only": {
        "available_log_sources": ["authentication"],
        "missing_expected_log_sources": ["process_creation"],
    },
    "gap_bash_history_only": {
        "available_log_sources": ["bash_history"],
        "missing_expected_log_sources": ["process_creation"],
    },
    "gap_file_timestamp_only": {
        "available_log_sources": ["file_system"],
        "missing_expected_log_sources": ["process_creation", "network_connection"],
    },
    "gap_web_app_log_only": {
        "available_log_sources": ["web_application_log"],
        "missing_expected_log_sources": ["process_creation"],
    },
    "gap_cloud_trail_sparse": {
        "available_log_sources": ["cloudtrail"],
        "missing_expected_log_sources": ["process_creation"],
    },
}


def main() -> int:
    prior = PriorManager()
    n = 0
    for path in sorted(FIX.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        alert = data.get("alert") or {}
        tech = alert.get("technique_id")
        platform = alert.get("platform")
        if not tech:
            continue
        sources = prior.recommended_log_sources(tech, platform)
        expected = [s["log_source"] for s in sources[:3]]
        if not expected:
            continue
        exp = dict(data.get("expected_behavior") or data.get("expect") or {})
        gap = GAP_OVERRIDES.get(data["case_id"])
        annotation = "manual_gap_design" if gap else "derived_from_prior_recommendation"
        ev = dict(data.get("evaluation") or {})
        ev["visibility_annotation_source"] = annotation
        data["evaluation"] = ev
        exp["visibility_annotation_source"] = annotation

        if not exp.get("expected_log_sources"):
            exp["expected_log_sources"] = expected
            exp["expected_probe_sources"] = expected[:2]
            n += 1
        data["expected_behavior"] = exp
        gap = GAP_OVERRIDES.get(data["case_id"])
        if gap:
            attrs = dict(alert.get("attributes") or {})
            attrs["available_log_sources"] = gap["available_log_sources"]
            alert["attributes"] = attrs
            data["alert"] = alert
            exp = data.setdefault("expected_behavior", {})
            exp["missing_expected_log_sources"] = gap["missing_expected_log_sources"]
            exp.setdefault("expected_log_sources", expected)
            exp.setdefault("expected_probe_sources", expected[:2])
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"annotated fixtures (expected_log_sources added/updated on {n} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
