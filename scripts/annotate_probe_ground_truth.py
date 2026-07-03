#!/usr/bin/env python3
"""Add probe_ground_truth blocks to replay fixtures (P3 schema pass)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from trace_agent.eval.probe_metrics import DEFAULT_MUST_NOT, DEFAULT_PROBE_COSTS  # noqa: E402

FIX = ROOT / "tests" / "replay" / "fixtures"

OUTCOME_HINTS = {
    "process_creation": "confirm_parent_lineage",
    "script_execution": "confirm_script_content",
    "network_connection": "confirm_payload_download_or_c2",
    "dns_query": "confirm_c2_domain",
    "authentication": "confirm_logon_context",
}


def main() -> int:
    n = 0
    for path in sorted(FIX.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        exp = dict(data.get("expected_behavior") or data.get("expect") or {})
        expected = exp.get("expected_probe_sources") or exp.get("expected_log_sources") or []
        if not expected:
            continue
        expected = expected[:3]
        vis_ann = (data.get("evaluation") or {}).get("visibility_annotation_source") or exp.get(
            "visibility_annotation_source", "derived_from_prior_recommendation"
        )
        annotation = (
            "manual_expected"
            if vis_ann == "manual_gap_design"
            else "derived_from_visibility_expectation"
        )
        outcomes = {src: OUTCOME_HINTS.get(src, "confirm_or_refute") for src in expected[:2]}
        data["probe_ground_truth"] = {
            "expected_probe_sources": expected,
            "must_not_probe": list(DEFAULT_MUST_NOT),
            "probe_cost_profile": {k: DEFAULT_PROBE_COSTS[k] for k in expected if k in DEFAULT_PROBE_COSTS},
            "expected_probe_outcome": outcomes,
            "label_quality": data.get("label_quality", "synthetic"),
            "annotation_source": annotation,
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        n += 1
    print(f"probe_ground_truth added/updated on {n} fixtures")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
