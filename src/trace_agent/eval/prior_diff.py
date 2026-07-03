"""Snapshot prior products and report drift between builds."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "src" / "trace_agent" / "data"
SNAPSHOT = ROOT / "reports" / "prior_snapshot.json"
THRESHOLD = 0.15


def _l1_stats(matrix: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for curr, row in (matrix.get("matrix") or {}).items():
        for prev, val in row.items():
            if isinstance(val, dict):
                out[f"{curr}|{prev}"] = float(val.get("probability", 0))
    return out


def _l2_stats(graph: dict) -> dict[str, float]:
    out: dict[str, float] = {}
    for e in graph.get("edges") or []:
        key = f"{e.get('src')}|{e.get('dst')}"
        out[key] = float(e.get("probability", 0))
    return out


def current_fingerprint() -> dict[str, Any]:
    am = json.loads((DATA / "attack_matrix.json").read_text(encoding="utf-8"))
    cg = json.loads((DATA / "causal_graph.json").read_text(encoding="utf-8"))
    return {
        "l1_pairs": len(_l1_stats(am)),
        "l2_edges": len(_l2_stats(cg)),
        "flow_stats": am.get("metadata", {}).get("flow_stats"),
        "l1_probs": _l1_stats(am),
        "l2_probs": _l2_stats(cg),
    }


def diff_reports(old: dict, new: dict) -> dict[str, Any]:
    shifts: list[dict] = []
    for layer, key in (("L1", "l1_probs"), ("L2", "l2_probs")):
        o, n = old.get(key, {}), new.get(key, {})
        for k in set(o) | set(n):
            delta = n.get(k, 0) - o.get(k, 0)
            if abs(delta) >= THRESHOLD:
                shifts.append({"layer": layer, "edge": k, "delta": round(delta, 4)})
    shifts.sort(key=lambda x: abs(x["delta"]), reverse=True)
    return {
        "l1_pair_delta": new.get("l1_pairs", 0) - old.get("l1_pairs", 0),
        "l2_edge_delta": new.get("l2_edges", 0) - old.get("l2_edges", 0),
        "probability_shift_top10": shifts[:10],
        "high_risk_changes": [s for s in shifts if abs(s["delta"]) >= THRESHOLD],
        "needs_review": len(shifts) > 0,
    }


def run_diff(write_snapshot: bool = False) -> dict[str, Any]:
    new = current_fingerprint()
    if not SNAPSHOT.is_file():
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(new, indent=2), encoding="utf-8")
        return {"status": "baseline_created", "snapshot": str(SNAPSHOT), "fingerprint": new}
    old = json.loads(SNAPSHOT.read_text(encoding="utf-8"))
    report = diff_reports(old, new)
    if write_snapshot:
        SNAPSHOT.write_text(json.dumps(new, indent=2), encoding="utf-8")
    return report


def report_markdown(report: dict[str, Any]) -> str:
    if report.get("status") == "baseline_created":
        return "# Prior Diff Report\n\nBaseline snapshot created.\n"
    lines = ["# Prior Diff Report", "", f"**Needs review:** {report.get('needs_review')}", ""]
    for s in report.get("probability_shift_top10", []):
        lines.append(f"- {s['layer']} `{s['edge']}` Δ={s['delta']}")
    return "\n".join(lines) + "\n"
