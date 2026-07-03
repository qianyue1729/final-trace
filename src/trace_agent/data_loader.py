"""Load prior knowledge JSON products for runtime (L1–L4 + score + loss)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ATTACK_MATRIX_CANDIDATES = ["attack_matrix.json"]
CAUSAL_GRAPH_CANDIDATES = ["causal_graph.json", "tech_causal_graph.json"]
LOG_SOURCE_TRUST_CANDIDATES = ["log_source_trust.json", "log_source_trust.template.json"]
ENV_CONFIG_CANDIDATES = ["env_config.json", "env_config.template.json"]
LIFECYCLE_CANDIDATES = ["lifecycle_templates.json"]
SCORE_WEIGHTS_CANDIDATES = ["score_v3_weights.json"]
LOSS_BASELINE_CANDIDATES = ["loss_baseline.json"]
PRIOR_MANIFEST_CANDIDATES = ["prior_manifest.json", "manifest.json"]

DEFAULT_SCORE_V3_WEIGHTS: dict[str, Any] = {
    "temperature": 2.0,
    "weights": {
        "tactic_fit": 0.18,
        "technique_fit": 0.22,
        "lifecycle_fit": 0.18,
        "environment_fit": 0.12,
        "temporal_fit": 0.12,
        "threat_prevalence": 0.08,
        "boundary_risk": 0.10,
    },
}

DEFAULT_LOSS_BASELINE: dict[str, Any] = {
    "lambda_miss": 10.0,
    "lambda_over": 2.0,
    "lambda_oos": 4.0,
}

DEFAULT_LOG_SOURCE_TRUST: dict[str, Any] = {}
DEFAULT_ENV_CONFIG: dict[str, Any] = {
    "available_log_sources": [],
    "platforms": ["windows", "linux", "macos"],
}
DEFAULT_LIFECYCLE_TEMPLATES: dict[str, Any] = {"templates": []}


class PriorDataLoadError(RuntimeError):
    pass


@dataclass
class PriorDataBundle:
    data_dir: Path
    attack_matrix: dict[str, Any]
    causal_graph: dict[str, Any]
    log_source_trust: dict[str, Any]
    env_config: dict[str, Any]
    lifecycle_templates: dict[str, Any]
    score_v3_weights: dict[str, Any]
    loss_baseline: dict[str, Any]
    prior_manifest: dict[str, Any] | None


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def _search_dirs(data_dir: Path | None) -> list[Path]:
    root = _project_root()
    dirs: list[Path] = []
    if data_dir is not None:
        dirs.append(Path(data_dir))
    dirs.extend(
        [
            root / "src" / "trace_agent" / "data",
            root / "prior_knowledge" / "templates",
            root / "prior_knowledge" / "raw",
            root / "prior_knowledge",
        ]
    )
    seen: set[Path] = set()
    out: list[Path] = []
    for d in dirs:
        r = d.resolve()
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _find_file(candidates: list[str], search_dirs: list[Path], required: bool) -> Path | None:
    for directory in search_dirs:
        for name in candidates:
            path = directory / name
            if path.is_file():
                return path
    if required:
        raise PriorDataLoadError(
            f"Required prior product not found: {candidates[0]}. "
            f"Searched dirs: {[str(d) for d in search_dirs]}. "
            "Run: python prior_knowledge/build/run_all.py --offline"
        )
    return None


def _load_json(path: Path | None, default: dict[str, Any]) -> dict[str, Any]:
    if path is None:
        return dict(default)
    return json.loads(path.read_text(encoding="utf-8"))


def load_prior_bundle(data_dir: str | Path | None = None) -> PriorDataBundle:
    """Load runtime prior products; fail fast if L1/L2 missing."""
    resolved = Path(data_dir).resolve() if data_dir else None
    search = _search_dirs(resolved)

    attack_path = _find_file(ATTACK_MATRIX_CANDIDATES, search, required=True)
    graph_path = _find_file(CAUSAL_GRAPH_CANDIDATES, search, required=True)
    trust_path = _find_file(LOG_SOURCE_TRUST_CANDIDATES, search, required=False)
    env_path = _find_file(ENV_CONFIG_CANDIDATES, search, required=False)
    lifecycle_path = _find_file(LIFECYCLE_CANDIDATES, search, required=False)
    score_path = _find_file(SCORE_WEIGHTS_CANDIDATES, search, required=False)
    loss_path = _find_file(LOSS_BASELINE_CANDIDATES, search, required=False)
    manifest_path = _find_file(PRIOR_MANIFEST_CANDIDATES, search, required=False)

    primary_dir = attack_path.parent if attack_path else (resolved or search[0])

    return PriorDataBundle(
        data_dir=primary_dir,
        attack_matrix=_load_json(attack_path, {}),
        causal_graph=_load_json(graph_path, {}),
        log_source_trust=_load_json(trust_path, DEFAULT_LOG_SOURCE_TRUST),
        env_config=_load_json(env_path, DEFAULT_ENV_CONFIG),
        lifecycle_templates=_load_json(lifecycle_path, DEFAULT_LIFECYCLE_TEMPLATES),
        score_v3_weights=_load_json(score_path, DEFAULT_SCORE_V3_WEIGHTS),
        loss_baseline=_load_json(loss_path, DEFAULT_LOSS_BASELINE),
        prior_manifest=_load_json(manifest_path, {}) if manifest_path else None,
    )
