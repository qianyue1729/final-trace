"""Prior Knowledge Factory for Decision-Ledger LOCK.

Build pipeline (L1-L4 + trust + loss) + DecisionLedger seed.
See README.md for the full architecture.
Build scripts live in ``prior_knowledge/build/``;
runtime consumers remain in ``src/trace_agent/prior_v2.py`` and ``decision/belief.py``.
"""
from __future__ import annotations

from .paths import (
    ATTACK_MATRIX_PATH,
    DATA_DIR,
    DEFAULT_STIX_PATH,
    ENV_CONFIG_TEMPLATE_PATH,
    LIFECYCLE_TEMPLATES_PATH,
    LIFECYCLE_TEMPLATES_TEMPLATE_PATH,
    LOG_SOURCE_TRUST_PATH,
    LOG_SOURCE_TRUST_TEMPLATE_PATH,
    LOSS_BASELINE_PATH,
    MANIFEST_PATH,
    PROJECT_ROOT,
    SCORE_V3_WEIGHTS_PATH,
    TECH_CAUSAL_GRAPH_PATH,
)

__all__ = [
    "ATTACK_MATRIX_PATH",
    "DATA_DIR",
    "DEFAULT_STIX_PATH",
    "ENV_CONFIG_TEMPLATE_PATH",
    "LIFECYCLE_TEMPLATES_PATH",
    "LIFECYCLE_TEMPLATES_TEMPLATE_PATH",
    "LOG_SOURCE_TRUST_PATH",
    "LOG_SOURCE_TRUST_TEMPLATE_PATH",
    "LOSS_BASELINE_PATH",
    "MANIFEST_PATH",
    "PROJECT_ROOT",
    "SCORE_V3_WEIGHTS_PATH",
    "TECH_CAUSAL_GRAPH_PATH",
]
