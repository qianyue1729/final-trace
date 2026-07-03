"""Canonical paths for prior knowledge artifacts (L1-L4 + trust + loss + weights)."""
from __future__ import annotations

from pathlib import Path

# trace_agent/prior_knowledge/
PKG_ROOT = Path(__file__).resolve().parent

# trace_agent/
PROJECT_ROOT = PKG_ROOT.parent

# Runtime-loaded JSON (PriorManager default)
DATA_DIR = PROJECT_ROOT / "src" / "trace_agent" / "data"

# --- L1: Tactic Transition Matrix ---
ATTACK_MATRIX_PATH = DATA_DIR / "attack_matrix.json"

# --- L2: Technique Causal Graph (with BoundaryBelief priors) ---
TECH_CAUSAL_GRAPH_PATH = DATA_DIR / "tech_causal_graph.json"

# --- L3: Environment Config + Evidence Trust ---
ENV_CONFIG_TEMPLATE_PATH = PKG_ROOT / "templates" / "env_config.template.json"
LOG_SOURCE_TRUST_TEMPLATE_PATH = PKG_ROOT / "templates" / "log_source_trust.template.json"
LOG_SOURCE_TRUST_PATH = DATA_DIR / "log_source_trust.json"

# --- L4: Lifecycle Templates ---
LIFECYCLE_TEMPLATES_TEMPLATE_PATH = PKG_ROOT / "templates" / "lifecycle_templates.json"
LIFECYCLE_TEMPLATES_PATH = DATA_DIR / "lifecycle_templates.json"

# --- score_v3 weights ---
SCORE_V3_WEIGHTS_PATH = PKG_ROOT / "templates" / "score_v3_weights.json"

# --- Loss baseline ---
LOSS_BASELINE_PATH = PKG_ROOT / "templates" / "loss_baseline.json"

# --- Prior bundle manifest ---
MANIFEST_PATH = DATA_DIR / "prior_manifest.json"

# --- Optional STIX input for L1 rebuild ---
DEFAULT_STIX_PATH = PROJECT_ROOT / "enterprise-attack.json"

# --- Raw open-source layer (authoritative input) ---
RAW_DIR = PKG_ROOT / "raw"
RAW_SOURCES_PATH = RAW_DIR / "sources.json"
RAW_MANIFEST_PATH = RAW_DIR / "manifest.json"
RAW_STIX_PATH = RAW_DIR / "mitre" / "enterprise-attack.json"
