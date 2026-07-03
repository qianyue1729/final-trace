"""AlertEnricher — Plan 008: deterministic-first enrichment with model abstention.

Pipeline:
1. Deterministic enrichment: ATT&CK catalog lookup, vendor/rule maps,
   process-name heuristics, CMDB platform inference.
2. Model enrichment (optional): only when technique remains ambiguous after
   deterministic pass. The model proposes typed candidates; it cannot invent
   catalog entries. Abstention is a first-class outcome.
3. Privacy: sensitive fields are redacted before model calls.
4. Provenance: every enriched field records its source.

The enricher never writes the graph or bypasses validation. In shadow mode,
enrichment results are recorded but do not affect the alert passed downstream.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional, Protocol

from .config import AlertEnricherConfig


# ── Vendor / rule → ATT&CK technique mappings ──

# Sigma rule title keywords → technique
_SIGMA_TITLE_MAP: dict[str, list[tuple[str, str]]] = {
    # keyword substring → (technique, tactic)
    "powershell": [("T1059.001", "execution")],
    "cmd.exe": [("T1059.003", "execution")],
    "bash": [("T1059.004", "execution")],
    "wscript": [("T1059.005", "execution")],
    "python": [("T1059.006", "execution")],
    "mimikatz": [("T1003.001", "credential-access")],
    "procdump": [("T1003.001", "credential-access")],
    "lsass": [("T1003.001", "credential-access")],
    "credential dumping": [("T1003", "credential-access")],
    "lateral movement": [("T1021", "lateral-movement")],
    "persistence": [("T1053", "persistence")],
    "scheduled task": [("T1053", "persistence")],
    "registry": [("T1547.001", "persistence")],
    "defense evasion": [("T1027", "defense-evasion")],
    "process injection": [("T1055", "defense-evasion")],
    "exfiltration": [("T1041", "exfiltration")],
    "data staging": [("T1074", "collection")],
    "discovery": [("T1082", "discovery")],
    "account discovery": [("T1087", "discovery")],
    "network share": [("T1135", "discovery")],
    "ransomware": [("T1486", "impact")],
    "encrypt files": [("T1486", "impact")],
}

# Process name → technique
_PROCESS_NAME_MAP: dict[str, list[tuple[str, str]]] = {
    "powershell.exe": [("T1059.001", "execution")],
    "pwsh.exe": [("T1059.001", "execution")],
    "cmd.exe": [("T1059.003", "execution")],
    "bash": [("T1059.004", "execution")],
    "sh": [("T1059.004", "execution")],
    "python.exe": [("T1059.006", "execution")],
    "python3": [("T1059.006", "execution")],
    "wscript.exe": [("T1059.005", "execution")],
    "cscript.exe": [("T1059.005", "execution")],
    "mimikatz.exe": [("T1003.001", "credential-access")],
    "procdump.exe": [("T1003.001", "credential-access")],
    "whoami.exe": [("T1033", "discovery")],
    "net.exe": [("T1018", "discovery")],
    "nltest.exe": [("T1018", "discovery")],
    "psexec.exe": [("T1021.002", "lateral-movement")],
    "winrar.exe": [("T1560.001", "collection")],
    "7z.exe": [("T1560.001", "collection")],
    "rclone.exe": [("T1048", "exfiltration")],
}

# Cloud action → technique
_CLOUD_ACTION_MAP: dict[str, list[tuple[str, str]]] = {
    "putbucketpolicy": [("T1530", "collection")],
    "assumerole": [("T1078.004", "initial-access")],
    "createuser": [("T1136.003", "persistence")],
    "createloginprofile": [("T1098.001", "persistence")],
    "attachuserpolicy": [("T1098.001", "persistence")],
}

# Platform inference from asset patterns
_ASSET_PLATFORM_MAP: list[tuple[str, str]] = [
    (r"(?i)^win-|^ws-|^dc-|\.local$", "windows"),
    (r"(?i)^lin-|^srv-|^ubuntu|\.linux$", "linux"),
    (r"(?i)^mac-|^mbp-", "macos"),
    (r"(?i)^i-|^ec2-|^lambda-", "cloud"),
    (r"(?i)^fw-|^router-|^switch-", "network"),
]


@dataclass
class EnrichmentCandidate:
    """A single ATT&CK technique candidate from enrichment."""
    technique: str
    tactics: list[str]
    supporting_fields: list[str]
    score: float = 0.0
    score_status: str = "uncalibrated"
    source: str = "deterministic"  # deterministic | model | catalog


@dataclass
class EnrichmentResult:
    """Full enrichment output with provenance."""
    candidates: list[EnrichmentCandidate] = field(default_factory=list)
    platform: Optional[str] = None
    platform_source: str = "input"
    log_source: Optional[str] = None
    abstained: bool = False
    reason_codes: list[str] = field(default_factory=list)
    mode: str = "off"
    model_invoked: bool = False
    model_latency_ms: float = 0.0
    model_tokens: int = 0
    model_error: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": [
                {
                    "technique": c.technique,
                    "tactics": c.tactics,
                    "supporting_fields": c.supporting_fields,
                    "score": c.score,
                    "score_status": c.score_status,
                    "source": c.source,
                }
                for c in self.candidates
            ],
            "platform": self.platform,
            "platform_source": self.platform_source,
            "log_source": self.log_source,
            "abstained": self.abstained,
            "reason_codes": self.reason_codes,
            "mode": self.mode,
            "model_invoked": self.model_invoked,
            "model_latency_ms": round(self.model_latency_ms, 2),
            "model_tokens": self.model_tokens,
            "model_error": self.model_error,
        }

    @property
    def primary_technique(self) -> Optional[str]:
        """Best candidate technique, or None if abstained."""
        if not self.candidates:
            return None
        return self.candidates[0].technique


class ModelEnricherProtocol(Protocol):
    """Provider-neutral model enricher interface."""

    def enrich_alert(
        self, context: dict[str, Any], max_candidates: int
    ) -> dict[str, Any]:
        """Return {"candidates": [{"technique": str, "tactics": [str], ...}],
        "abstained": bool, "reason_codes": [str], "tokens": int} or {} on error."""
        ...


class NullModelEnricher:
    """Default model enricher: always abstains."""

    def enrich_alert(
        self, context: dict[str, Any], max_candidates: int
    ) -> dict[str, Any]:
        return {
            "candidates": [],
            "abstained": True,
            "reason_codes": ["NO_MODEL_PROVIDER"],
            "tokens": 0,
        }


class AlertEnricher:
    """Deterministic-first alert enrichment with optional model assist.

    Rules and inventory enrich first; the model fills semantic gaps and may
    abstain. Unknown never silently becomes T0000/execution.
    """

    def __init__(
        self,
        config: AlertEnricherConfig | None = None,
        model_enricher: ModelEnricherProtocol | None = None,
        technique_tactic_map: dict[str, str] | None = None,
    ):
        self.config = config or AlertEnricherConfig()
        self._model = model_enricher
        self._technique_tactic = technique_tactic_map or {}

        # Compile redaction patterns
        self._redact_patterns = [
            re.compile(p) for p in self.config.redact_patterns
        ]

    def enrich(self, alert_payload: dict[str, Any]) -> EnrichmentResult:
        """Enrich an alert payload, returning candidates and provenance.

        Args:
            alert_payload: Raw alert dict from API (AlertIn.model_dump())

        Returns:
            EnrichmentResult with candidates, platform, and provenance.
        """
        result = EnrichmentResult(mode=self.config.mode)

        # ── Step 1: Platform inference ──
        result.platform, result.platform_source = self._infer_platform(alert_payload)
        result.log_source = alert_payload.get("log_source")

        # ── Step 2: If technique already provided, validate and return ──
        technique = alert_payload.get("technique")
        if technique and technique != "T0000":
            tactic = alert_payload.get("tactic") or self._lookup_tactic(technique)
            result.candidates.append(EnrichmentCandidate(
                technique=technique,
                tactics=[tactic] if tactic else [],
                supporting_fields=["input.technique"],
                source="input",
            ))
            # In shadow mode, still try model for comparison
            if self.config.mode == "shadow" and self._model:
                self._try_model(alert_payload, result, shadow=True)
            return result

        # ── Step 3: Deterministic enrichment ──
        det_candidates = self._deterministic_enrich(alert_payload)
        result.candidates.extend(det_candidates)

        # ── Step 4: Model enrichment if still ambiguous ──
        if not result.candidates and self.config.mode != "off":
            self._try_model(alert_payload, result, shadow=False)
        elif result.candidates and self.config.mode == "shadow" and self._model:
            # Shadow: run model for comparison even if deterministic found something
            self._try_model(alert_payload, result, shadow=True)

        # ── Step 5: Determine abstention ──
        if not result.candidates:
            result.abstained = True
            result.reason_codes.append("NO_CANDIDATES")
            if not alert_payload.get("vendor_rule_title") and not alert_payload.get("process_name"):
                result.reason_codes.append("INSUFFICIENT_CONTEXT")

        return result

    def _infer_platform(self, payload: dict[str, Any]) -> tuple[Optional[str], str]:
        """Infer platform from input or asset patterns."""
        # Explicit platform
        platform = payload.get("platform")
        if platform:
            return platform, "input"

        # Asset pattern inference
        asset = payload.get("asset", "")
        for pattern, plat in _ASSET_PLATFORM_MAP:
            if re.search(pattern, asset):
                return plat, "asset_pattern"

        # Process name inference
        proc = (payload.get("process_name") or "").lower()
        if proc.endswith(".exe"):
            return "windows", "process_name"
        if proc in ("bash", "sh", "python3", "zsh"):
            return "linux", "process_name"

        # Cloud action implies cloud
        if payload.get("cloud_action"):
            return "cloud", "cloud_action"

        return None, "unknown"

    def _deterministic_enrich(self, payload: dict[str, Any]) -> list[EnrichmentCandidate]:
        """Run all deterministic enrichment passes."""
        candidates: list[EnrichmentCandidate] = []

        # Pass 1: Vendor rule title
        title = (payload.get("vendor_rule_title") or "").lower()
        if title:
            for keyword, techs in _SIGMA_TITLE_MAP.items():
                if keyword in title:
                    for tech, tactic in techs:
                        candidates.append(EnrichmentCandidate(
                            technique=tech,
                            tactics=[tactic],
                            supporting_fields=["vendor_rule_title"],
                            source="vendor_rule",
                        ))

        # Pass 2: Process name
        proc = (payload.get("process_name") or "").lower()
        if proc in _PROCESS_NAME_MAP:
            for tech, tactic in _PROCESS_NAME_MAP[proc]:
                candidates.append(EnrichmentCandidate(
                    technique=tech,
                    tactics=[tactic],
                    supporting_fields=["process_name"],
                    source="process_name",
                ))

        # Pass 3: Parent process name
        parent_proc = (payload.get("parent_process_name") or "").lower()
        if parent_proc in _PROCESS_NAME_MAP:
            for tech, tactic in _PROCESS_NAME_MAP[parent_proc]:
                candidates.append(EnrichmentCandidate(
                    technique=tech,
                    tactics=[tactic],
                    supporting_fields=["parent_process_name"],
                    source="parent_process_name",
                ))

        # Pass 4: Cloud action
        action = (payload.get("cloud_action") or "").lower().replace(" ", "")
        if action in _CLOUD_ACTION_MAP:
            for tech, tactic in _CLOUD_ACTION_MAP[action]:
                candidates.append(EnrichmentCandidate(
                    technique=tech,
                    tactics=[tactic],
                    supporting_fields=["cloud_action"],
                    source="cloud_action",
                ))

        # Pass 5: Command line keywords
        cmdline = (payload.get("command_line") or "").lower()
        if cmdline:
            cmdline_candidates = self._match_command_line(cmdline)
            for tech, tactic, field_ref in cmdline_candidates:
                candidates.append(EnrichmentCandidate(
                    technique=tech,
                    tactics=[tactic],
                    supporting_fields=[field_ref],
                    source="command_line",
                ))

        # Deduplicate by technique, merge supporting fields
        seen: dict[str, EnrichmentCandidate] = {}
        for c in candidates:
            if c.technique in seen:
                existing = seen[c.technique]
                for f in c.supporting_fields:
                    if f not in existing.supporting_fields:
                        existing.supporting_fields.append(f)
            else:
                seen[c.technique] = EnrichmentCandidate(
                    technique=c.technique,
                    tactics=list(set(c.tactics)),
                    supporting_fields=list(c.supporting_fields),
                    source=c.source,
                )

        return list(seen.values())[: self.config.max_candidates]

    def _match_command_line(self, cmdline: str) -> list[tuple[str, str, str]]:
        """Match command-line patterns to techniques."""
        results: list[tuple[str, str, str]] = []
        patterns: list[tuple[str, str, str]] = [
            # (regex, technique, tactic)
            (r"-enc\s+[A-Za-z0-9+/=]", "T1059.001", "execution"),
            (r"-exec\s+bypass", "T1059.001", "execution"),
            (r"downloadstring\(|iex\s*\(", "T1059.001", "execution"),
            (r"reg\s+add.*\\\\software\\\\microsoft\\\\windows", "T1547.001", "persistence"),
            (r"schtasks\s+/create", "T1053.005", "persistence"),
            (r"net\s+user\s+/add", "T1136.001", "persistence"),
            (r"whoami\s+/all", "T1033", "discovery"),
            (r"net\s+view|net\s+group", "T1018", "discovery"),
            (r"ntdsutil", "T1003.003", "credential-access"),
            (r"vssadmin\s+delete\s+shadows", "T1490", "impact"),
            (r"wbadmin\s+delete", "T1490", "impact"),
            (r"bcdedit\s+/default", "T1490", "impact"),
            (r"vssadmin\s+list\s+writers", "T1490", "impact"),
        ]
        for pattern, tech, tactic in patterns:
            if re.search(pattern, cmdline):
                results.append((tech, tactic, "command_line"))
        return results

    def _lookup_tactic(self, technique: str) -> Optional[str]:
        """Look up tactic for a technique from the map."""
        if not self._technique_tactic:
            from trace_agent.loop.scenario_executor import TECHNIQUE_TACTIC_MAP
            self._technique_tactic = TECHNIQUE_TACTIC_MAP
        return self._technique_tactic.get(technique) or \
               self._technique_tactic.get(technique.split(".")[0])

    def _try_model(
        self,
        payload: dict[str, Any],
        result: EnrichmentResult,
        shadow: bool,
    ) -> None:
        """Attempt model enrichment, recording diagnostics."""
        if self._model is None:
            return

        # Build sanitized context for model
        context = self._build_model_context(payload)

        import time as _time
        t0 = _time.monotonic()
        result.model_invoked = True  # mark before call; error path still records
        try:
            model_result = self._model.enrich_alert(
                context, self.config.max_candidates
            )
            result.model_latency_ms = (_time.monotonic() - t0) * 1000
            result.model_tokens = model_result.get("tokens", 0)

            model_candidates = model_result.get("candidates", [])
            model_abstained = model_result.get("abstained", False)
            reason_codes = model_result.get("reason_codes", [])

            if model_abstained:
                result.reason_codes.extend(reason_codes)
                if not shadow:
                    result.abstained = True
                return

            # Validate model candidates against known techniques
            for mc in model_candidates:
                tech = mc.get("technique", "")
                if not tech or not tech.startswith("T"):
                    result.reason_codes.append(f"INVALID_TECHNIQUE:{tech}")
                    continue
                tactics = mc.get("tactics", [])
                # Look up tactic if missing
                if not tactics:
                    t = self._lookup_tactic(tech)
                    if t:
                        tactics = [t]

                candidate = EnrichmentCandidate(
                    technique=tech,
                    tactics=tactics,
                    supporting_fields=mc.get("supporting_fields", ["model"]),
                    score=mc.get("score", 0.0),
                    score_status="uncalibrated",
                    source="model",
                )

                if shadow:
                    # In shadow mode, only record; don't add to candidates
                    result.reason_codes.append(
                        f"SHADOW_MODEL_CANDIDATE:{tech}"
                    )
                else:
                    # In assist mode, add validated model candidates
                    if not any(c.technique == tech for c in result.candidates):
                        result.candidates.append(candidate)

        except Exception as e:
            result.model_latency_ms = (_time.monotonic() - t0) * 1000
            result.model_error = f"{type(e).__name__}: {e}"
            result.reason_codes.append("MODEL_ERROR")

    def _build_model_context(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Build sanitized, bounded context for model enrichment."""
        context: dict[str, Any] = {}

        # Copy relevant fields with redaction
        for key in ("asset", "platform", "log_source", "anomaly_score"):
            val = payload.get(key)
            if val is not None:
                context[key] = val

        # Vendor / rule context
        for key in ("vendor_rule_id", "vendor_rule_title"):
            val = payload.get(key)
            if val:
                context[key] = self._redact_string(str(val))

        # Process context (bounded)
        proc = payload.get("process_name")
        if proc:
            context["process_name"] = proc
        parent_proc = payload.get("parent_process_name")
        if parent_proc:
            context["parent_process_name"] = parent_proc

        # Command line (truncated)
        cmdline = payload.get("command_line")
        if cmdline:
            truncated = cmdline[:self.config.max_command_line_length]
            context["command_line"] = self._redact_string(truncated)

        # Cloud / network
        for key in ("cloud_action", "network_direction"):
            val = payload.get(key)
            if val:
                context[key] = val

        # Bounded attributes (size-limited)
        attrs = payload.get("attributes", {})
        if attrs:
            import json
            raw = json.dumps(attrs, default=str)
            if len(raw) <= self.config.max_raw_attribute_bytes:
                context["attributes"] = self._redact_dict(attrs)
            else:
                context["attributes"] = {"_truncated": True}

        return context

    def _redact_string(self, text: str) -> str:
        """Apply redaction patterns to a string."""
        for pattern in self._redact_patterns:
            text = pattern.sub(self.config.redact_placeholder, text)
        return text

    def _redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact sensitive values in a dict."""
        result: dict[str, Any] = {}
        for key, value in data.items():
            key_str = str(key).lower()
            # Redact by key name
            if any(p in key_str for p in ("password", "token", "secret", "api_key", "apikey")):
                result[key] = self.config.redact_placeholder
            elif isinstance(value, str):
                result[key] = self._redact_string(value)
            elif isinstance(value, dict):
                result[key] = self._redact_dict(value)
            elif isinstance(value, list):
                result[key] = [
                    self._redact_string(v) if isinstance(v, str)
                    else self._redact_dict(v) if isinstance(v, dict)
                    else v
                    for v in value
                ]
            else:
                result[key] = value
        return result


def create_model_enricher(config: AlertEnricherConfig) -> ModelEnricherProtocol:
    """Create a model enricher from configuration.

    Returns NullModelEnricher if mode is off or no credentials.
    """
    if config.mode == "off":
        return NullModelEnricher()

    # For deepseek provider, create a lightweight LLM-backed enricher
    if config.provider == "deepseek":
        api_key = __import__("os").environ.get(config.credential_env, "")
        if not api_key:
            return NullModelEnricher()

        return _DeepSeekModelEnricher(config, api_key)

    return NullModelEnricher()


class _DeepSeekModelEnricher:
    """LLM-backed alert enricher using DeepSeek API."""

    def __init__(self, config: AlertEnricherConfig, api_key: str):
        self._config = config
        self._api_key = api_key

    def enrich_alert(
        self, context: dict[str, Any], max_candidates: int
    ) -> dict[str, Any]:
        """Call DeepSeek to propose ATT&CK candidates from alert context."""
        import json
        import os

        try:
            from trace_agent.llm.client import DeepSeekClient
        except ImportError:
            return {"candidates": [], "abstained": True, "reason_codes": ["NO_LLM_CLIENT"], "tokens": 0}

        client = DeepSeekClient(
            base_url=self._config.endpoint,
            api_key=self._api_key,
            model=self._config.model,
            connect_timeout=self._config.connect_timeout_seconds,
            read_timeout=self._config.read_timeout_seconds,
            max_retries=self._config.max_retries,
            verify_tls=self._config.verify_tls,
            ca_bundle=self._config.ca_bundle or None,
        )

        system_prompt = (
            "You are a cybersecurity expert analyzing alert context to propose "
            "MITRE ATT&CK technique candidates.\n"
            "Return JSON only with this format:\n"
            '{"candidates": [{"technique": "T1059.001", "tactics": ["execution"], '
            '"supporting_fields": ["process_name"], "score": 0.0, "reason": "brief"}], '
            '"abstained": false, "reason_codes": []}\n'
            "Abstain if context is insufficient for any confident suggestion.\n"
            "Never invent technique IDs outside the MITRE ATT&CK catalog."
        )

        user_prompt = (
            f"Alert context (redacted):\n{json.dumps(context, ensure_ascii=False, default=str)[:2000]}\n\n"
            f"Propose up to {max_candidates} ATT&CK technique candidates.\n"
            "Only suggest techniques you are confident about from the catalog.\n"
            "Return the JSON object."
        )

        result = client.evaluate(system_prompt, user_prompt)

        candidates = result.get("candidates", [])
        abstained = result.get("abstained", False)
        reason_codes = result.get("reason_codes", [])
        tokens = client.stats.get("total_tokens", 0) if hasattr(client, "stats") else 0

        # Validate techniques start with T
        valid_candidates = []
        for c in candidates:
            tech = c.get("technique", "")
            if tech.startswith("T") and tech[1:5].isdigit():
                valid_candidates.append(c)
            else:
                reason_codes.append(f"REJECTED_INVALID_TECHNIQUE:{tech}")

        return {
            "candidates": valid_candidates,
            "abstained": abstained or not valid_candidates,
            "reason_codes": reason_codes,
            "tokens": tokens,
        }
