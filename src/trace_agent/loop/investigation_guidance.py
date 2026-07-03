"""Bounded investigation guidance distilled from the bundled cyber skills.

The runtime never loads SKILL.md text or executes skill scripts.  Only this
reviewed, typed subset is exposed to models as advisory domain knowledge.
"""
from __future__ import annotations

from typing import Any


_T1110_GUIDANCE: dict[str, Any] = {
    "id": "skill-guidance:t1110-auth-chain",
    "source_skills": [
        "analyzing-windows-event-logs-in-splunk",
        "performing-log-analysis-for-forensic-investigation",
        "performing-false-positive-reduction-in-siem",
    ],
    "applies_to": ["T1110", "credential-access"],
    "objective": (
        "Correlate authentication failures by source IP and target account, "
        "then look for a success and subsequent activity from the same identity."
    ),
    "useful_fields": [
        "src_ip",
        "user",
        "auth_outcome",
        "event_code",
        "logon_type",
        "status",
    ],
    "preferred_operators": ["auth_log", "network_flow"],
    "supporting_patterns": [
        "many failures followed by a success for the same source/account",
        "one source targeting many accounts in a short window",
        "post-authentication process, privilege, or lateral activity",
    ],
    "benign_alternatives": [
        "expected scanner or health check",
        "known service account retry loop",
        "approved maintenance or password rotation",
    ],
    "guardrail": (
        "Failures alone do not prove compromise; missing success or downstream "
        "activity is unresolved evidence, not proof of benignness."
    ),
}


_LATERAL_GUIDANCE: dict[str, Any] = {
    "id": "skill-guidance:lateral-movement",
    "source_skills": ["detecting-lateral-movement-in-network"],
    "applies_to": ["T1021", "T1550.002", "lateral-movement"],
    "objective": (
        "Correlate source host, destination host, identity, authentication "
        "method, and east-west network activity."
    ),
    "useful_fields": [
        "src_ip",
        "dst_ip",
        "user",
        "event_code",
        "logon_type",
        "auth_package",
        "dst_port",
    ],
    "preferred_operators": [
        "auth_log",
        "network_flow",
        "lateral_movement_check",
    ],
    "supporting_patterns": [
        "network or remote-interactive logon followed by remote execution",
        "one identity or source reaching multiple internal hosts",
        "SMB, RDP, Kerberos, NTLM, service-install, or admin-share evidence",
    ],
    "benign_alternatives": [
        "approved administrative jump host",
        "software deployment or backup infrastructure",
        "documented service-to-service communication",
    ],
    "guardrail": (
        "A single internal connection is not lateral movement without identity, "
        "protocol, temporal, or endpoint corroboration."
    ),
}


def guidance_for(
    tactic: str | None,
    technique: str | None,
    *,
    max_items: int = 2,
) -> list[dict[str, Any]]:
    """Return a small deterministic knowledge slice for model reasoning."""
    tactic_key = str(tactic or "").strip().lower().replace("_", "-")
    technique_key = str(technique or "").strip().upper()
    candidates: list[dict[str, Any]] = []
    if technique_key == "T1110" or technique_key.startswith("T1110."):
        candidates.append(_T1110_GUIDANCE)
    elif tactic_key == "credential-access":
        candidates.append(_T1110_GUIDANCE)
    if (
        technique_key == "T1021"
        or technique_key.startswith("T1021.")
        or technique_key == "T1550.002"
        or tactic_key == "lateral-movement"
    ):
        candidates.append(_LATERAL_GUIDANCE)
    return [dict(item) for item in candidates[:max(0, max_items)]]
