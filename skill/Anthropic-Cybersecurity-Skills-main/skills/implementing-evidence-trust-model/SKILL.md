---
name: implementing-evidence-trust-model
description: 'Implements a structured evidence trust assessment framework for alert
  triage and forensic investigations. Evaluates integrity, provenance, adversary controllability,
  and corroboration of each evidence artifact to weight likelihoods, enforce VETO gates,
  and generate investigation obligations when expected evidence is absent. Activates
  for requests involving evidence reliability assessment, anti-forensics detection,
  forge-resistance evaluation, or trust-weighted Bayesian reasoning in incident investigations.

  '
domain: cybersecurity
subdomain: digital-forensics
tags:
- evidence-trust
- integrity
- anti-forensics
- adversary-controlled
- forge-resistant
- chain-of-custody
mitre_attack:
- T1070
- T1070.001
- T1070.002
- T1070.003
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.AN-03
- RS.AN-01
- DE.AE-02
---

# Implementing an Evidence Trust Model

## When to Use

- Evaluating whether forensic evidence can be trusted during active incident response
- Determining if a VETO (temporal order violation, disconfirmation) should trigger as a hard gate vs. a soft prior
- Weighting likelihood ratios in Bayesian hypothesis scoring when evidence sources vary in reliability
- Detecting anti-forensics activity (log gaps, timestamp manipulation, EDR silence)
- Generating investigation obligations when expected evidence is conspicuously absent
- Assessing whether an adversary could have planted or suppressed specific evidence on a compromised host

**Do not use** for routine log parsing where all sources are trusted and the environment has not been compromised.

## Prerequisites

- Inventory of evidence sources mapped to integrity tiers (kernel audit, EDR telemetry, user-space logs, wall-clock)
- Confirmed or suspected compromise scope identifying which hosts/layers the adversary controls
- Familiarity with the LOCK investigation loop (Locate → Orient → Confirm → Know) from RFC-004-02
- Bayesian reasoning engine or scoring framework that accepts weighted likelihood ratios
- Detection rules for common anti-forensics indicators (Event ID 1102, audit.log truncation, .bash_history clearing)

## Workflow

### Step 1: Define the EvidenceTrust Data Structure

Assign a trust vector to every evidence artifact entering the reasoning pipeline:

```python
from dataclasses import dataclass

@dataclass
class EvidenceTrust:
    """Trust vector for a single evidence artifact."""
    integrity: float          # 0.0–1.0: resistance to forgery/tampering
    provenance: str           # chain of custody, e.g. "kernel_audit→syslog→SIEM"
    adversary_controllable: bool  # True if artifact is within adversary's control surface
    corroboration: int        # number of independent sources confirming same fact

TAU_HARD = 0.7  # threshold for forge-resistant classification

def is_forge_resistant(ev: EvidenceTrust) -> bool:
    """Evidence is forge-resistant iff high integrity AND not adversary-controllable."""
    return ev.integrity >= TAU_HARD and not ev.adversary_controllable
```

Integrity reference values:

| Source Type | Typical Integrity | Rationale |
|-------------|------------------|-----------|
| Kernel audit (auditd, ETW) | 0.9 | Requires root/SYSTEM to tamper |
| EDR telemetry (signed agent) | 0.85 | Agent integrity protected by vendor |
| Network flow (tap/span) | 0.8 | Out-of-band, not on compromised host |
| Application logs (syslog) | 0.5 | Writable by application-level attacker |
| Wall-clock timestamps | 0.4 | NTP spoofable, local clock adjustable |
| User-reported observations | 0.3 | Subject to error and manipulation |

### Step 2: Classify Anti-Forensics Indicators

Detect evidence that has been tampered with or suppressed:

```
ANTI-FORENSICS CLASSIFICATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Category              Indicators                                   Severity
──────────────────────────────────────────────────────────────────────────────
Log gap               Event ID 1102 (audit log cleared)            Critical
                      Unexpected log rotation during incident
                      auth.log size smaller than daily baseline

Temporal discontinuity  Timestamp jumps > 60s between sequential     High
                        events; backward timestamps; timezone shifts

EDR silence           Zero events from high-risk host in window     Critical
                      where peer hosts generate normal telemetry

History wipe          .bash_history truncated/deleted               High
                      PowerShell ConsoleHost_history.txt cleared
                      audit.log truncated mid-stream

Artifact destruction  $MFT entries zeroed; prefetch files deleted   High
                      USN journal gap; Event .evtx file missing
```

### Step 3: Determine Adversary Control Surface

Map which evidence layers the adversary can manipulate given confirmed access:

```python
def mark_adversary_controllable(evidence_list, compromised_hosts, adversary_access_level):
    """
    For each evidence artifact, determine if adversary could have
    forged or suppressed it given their confirmed access.

    adversary_access_level: one of 'user', 'admin', 'kernel', 'physical'
    """
    CONTROL_MAP = {
        'user':     ['application_logs', 'bash_history', 'user_files'],
        'admin':    ['application_logs', 'bash_history', 'user_files',
                     'syslog', 'scheduled_tasks', 'registry'],
        'kernel':   ['application_logs', 'bash_history', 'user_files',
                     'syslog', 'scheduled_tasks', 'registry',
                     'kernel_audit', 'edr_telemetry'],
        'physical': ['all']
    }

    controllable_types = CONTROL_MAP.get(adversary_access_level, [])

    for ev in evidence_list:
        if ev.host in compromised_hosts:
            if 'all' in controllable_types or ev.source_type in controllable_types:
                ev.trust.adversary_controllable = True
```

### Step 4: Enforce Hard Constraints on VETO Gates

Apply the three hard constraints that govern how trusted evidence interacts with decision logic:

```python
def evaluate_veto(veto_type, supporting_evidence):
    """
    Hard VETO (TemporalOrderVeto, DisconfirmedVeto) requires
    forge-resistant evidence. Otherwise, downgrade to strong negative prior.
    """
    forge_resistant_evidence = [e for e in supporting_evidence if is_forge_resistant(e.trust)]

    if forge_resistant_evidence:
        # Full hard VETO: hypothesis is eliminated
        return VetoResult(strength='hard', confidence=0.99)
    else:
        # Downgrade: cannot fully eliminate, but apply strong negative prior
        return VetoResult(strength='soft_prior', confidence=0.75)
```

### Step 5: Apply "Absence as Signal" (The Dog That Didn't Bark)

Generate investigation obligations when expected evidence is missing:

```python
def check_expected_evidence(hypothesis, available_evidence, environment):
    """
    For a given hypothesis, identify evidence that SHOULD exist
    but is absent. Absence from a forge-resistant source is highly
    informative; absence from a compromised source generates an obligation.
    """
    expected = hypothesis.predict_expected_artifacts(environment)
    obligations = []

    for expected_artifact in expected:
        if expected_artifact not in available_evidence:
            source = environment.get_source(expected_artifact)
            if is_forge_resistant(source.trust):
                # Strong disconfirmation: expected artifact would exist if hypothesis true
                yield LikelihoodUpdate(hypothesis, ratio=0.1, reason="absence_from_trusted_source")
            else:
                # Cannot trust absence → generate MANDATE to actively verify
                obligations.append(Mandate(
                    type='anti_forensics_debt',
                    target=expected_artifact,
                    reason="Expected evidence absent from potentially compromised source",
                    priority='high'
                ))
    return obligations
```

### Step 6: Weight Likelihoods by Trust

Adjust Bayesian likelihood ratios based on evidence trust:

```python
def trust_weighted_likelihood(evidence, base_likelihood_ratio):
    """
    Scale likelihood ratio toward 1.0 (neutral) for low-trust evidence.
    Prevents adversary-planted decoys from dominating posterior.
    """
    trust_weight = evidence.trust.integrity * (1 - 0.5 * evidence.trust.adversary_controllable)
    # Corroboration bonus: independent sources increase effective weight
    corroboration_factor = min(1.0, 0.5 + 0.2 * evidence.trust.corroboration)
    effective_weight = trust_weight * corroboration_factor

    # Shrink LR toward 1.0 proportionally to distrust
    adjusted_lr = 1.0 + (base_likelihood_ratio - 1.0) * effective_weight
    return max(adjusted_lr, 0.01)  # floor to avoid zero
```

## Key Concepts

| Term | Definition |
|------|------------|
| **EvidenceTrust** | Data structure encoding integrity, provenance, adversary controllability, and corroboration for an evidence artifact |
| **Forge Resistance** | Property of evidence that cannot be plausibly fabricated by the adversary; requires high integrity AND absence of adversary control |
| **TAU_HARD** | Threshold (default 0.7) above which an evidence source is considered tamper-resistant |
| **Adversary Control Surface** | Set of evidence sources the adversary can manipulate given their confirmed access level on compromised hosts |
| **Absence as Signal** | Investigative principle that missing expected evidence is informative—either disconfirming a hypothesis or indicating anti-forensics |
| **Trust-Weighted Likelihood** | Bayesian likelihood ratio scaled by evidence trust to prevent low-quality or adversary-controlled evidence from dominating inference |
| **Hard VETO Gate** | Logical elimination of a hypothesis that requires forge-resistant evidence to activate; otherwise downgrades to a strong prior |
| **Anti-Forensics Debt** | Investigation obligation generated when tampering indicators suggest evidence has been deliberately destroyed or altered |

## Tools & Systems

- **Kernel Audit Frameworks (auditd, ETW)**: High-integrity evidence sources requiring privileged access to tamper with
- **EDR Platforms (CrowdStrike, Defender for Endpoint)**: Signed telemetry agents providing forge-resistant process and file event data
- **Network TAPs / SPAN ports**: Out-of-band packet capture not subject to host-level manipulation
- **SIEM Correlation Engines (Splunk, Sentinel)**: Aggregate evidence from multiple sources to compute corroboration scores
- **Forensic Imaging Tools (dc3dd, FTK Imager)**: Preserve evidence with cryptographic integrity verification

## Common Scenarios

### Scenario: Evaluating Log Evidence on a Compromised Domain Controller

**Context**: A domain controller shows signs of compromise (golden ticket usage suspected). The SOC needs to determine whether Windows Security Event Logs on this DC can be trusted for timeline reconstruction.

**Approach**:
1. Assign integrity=0.9 to kernel ETW events captured before compromise confirmed
2. Check for Event ID 1102 (log cleared) → if present, flag as anti-forensics
3. Adversary has domain admin → mark all DC-local logs as `adversary_controllable=True`
4. Rely on network flow data (integrity=0.8, adversary_controllable=False) for timeline
5. Any VETO based solely on DC event logs downgrades to soft prior (not forge-resistant)
6. Generate obligation: "Verify Kerberos TGT anomalies from network-level Kerberos traffic capture"

**Pitfalls**:
- Trusting event logs on a host where the adversary has SYSTEM/kernel access
- Failing to generate obligations when expected artifacts are absent from compromised sources
- Allowing a single adversary-controllable timestamp to anchor the entire investigation timeline
- Not checking for EDR silence on the compromised host during the suspected attack window

## Output Format

```
EVIDENCE TRUST ASSESSMENT
============================
Investigation ID:   INV-2025-0042
Assessment Time:    2025-09-15T14:30:00Z
Compromise Scope:   DC01 (kernel-level), WS-FINANCE-03 (admin-level)

EVIDENCE INVENTORY
ID      Source              Host        Integrity  Adv_Ctrl  Corroboration  Forge-Resistant
E-001   Windows EventLog    DC01        0.90       YES       1              NO
E-002   Network TAP flow    SPAN-CORE   0.80       NO        1              YES
E-003   CrowdStrike EDR     WS-FIN-03   0.85       NO        2              YES
E-004   Syslog (app-level)  DC01        0.50       YES       1              NO
E-005   .bash_history       LNX-WEB-01  0.30       YES       0              NO

ANTI-FORENSICS DETECTED
Host        Indicator                   Category               Severity
DC01        Event ID 1102 at 14:05Z     Log gap                Critical
WS-FIN-03   EDR silent 13:50-14:10Z    EDR silence            Critical
LNX-WEB-01  .bash_history size=0        History wipe           High

VETO GATE EVALUATION
Veto Type             Evidence Used      Forge-Resistant?   Result
TemporalOrderVeto     E-001 (EventLog)   NO                 Downgraded to soft prior
DisconfirmedVeto      E-002 (NetFlow)    YES                Hard VETO applied

OBLIGATIONS GENERATED
ID          Type                Target                              Priority
OBL-001     anti_forensics      Recover DC01 EventLog from backup   High
OBL-002     structural          Verify EDR gap on WS-FIN-03         High
OBL-003     absence_signal      Check NetFlow for expected C2       Medium
```
