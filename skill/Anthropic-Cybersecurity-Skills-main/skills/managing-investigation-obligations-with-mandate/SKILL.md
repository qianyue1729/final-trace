---
name: managing-investigation-obligations-with-mandate
description: 'Manages and schedules investigation obligations (mandates) that represent
  unfulfilled reasoning debts in alert triage and incident response. Defines four debt
  categories—structural, lifecycle, anti-forensics, and discriminative—and implements
  value-oriented scheduling, hard-blocking semantics, and escalation policies. Activates
  for requests involving investigation task prioritization, obligation tracking,
  incomplete kill-chain coverage, evidence gap management, or automated investigation
  workflow orchestration.

  '
domain: cybersecurity
subdomain: incident-response
tags:
- mandate
- obligations
- lifecycle-debt
- anti-forensics-debt
- discriminative-debt
- structural-debt
- investigation-management
mitre_attack:
- T1070
- T1078
- T1486
- T1021
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- DE.AE-06
---

# Managing Investigation Obligations with MANDATE

## When to Use

- Tracking incomplete investigative threads that must be resolved before case closure
- Scheduling next-best investigative actions based on value and urgency rather than simple FIFO
- Enforcing hard-blocking constraints that prevent premature case dismissal
- Detecting when an investigation has unresolved kill-chain phases or unexplained structural gaps
- Managing anti-forensics findings that themselves become high-priority investigation targets
- Deciding between competing hypotheses when confidence margins are too narrow

**Do not use** for routine alert triage where a single detection-to-disposition path suffices without backtracking.

## Prerequisites

- Active LOCK-loop investigation engine with hypothesis scoring (posterior probabilities)
- Evidence trust model (see `implementing-evidence-trust-model`) for anti-forensics detection
- Kill-chain or attack-lifecycle template mapped to the leading hypothesis
- Budget-aware investigation scheduler with remaining step budget (B)
- VOI (Value of Information) estimator for candidate investigative actions

## Workflow

### Step 1: Define the Four Obligation Categories

Each obligation represents an investigative debt that must be resolved or explicitly waived:

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import time

class ObligationType(Enum):
    STRUCTURAL = "structural"          # Unexplained graph topology
    LIFECYCLE = "lifecycle"            # Missing kill-chain phases
    ANTI_FORENSICS = "anti_forensics"  # Evidence tampering detected
    DISCRIMINATIVE = "discriminative"  # Hypotheses too close to distinguish

class BlockingLevel(Enum):
    HARD = "hard"          # Unconditionally blocks stop/dismiss
    VALUE_GATED = "value_gated"  # Blocks only if VOI >= EPS

@dataclass
class Mandate:
    id: str
    type: ObligationType
    description: str
    target_artifact: str
    created_at: float = field(default_factory=time.time)
    deadline: Optional[float] = None
    voi: float = 0.0
    resolved: bool = False
    resolution: Optional[str] = None

    @property
    def blocking_level(self) -> BlockingLevel:
        if self.type in (ObligationType.STRUCTURAL, ObligationType.ANTI_FORENSICS):
            return BlockingLevel.HARD
        return BlockingLevel.VALUE_GATED

    @property
    def time_to_deadline(self) -> float:
        if self.deadline is None:
            return float('inf')
        return max(0, self.deadline - time.time())
```

### Step 2: Identify Trigger Conditions for Each Category

```
OBLIGATION TRIGGER MAP
━━━━━━━━━━━━━━━━━━━━━━
Category          Trigger Condition                                Example
────────────────────────────────────────────────────────────────────────────────
Structural        Malicious orphan node (effect without cause)     C2 callback with no
                  Bridge host with no explained mechanism           initial access vector
                  Dangling credential (used but origin unknown)

Lifecycle         Leading hypothesis kill-chain has unexplained    Ransomware hypothesis
                  phase (especially objective/impact phase)         missing exfil phase

Anti-forensics    §5 detects log gap, temporal discontinuity,      Event ID 1102 on DC +
                  EDR silence, or history wipe                      EDR silent for 20 min

Discriminative    Top two hypotheses margin < MARGIN_THRESHOLD     P(APT)=0.42, P(insider)=0.38
                  AND a probe exists where they predict             with divergent lateral
                  divergent outcomes                                movement predictions
```

### Step 3: Implement Obligation Scheduling

Schedule obligations by composite priority (VOI × urgency), not pure earliest-deadline-first:

```python
def schedule_obligations(obligations: list[Mandate], budget_remaining: int) -> list[Mandate]:
    """
    Sort obligations by composite priority score.
    Primary key: VOI / time_to_deadline (value density under urgency)
    Secondary key: blocking level (HARD obligations float to top)
    """
    def priority_score(m: Mandate) -> tuple:
        ttd = m.time_to_deadline if m.time_to_deadline > 0 else 0.001
        urgency_weighted_voi = m.voi / ttd

        # HARD obligations get infinite priority boost
        blocking_boost = float('inf') if m.blocking_level == BlockingLevel.HARD else 0

        return (blocking_boost + urgency_weighted_voi, m.voi)

    active = [m for m in obligations if not m.resolved]
    return sorted(active, key=priority_score, reverse=True)
```

### Step 4: Enforce Blocking Semantics on Stop Decisions

```python
EPS_VOI = 0.05  # minimum VOI threshold for value-gated obligations

def can_stop_investigation(obligations: list[Mandate], max_voi: float) -> tuple[bool, str]:
    """
    Determine whether the investigation can stop given outstanding obligations.

    Returns (can_stop, reason).
    """
    active = [m for m in obligations if not m.resolved]

    # Hard blockers: unconditionally prevent stopping
    hard_blockers = [m for m in active if m.blocking_level == BlockingLevel.HARD]
    if hard_blockers:
        return False, f"Hard obligations outstanding: {[m.id for m in hard_blockers]}"

    # Value-gated: convert to probes, check if VOI >= EPS
    value_gated = [m for m in active if m.blocking_level == BlockingLevel.VALUE_GATED]
    high_value_gated = [m for m in value_gated if m.voi >= EPS_VOI]
    if high_value_gated:
        return False, f"Value-gated obligations with VOI >= EPS: {[m.id for m in high_value_gated]}"

    return True, "All obligations resolved or below VOI threshold"
```

### Step 5: Resolve and Close Obligations

```python
def resolve_obligation(mandate: Mandate, resolution_type: str, evidence=None):
    """
    Close an obligation via one of:
    - 'covered': An investigative operator addressed the target artifact
    - 'not_applicable': The phase/artifact is not relevant under current leading hypothesis
    - 'escalated': Exceeded deadline, escalated to human analyst

    Closing an obligation triggers a reverse update to the decision ledger.
    """
    mandate.resolved = True
    mandate.resolution = resolution_type

    if resolution_type == 'covered' and evidence:
        # Feed new evidence back into hypothesis scoring
        yield DecisionLedgerUpdate(
            action='obligation_fulfilled',
            mandate_id=mandate.id,
            new_evidence=evidence
        )
    elif resolution_type == 'not_applicable':
        # Record justification for audit trail
        yield DecisionLedgerUpdate(
            action='obligation_waived',
            mandate_id=mandate.id,
            justification=f"Phase not applicable under hypothesis: {mandate.description}"
        )
```

### Step 6: Apply Protection Mechanisms

Prevent obligation overload from consuming the entire investigation budget:

```python
def apply_protection_mechanisms(obligations: list[Mandate], budget: int):
    """
    Protection mechanisms:
    1. Pre-emption slot cap: obligations consume at most ceil(B/2) budget slots
    2. Overdue escalation: obligations past deadline escalate to human
    3. Persistent overflow: if obligations persistently exceed capacity, escalate batch
    """
    MAX_OBLIGATION_SLOTS = -(-budget // 2)  # ceil(B/2)
    OVERDUE_ESCALATION_WINDOW = 300  # seconds

    active = [m for m in obligations if not m.resolved]
    scheduled = schedule_obligations(active, budget)

    # Cap: only top ceil(B/2) obligations get budget allocation
    allocated = scheduled[:MAX_OBLIGATION_SLOTS]
    overflow = scheduled[MAX_OBLIGATION_SLOTS:]

    # Overdue escalation
    now = time.time()
    for m in active:
        if m.deadline and now > m.deadline + OVERDUE_ESCALATION_WINDOW:
            escalate_to_human(m, reason="Obligation overdue beyond escalation window")

    # Persistent overflow → batch escalation
    if len(overflow) > MAX_OBLIGATION_SLOTS:
        escalate_batch_to_human(overflow, reason="Obligation count exceeds capacity")

    return allocated
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Mandate** | A tracked investigation obligation representing an unresolved reasoning debt that may block case closure |
| **Structural Debt** | Obligation arising from unexplained graph topology: malicious orphan nodes, bridge hosts without mechanism, dangling credentials |
| **Lifecycle Debt** | Obligation arising when the leading hypothesis's kill-chain template has phases not yet evidenced (especially objective/impact) |
| **Anti-Forensics Debt** | Obligation triggered by evidence tampering detection; the tampering itself is a high-value investigative lead |
| **Discriminative Debt** | Obligation generated when top hypotheses are too close in posterior probability and a discriminating probe exists |
| **VOI (Value of Information)** | Expected reduction in decision risk from executing a specific investigative action; used to prioritize obligations |
| **Hard Blocker** | Obligation (structural or anti-forensics) that unconditionally prevents investigation termination until resolved |
| **Value-Gated Blocker** | Obligation (lifecycle or discriminative) that blocks termination only if its materialized probe has VOI >= EPS |

## Tools & Systems

- **SOAR Platforms (Cortex XSOAR, Splunk SOAR)**: Automate obligation creation, scheduling, and escalation workflows
- **Case Management (TheHive, ServiceNow)**: Track obligation lifecycle with SLA timers and escalation rules
- **Kill-Chain Frameworks (MITRE ATT&CK, Lockheed Martin)**: Provide templates for lifecycle debt detection
- **Evidence Trust Engine**: Feeds anti-forensics detections that trigger obligation generation
- **VOI Estimation Module**: Computes expected information value for prioritizing among competing obligations

## Common Scenarios

### Scenario: Ransomware Investigation with Missing Exfiltration Phase

**Context**: A ransomware incident has been confirmed (encryption detected). The leading hypothesis maps to a double-extortion playbook, but no evidence of data exfiltration has been found. Multiple hosts show EDR gaps during the suspected staging period.

**Approach**:
1. Generate lifecycle obligation: "Exfiltration phase unexplained in double-extortion hypothesis"
2. Generate anti-forensics obligation: "EDR silence on hosts HR-WS-04, FIN-SRV-02 during 02:00-04:00Z"
3. Schedule anti-forensics obligations first (HARD blocking, high urgency)
4. Convert lifecycle obligation to probe: check network flow for large outbound transfers to cloud storage
5. If EDR gaps resolved (agent crash confirmed, not adversary action) → close anti-forensics obligation
6. If no exfiltration found AND NetFlow confirms no large transfers → close lifecycle obligation as "not applicable for this variant"

**Pitfalls**:
- Dismissing the case as "simple ransomware" without checking for exfiltration (lifecycle debt ignored)
- Not treating EDR silence as an obligation-generating anti-forensics indicator
- Allowing lifecycle obligations to consume entire budget without the ceil(B/2) cap
- Failing to escalate obligations that exceed their deadline

### Scenario: Discriminative Debt Between APT and Insider Threat

**Context**: An investigation has narrowed to two hypotheses: APT lateral movement vs. malicious insider. Posterior probabilities are P(APT)=0.44, P(insider)=0.39. The two hypotheses predict different behavior on the VPN logs (APT: connections from known proxy infrastructure; insider: connections from employee home IP at unusual hours).

**Approach**:
1. Detect margin < MARGIN_THRESHOLD (0.44 - 0.39 = 0.05 < 0.10)
2. Identify discriminating probe: VPN source IP analysis
3. Generate discriminative obligation with VOI proportional to the decision risk reduction
4. Execute VPN log analysis → if proxy IP found, update posterior strongly toward APT
5. Close discriminative obligation as 'covered' with new evidence

**Pitfalls**:
- Acting on the leading hypothesis without resolving the narrow margin (premature containment scoping)
- Not materializing the discriminative obligation into a concrete probe (abstract debt without action)
- Allowing the probe to consume budget when a cheaper alternative exists

## Output Format

```
OBLIGATION LEDGER
============================
Investigation ID:   INV-2025-0042
Budget Remaining:   12 steps
Max Obligation Slots: 6 (ceil(12/2))
Active Obligations: 4
Resolved:           2

ACTIVE OBLIGATIONS (sorted by priority)
ID       Type             Blocking    VOI    TTD      Target
─────────────────────────────────────────────────────────────────────
OBL-003  anti_forensics   HARD        0.82   120s     Recover EDR telemetry for HR-WS-04
OBL-001  structural       HARD        0.71   300s     Identify initial access for C2 node
OBL-004  lifecycle        VALUE_GATED 0.45   600s     Verify exfiltration phase
OBL-005  discriminative   VALUE_GATED 0.38   900s     VPN source IP discriminator

RESOLVED OBLIGATIONS
ID       Type             Resolution       Evidence Added
─────────────────────────────────────────────────────────
OBL-002  structural       covered          Phishing email E-012 identified
OBL-006  lifecycle        not_applicable   Single-extortion variant confirmed

STOP DECISION: BLOCKED
Reason: Hard obligations outstanding [OBL-003, OBL-001]
Action: Continue investigation, prioritize OBL-003 (highest urgency)
```
