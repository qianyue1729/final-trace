---
name: analyzing-cyber-kill-chain
description: 'Analyzes intrusion activity against the Lockheed Martin Cyber Kill Chain
  framework to identify which phases an adversary has completed, where defenses succeeded
  or failed, and what controls would have interrupted the attack at earlier phases.
  Use when conducting post-incident analysis, building prevention-focused security
  controls, or mapping detection gaps to kill chain phases. Activates for requests
  involving kill chain analysis, intrusion kill chain, attack phase mapping, or Lockheed
  Martin kill chain framework.

  '
domain: cybersecurity
subdomain: threat-intelligence
tags:
- kill-chain
- Lockheed-Martin
- MITRE-ATT&CK
- intrusion-analysis
- defense-in-depth
- NIST-CSF
- decision-ledger
- voi
- lifecycle-debt
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
mitre_attack:
- T1566.001
- T1190
- T1547.001
- T1071.001
- T1486
---
# Analyzing Cyber Kill Chain

## When to Use

Use this skill when:
- Conducting post-incident analysis to determine how far an adversary progressed through an attack sequence
- Designing layered defensive controls with the goal of interrupting attacks at the earliest possible phase
- Producing threat intelligence reports that communicate attack progression to non-technical stakeholders

**Do not use** this skill as a standalone framework — combine with MITRE ATT&CK for technique-level granularity beyond what the 7-phase kill chain provides.

## Prerequisites

- Complete incident timeline with forensic artifacts mapped to specific adversary actions
- MITRE ATT&CK Enterprise matrix for technique-level mapping within each kill chain phase
- Access to threat intelligence on the suspected adversary group's typical kill chain progression
- Post-incident report or IR timeline from responding team

## Workflow

### Step 1: Map Observed Actions to Kill Chain Phases

The Lockheed Martin Cyber Kill Chain consists of seven phases. Map all observed adversary actions:

**Phase 1 - Reconnaissance**: Adversary gathers target information before attack.
- Indicators: DNS queries from adversary IP, LinkedIn scraping, job posting analysis, Shodan scans of organization infrastructure

**Phase 2 - Weaponization**: Adversary creates attack tool (malware + exploit).
- Indicators: Malware compilation timestamps, exploit document metadata, builder artifacts in malware samples

**Phase 3 - Delivery**: Adversary transmits weapon to target.
- Indicators: Phishing emails, malicious attachments, drive-by downloads, USB drops, supply chain compromise

**Phase 4 - Exploitation**: Adversary exploits vulnerability to execute code.
- Indicators: CVE exploitation events in application/OS logs, memory corruption artifacts, shellcode execution

**Phase 5 - Installation**: Adversary establishes persistence on target.
- Indicators: New scheduled tasks, registry run keys, service installation, web shells, bootkits

**Phase 6 - Command & Control (C2)**: Adversary communicates with compromised system.
- Indicators: Beaconing traffic (regular intervals), DNS tunneling, HTTPS to uncommon domains, C2 framework signatures (Cobalt Strike, Sliver)

**Phase 7 - Actions on Objectives**: Adversary achieves goals.
- Indicators: Data staging/exfiltration, lateral movement, ransomware execution, destructive activity

### Step 2: Identify Phase Completion and Detection Points

Create a phase matrix for the incident:
```
Phase 1: Recon        → Completed (undetected)
Phase 2: Weaponize    → Completed (undetected — pre-attack)
Phase 3: Delivery     → Completed; phishing email bypassed SEG
Phase 4: Exploit      → Completed; CVE-2023-23397 exploited
Phase 5: Install      → DETECTED: EDR flagged scheduled task creation (attack stalled here)
Phase 6: C2           → Not achieved (installation blocked)
Phase 7: Objectives   → Not achieved
```

For each phase completed without detection, document the defensive control gap.

#### Lifecycle Debt Identification

For every phase marked "Not achieved" or "Completed (undetected)", assess whether it constitutes a **Lifecycle Debt** — an obligation to investigate further because the attack story is incomplete in a decision-relevant way.

Key principle: If the **objective/impact phase** (Phase 7) is unconfirmed, the story has not concluded — this is the highest-priority lifecycle debt because disposition decisions (containment scope, executive notification, regulatory reporting) depend on knowing what the adversary achieved.

| Phase | Status | Lifecycle Debt? | Obligation Priority | Rationale |
|---|---|---|---|---|
| Phase 1: Recon | Completed (undetected) | No | — | Pre-attack; no actionable gap |
| Phase 2: Weaponize | Completed (undetected) | No | — | Pre-delivery; intelligence value only |
| Phase 6: C2 | Not achieved | Yes — Conditional | Medium | If install succeeded, C2 absence is suspicious (anti-forensics?) |
| Phase 7: Objectives | Not achieved | Yes — Hard | Critical | Attack outcome unknown → disposition undecidable |

**Decision relevance test**: A phase constitutes lifecycle debt **only if** confirming or denying it could change the disposition, containment scope, or attribution conclusion. Phases that are merely "nice to know" do not generate hard obligations.

### Step 3: Map to MITRE ATT&CK for Technique Detail

Each kill chain phase maps to multiple ATT&CK tactics:
- Delivery → Initial Access (TA0001)
- Exploitation → Execution (TA0002)
- Installation → Persistence (TA0003), Privilege Escalation (TA0004)
- C2 → Command and Control (TA0011)
- Actions on Objectives → Exfiltration (TA0010), Impact (TA0040)

Within each phase, enumerate specific ATT&CK techniques observed and map to existing detections.

### Step 4: Identify Courses of Action per Phase

For each phase, document applicable defensive courses of action (COAs):
- **Detect COA**: What detection would alert on adversary activity in this phase?
- **Deny COA**: What control would prevent the adversary from completing this phase?
- **Disrupt COA**: What control would interrupt the adversary mid-phase?
- **Degrade COA**: What control would reduce the adversary's effectiveness in this phase?
- **Deceive COA**: What deception (honeypots, canary tokens) would expose activity in this phase?
- **Destroy COA**: What active defense capability would neutralize adversary infrastructure?

### Step 5: Lifecycle Template Comparison

For the **leading explanation** (the most probable attack hypothesis), retrieve the expected kill chain template for that adversary type and scan for **phases that should have occurred but lack evidence in the investigation graph**.

#### Template Scanning Process

1. Select the kill chain template matching the leading hypothesis (e.g., "APT lateral movement campaign", "ransomware delivery chain", "insider data theft")
2. For each template phase, classify the current evidence state:
   - **Confirmed**: Evidence exists and is attributed to this campaign
   - **Denied**: Evidence actively contradicts this phase occurring
   - **Unexplained**: No evidence either way — the phase *could* have occurred undetected

3. For each "Unexplained" phase, determine:
   - **"Didn't happen"**: Structural or logical reasons the adversary would skip this phase (e.g., insider skips Phases 1-4)
   - **"Happened but undetected"**: Plausible given adversary capability and detection gaps → generates a **MANDATE obligation**

#### Example: APT Lateral Movement Hypothesis

```
Template: APT Lateral Movement Campaign
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 1 (Recon):       Unexplained → "Didn't happen" (spear-phish was opportunistic)
Phase 2 (Weaponize):   Confirmed (malware sample recovered)
Phase 3 (Delivery):    Confirmed (phishing email in logs)
Phase 4 (Exploit):     Confirmed (CVE exploitation artifact)
Phase 5 (Install):     Confirmed (persistence mechanism found)
Phase 6 (C2):          Confirmed (beacon traffic identified)
Phase 7 (Objectives):  UNEXPLAINED → "Happened but undetected"?
                       → MANDATE: Investigate exfiltration channels
```

The Exfiltration/Objectives phase is unexplained despite C2 being confirmed. For an APT with established C2, *not* pursuing objectives is implausible → this generates a hard MANDATE obligation to investigate data staging and exfiltration paths.

### Step 6: Kill Chain Completeness vs Decision Value

Lifecycle template scanning (Step 5) can generate many obligations. Without a stopping criterion, analysts fall into the **completionism trap** — treating every unexplained phase as a hard obligation leads to infinite investigation.

#### The VOI-Gated Stopping Principle

A lifecycle obligation **blocks investigation stopping** only when:

```
VOI(investigating phase X) ≥ EPS (investigation cost threshold)
```

Where VOI is defined as: *"If I confirm/deny this phase, could it change my disposition, containment scope, or attribution?"*

#### Decision-Relevant vs Decision-Irrelevant Gaps

| Unexplained Phase | VOI Assessment | Blocks Stopping? |
|---|---|---|
| Objectives/Impact not confirmed | High — changes containment scope and regulatory obligation | Yes |
| Reconnaissance method unknown | Low — does not affect current disposition | No |
| Exact weaponization tool unknown | Low — attribution nice-to-have but disposition unchanged | No |
| C2 channel undiscovered (but install confirmed) | High — active C2 means ongoing compromise | Yes |

#### Precise Semantics of "Must Investigate"

"Objective/impact must be investigated" does **not** mean "investigate until you find something." It means: **investigate until the posterior probability that objectives were achieved is either high enough to trigger escalation or low enough to be decision-irrelevant** — i.e., until the decision is robust to remaining uncertainty.

This prevents two failure modes:
1. **Under-investigation**: Stopping while outcome uncertainty could flip the disposition
2. **Over-investigation (completionism)**: Pursuing phases that cannot change the decision regardless of findings

### Step 7: Produce Kill Chain Analysis Report

Structure findings as:
1. Attack narrative (timeline of phases)
2. Phase-by-phase analysis with evidence
3. Detection point analysis (what worked, what failed)
4. Defensive recommendation per phase prioritized by cost/effectiveness
5. Control improvement roadmap

## Key Concepts

| Term | Definition |
|------|-----------|
| **Kill Chain** | Sequential model of adversary intrusion phases; breaking any link theoretically stops the attack |
| **Courses of Action (COA)** | Defensive responses mapped to each kill chain phase: detect, deny, disrupt, degrade, deceive, destroy |
| **Beaconing** | Regular, periodic C2 check-in pattern from compromised host to adversary server; detectable by frequency analysis |
| **Phase Completion** | Adversary successfully finishes a kill chain phase and progresses to the next; defense-in-depth aims to prevent this |
| **Intelligence Gain/Loss** | Analysis of whether detecting at Phase 5 (vs. Phase 3) reduced intelligence about adversary capabilities or intent |
| **Lifecycle Debt** | An obligation to investigate an unexplained kill chain phase because its resolution could change the disposition decision |
| **unexplained_stages** | Kill chain phases that lack evidence for or against occurrence; candidates for lifecycle debt if decision-relevant |
| **VOI-Gated Obligation** | A lifecycle debt that blocks investigation stopping only when its Value of Information exceeds the cost threshold (VOI ≥ EPS) |
| **Completionism Trap** | Anti-pattern where every unexplained phase is treated as a hard obligation, leading to infinite investigation loops without decision progress |

## Tools & Systems

- **MITRE ATT&CK Navigator**: Overlay kill chain phases with ATT&CK technique coverage for integrated analysis
- **Elastic Security EQL**: Event Query Language for querying multi-phase attack sequences in Elastic SIEM
- **Splunk ES**: Timeline visualization and correlation searches for kill chain phase sequencing
- **MISP**: Kill chain tagging via galaxy clusters for structured incident event documentation

## Common Pitfalls

- **Linear assumption**: Adversaries don't always progress linearly — they may skip phases (weaponization already complete from previous campaign) or loop back (re-establish C2 after detection).
- **Ignoring Phases 1 and 2**: Reconnaissance and weaponization occur before the defender has visibility. Intelligence about these phases requires external sources (OSINT, threat intelligence).
- **Missing insider threats**: The kill chain was designed for external adversaries. Insider threats may skip directly to Phase 7 without traversing earlier phases.
- **Confusing with ATT&CK tactics**: The 7-phase kill chain and 14 ATT&CK tactics are complementary but not directly equivalent. Maintain distinction to prevent analytic confusion.
- **Completionism trap**: Treating every unexplained kill chain phase as a hard obligation leads to infinite investigation loops. Only phases whose resolution could change the disposition decision (VOI ≥ threshold) should block stopping. Template scanning is a generative tool, not a mandatory checklist — each generated obligation must pass the VOI gate before consuming analyst time.
