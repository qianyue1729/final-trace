---
name: performing-alert-triage-with-elastic-siem
description: Perform systematic alert triage in Elastic Security SIEM to rapidly classify,
  prioritize, and investigate security alerts for SOC operations.
domain: cybersecurity
subdomain: soc-operations
tags:
- elastic
- siem
- alert-triage
- soc
- elastic-security
- detection
- esql
- kibana
- decision-ledger
- voi
- null-anchor
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Token Binding
- Restore Access
- Application Protocol Command Analysis
- Password Authentication
- Reissue Credential
nist_csf:
- DE.CM-01
- DE.AE-02
- RS.MA-01
- DE.AE-06
mitre_attack:
- T1078
- T1685.002
- T1685.005
- T1566
---

# Performing Alert Triage with Elastic SIEM

## Overview

Alert triage in Elastic Security is the systematic process of reviewing, classifying, and prioritizing security alerts to determine which represent genuine threats. Elastic's AI-driven Attack Discovery feature can triage hundreds of alerts down to discrete attack chains, but skilled analyst triage remains essential. A structured triage workflow typically takes 5-10 minutes per alert cluster using Elastic's built-in tools.


## When to Use

- When conducting security assessments that involve performing alert triage with elastic siem
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Prerequisites

- Elastic Security deployed (version 8.x or later)
- Elastic Agent or Beats configured for endpoint and network data collection
- Detection rules enabled and generating alerts
- Elastic Common Schema (ECS) compliance across data sources
- Analyst access to Kibana Security app with appropriate privileges

## Alert Triage Workflow

### Step 1: Initial Alert Assessment (2 minutes)

When viewing an alert in Elastic Security, review the alert details panel:

```
Alert Details Panel:
- Rule Name and Description
- Severity and Risk Score
- MITRE ATT&CK Mapping
- Host and User Context
- Process Tree (for endpoint alerts)
- Timeline of related events
```

#### Key Fields to Examine First

| Field | Purpose | ECS Field |
|---|---|---|
| Rule severity | Initial priority assessment | `kibana.alert.severity` |
| Risk score | Quantified threat level | `kibana.alert.risk_score` |
| Host name | Affected system | `host.name` |
| User name | Affected identity | `user.name` |
| Process name | Executing process | `process.name` |
| Source IP | Origin of activity | `source.ip` |
| Destination IP | Target of activity | `destination.ip` |
| MITRE tactic | Attack stage | `threat.tactic.name` |

### Step 2: Context Gathering (3 minutes)

#### Query Related Events with ES|QL

```esql
FROM logs-endpoint.events.*
| WHERE host.name == "affected-host" AND @timestamp > NOW() - 1 HOUR
| STATS count = COUNT(*) BY event.category, event.action
| SORT count DESC
```

#### Find All Activity from Suspicious User

```esql
FROM logs-*
| WHERE user.name == "suspicious-user" AND @timestamp > NOW() - 24 HOURS
| STATS count = COUNT(*), unique_hosts = COUNT_DISTINCT(host.name) BY event.category
| SORT count DESC
```

#### Check for Related Alerts from Same Source

```esql
FROM .alerts-security.alerts-default
| WHERE source.ip == "10.0.0.50" AND @timestamp > NOW() - 24 HOURS
| STATS alert_count = COUNT(*) BY kibana.alert.rule.name, kibana.alert.severity
| SORT alert_count DESC
```

#### Investigate Lateral Movement from Same IP

```esql
FROM logs-system.auth-*
| WHERE source.ip == "10.0.0.50" AND event.outcome == "success"
| STATS login_count = COUNT(*), hosts = COUNT_DISTINCT(host.name) BY user.name
| WHERE hosts > 3
```

### Step 3: Threat Intelligence Enrichment (2 minutes)

Check indicators against threat intelligence:

```esql
FROM logs-ti_*
| WHERE threat.indicator.ip == "203.0.113.50"
| KEEP threat.indicator.type, threat.indicator.provider, threat.indicator.confidence, threat.feed.name
```

#### Check File Hash Against Known Threats

```esql
FROM logs-endpoint.events.file-*
| WHERE file.hash.sha256 == "abc123..."
| STATS occurrences = COUNT(*) BY host.name, file.path, user.name
```

### Step 4: Classification Decision (2 minutes)

| Classification | Criteria | Action |
|---|---|---|
| True Positive | Confirmed malicious activity | Escalate to incident, begin containment |
| Benign True Positive | Expected behavior matching rule | Document in alert notes, acknowledge |
| False Positive | Rule triggered on benign activity | Mark as false positive, create tuning task |
| Needs Investigation | Insufficient data for determination | Assign for deeper investigation |

#### Decision Ledger Perspective

Rather than committing to a single binary classification, maintain a **Decision Ledger** with ≤4-6 competing explanations plus a **null anchor** ("this alert is benign noise unrelated to any threat"):

- Each classification conclusion maps to which competing explanation gained probability mass
- For disputed correlation edges, annotate a **ternary attribution**: `{in_attack, benign, oos}` (in-scope attack / benign unrelated / out-of-scope true malicious)
- Avoid premature collapse: hold multiple hypotheses until evidence forces convergence

**Example**: A brute-force alert on a privileged account may carry:

| Explanation | Posterior | Disposition if Leading |
|---|---|---|
| Ransomware initial access (H1) | 60% | Escalate to IR immediately |
| Legitimate admin password rotation (H2) | 25% | Acknowledge, document |
| Out-of-scope cryptominer (H3) | 15% | SPAWN separate investigation |
| Null anchor (benign noise) | 10% | Close alert |

The null anchor carries probability mass (typically low prior 5-15% post initial-triage) — it provides a **principled landing surface against confirmation bias**, ensuring "this edge is benign" always has a path to be validated. Unlike a mere rhetorical check, null competes with substantive hypotheses in posterior updates: if no evidence actively disconfirms it, its mass grows, preventing premature escalation.

### Step 4.5: Boundary Belief Assessment

For every correlation edge (pivot) discovered during context gathering, assess its **boundary belief** — does this activity belong to the attack being triaged, or is it something else?

Three-way classification for each edge:
- **in_attack**: Evidence supports this edge is part of the same attack campaign
- **benign**: Activity is legitimate and unrelated — prune from investigation scope
- **oos** (out-of-scope): Activity is truly malicious but belongs to a *different* threat — SPAWN a new investigation

#### Gathering Attribution Evidence with ES|QL

```esql
FROM logs-endpoint.events.*
| WHERE host.name == "affected-host" AND @timestamp > NOW() - 2 HOURS
| WHERE process.name == "rundll32.exe"
| STATS count = COUNT(*),
        unique_parents = COUNT_DISTINCT(process.parent.name),
        unique_users = COUNT_DISTINCT(user.name),
        unique_destinations = COUNT_DISTINCT(destination.ip)
  BY process.args
| SORT count DESC
```

This query helps determine whether a correlated `rundll32.exe` execution shares attacker fingerprint (same parent chain, same user, same C2 destination) or is coincidental system activity.

#### Boundary Belief Output Format

| Edge ID | Pivot Description | p_in_attack | p_benign | p_oos | Rationale |
|---|---|---|---|---|---|
| E-001 | rundll32 from same parent tree | 0.80 | 0.15 | 0.05 | Same user + temporal proximity |
| E-002 | DNS query to rare domain | 0.45 | 0.40 | 0.15 | Domain registered recently but no known TI match |
| E-003 | Lateral auth to file server | 0.30 | 0.60 | 0.10 | Common admin pattern on this host |

Edges with `p_benign > 0.5` are pruned from the attack scope. Edges with `p_oos > 0.3` trigger a SPAWN decision for separate investigation.

### Step 4.7: VOI-Based Reprioritization

Traditional triage prioritizes by `severity` and `risk_score` alone. This misses a critical dimension: **Value of Information (VOI)** — how much would investigating a particular direction *reduce decision risk*?

#### Why Pure Severity Is Insufficient

- A severity=high alert that merely confirms what you already know (redundant evidence) adds no decision value
- A severity=medium alert that could **discriminate** between two competing explanations may be the single most valuable thing to investigate
- Boundary-defining probes ("is this edge in-scope or out-of-scope?") receive zero reward under pure severity ranking, yet they directly reduce blast radius uncertainty

#### VOI Estimation (Simplified)

For each candidate investigation direction, estimate:

```
VOI(probe) = P(probe changes leading explanation) × |Decision impact of change|
```

More concretely:
- **Decision risk before probe**: How uncertain is the current disposition? (e.g., 60/25/15 split = high uncertainty)
- **Expected risk reduction**: If this probe returns positive vs. negative, how much does the posterior shift?
- **Discriminative power**: Does the probe differentiate between the top-2 explanations?

**Example**: Two pending investigation directions:

| Probe | Severity | VOI Score | Reason |
|---|---|---|---|
| Check C2 beacon pattern on affected host | High | 0.85 | Would confirm/deny ransomware H1 vs. admin-tool H2 |
| Review additional failed logins on same IP | High | 0.20 | Redundant — already have 5 failed login indicators |
| Query DNS for rare domain resolution timing | Medium | 0.72 | High discriminative power: APT C2 vs. legitimate CDN |

The medium-severity DNS probe should be investigated **before** the redundant high-severity login probe because it carries more decision value.

### Step 5: Documentation and Escalation (1 minute)

For each triaged alert, document:
- Classification decision with rationale
- Evidence artifacts examined
- Related alerts or investigations
- Recommended next steps

## Detection Rules for Triage

### Pre-Built Detection Rules

Elastic Security includes 1000+ pre-built detection rules organized by:
- **MITRE ATT&CK Tactic**: Initial Access, Execution, Persistence, etc.
- **Platform**: Windows, Linux, macOS, Cloud
- **Data Source**: Endpoint, Network, Cloud, Identity

### Custom Alert Correlation Rule

```json
{
  "name": "Multiple Failed Logins Followed by Success",
  "type": "threshold",
  "query": "event.category:authentication AND event.outcome:failure",
  "threshold": {
    "field": ["source.ip", "user.name"],
    "value": 5,
    "cardinality": [
      {
        "field": "user.name",
        "value": 3
      }
    ]
  },
  "severity": "high",
  "risk_score": 73,
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0006",
        "name": "Credential Access"
      },
      "technique": [
        {
          "id": "T1110",
          "name": "Brute Force"
        }
      ]
    }
  ]
}
```

## AI-Assisted Triage

### Elastic AI Assistant Integration

1. Open alert in Elastic Security
2. Click AI Assistant panel
3. Use quick prompts:
   - "Summarize this alert" - Get initial assessment
   - "Generate ES|QL query to find related activity" - Expand investigation
   - "What are the recommended response actions?" - Get playbook guidance
   - "Is this likely a false positive?" - Get AI confidence assessment

### Attack Discovery

Elastic's Attack Discovery automatically:
- Groups related alerts into attack chains
- Maps alerts to MITRE ATT&CK kill chain stages
- Filters false positives using ML models
- Prioritizes based on business impact
- Provides narrative summary of the attack

## Key Concepts

| Term | Definition |
|------|------------|
| **Alert Triage** | Systematic process of reviewing, classifying, and prioritizing security alerts to determine genuine threats |
| **ES\|QL** | Elastic's pipe-based query language for aggregation and filtering across indices |
| **Risk Score** | Quantified threat level assigned by detection rule or ML model |
| **Attack Discovery** | Elastic AI feature that groups related alerts into discrete attack chains |
| **Decision Ledger** | A structured posterior over ≤4-6 competing explanations for an alert cluster, updated as evidence arrives; replaces binary TP/FP thinking |
| **Null Anchor** | An explicit "this is benign noise" baseline held throughout triage to counteract confirmation bias; not a probability-bearing hypothesis but a cognitive anchor |
| **Boundary Belief** | Three-way attribution for each correlation edge: in_attack / benign / oos (out-of-scope malicious); determines investigation scope |
| **VOI (Value of Information)** | Estimated decision-risk reduction from pursuing a specific investigation direction; used to reprioritize probes beyond raw severity |

## Triage Prioritization Matrix

| Risk Score | Severity | Asset Criticality | VOI Score | Response SLA |
|---|---|---|---|---|
| 90-100 | Critical | High | Any | 15 minutes |
| 70-89 | High | High | ≥ 0.7 | 30 minutes |
| 70-89 | High | Medium | ≥ 0.5 | 1 hour |
| 50-69 | Medium | Any | ≥ 0.7 | 1 hour (VOI-elevated) |
| 50-69 | Medium | Any | < 0.5 | 4 hours |
| 21-49 | Low | Any | ≥ 0.7 | 4 hours (VOI-elevated) |
| 21-49 | Low | Any | < 0.5 | 8 hours |
| 1-20 | Informational | Any | Any | 24 hours |

> **Note**: The VOI column allows medium/low severity alerts to be elevated when they carry high discriminative value for resolving competing explanations. A VOI ≥ 0.7 alert that could flip the disposition decision is more urgent than a redundant high-severity confirmation.

## Triage Metrics and KPIs

| Metric | Target | Measurement |
|---|---|---|
| Mean Time to Triage (MTTT) | < 10 minutes | Time from alert creation to classification |
| False Positive Rate | < 30% | False positives / total alerts |
| Escalation Rate | 10-20% | Escalated alerts / total alerts |
| Alert Coverage | > 80% | Triaged alerts / generated alerts per shift |
| Reclassification Rate | < 5% | Changed classifications / total classified |

## References

- [Elastic Security - Triage Alerts Documentation](https://www.elastic.co/docs/solutions/security/ai/triage-alerts)
- [SOC Analyst's Guide to Triage with Elastic](https://systemweakness.com/from-alert-to-action-a-soc-analysts-guide-to-triage-with-elastic-%EF%B8%8F-4e5354ab5da9)
- [Elastic Blog - AI and 2025 SIEM Landscape](https://www.elastic.co/blog/ai-siem-landscape)
- [Reducing False Positives with Elastic and Tines](https://www.elastic.co/blog/false-positives-automated-siem-investigations-elastic-tines)
