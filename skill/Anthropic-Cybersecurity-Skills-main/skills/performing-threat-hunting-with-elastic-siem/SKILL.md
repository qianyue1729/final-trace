---
name: performing-threat-hunting-with-elastic-siem
description: 'Performs proactive threat hunting in Elastic Security SIEM using KQL/EQL
  queries, detection rules, and Timeline investigation to identify threats that evade
  automated detection. Use when SOC teams need to hunt for specific ATT&CK techniques,
  investigate anomalous behaviors, or validate detection coverage gaps using Elasticsearch
  and Kibana Security.

  '
domain: cybersecurity
subdomain: soc-operations
tags:
- soc
- elastic
- siem
- threat-hunting
- kql
- eql
- mitre-attack
- kibana
- decision-ledger
- voi
- null-anchor
- competing-hypotheses
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
- MAP-5.1
- MANAGE-2.4
atlas_techniques:
- AML.T0070
- AML.T0066
- AML.T0082
d3fend_techniques:
- Application Protocol Command Analysis
- Network Isolation
- Network Traffic Analysis
- Client-server Payload Profiling
- Network Traffic Community Deviation
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
- T1027
---
# Performing Threat Hunting with Elastic SIEM

## When to Use

Use this skill when:
- SOC teams need to proactively search for threats not caught by existing detection rules
- Threat intelligence reports describe new TTPs requiring validation against historical data
- Red team exercises reveal detection gaps that need hunting query development
- Periodic hunting cadence requires structured hypothesis-driven investigations

**Do not use** for real-time alert triage — that belongs in the Elastic Security Alerts queue with automated detection rules.

## Prerequisites

- Elastic Security 8.x+ with Security app enabled in Kibana
- Data ingestion via Elastic Agent (Endpoint Security integration) or Beats (Winlogbeat, Filebeat, Packetbeat)
- Data normalized to Elastic Common Schema (ECS) field mappings
- User role with `kibana_security_solution` and `read` access to relevant indices
- MITRE ATT&CK framework knowledge for hypothesis generation

## Workflow

### Step 1: Develop Hunting Hypothesis

Start with a hypothesis based on threat intelligence, ATT&CK technique, or anomaly:

**Example Hypothesis**: "Attackers are using living-off-the-land binaries (LOLBins) for execution, specifically certutil.exe for file downloads (T1105 — Ingress Tool Transfer)."

Define scope:
- **Data sources**: `logs-endpoint.events.process-*`, `logs-windows.sysmon_operational-*`
- **Time range**: Last 30 days
- **Expected indicators**: certutil.exe with `-urlcache`, `-split`, or `-decode` flags

#### Competing Hypothesis Seeding

Upgrade from a single hypothesis to **≤4 competing hypotheses + 1 null anchor**. This is not "making up stories" — it is the legitimate starting point for abductive reasoning (inference to the best explanation).

**Example Seeding**:

| ID | Hypothesis | Prior Probability | Expected Indicators |
|---|---|---|---|
| H1 | APT lateral movement using LOLBins | 60% | certutil downloads from external IPs, followed by execution of downloaded payload |
| H2 | Legitimate admin tooling / SCCM operations | 20% | certutil called by SCCM parent process, targets internal update servers |
| H3 | Insider threat staging tools | 10% | certutil used by non-admin user on sensitive host, off-hours timing |
| null | Benign noise / unrelated automation | 10% | certutil in scheduled task with known-good hash, no network activity |

**Seeding Principles**:
- Hypotheses must be **mutually exclusive** and **collectively exhaustive** (with null as catch-all)
- Prior probabilities are informed by threat intelligence, environment context, and base rates
- The null anchor exists to prevent confirmation bias — always ask "could this be nothing?"
- Each hypothesis should predict **different observable patterns** (this enables discriminative hunting)
- Seeding is the beginning of investigation, not the conclusion — priors will be updated by evidence

### Step 2: Hunt Using KQL in Discover

Open Kibana Discover and query with KQL (Kibana Query Language):

```kql
process.name: "certutil.exe" and process.args: ("-urlcache" or "-split" or "-decode" or "-encode" or "-verifyctl")
```

Refine to exclude known legitimate use:

```kql
process.name: "certutil.exe"
  and process.args: ("-urlcache" or "-split" or "-decode")
  and not process.parent.name: ("sccm*.exe" or "ccmexec.exe")
  and not user.name: "SYSTEM"
```

For PowerShell-based hunting with encoded commands (T1059.001):

```kql
process.name: "powershell.exe"
  and process.args: ("-enc" or "-encodedcommand" or "-e " or "frombase64string" or "iex" or "invoke-expression")
  and not process.parent.executable: "C:\\Windows\\System32\\svchost.exe"
```

### Step 3: Use EQL for Sequence Detection

Elastic Event Query Language (EQL) enables hunting for multi-step attack sequences:

**Detect parent-child process anomalies (T1055 — Process Injection):**

```eql
sequence by host.name with maxspan=5m
  [process where event.type == "start" and process.name == "explorer.exe"]
  [process where event.type == "start" and process.parent.name == "explorer.exe"
    and process.name in ("cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe")]
```

**Detect credential dumping sequence (T1003):**

```eql
sequence by host.name with maxspan=2m
  [process where event.type == "start"
    and process.name in ("procdump.exe", "procdump64.exe", "rundll32.exe", "taskmgr.exe")
    and process.args : "*lsass*"]
  [file where event.type == "creation"
    and file.extension in ("dmp", "dump", "bin")]
```

**Detect lateral movement via PsExec (T1021.002):**

```eql
sequence by source.ip with maxspan=1m
  [authentication where event.outcome == "success" and winlog.logon.type == "Network"]
  [process where event.type == "start"
    and process.name == "psexesvc.exe"]
```

### Step 4: Investigate with Elastic Security Timeline

Create a Timeline investigation in Elastic Security for collaborative analysis:

1. Navigate to **Security > Timelines > Create new timeline**
2. Add events from hunting queries using "Add to timeline" from Discover
3. Pin critical events and add investigation notes
4. Use the Timeline query bar for additional filtering:

```kql
host.name: "WORKSTATION-042" and event.category: ("process" or "network" or "file")
```

Add columns for key fields: `@timestamp`, `event.action`, `process.name`, `process.args`, `user.name`, `source.ip`, `destination.ip`

### Step 5: Build Detection Rules from Findings

Convert successful hunting queries into Elastic detection rules:

```json
{
  "name": "Certutil Download Activity",
  "description": "Detects certutil.exe used for file download, a common LOLBin technique",
  "risk_score": 73,
  "severity": "high",
  "type": "eql",
  "query": "process where event.type == \"start\" and process.name == \"certutil.exe\" and process.args : (\"-urlcache\", \"-split\", \"-decode\") and not process.parent.name : (\"ccmexec.exe\", \"sccm*.exe\")",
  "threat": [
    {
      "framework": "MITRE ATT&CK",
      "tactic": {
        "id": "TA0011",
        "name": "Command and Control"
      },
      "technique": [
        {
          "id": "T1105",
          "name": "Ingress Tool Transfer"
        }
      ]
    }
  ],
  "tags": ["Hunting", "LOLBins", "T1105"],
  "interval": "5m",
  "from": "now-6m",
  "enabled": true
}
```

Deploy via Elastic Security API:

```bash
curl -X POST "https://kibana:5601/api/detection_engine/rules" \
  -H "kbn-xsrf: true" \
  -H "Content-Type: application/json" \
  -H "Authorization: ApiKey YOUR_API_KEY" \
  -d @certutil_rule.json
```

### Step 5.5: Null Anchor Assessment

When hunting evidence **disconfirms** a hypothesis or reveals activity unrelated to the original hunt, explicitly classify the finding:

- **benign**: The activity is legitimate and unrelated to any threat — prune from investigation, no further action
- **oos** (out-of-scope): The activity is genuinely malicious but belongs to a **different** threat campaign — SPAWN a new, separate investigation

This distinction prevents two failure modes:
1. Discarding truly malicious findings because they don't match the current hypothesis
2. Polluting the current investigation with unrelated threat activity (scope creep)

#### Example

While hunting for certutil-based tool transfer (H1), you discover:
- `WORKSTATION-042` has certutil activity that matches SCCM patterns → **benign** → prune
- `SERVER-DB-03` has certutil decoding a cryptominer binary unrelated to the APT campaign → **oos** → SPAWN new hunt "TH-2024-013: Cryptominer on database servers"
- `LAPTOP-EXEC-07` has certutil downloading payload from known APT infrastructure → **in_attack** → continue hunting within current scope

#### Decision Matrix

| Finding | Matches Any Hypothesis? | Malicious? | Classification | Action |
|---|---|---|---|---|
| Activity matches H1/H2/H3 | Yes | Varies | Update posteriors | Continue in current hunt |
| Activity doesn't match any H | No | No | benign | Prune and document |
| Activity doesn't match any H | No | Yes | oos | SPAWN new investigation |
| Activity weakly matches null | — | No | null confirmation | Reduce priors on H1-H3 |

### Step 5.7: Discriminative Debt Identification

When two or more competing hypotheses have **similar posterior probabilities** (small margin) and **divergent predictions** on a specific observable, this creates a **discriminative debt** — a high-priority obligation to collect the evidence that would separate them.

#### Identifying Discriminative Probes

A probe has high discriminative value when:
1. The top-2 hypotheses have a margin < 20% (e.g., H1=45%, H2=35%)
2. The probe's expected outcome differs significantly between H1 and H2
3. The probe is practically executable (data exists, query is feasible)

#### Example

| Probe | H1 (APT) Predicts | H2 (Admin Tools) Predicts | Discriminative Value |
|---|---|---|---|
| C2 beacon pattern analysis | Regular interval beaconing to external IP | No outbound beaconing | **High** — mutually exclusive predictions |
| Time-of-day analysis | Off-hours execution | Business-hours execution | **Medium** — some overlap possible |
| certutil download target | External IP, rare domain | Internal SCCM server | **High** — clear separation |
| User account privilege level | Any user | Admin service account | **Low** — both possible for either H |

**Priority Rule**: When discriminative debt exists, the highest-discriminative-value probe should be executed **before** probes that would merely confirm an already-leading hypothesis. Confirming what you already believe is less valuable than resolving genuine ambiguity.

#### ES|QL for Discriminative Probe (C2 Beacon Detection)

```esql
FROM logs-endpoint.events.network-*
| WHERE host.name == "LAPTOP-EXEC-07" AND @timestamp > NOW() - 7 DAYS
| WHERE destination.ip != "10.0.0.0/8" AND destination.ip != "172.16.0.0/12"
| EVAL hour_bucket = DATE_TRUNC(1 hour, @timestamp)
| STATS conn_count = COUNT(*) BY destination.ip, hour_bucket
| WHERE conn_count > 3
| SORT destination.ip, hour_bucket
```

Regular connection counts to the same external IP across hour buckets strongly indicates beaconing (H1) vs. one-time admin download (H2).

### Step 6: Aggregate and Visualize Findings

Create hunting dashboard with aggregations:

```json
GET logs-endpoint.events.process-*/_search
{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"term": {"process.name": "certutil.exe"}},
        {"range": {"@timestamp": {"gte": "now-30d"}}}
      ]
    }
  },
  "aggs": {
    "by_host": {
      "terms": {"field": "host.name", "size": 20},
      "aggs": {
        "by_user": {
          "terms": {"field": "user.name", "size": 10}
        },
        "by_args": {
          "terms": {"field": "process.args", "size": 10}
        }
      }
    }
  }
}
```

### Step 7: Posterior Update and Stopping Decision

Rather than a simple "hypothesis validated/refuted" conclusion, perform a structured posterior update and stopping assessment:

#### 7.1 Update Competing Explanation Posteriors

Based on all evidence collected during the hunt, update the probability distribution across hypotheses:

```
Posterior Update — TH-2024-012
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
H1 (APT lateral movement):  Prior 60% → Posterior 88%  [+28%]
   Evidence: C2 beaconing confirmed, payload matches known APT tooling
H2 (Legitimate admin):      Prior 20% → Posterior  5%  [-15%]
   Evidence: No SCCM correlation, off-hours timing
H3 (Insider threat):        Prior 10% → Posterior  5%  [-5%]
   Evidence: User account compromised (not insider)
Null (benign noise):        Prior 10% → Posterior  2%  [-8%]
   Evidence: Confirmed malicious payload execution
```

#### 7.2 Stopping Decision: maxVOI vs. EPS

Check whether continued hunting is justified:

- **maxVOI**: The maximum Value of Information across all remaining uninvestigated probes
- **EPS**: The cost threshold (analyst time, system resources, opportunity cost of not hunting other threats)

**Stop hunting when**: `maxVOI < EPS` — no remaining probe could change the disposition decision enough to justify its cost.

**Continue hunting when**: There exists at least one probe where investigating could flip the leading explanation or materially change containment scope.

#### 7.3 Decision Robustness Check

Before closing, verify the disposition is **robust to perturbation**:
- If the top explanation dropped by 10%, would the recommended action change?
- Is there a plausible evidence scenario that could flip H1 and H2?
- Are all decision-critical edges attributed (boundary beliefs resolved)?

If the decision is fragile (small perturbation flips action), continue hunting despite apparent convergence.

#### 7.4 Standard Outputs (Preserved)

- IOCs and affected hosts discovered
- Detection rules created or updated
- ATT&CK Navigator layer updated with new coverage
- Recommendations for security control improvements
- **New**: Posterior distribution, stopping rationale, and residual uncertainty documented

## Key Concepts

| Term | Definition |
|------|-----------|
| **KQL** | Kibana Query Language — simplified query syntax for filtering data in Kibana Discover and dashboards |
| **EQL** | Event Query Language — Elastic's sequence-aware query language for detecting multi-step attack patterns |
| **ECS** | Elastic Common Schema — standardized field naming convention enabling cross-source correlation |
| **Timeline** | Elastic Security investigation workspace for collaborative event analysis and annotation |
| **Hypothesis-Driven Hunting** | Structured approach starting with a theory about attacker behavior, tested against telemetry data |
| **LOLBins** | Living Off the Land Binaries — legitimate Windows tools (certutil, mshta, rundll32) abused by attackers |
| **Competing Hypotheses** | Set of ≤4 mutually exclusive explanations seeded at hunt start; updated via Bayesian posterior as evidence arrives |
| **Null Anchor** | Explicit "this is benign" baseline maintained throughout the hunt to counteract confirmation bias |
| **Discriminative Debt** | Obligation to collect evidence that separates two close-margin hypotheses; highest-priority probe type |
| **VOI (Value of Information)** | Estimated decision-risk reduction from a probe; used for stopping decisions (stop when maxVOI < EPS) |
| **Posterior Update** | Bayesian revision of hypothesis probabilities after each evidence collection step |

## Tools & Systems

- **Elastic Security**: SIEM platform built on Elasticsearch with detection rules, Timeline, and case management
- **Elastic Agent**: Unified data collection agent replacing Beats for endpoint and network telemetry
- **Elastic Endpoint Security**: EDR capabilities integrated into Elastic Agent for process, file, and network monitoring
- **ATT&CK Navigator**: MITRE tool for tracking detection and hunting coverage across the ATT&CK matrix

## Common Scenarios

- **LOLBin Abuse**: Hunt for mshta.exe, regsvr32.exe, rundll32.exe, certutil.exe with suspicious arguments
- **Persistence Mechanisms**: Query for scheduled task creation, registry run key modification, WMI subscriptions
- **C2 Beaconing**: Analyze network flow data for periodic outbound connections with consistent intervals
- **Data Staging**: Hunt for large file compression (7z, rar, zip) followed by outbound transfers
- **Account Manipulation**: Search for net.exe user creation, group membership changes, or password resets by non-admin users

## Output Format

```
THREAT HUNT REPORT — TH-2024-012
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SECTION 1: POSTERIOR DISTRIBUTION
────────────────────────────────
Leading Explanation:  H1 — APT lateral movement using LOLBins (88%)
Second-Best:         H2 — Legitimate admin tooling (5%)
Margin:              83% (decision robust)
Null Anchor:         2% (effectively eliminated)

SECTION 2: EVIDENCE SUMMARY
────────────────────────────────
Hypothesis:   Attackers using certutil.exe for tool download (T1105)
Period:       2024-02-15 to 2024-03-15
Data Sources: Elastic Endpoint (process events), Sysmon

Findings:
  Total certutil executions:     342
  With -urlcache flag:           12 (3.5%)
  Suspicious (non-SCCM):        3 confirmed anomalous

Affected Hosts:
  WORKSTATION-042 (Finance)  — certutil downloading payload.exe from external IP
  SERVER-DB-03 (Database)    — certutil decoding base64 encoded binary [oos: cryptominer]
  LAPTOP-EXEC-07 (Executive) — certutil downloading script from Pastebin

SECTION 3: STOPPING DECISION
────────────────────────────────
maxVOI of remaining probes:  0.08 (below EPS threshold of 0.15)
Decision robustness:         Robust — 10% perturbation does not flip disposition
Stopping rationale:          Leading explanation dominates; no remaining probe
                             could shift posterior enough to change response action

SECTION 4: COUNTERFACTUAL ANALYSIS
────────────────────────────────
If H2 were true (legitimate admin): Would require SCCM correlation + business-hours
  pattern + internal targets — none observed. Counterfactual confidence: Low (5%)
If null were true (benign noise):    Would require no payload execution + known-good
  hash — contradicted by confirmed malicious binary. Counterfactual confidence: Minimal (2%)

SECTION 5: ACTIONS AND SPAWNED INVESTIGATIONS
────────────────────────────────
  [DONE] 2 hosts isolated for forensic investigation (WORKSTATION-042, LAPTOP-EXEC-07)
  [DONE] Detection rule "Certutil Download Activity" deployed (ID: elastic-th012)
  [DONE] ATT&CK Navigator updated: T1105 coverage = GREEN
  [SPAWNED] TH-2024-013: Cryptominer on SERVER-DB-03 (oos finding)

Verdict:      HYPOTHESIS H1 CONFIRMED (posterior 88%) — 2 true positives escalated to IR
              1 out-of-scope finding spawned as separate investigation
```
