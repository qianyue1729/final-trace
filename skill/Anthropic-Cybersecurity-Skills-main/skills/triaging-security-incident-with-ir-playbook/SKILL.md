---
name: triaging-security-incident-with-ir-playbook
description: Classify and prioritize security incidents using structured IR playbooks
  to determine severity, assign response teams, and initiate appropriate response
  procedures.
domain: cybersecurity
subdomain: incident-response
tags:
- incident-response
- triage
- playbook
- severity-classification
- soc
- asymmetric-loss-model
- obligation-scan
- value-urgency-scheduling
- four-exit-decision
mitre_attack:
- T1486
- T1490
- T1070
- T1078
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
---

# Triaging Security Incidents with IR Playbooks

## When to Use
- New security alert received from SIEM, EDR, or other detection sources
- SOC analyst needs to determine if an alert is a true positive requiring response
- Incident needs severity classification and team assignment
- Multiple concurrent incidents require prioritization
- Automated triage rules need validation or tuning

## Prerequisites
- SIEM platform with alert correlation (Splunk, Elastic, QRadar, Sentinel)
- Incident response playbook library (by incident type)
- Severity classification matrix approved by CISO
- On-call rotation and escalation procedures
- Ticketing system for incident tracking (ServiceNow, Jira, TheHive)
- Threat intelligence feeds for IOC enrichment

## Workflow

### Step 1: Receive and Acknowledge Alert
```bash
# Query Splunk for new critical/high severity alerts
index=notable status=new severity IN ("critical","high")
| table _time, rule_name, src, dest, severity, description
| sort -_time

# Query TheHive for new cases
curl -s -H "Authorization: Bearer $THEHIVE_API_KEY" \
  "https://thehive.local/api/v1/query?name=list-alerts" \
  -H "Content-Type: application/json" \
  -d '{"query":[{"_name":"listAlert"},{"_name":"filter","_field":"status","_value":"New"}]}'

# Acknowledge alert in SIEM to prevent duplicate triage
curl -X POST "https://splunk.local:8089/services/notable_update" \
  -H "Authorization: Bearer $SPLUNK_TOKEN" \
  -d "ruleUIDs=$RULE_UID&status=1&comment=Triage+initiated+by+analyst"
```

### Step 2: Enrich Alert Data
```bash
# Enrich source IP with VirusTotal
curl -s "https://www.virustotal.com/api/v3/ip_addresses/$SRC_IP" \
  -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats'

# Check IP reputation with AbuseIPDB
curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$SRC_IP&maxAgeInDays=90" \
  -H "Key: $ABUSEIPDB_KEY" -H "Accept: application/json" | jq '.data'

# Enrich file hash with threat intelligence
curl -s "https://www.virustotal.com/api/v3/files/$FILE_HASH" \
  -H "x-apikey: $VT_API_KEY" | jq '.data.attributes.last_analysis_stats'

# Query internal asset database for affected systems
curl -s "https://cmdb.local/api/assets?ip=$DEST_IP" \
  -H "Authorization: Bearer $CMDB_TOKEN" | jq '.asset_criticality, .owner, .environment'
```

### Step 3: Classify Incident Type
```bash
# Map alert to incident category using playbook lookup
# Categories: Malware, Phishing, Unauthorized Access, Data Exfiltration,
# DoS/DDoS, Insider Threat, Ransomware, Account Compromise, Web Attack

# Check if alert matches known playbook trigger conditions
grep -i "$ALERT_SIGNATURE" /opt/ir/playbooks/trigger_conditions.yaml

# Determine incident type from MITRE ATT&CK technique
curl -s "https://attack.mitre.org/api/techniques/$TECHNIQUE_ID" | jq '.name, .tactic'
```

### Step 4: Assign Severity Level
```bash
# Severity matrix factors:
# 1. Asset criticality (Critical/High/Medium/Low)
# 2. Data sensitivity (PII/PHI/PCI/Confidential/Public)
# 3. Number of affected systems
# 4. Active vs historical threat
# 5. Confirmed vs suspected compromise

# Automated severity calculation
python3 -c "
severity_score = 0
# Asset criticality: Critical=4, High=3, Medium=2, Low=1
severity_score += 4  # Critical server
# Data sensitivity: PII/PHI=4, PCI=3, Confidential=2, Public=1
severity_score += 3  # PCI data
# Scope: Enterprise=4, Department=3, Single system=2, Single user=1
severity_score += 2  # Single system
# Threat status: Active=4, Recent=3, Historical=2, Potential=1
severity_score += 4  # Active threat

if severity_score >= 12: print('CRITICAL - P1')
elif severity_score >= 9: print('HIGH - P2')
elif severity_score >= 6: print('MEDIUM - P3')
else: print('LOW - P4')
print(f'Score: {severity_score}/16')
"
```

#### Asymmetric Loss Model

The simple additive severity score above provides initial triage, but real-world decision-making requires acknowledging that **miss costs and over-attribution costs are fundamentally asymmetric**.

```python
# Asymmetric Loss Model for Incident Prioritization
# Replaces simple severity addition with decision-theoretic framework

# Core principle: LAMBDA_MISS >> LAMBDA_OVER > 0
# Both MUST be non-zero (if LAMBDA_OVER=0, bounding probes have VOI≈0)
LAMBDA_MISS = 100    # Cost of missing a real attack (data breach, ransomware spread)
LAMBDA_OVER = 5      # Cost of over-attributing benign as attack (wasted IR resources)
# Ratio typically 10:1 to 50:1 depending on asset criticality

def expected_loss(p_attack, miss_risk, over_attr_risk):
    """
    Expected Loss = P(attack) × LAMBDA_MISS × miss_risk
                  + P(benign) × LAMBDA_OVER × over_attr_risk

    Where:
      - p_attack: current posterior probability that this is a true attack
      - miss_risk: probability of missing the attack given current investigation depth
      - over_attr_risk: probability of over-attributing given current evidence
    """
    p_benign = 1 - p_attack
    loss = (p_attack * LAMBDA_MISS * miss_risk) + (p_benign * LAMBDA_OVER * over_attr_risk)
    return loss

# Example: Alert with 70% attack probability
loss = expected_loss(p_attack=0.7, miss_risk=0.3, over_attr_risk=0.2)
print(f"Expected Loss: {loss:.1f}")
print(f"  Miss component: {0.7 * LAMBDA_MISS * 0.3:.1f}")
print(f"  Over-attr component: {0.3 * LAMBDA_OVER * 0.2:.1f}")
print(f"")
print("WHY both lambdas must be non-zero:")
print("  If LAMBDA_OVER=0: no cost to investigate everything → VOI of bounding probes ≈ 0")
print("  If LAMBDA_MISS=0: no cost to ignoring attacks → everything dismissed as benign")
print("  Non-zero LAMBDA_OVER ensures we value EFFICIENT investigation, not just thoroughness")
```

**Key Principles:**
- LAMBDA_MISS ≫ LAMBDA_OVER: Missing a real attack is far costlier than over-investigating
- Both lambdas MUST be non-zero: LAMBDA_OVER=0 makes bounding probes worthless (VOI≈0)
- This model replaces the simple P1-P4 ranking with a continuous expected-loss metric
- Incidents are ranked by expected loss, not arbitrary severity scores

### Step 5: Select and Initiate Playbook
```bash
# Load appropriate playbook based on incident type
cat /opt/ir/playbooks/ransomware_playbook.yaml
cat /opt/ir/playbooks/phishing_playbook.yaml
cat /opt/ir/playbooks/unauthorized_access_playbook.yaml

# Create incident ticket in TheHive
curl -X POST "https://thehive.local/api/v1/case" \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "IR-2024-XXX: [Incident Type] - [Brief Description]",
    "description": "Triage summary and initial findings",
    "severity": 3,
    "tlp": 2,
    "pap": 2,
    "tags": ["ransomware", "triage-complete"],
    "customFields": {
      "playbook": {"string": "ransomware_v2"},
      "affected_systems": {"integer": 5}
    }
  }'
```

#### Four-Exit Decision Model

Replace binary "escalate or close" with four distinct exits. Each exit has different evidence requirements:

| Exit | Meaning | Evidence Requirement |
|------|---------|---------------------|
| **CONTAIN / ESCALATE** | Confirmed or high-probability attack → activate containment | P(attack) > threshold OR critical asset at risk |
| **MONITOR** | Insufficient evidence to confirm or dismiss → add instrumentation | Unresolved obligations remain, margin between hypotheses too small |
| **DISMISS-BENIGN** | Confirmed benign activity, not an attack | Requires **triple gate**: (1) forge-resistant evidence contradicts attack, (2) all structural obligations resolved, (3) absence-as-signal scan clean |
| **BRANCH-PRUNE** | Specific attack hypothesis eliminated, others remain | Single hypothesis eliminated by forge-resistant VETO, but case continues under remaining hypotheses |

**Critical Rule for DISMISS-BENIGN (Triple Gate):**
1. At least one forge-resistant evidence item directly contradicts the attack hypothesis
2. All four obligation types (structural/lifecycle/anti-forensics/discriminative) are resolved
3. Absence-as-signal scan found no unexplained missing artifacts

Dismiss-benign is the **rarest** exit — most alerts resolve via contain/escalate or monitor.

### Step 6: Assign Response Team
```bash
# Check on-call schedule
curl -s "https://pagerduty.com/api/v2/oncalls?schedule_ids[]=$SCHEDULE_ID" \
  -H "Authorization: Token token=$PD_TOKEN" | jq '.oncalls[].user.summary'

# Page incident responders based on severity
# P1/Critical: Page IR lead + senior analysts + CISO
# P2/High: Page IR lead + available analysts
# P3/Medium: Assign to next available analyst
# P4/Low: Queue for business hours processing

curl -X POST "https://events.pagerduty.com/v2/enqueue" \
  -H "Content-Type: application/json" \
  -d '{
    "routing_key": "'$PD_ROUTING_KEY'",
    "event_action": "trigger",
    "payload": {
      "summary": "P1 Security Incident: Ransomware detected on PROD-DB-01",
      "severity": "critical",
      "source": "SIEM-Splunk",
      "custom_details": {"incident_id": "IR-2024-042", "playbook": "ransomware_v2"}
    }
  }'
```

### Step 7: Document Triage Decision and Hand Off
```bash
# Update incident ticket with triage summary
curl -X PATCH "https://thehive.local/api/v1/case/$CASE_ID" \
  -H "Authorization: Bearer $THEHIVE_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "status": "InProgress",
    "customFields": {
      "triage_analyst": {"string": "analyst_name"},
      "triage_time": {"date": '$(date +%s000)'},
      "severity_justification": {"string": "Critical asset + active threat + PCI data"}
    }
  }'
```

### Step 8: Four-Type Obligation Scan

Before finalizing triage, systematically scan for unresolved obligations across four categories. Each unresolved obligation blocks the "stop investigation" exit.

```python
# Four-Type Obligation Scanner
import json
from datetime import datetime

obligations = []

# === 1. STRUCTURAL OBLIGATIONS ===
# Are there malicious orphans (events with no traced origin)?
# Are there bridging hosts (systems connecting two otherwise-separate attack segments)?
# Are there dangling credentials (compromised accounts not yet contained)?
def scan_structural_obligations(case_data):
    checks = [
        ('Malicious orphan event', 'Malicious event E-042 has no traced parent process or source',
         'Find the origin of this event or mark as unexplained anomaly'),
        ('Bridging host', 'Host WKS-15 connects initial access segment to lateral movement segment',
         'Fully investigate WKS-15 to confirm or deny bridging role'),
        ('Dangling credential', 'Account svc-backup compromised but not disabled/rotated',
         'Contain credential before stopping investigation')
    ]
    for name, trigger, action in checks:
        obligations.append({
            'type': 'STRUCTURAL',
            'trigger': trigger,
            'priority': 'HIGH',
            'blocks_stopping': 'YES',
            'action': action
        })

# === 2. LIFECYCLE OBLIGATIONS ===
# Which kill-chain phases of the leading hypothesis are unconfirmed?
def scan_lifecycle_obligations(case_data):
    kill_chain_phases = ['Initial Access', 'Execution', 'Persistence',
                        'Privilege Escalation', 'Lateral Movement',
                        'Collection', 'Exfiltration', 'Impact']
    confirmed = ['Initial Access', 'Execution', 'Lateral Movement']
    unconfirmed = [p for p in kill_chain_phases if p not in confirmed]
    for phase in unconfirmed:
        obligations.append({
            'type': 'LIFECYCLE',
            'trigger': f'Kill-chain phase "{phase}" unconfirmed in leading hypothesis',
            'priority': 'MEDIUM' if phase in ['Collection', 'Impact'] else 'LOW',
            'blocks_stopping': 'YES' if phase in ['Persistence', 'Privilege Escalation'] else 'NO',
            'action': f'Seek evidence for or against {phase} phase'
        })

# === 3. ANTI-FORENSICS OBLIGATIONS ===
# Were logs cleared? Time anomalies detected? Audit configs modified?
def scan_anti_forensics_obligations(case_data):
    af_indicators = [
        ('Event ID 1102 detected', 'Security log cleared at 2024-01-18 03:00', 'HIGH'),
        ('Time gap in auth.log', '4h gap between 02:15 and 06:38 on compromised host', 'HIGH'),
        ('auditd rules modified', 'Rule removed: -w /etc/shadow -p wa', 'MEDIUM')
    ]
    for indicator, evidence, priority in af_indicators:
        obligations.append({
            'type': 'ANTI-FORENSICS',
            'trigger': f'{indicator}: {evidence}',
            'priority': priority,
            'blocks_stopping': 'YES',
            'action': 'Investigate anti-forensics indicator, switch to remote log sources'
        })

# === 4. DISCRIMINATIVE OBLIGATIONS ===
# Is the margin between leading and runner-up hypotheses too small?
def scan_discriminative_obligations(case_data):
    leading_hypothesis_prob = 0.55  # H1: Ransomware precursor
    runner_up_prob = 0.35           # H2: Legitimate admin activity
    margin = leading_hypothesis_prob - runner_up_prob
    if margin < 0.3:  # Threshold for confident decision
        obligations.append({
            'type': 'DISCRIMINATIVE',
            'trigger': f'Hypothesis margin too small: H1={leading_hypothesis_prob:.0%} vs H2={runner_up_prob:.0%} (margin={margin:.0%} < 30%)',
            'priority': 'HIGH',
            'blocks_stopping': 'YES',
            'action': 'Design discriminative probe that would differentiate H1 from H2'
        })

# Run all scans
scan_structural_obligations({})
scan_lifecycle_obligations({})
scan_anti_forensics_obligations({})
scan_discriminative_obligations({})

# Output Obligation Table
print("FOUR-TYPE OBLIGATION SCAN RESULTS")
print("=" * 90)
print(f"{'Type':<18} {'Trigger':<45} {'Priority':<10} {'Blocks Stopping?'}")
print("-" * 90)
for ob in obligations:
    print(f"{ob['type']:<18} {ob['trigger'][:43]:<45} {ob['priority']:<10} {ob['blocks_stopping']}")

blocking = [o for o in obligations if o['blocks_stopping'] == 'YES']
print(f"\nTotal obligations: {len(obligations)}")
print(f"Blocking obligations (prevent case closure): {len(blocking)}")
print("\nCase CANNOT be stopped/dismissed while blocking obligations remain unresolved.")
```

### Step 9: Value × Urgency Scheduling

Prioritize investigation actions using Value × Urgency rather than pure severity or deadline proximity.

```python
# Value × Urgency Scheduler
# Replaces simple severity ordering with VOI-based scheduling
import math

def calculate_voi(obligation):
    """Value of Information: how much resolving this obligation reduces expected loss."""
    voi_map = {
        'STRUCTURAL': 8.0,      # High: orphans/bridges can change entire narrative
        'ANTI-FORENSICS': 9.0,  # Very high: affects trust of all other evidence
        'DISCRIMINATIVE': 7.0,  # High: resolves hypothesis ambiguity
        'LIFECYCLE': 4.0        # Moderate: fills narrative gaps
    }
    base_voi = voi_map.get(obligation['type'], 5.0)
    priority_multiplier = {'HIGH': 1.5, 'MEDIUM': 1.0, 'LOW': 0.6}
    return base_voi * priority_multiplier.get(obligation['priority'], 1.0)

def calculate_urgency(obligation, hours_to_deadline):
    """Urgency increases as deadline approaches, but caps at finite value."""
    if hours_to_deadline <= 0:
        return 10.0  # Past deadline
    return min(10.0, 1.0 / (hours_to_deadline / 24.0))  # Normalized

def schedule_obligations(obligations, budget_slots):
    """Schedule by primary key = VOI / time_to_deadline.
    Pre-emption cap: at most ceil(B/2) slots for urgent items."""
    preempt_cap = math.ceil(budget_slots / 2)

    scored = []
    for i, ob in enumerate(obligations):
        hours_left = 48 - (i * 4)  # Simulated deadlines
        voi = calculate_voi(ob)
        urgency = calculate_urgency(ob, hours_left)
        score = voi * urgency  # Combined priority score
        scored.append((score, voi, urgency, ob))

    # Sort by combined score descending
    scored.sort(key=lambda x: x[0], reverse=True)

    print("VALUE × URGENCY SCHEDULE")
    print("=" * 80)
    print(f"Budget slots: {budget_slots} | Pre-emption cap: {preempt_cap}")
    print(f"{'Rank':<6} {'Score':<8} {'VOI':<6} {'Urg':<6} {'Type':<18} {'Trigger (truncated)'}")
    print("-" * 80)

    urgent_count = 0
    for rank, (score, voi, urgency, ob) in enumerate(scored[:budget_slots], 1):
        is_urgent_preempt = urgency > 5.0 and voi < 5.0
        if is_urgent_preempt:
            urgent_count += 1
            if urgent_count > preempt_cap:
                continue  # Skip low-value urgent items beyond cap
        print(f"{rank:<6} {score:<8.1f} {voi:<6.1f} {urgency:<6.1f} {ob['type']:<18} {ob['trigger'][:40]}")

    print(f"\nPrinciple: High-VOI obligations execute first even if deadline is far.")
    print(f"Low-value obligations do NOT preempt critical ones regardless of urgency.")
    print(f"Pre-emption cap ⌈B/2⌉ = {preempt_cap} prevents urgency-only items from dominating.")

schedule_obligations(obligations, budget_slots=8)
```

**Scheduling Principles:**
- Primary key: `VOI(obligation) / time_to_deadline`
- High-value obligations execute first, even if their deadline is distant
- Low-value obligations near deadline do NOT preempt critical high-value work
- Pre-emption cap: at most ⌈B/2⌉ slots allocated to urgency-driven (low-VOI) items
- This prevents the "tyranny of the urgent" where trivial deadlines crowd out important investigation

## Key Concepts

| Concept | Description |
|---------|-------------|
| True Positive | Alert correctly identifying a real security incident |
| False Positive | Alert incorrectly flagging benign activity as malicious |
| Severity Classification | Ranking incident priority based on impact and urgency |
| Playbook Selection | Choosing the appropriate response procedure based on incident type |
| IOC Enrichment | Adding context to indicators from threat intelligence sources |
| Escalation Threshold | Criteria triggering escalation to higher severity or management |
| Triage SLA | Time target for initial assessment (typically 15-30 min for critical) |
| Asymmetric Loss Model | Decision framework where LAMBDA_MISS ≫ LAMBDA_OVER, replacing simple severity scores with expected-loss calculation |
| Four-Type Obligations | Structural / Lifecycle / Anti-Forensics / Discriminative debts that must be resolved before case closure |
| Value × Urgency Scheduling | Prioritization by VOI/time_to_deadline rather than pure severity; prevents low-value urgent items from preempting critical work |
| Four-Exit Decision Model | Contain-escalate / Monitor / Dismiss-benign (triple gate) / Branch-prune — replaces binary escalate-or-close |
| MANDATE | Investigation obligation generated by detected anomaly that blocks the "stop" exit until resolved |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| Splunk/Elastic/QRadar | SIEM alert correlation and querying |
| TheHive/SIRP | Incident case management and playbook tracking |
| VirusTotal/AbuseIPDB | IOC reputation and enrichment |
| PagerDuty/OpsGenie | On-call management and alerting |
| MITRE ATT&CK | Technique classification and mapping |
| Cortex XSOAR | SOAR platform for automated triage workflows |

## Common Scenarios

1. **Brute Force Alert**: Multiple failed logins from single IP. Enrich IP reputation, check geo-location, verify if account was compromised, assign P3 if unsuccessful.
2. **Malware Detection on Endpoint**: AV/EDR quarantined malware. Verify quarantine success, check for lateral movement, assign P2 if persistence detected.
3. **Suspicious Outbound Traffic**: Large data transfer to unknown external IP. Check if known cloud service, verify data classification, assign P1 if exfiltration confirmed.
4. **Phishing Email Reported**: User reports suspicious email. Extract IOCs, check if others received it, assign P2 if credentials were entered.
5. **Privilege Escalation**: User gained admin rights unexpectedly. Verify if authorized change, check for exploitation, assign P1 if unauthorized.

## Output Format
- Triage decision document with severity justification
- Incident ticket with assigned playbook and team
- IOC enrichment summary attached to case
- Escalation notification to appropriate stakeholders
- Initial timeline of events from alert data
