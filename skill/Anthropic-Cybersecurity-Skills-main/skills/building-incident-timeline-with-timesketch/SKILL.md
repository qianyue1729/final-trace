---
name: building-incident-timeline-with-timesketch
description: Build collaborative forensic incident timelines using Timesketch to ingest,
  normalize, and analyze multi-source event data for attack chain reconstruction and
  investigation documentation.
domain: cybersecurity
subdomain: incident-response
tags:
- timesketch
- timeline-analysis
- forensic-timeline
- plaso
- dfir
- incident-investigation
- collaborative-forensics
- session-graph
- causal-subgraph
- boundary-belief
- explanation-attribution
mitre_attack:
- T1059.001
- T1021.002
- T1547.001
- T1053.005
- T1070.006
version: '1.0'
author: mahipal
license: Apache-2.0
d3fend_techniques:
- Executable Denylisting
- Execution Isolation
- File Metadata Consistency Validation
- Content Format Conversion
- File Content Analysis
nist_csf:
- RS.MA-01
- RS.MA-02
- RS.AN-03
- RC.RP-01
---

# Building Incident Timeline with Timesketch

## Overview

Timesketch is an open-source collaborative forensic timeline analysis tool developed by Google that enables security teams to visualize and analyze chronological data from multiple sources during incident investigations. It ingests logs and artifacts from endpoints, servers, and cloud services, normalizes them into a unified searchable timeline, and provides powerful analysis capabilities including built-in analyzers, tagging, sketch annotations, and story building. Timesketch integrates with Plaso (log2timeline) for artifact parsing and supports direct CSV/JSONL ingestion for rapid timeline construction during active incidents.


## When to Use

- When deploying or configuring building incident timeline with timesketch capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Prerequisites

- Familiarity with incident response concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Architecture and Components

### Core Components
- **Timesketch Server**: Web application with REST API for timeline management
- **OpenSearch/Elasticsearch**: Backend storage and search engine for timeline events
- **PostgreSQL**: Metadata storage for sketches, stories, and user data
- **Redis**: Task queue management for background processing
- **Celery Workers**: Asynchronous processing of timeline uploads and analyzers

### Data Flow
```
Evidence Sources --> Plaso/log2timeline --> Plaso storage file (.plaso)
     |                                           |
     v                                           v
  CSV/JSONL --> Timesketch Importer --> OpenSearch Index
                                           |
                                           v
                                    Timesketch Web UI
                                    (Search, Analyze, Story)
```

## Deployment

### Docker Deployment (Recommended)
```bash
# Clone Timesketch repository
git clone https://github.com/google/timesketch.git
cd timesketch

# Run deployment helper script
cd docker
sudo docker compose up -d

# Default access: https://localhost:443
# Admin credentials generated during first run
```

### System Requirements
- Minimum 8 GB RAM (16+ GB recommended for large investigations)
- 4 CPU cores minimum
- SSD storage for OpenSearch indices
- Docker and Docker Compose installed

## Data Ingestion Methods

### Method 1: Plaso Integration (Comprehensive)
```bash
# Process disk image with log2timeline
log2timeline.py --storage-file evidence.plaso /path/to/disk/image

# Process Windows event logs
log2timeline.py --parsers winevtx --storage-file windows_events.plaso /path/to/evtx/

# Process multiple evidence sources
log2timeline.py --parsers "winevtx,prefetch,amcache,shimcache,userassist" \
  --storage-file full_analysis.plaso /path/to/mounted/image/

# Import Plaso file into Timesketch
timesketch_importer -s "Case-2025-001" -t "Endpoint-WKS01" evidence.plaso
```

### Method 2: CSV Import (Quick Ingestion)
```csv
message,datetime,timestamp_desc,source,hostname
"User login detected","2025-01-15T08:30:00Z","Event Recorded","Security Log","DC01"
"PowerShell execution","2025-01-15T08:31:15Z","Event Recorded","PowerShell","WKS042"
```

```bash
# Import CSV directly
timesketch_importer -s "Case-2025-001" -t "Quick-Triage" events.csv
```

### Method 3: JSONL Import (Structured Data)
```json
{"message": "Suspicious logon from 10.1.2.3", "datetime": "2025-01-15T08:30:00Z", "timestamp_desc": "Event Recorded", "source_short": "Security", "hostname": "DC01"}
```

### Method 4: Sigma Rule Integration
```bash
# Upload Sigma rules for automated detection
timesketch_importer --sigma-rules /path/to/sigma/rules/
```

## Analysis Workflow

### Step 1: Create Investigation Sketch
```
1. Log into Timesketch web interface
2. Create new sketch (investigation case)
3. Add relevant timelines to the sketch
4. Set sketch description and tags
```

### Step 2: Run Built-in Analyzers
Timesketch includes analyzers that automatically identify:
- **Browser Search Analyzer**: Extracts search queries from browser history
- **Chain of Events Analyzer**: Links related events (download -> execute)
- **Domain Analyzer**: Extracts and categorizes domain names
- **Feature Extraction Analyzer**: Identifies IPs, URLs, hashes
- **Geo Location Analyzer**: Maps events to geographic locations
- **Similarity Scorer**: Finds similar events across timelines
- **Sigma Analyzer**: Matches events against Sigma detection rules
- **Account Finder**: Identifies user account activity patterns
- **Tagger**: Applies labels based on predefined rules

### Step 3: Search and Filter
```
# Search examples in Timesketch query language

# Find all events related to specific user
source_short:Security AND message:"john.admin"

# Find PowerShell execution events
data_type:"windows:evtx:record" AND event_identifier:4104

# Find lateral movement indicators
source_short:Security AND event_identifier:4624 AND xml_string:"LogonType\">3"

# Find events within specific time range
datetime:[2025-01-15T00:00:00 TO 2025-01-15T23:59:59]

# Find file creation events
data_type:"fs:stat" AND timestamp_desc:"Creation Time"

# Search with tags
tag:"suspicious" OR tag:"lateral_movement"
```

### Step 4: Build Investigation Story
```
1. Create new story within the sketch
2. Add search views that support each finding
3. Annotate key events with investigator notes
4. Link events to MITRE ATT&CK techniques
5. Document the attack narrative chronologically
6. Export story for inclusion in incident report
```

### Step 5: Explanation Attribution Annotation

Annotate each timeline event with its attribution to one or more competing explanations (hypotheses). This transforms the timeline from a flat chronology into an evidence-hypothesis map.

```python
from timesketch_api_client import client as ts_client

# Connect to Timesketch
ts = ts_client.TimesketchApi(
    host_uri="https://timesketch.local",
    username="analyst",
    password="password"
)
sketch = ts.get_sketch(1)

# Attribution tag schema:
# attr:H1-<hypothesis_name>  - Event supports Hypothesis 1
# attr:H2-<hypothesis_name>  - Event supports Hypothesis 2
# attr:null-benign           - Event is benign/irrelevant
# attr:null-oos              - Event is out-of-scope (real malicious but different incident)

# Example: Tag events with hypothesis attribution
attribution_rules = [
    {
        'query': 'event_identifier:4624 AND LogonType:3 AND source_ip:"10.1.2.99"',
        'tags': ['attr:H1-ransomware-precursor'],
        'confidence': 0.75,
        'note': 'Lateral movement from known-compromised host supports ransomware hypothesis'
    },
    {
        'query': 'event_identifier:4624 AND LogonType:3 AND source_ip:"10.1.2.99" AND user:"svc-backup"',
        'tags': ['attr:H1-ransomware-precursor', 'attr:H2-legitimate-backup'],
        'confidence': None,  # Contested - belongs to both hypotheses
        'note': 'Service account logon is consistent with BOTH attack and normal backup operations'
    },
    {
        'query': 'event_identifier:4698 AND TaskName:"SystemHealthCheck"',
        'tags': ['attr:H1-ransomware-precursor'],
        'confidence': 0.85,
        'note': 'Scheduled task creation matches known ransomware TTP'
    },
    {
        'query': 'event_identifier:4688 AND CommandLine:"robocopy"',
        'tags': ['attr:null-benign'],
        'confidence': 0.90,
        'note': 'Known legitimate backup script, pre-existing before incident window'
    }
]

for rule in attribution_rules:
    results = sketch.explore(query_string=rule['query'])
    for event in results.get('objects', []):
        # Apply attribution tags
        sketch.tag_event(event['_id'], rule['tags'])
        # Add confidence annotation as comment
        if rule['confidence']:
            sketch.comment_event(
                event['_id'],
                f"Attribution confidence: {rule['confidence']:.0%} | {rule['note']}"
            )
        else:
            sketch.comment_event(
                event['_id'],
                f"CONTESTED: Multi-hypothesis attribution | {rule['note']}"
            )

print("Attribution annotation complete.")
print("Events with multiple attr: tags are CONTESTED and require discriminative probes.")
```

**Attribution Principles:**
- Every event gets at least one `attr:` tag (no unattributed events in final timeline)
- Contested events carry multiple tags with confidence weight annotations
- `attr:null-benign` = confirmed irrelevant to any attack hypothesis
- `attr:null-oos` = malicious but belonging to a different incident (out-of-scope)
- Events with multiple competing attributions are priority targets for discriminative probes

### Step 6: Causal Subgraph Construction

Upgrade the linear timeline into a causal directed graph (SessionGraph) where edges represent causal relationships, not mere temporal proximity.

```python
import json
from datetime import datetime

# Causal Subgraph (SessionGraph) Construction
# Each edge represents: A CAUSED B (not just A preceded B)

session_graph = {
    'nodes': [],
    'edges': [],
    'metadata': {
        'case_id': 'IR-2024-042',
        'created': datetime.utcnow().isoformat(),
        'graph_type': 'SessionGraph-CausalSubgraph'
    }
}

# Define causal edges with trust annotations
causal_edges = [
    {
        'source': 'E001-phishing-email-received',
        'target': 'E002-malicious-attachment-opened',
        'direction': 'forward',  # A caused B
        'confidence': 0.95,
        'evidence_trust': 'HIGH',  # Email server log is forge-resistant
        'relationship': 'Phishing email delivery caused user to open attachment',
        'evidence_source': 'Exchange message tracking log (remote, non-compromised)'
    },
    {
        'source': 'E002-malicious-attachment-opened',
        'target': 'E003-powershell-execution',
        'direction': 'forward',
        'confidence': 0.90,
        'evidence_trust': 'MEDIUM-HIGH',  # Sysmon on compromised host
        'relationship': 'Macro execution spawned PowerShell process',
        'evidence_source': 'Sysmon Event ID 1 (process creation with parent)'
    },
    {
        'source': 'E003-powershell-execution',
        'target': 'E004-c2-beacon-established',
        'direction': 'forward',
        'confidence': 0.85,
        'evidence_trust': 'HIGH',  # Network firewall log
        'relationship': 'PowerShell downloaded and executed C2 stager',
        'evidence_source': 'Firewall log (independent infrastructure)'
    },
    {
        'source': 'E004-c2-beacon-established',
        'target': 'E005-credential-dump',
        'direction': 'forward',
        'confidence': 0.70,
        'evidence_trust': 'MEDIUM',  # Security.evtx on compromised host
        'relationship': 'C2 operator used beacon to dump credentials',
        'evidence_source': 'Security.evtx Event 4648 (compromised host - medium trust)'
    },
    {
        'source': 'E005-credential-dump',
        'target': 'E006-lateral-movement',
        'direction': 'forward',
        'confidence': 0.60,  # Lower confidence - gap in evidence
        'evidence_trust': 'CONTESTED',
        'relationship': 'Stolen credentials used for lateral movement (time gap exists)',
        'evidence_source': 'DC Security.evtx + network flow (partial corroboration)'
    }
]

# Build graph
for edge in causal_edges:
    session_graph['nodes'].append({'id': edge['source'], 'type': 'event'})
    session_graph['nodes'].append({'id': edge['target'], 'type': 'event'})
    session_graph['edges'].append(edge)

# Deduplicate nodes
seen = set()
session_graph['nodes'] = [n for n in session_graph['nodes']
                          if n['id'] not in seen and not seen.add(n['id'])]

# Export as DOT format for visualization
def export_dot(graph):
    dot = 'digraph SessionGraph {\n'
    dot += '  rankdir=LR;\n'
    dot += '  node [shape=box];\n'
    for edge in graph['edges']:
        label = f"{edge['confidence']:.0%} [{edge['evidence_trust']}]"
        color = 'red' if edge['evidence_trust'] == 'CONTESTED' else 'black'
        dot += f'  "{edge["source"]}" -> "{edge["target"]}" '
        dot += f'[label="{label}" color="{color}"];\n'
    dot += '}\n'
    return dot

# Export as JSON for Timesketch graph view
with open('/cases/IR-2024-042/session_graph.json', 'w') as f:
    json.dump(session_graph, f, indent=2)

with open('/cases/IR-2024-042/session_graph.dot', 'w') as f:
    f.write(export_dot(session_graph))

print(f"SessionGraph: {len(session_graph['nodes'])} nodes, {len(session_graph['edges'])} causal edges")
print("Edges with CONTESTED trust require additional corroboration before hard conclusions.")
```

**Causal Subgraph Principles:**
- Edges represent **causation** (A caused B), not temporal sequence (A preceded B)
- Each edge carries: direction / confidence / evidence_trust
- Low-confidence edges identify gaps in the causal narrative
- CONTESTED edges are priority targets for additional evidence collection
- Export as DOT/JSON for visualization and integration with Timesketch graph features

### Step 7: Boundary Dispute Annotation

For contested edges and pivot points, annotate with BoundaryBelief probability vectors that capture uncertainty about whether an event belongs to the attack chain.

```python
# Boundary Dispute Annotation
# For each contested event/edge, assign probability distribution:
#   p_in_attack: probability this belongs to the attack chain
#   p_benign:    probability this is benign domain-internal activity
#   p_oos:       probability this is real malicious but out-of-scope (different incident)

boundary_disputes = [
    {
        'edge_id': 'E005->E006',
        'description': 'Credential dump to lateral movement (4h time gap)',
        'boundary_belief': {
            'p_in_attack': 0.55,  # Probably part of attack but gap is suspicious
            'p_benign': 0.15,     # Could be legitimate admin using same account
            'p_oos': 0.30         # Could be a DIFFERENT attacker using same creds
        },
        'dispute_reason': 'Time gap + credential reuse pattern ambiguous',
        'discriminative_probe': 'Check if C2 beacon was active during the gap period (network flow)'
    },
    {
        'edge_id': 'E003->E004',
        'description': 'PowerShell to C2 beacon establishment',
        'boundary_belief': {
            'p_in_attack': 0.85,
            'p_benign': 0.10,  # Could be legitimate admin tool with similar network pattern
            'p_oos': 0.05
        },
        'dispute_reason': 'Destination IP not in known C2 lists but JA3 matches known framework',
        'discriminative_probe': 'Passive DNS history of destination + TLS cert analysis'
    },
    {
        'edge_id': 'E006->E007-data-staging',
        'description': 'Lateral movement to data staging on file server',
        'boundary_belief': {
            'p_in_attack': 0.45,
            'p_benign': 0.40,  # svc-backup account legitimately accesses file shares
            'p_oos': 0.15
        },
        'dispute_reason': 'Access pattern matches both attack staging AND normal backup job',
        'discriminative_probe': 'Compare file access list with normal backup manifest - delta reveals attack-specific files'
    }
]

# Identify high-dispute edges (where probabilities are close to uniform)
def entropy(belief):
    """Shannon entropy of belief vector - higher = more uncertain."""
    import math
    values = [v for v in belief.values() if v > 0]
    return -sum(p * math.log2(p) for p in values)

max_entropy = 1.585  # log2(3) for uniform distribution over 3 outcomes

print("CONTESTED EDGES TABLE (Boundary Disputes)")
print("=" * 95)
print(f"{'Edge':<20} {'p_attack':<10} {'p_benign':<10} {'p_oos':<8} {'Entropy':<8} {'Needs Probe?'}")
print("-" * 95)

for dispute in boundary_disputes:
    b = dispute['boundary_belief']
    h = entropy(b)
    needs_probe = "YES - HIGH PRIORITY" if h > (max_entropy * 0.7) else "Monitor"
    print(f"{dispute['edge_id']:<20} {b['p_in_attack']:<10.2f} {b['p_benign']:<10.2f} "
          f"{b['p_oos']:<8.2f} {h:<8.2f} {needs_probe}")
    if h > (max_entropy * 0.7):
        print(f"  → Discriminative probe: {dispute['discriminative_probe']}")

print(f"\nDispute threshold: entropy > {max_entropy * 0.7:.2f} (70% of max entropy)")
print("High-entropy edges block confident narrative construction.")
print("Each generates a DISCRIMINATIVE OBLIGATION requiring a targeted probe.")

# Apply boundary annotations in Timesketch
for dispute in boundary_disputes:
    # Tag contested events
    b = dispute['boundary_belief']
    tag = f"boundary-dispute:H={entropy(b):.2f}"
    annotation = (f"BoundaryBelief: p_attack={b['p_in_attack']:.2f}, "
                  f"p_benign={b['p_benign']:.2f}, p_oos={b['p_oos']:.2f} | "
                  f"Probe: {dispute['discriminative_probe']}")
    print(f"\nAnnotating {dispute['edge_id']}: {annotation}")
```

**Boundary Dispute Principles:**
- Every contested edge gets a BoundaryBelief vector: (p_in_attack, p_benign, p_oos)
- High entropy (close to uniform distribution) = high dispute = needs discriminative probe
- Probes are designed to maximally shift the belief vector in one direction
- Dispute resolution is a DISCRIMINATIVE OBLIGATION that blocks confident narrative
- The three categories are exhaustive: attack-chain / benign-in-scope / out-of-scope-malicious

## Key Concepts

| Concept | Description |
|---------|-------------|
| SessionGraph | Causal directed graph representing attack chain relationships (not just temporal sequence); edges are causation, not correlation |
| Explanation Attribution | Annotation system linking each timeline event to one or more competing hypotheses with confidence weights |
| Causal Subgraph | Directed acyclic graph where edges represent proven or suspected causal relationships between events, each annotated with confidence and evidence trust |
| BoundaryBelief | Three-component probability vector (p_in_attack, p_benign, p_oos) expressing uncertainty about whether a contested event belongs to the attack chain |

## Advanced Features

### Collaborative Investigation
- Multiple analysts work on the same sketch simultaneously
- Comments and annotations persist on events
- Saved searches shared across the team
- Investigation stories document findings in context

### API Automation
```python
from timesketch_api_client import config
from timesketch_api_client import client as ts_client

# Connect to Timesketch
ts = ts_client.TimesketchApi(
    host_uri="https://timesketch.local",
    username="analyst",
    password="password"
)

# Get sketch
sketch = ts.get_sketch(1)

# Search events
search = sketch.explore(
    query_string='event_identifier:4624 AND LogonType:3',
    return_fields='datetime,message,hostname,source_short'
)

# Add tags to events
for event in search.get('objects', []):
    sketch.tag_event(event['_id'], ['lateral_movement'])
```

### Integration with Dissect
```bash
# Use Dissect for faster artifact parsing (alternative to Plaso)
target-query -f timesketch://timesketch.local/case-001 \
  targets/hostname/ -q "windows.evtx" --limit 0
```

## Key Data Sources for Timeline Building

| Source | Parser | Evidence Value |
|--------|--------|---------------|
| Windows Event Logs (.evtx) | winevtx | Authentication, process execution, services |
| Prefetch Files | prefetch | Program execution history |
| MFT ($MFT) | mft | File system activity |
| Registry Hives | winreg | System configuration, persistence |
| Browser History | chrome/firefox | Web activity, downloads |
| Syslog | syslog | Linux/network device events |
| CloudTrail Logs | jsonl | AWS API activity |
| Azure Activity Logs | jsonl | Azure resource operations |
| Firewall Logs | csv/jsonl | Network connections |
| Proxy Logs | csv/jsonl | HTTP/HTTPS traffic |

## MITRE ATT&CK Mapping

| Technique | Timeline Indicators |
|-----------|-------------------|
| Initial Access (TA0001) | First malicious event, phishing email receipt |
| Execution (T1059) | PowerShell/CMD events, process creation |
| Persistence (TA0003) | Registry modifications, scheduled tasks, services |
| Lateral Movement (TA0008) | Remote logons, SMB connections, RDP sessions |
| Exfiltration (TA0010) | Large data transfers, cloud storage uploads |

## References

- [Timesketch Official Documentation](https://timesketch.org/)
- [Timesketch GitHub Repository](https://github.com/google/timesketch)
- [CISA Timesketch Resource](https://www.cisa.gov/resources-tools/services/timesketch)
- [Hunt and Hackett: Scalable Forensics with Dissect and Timesketch](https://www.huntandhackett.com/blog/scalable-forensics-timeline-analysis-using-dissect-and-timesketch)
- [Plaso (log2timeline) Documentation](https://plaso.readthedocs.io/)
- [RFC-004-02: LOCK + Decision Ledger Framework](../../docs/RFC-004-02.md)
