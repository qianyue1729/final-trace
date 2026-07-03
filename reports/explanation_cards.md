# admin_high_anomaly

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# admin_powershell_inventory

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# ambiguous_discovery

# Seed Explanation Cards — T1083

**Null anchor:** benign=0.45 oos=0.15

### H1 — T1083 fits insider_misuse_v1:discovery

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `insider_misuse_v1`
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1083 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1083 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1083 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# atomic_red_team_sim

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# backup_registry_touch

# Seed Explanation Cards — T1112

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1112 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1112 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1112 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1112 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# backup_smb

# Seed Explanation Cards — T1021.002

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1021.002 fits ransomware_enterprise_v1:lateral_movement

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H2 — T1021.002 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H3 — T1021.002 preceded by credential-access (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H4 — T1021.002 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** True


---

# c2_beacon

# Seed Explanation Cards — T1071.001

**Null anchor:** benign=0.45 oos=0.15

### H1 — T1071.001 fits commodity_malware_v1:command_and_control

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1071.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1071.001 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1071.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# cert_rotation_iam

# Seed Explanation Cards — T1078.004

**Null anchor:** benign=0.35 oos=0.25

### H1 — T1078.004 fits credential_theft_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1078.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1078.004 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1078.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# cicd_bash_curl

# Seed Explanation Cards — T1059.004

**Null anchor:** benign=0.55 oos=0.15

### H1 — T1059.004 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.004 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# cloud_assume_role_normal

# Seed Explanation Cards — T1078.004

**Null anchor:** benign=0.35 oos=0.25

### H1 — T1078.004 fits credential_theft_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1078.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1078.004 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1078.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# cloud_iam_anomaly

# Seed Explanation Cards — T1098

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1098 fits cloud_compromise_v1:privilege_escalation

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `cloud_compromise_v1`
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1098 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1098 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1098 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- dual-use tool involved
- single or sparse log source mapping
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# cloud_s3_exfil

# Seed Explanation Cards — T1537

**Null anchor:** benign=0.2 oos=0.25

### H1 — T1537 fits ransomware_enterprise_v1:exfiltration

**Prior:** 0.52 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1537 preceded by collection (L1 tactic prior)

**Prior:** 0.48 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3


---

# cloud_terraform_apply

# Seed Explanation Cards — T1078.004

**Null anchor:** benign=0.35 oos=0.25

### H1 — T1078.004 fits credential_theft_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1078.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1078.004 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1078.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# concurrent_incident_oos

# Seed Explanation Cards — T1486

**Null anchor:** benign=0.35 oos=0.25

> **Telemetry gap:** file_system unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1486 fits ransomware_enterprise_v1:impact

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1486 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1486 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1486 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# concurrent_miner_ransomware

# Seed Explanation Cards — T1496

**Null anchor:** benign=0.2 oos=0.15

> **Telemetry gap:** file_system unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1496 fits ransomware_enterprise_v1:impact

**Prior:** 0.52 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: network_connection, process_creation, file_system

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1496 preceded by execution (L1 tactic prior)

**Prior:** 0.48 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3


---

# concurrent_ransom_oos

# Seed Explanation Cards — T1486

**Null anchor:** benign=0.35 oos=0.25

> **Telemetry gap:** file_system unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1486 fits ransomware_enterprise_v1:impact

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1486 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1486 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1486 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# conflict_platform_linux_win

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.45 oos=0.25

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# credential_dump

# Seed Explanation Cards — T1003.001

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1003.001 fits ransomware_enterprise_v1:credential_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1003.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1003.001 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1003.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# cross_case_c2_oos

# Seed Explanation Cards — T1071.001

**Null anchor:** benign=0.45 oos=0.25

### H1 — T1071.001 fits commodity_malware_v1:command_and_control

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1071.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1071.001 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1071.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# cross_tenant_oos

# Seed Explanation Cards — T1078

**Null anchor:** benign=0.5 oos=0.25

### H1 — T1078 fits credential_theft_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1078 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1078 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1078 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# defense_evasion_disable_av

# Seed Explanation Cards — T1562.001

**Null anchor:** benign=0.5 oos=0.15

> **Telemetry gap:** service_log unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1562.001 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, service_log

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1562.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, service_log

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1562.001 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, service_log

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1562.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, service_log

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# dev_powershell_test

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# discovery_netscan

# Seed Explanation Cards — T1046

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1046 fits insider_misuse_v1:discovery

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `insider_misuse_v1`
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1046 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1046 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1046 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# dll_side_load

# Seed Explanation Cards — T1574.002

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1574.002 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1574.002 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1574.002 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1574.002 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# dns_cdn_benign

# Seed Explanation Cards — T1071.001

**Null anchor:** benign=0.45 oos=0.15

### H1 — T1071.001 fits commodity_malware_v1:command_and_control

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1071.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1071.001 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1071.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# dual_use_rundll32

# Seed Explanation Cards — T1218.011

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1218.011 fits living_off_the_land_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `living_off_the_land_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1218.011 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1218.011 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1218.011 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# dual_use_uncertain

# Seed Explanation Cards — T1218.011

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1218.011 fits living_off_the_land_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `living_off_the_land_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1218.011 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1218.011 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1218.011 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# edr_health_check

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# edr_test_host

# Seed Explanation Cards — T1059.003

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1059.003 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.003 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.003 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.003 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# exfil_dns

# Seed Explanation Cards — T1048.003

**Null anchor:** benign=0.6 oos=0.15

### H1 — T1048.003 fits credential_theft_v1:exfiltration

**Prior:** 0.35 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1048.003 preceded by collection (L1 tactic prior)

**Prior:** 0.32 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1048.003 dual-use / boundary-contested execution path

**Prior:** 0.33 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# gap_auth_only

# Seed Explanation Cards — T1110.003

**Null anchor:** benign=0.35 oos=0.15

> **Telemetry gap:** process_creation unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1110.003 fits credential_theft_v1:credential_access

**Prior:** 0.35 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1110.003 preceded by execution (L1 tactic prior)

**Prior:** 0.33 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1110.003 dual-use / boundary-contested execution path

**Prior:** 0.33 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# gap_bash_history_only

# Seed Explanation Cards — T1059.004

**Null anchor:** benign=0.55 oos=0.15

> **Telemetry gap:** process_creation, script_execution unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1059.004 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.004 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# gap_cloud_trail_sparse

# Seed Explanation Cards — T1078.004

**Null anchor:** benign=0.35 oos=0.25

> **Telemetry gap:** process_creation, script_execution unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1078.004 fits credential_theft_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1078.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1078.004 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1078.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# gap_file_timestamp_only

# Seed Explanation Cards — T1070.006

**Null anchor:** benign=0.35 oos=0.15

> **Telemetry gap:** process_creation, script_execution unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1070.006 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1070.006 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1070.006 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1070.006 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# gap_no_network_telemetry

# Seed Explanation Cards — T1105

**Null anchor:** benign=0.6 oos=0.15

> **Telemetry gap:** dns_query, network_connection unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1105 fits commodity_malware_v1:command_and_control

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H2 — T1105 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H3 — T1105 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H4 — T1105 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** True


---

# gap_no_script_log

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

> **Telemetry gap:** network_connection, script_execution unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# gap_single_edr_gap

# Seed Explanation Cards — T1055

**Null anchor:** benign=0.5 oos=0.15

> **Telemetry gap:** network_connection, script_execution unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1055 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1055 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1055 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1055 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# gap_web_app_log_only

# Seed Explanation Cards — T1190

**Null anchor:** benign=0.35 oos=0.15

> **Telemetry gap:** authentication, email_gateway, network_connection, process_creation unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1190 fits commodity_malware_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1190 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1190 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1190 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# helpdesk_cred_reset

# Seed Explanation Cards — T1098

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1098 fits cloud_compromise_v1:privilege_escalation

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `cloud_compromise_v1`
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1098 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1098 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1098 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- dual-use tool involved
- single or sparse log source mapping
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# impact_stop_service

# Seed Explanation Cards — T1489

**Null anchor:** benign=0.35 oos=0.15

> **Telemetry gap:** file_system unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1489 fits ransomware_enterprise_v1:impact

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1489 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1489 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1489 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# inventory_scheduled_task

# Seed Explanation Cards — T1053.005

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1053.005 fits commodity_malware_v1:persistence

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1053.005 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1053.005 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1053.005 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# it_rdp_admin

# Seed Explanation Cards — T1021.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1021.001 fits ransomware_enterprise_v1:lateral_movement

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H2 — T1021.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H3 — T1021.001 preceded by credential-access (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H4 — T1021.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** True


---

# jenkins_bash_build

# Seed Explanation Cards — T1059.004

**Null anchor:** benign=0.55 oos=0.15

### H1 — T1059.004 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.004 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# kerberoast

# Seed Explanation Cards — T1558.003

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1558.003 fits ransomware_enterprise_v1:credential_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1558.003 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1558.003 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1558.003 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# linux_cron_persist

# Seed Explanation Cards — T1053.003

**Null anchor:** benign=0.45 oos=0.15

### H1 — T1053.003 fits commodity_malware_v1:persistence

**Prior:** 0.35 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1053.003 preceded by execution (L1 tactic prior)

**Prior:** 0.33 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1053.003 dual-use / boundary-contested execution path

**Prior:** 0.33 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# linux_gtfobins

# Seed Explanation Cards — T1059.004

**Null anchor:** benign=0.55 oos=0.15

### H1 — T1059.004 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.004 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# linux_package_update

# Seed Explanation Cards — T1059.004

**Null anchor:** benign=0.55 oos=0.15

### H1 — T1059.004 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.004 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# linux_ssh_bruteforce

# Seed Explanation Cards — T1110.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1110.001 fits credential_theft_v1:credential_access

**Prior:** 0.35 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `credential_theft_v1`
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1110.001 preceded by execution (L1 tactic prior)

**Prior:** 0.33 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1110.001 dual-use / boundary-contested execution path

**Prior:** 0.33 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# log_clearing

# Seed Explanation Cards — T1070.001

**Null anchor:** benign=0.35 oos=0.15

> **Telemetry gap:** event_log unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1070.001 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, event_log

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1070.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, event_log

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1070.001 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, event_log

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1070.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, event_log

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# misleading_dual_use_high

# Seed Explanation Cards — T1218.011

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1218.011 fits living_off_the_land_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `living_off_the_land_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1218.011 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1218.011 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1218.011 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# missing_logs_no_attack

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# monitoring_netscan

# Seed Explanation Cards — T1046

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1046 fits insider_misuse_v1:discovery

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `insider_misuse_v1`
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1046 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1046 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1046 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# msiexec_install

# Seed Explanation Cards — T1218.007

**Null anchor:** benign=0.6 oos=0.15

### H1 — T1218.007 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1218.007 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1218.007 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1218.007 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# noisy_low_anomaly

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# oos_cloud_wrong_tenant

# Seed Explanation Cards — T1537

**Null anchor:** benign=0.2 oos=0.35

### H1 — T1537 fits ransomware_enterprise_v1:exfiltration

**Prior:** 0.52 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1537 preceded by collection (L1 tactic prior)

**Prior:** 0.48 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3


---

# oos_high_impact

# Seed Explanation Cards — T1486

**Null anchor:** benign=0.35 oos=0.25

> **Telemetry gap:** file_system unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1486 fits ransomware_enterprise_v1:impact

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1486 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1486 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1486 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# oos_linux_on_windows_alert

# Seed Explanation Cards — T1059.004

**Null anchor:** benign=0.35 oos=0.35

### H1 — T1059.004 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.004 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.004 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.004 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# patch_mgmt_wmi

# Seed Explanation Cards — T1047

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1047 fits living_off_the_land_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `living_off_the_land_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1047 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1047 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1047 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# persistence_scheduled_task

# Seed Explanation Cards — T1053.005

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1053.005 fits commodity_malware_v1:persistence

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1053.005 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1053.005 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1053.005 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# phishing_attachment_exec

# Seed Explanation Cards — T1566.001

**Null anchor:** benign=0.45 oos=0.15

> **Telemetry gap:** email_gateway unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1566.001 fits commodity_malware_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1566.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1566.001 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1566.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# platform_mismatch_oos

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.45 oos=0.25

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# powershell_admin

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# powershell_download_payload

# Seed Explanation Cards — T1105

**Null anchor:** benign=0.6 oos=0.15

### H1 — T1105 fits commodity_malware_v1:command_and_control

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H2 — T1105 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H3 — T1105 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H4 — T1105 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, dns_query, process_creation

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** True


---

# ransomware_chain

# Seed Explanation Cards — T1486

**Null anchor:** benign=0.35 oos=0.15

> **Telemetry gap:** file_system unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1486 fits ransomware_enterprise_v1:impact

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1486 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1486 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1486 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, file_system

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# rdp_lateral

# Seed Explanation Cards — T1021.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1021.001 fits ransomware_enterprise_v1:lateral_movement

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H2 — T1021.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H3 — T1021.001 preceded by credential-access (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H4 — T1021.001 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** True


---

# registry_run_key

# Seed Explanation Cards — T1547.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1547.001 fits commodity_malware_v1:persistence

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1547.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1547.001 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1547.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- dual-use tool involved
- single or sparse log source mapping
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# simulation_high_score

# Seed Explanation Cards — T1059.003

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1059.003 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.003 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.003 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.003 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# soc_phish_sim

# Seed Explanation Cards — T1566.002

**Null anchor:** benign=0.45 oos=0.15

> **Telemetry gap:** email_gateway unavailable; absence of script/process evidence is NOT used to reject explanations.

### H1 — T1566.002 fits commodity_malware_v1:initial_access

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1566.002 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1566.002 preceded by resource-development (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1566.002 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication, email_gateway

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# software_deploy_gpo

# Seed Explanation Cards — T1053.005

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1053.005 fits commodity_malware_v1:persistence

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1053.005 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1053.005 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1053.005 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# sparse_telemetry

# Seed Explanation Cards — T1047

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1047 fits living_off_the_land_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `living_off_the_land_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1047 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1047 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1047 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# stix_only_weak_tech

# Seed Explanation Cards — T1595.001

**Null anchor:** benign=0.25 oos=0.3

### H2 — T1595.001 in ATT&CK Flow-backed technique context

**Prior:** 0.51 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- single or sparse log source mapping
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1595.001 dual-use / boundary-contested execution path

**Prior:** 0.49 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation

**Why this may be wrong:**
- dual-use tool involved
- single or sparse log source mapping
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# suspicious_parent_attack

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# timestamp_conflict

# Seed Explanation Cards — T1070.006

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1070.006 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1070.006 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1070.006 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1070.006 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# timestamp_spoofing

# Seed Explanation Cards — T1070.006

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1070.006 fits commodity_malware_v1:defense_evasion

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1070.006 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1070.006 preceded by reconnaissance (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1070.006 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# uncertain_lateral_smb

# Seed Explanation Cards — T1021.002

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1021.002 fits ransomware_enterprise_v1:lateral_movement

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H2 — T1021.002 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H3 — T1021.002 preceded by credential-access (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H4 — T1021.002 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** True


---

# vmware_admin_wmi

# Seed Explanation Cards — T1047

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1047 fits living_off_the_land_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `living_off_the_land_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1047 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1047 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1047 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# vuln_scanner_lateral_look

# Seed Explanation Cards — T1021.002

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1021.002 fits ransomware_enterprise_v1:lateral_movement

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `ransomware_enterprise_v1`
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H2 — T1021.002 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H3 — T1021.002 preceded by credential-access (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** 0.3

### H4 — T1021.002 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, authentication

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. network connection corroboration

**Boundary risk score (feature):** True


---

# weak_parent_no_network

# Seed Explanation Cards — T1059.001

**Null anchor:** benign=0.35 oos=0.15

### H1 — T1059.001 fits commodity_malware_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `commodity_malware_v1`
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1059.001 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1059.001 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1059.001 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True


---

# weak_signal_only

# Seed Explanation Cards — T1082

**Null anchor:** benign=0.45 oos=0.15

### H1 — T1082 fits cloud_compromise_v1:discovery

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `cloud_compromise_v1`
- Sigma/node maps to: network_connection, process_creation, auditd

**Why this may be wrong:**
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H2 — T1082 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: network_connection, process_creation, auditd

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H3 — T1082 preceded by execution (L1 tactic prior)

**Prior:** 0.24 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, auditd

**Why this may be wrong:**
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** 0.3

### H4 — T1082 dual-use / boundary-contested execution path

**Prior:** 0.25 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: network_connection, process_creation, auditd

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- low alert anomaly score
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event

**Boundary risk score (feature):** True


---

# wmi_remote_exec

# Seed Explanation Cards — T1047

**Null anchor:** benign=0.5 oos=0.15

### H1 — T1047 fits living_off_the_land_v1:execution

**Prior:** 0.26 | **Type:** lifecycle

**Why plausible:**
- Matches lifecycle template `living_off_the_land_v1`
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H2 — T1047 in ATT&CK Flow-backed technique context

**Prior:** 0.25 | **Type:** technique_context

**Why plausible:**
- ATT&CK Flow-backed technique context
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H3 — T1047 preceded by initial-access (L1 tactic prior)

**Prior:** 0.25 | **Type:** l1_predecessor

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- prior-only seed; no evidence update yet
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** 0.3

### H4 — T1047 dual-use / boundary-contested execution path

**Prior:** 0.24 | **Type:** dual_use_boundary

**Why plausible:**
- Sigma/node maps to: process_creation, script_execution

**Why this may be wrong:**
- dual-use tool involved
- no Flow-backed temporal support
- (none listed)

**What to check next:**
1. parent process lineage
2. independent EDR process event
3. script block / powershell operational log

**Boundary risk score (feature):** True
