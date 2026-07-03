#!/usr/bin/env python3
"""Bootstrap 30 semi-real analyst-labeled replay cases (T25)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "tests" / "replay" / "labeled"

# (case_id, title, category, source, tech, tactic, platform, log_source, score, attrs, ground_truth)
CASES = [
    ("mordor_ps_download_01", "Mordor-style PS download", "attack-like", "mordor", "T1059.001", "execution", "windows", "process_creation", 0.82, {}, {"true_family": "powershell_download_payload", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1059.001", "T1105"]}),
    ("mordor_ps_download_02", "Encoded PS execution", "attack-like", "mordor", "T1059.001", "execution", "windows", "script_execution", 0.78, {}, {"true_family": "powershell_download_payload", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1059.001"]}),
    ("atomic_sim_t1059", "Atomic T1059 simulation", "attack-like", "mordor", "T1059.003", "execution", "windows", "process_creation", 0.75, {"simulation": True}, {"true_family": "execution_test", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1059.003"]}),
    ("optc_lateral_rdp", "OpTC-style RDP lateral", "attack-like", "optc", "T1021.001", "lateral-movement", "windows", "authentication", 0.80, {}, {"true_family": "lateral_rdp", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1021.001"]}),
    ("optc_cred_dump", "OpTC cred access pattern", "attack-like", "optc", "T1003.001", "credential-access", "windows", "process_creation", 0.88, {}, {"true_family": "credential_dump", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1003.001"]}),
    ("manual_ransom_chain", "Ransomware chain pattern", "attack-like", "manual", "T1486", "impact", "windows", "process_creation", 0.90, {}, {"true_family": "ransomware_chain", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1486", "T1490"]}),
    ("manual_c2_beacon", "C2 beacon pattern", "attack-like", "manual", "T1071.001", "command-and-control", "windows", "network_connection", 0.77, {}, {"true_family": "c2_beacon", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1071.001"]}),
    ("manual_phish_exec", "Phish to execution", "attack-like", "manual", "T1566.001", "initial-access", "windows", "email_gateway", 0.85, {}, {"true_family": "phishing_execution", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1566.001", "T1059.001"]}),
    ("manual_wmi_exec", "WMI remote exec", "attack-like", "manual", "T1047", "execution", "windows", "process_creation", 0.76, {}, {"true_family": "wmi_execution", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1047"]}),
    ("manual_defense_evasion", "Disable AV pattern", "attack-like", "manual", "T1562.001", "defense-evasion", "windows", "process_creation", 0.81, {}, {"true_family": "defense_evasion", "true_boundary": "in_attack", "benign": False, "oos": False, "expected_techniques": ["T1562.001"]}),
    ("soc_benign_ps_admin_01", "SOC: admin PS inventory", "benign", "manual", "T1059.001", "execution", "windows", "process_creation", 0.22, {"admin_baseline": True, "known_admin_host": True}, {"true_family": "admin_powershell", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1059.001"]}),
    ("soc_benign_ps_admin_02", "SOC: GPO deploy script", "benign", "manual", "T1059.001", "execution", "windows", "process_creation", 0.28, {"backup_baseline": True}, {"true_family": "admin_powershell", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1059.001"]}),
    ("soc_benign_rdp_01", "SOC: IT RDP session", "benign", "manual", "T1021.001", "lateral-movement", "windows", "authentication", 0.30, {"known_admin_host": True}, {"true_family": "it_rdp", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1021.001"]}),
    ("soc_benign_backup_01", "SOC: backup SMB", "benign", "manual", "T1021.002", "lateral-movement", "windows", "network_connection", 0.25, {"backup_baseline": True}, {"true_family": "backup_smb", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1021.002"]}),
    ("soc_benign_cicd_01", "SOC: CI/CD bash", "benign", "manual", "T1059.004", "execution", "linux", "auditd", 0.24, {"admin_baseline": True}, {"true_family": "cicd_bash", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1059.004"]}),
    ("soc_benign_cloud_01", "SOC: Terraform apply", "benign", "manual", "T1078.004", "initial-access", "linux", "cloudtrail_management_event", 0.26, {"admin_baseline": True}, {"true_family": "cloud_admin", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1078.004"]}),
    ("soc_benign_scan_01", "SOC: vuln scanner", "benign", "manual", "T1046", "discovery", "windows", "network_connection", 0.32, {"simulation": True}, {"true_family": "vuln_scan", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1046"]}),
    ("soc_benign_msi_01", "SOC: software install", "benign", "manual", "T1218.007", "defense-evasion", "windows", "process_creation", 0.27, {}, {"true_family": "software_install", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1218.007"]}),
    ("soc_benign_edr_test", "SOC: EDR health check", "benign", "manual", "T1059.001", "execution", "windows", "process_creation", 0.35, {"simulation": True}, {"true_family": "edr_test", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1059.001"]}),
    ("soc_benign_helpdesk", "SOC: helpdesk reset", "benign", "manual", "T1098", "persistence", "windows", "authentication", 0.23, {"known_admin_host": True}, {"true_family": "helpdesk_admin", "true_boundary": "benign", "benign": True, "oos": False, "expected_techniques": ["T1098"]}),
    ("ambig_oos_ransom_01", "Concurrent ransom unrelated", "ambiguous", "manual", "T1486", "impact", "windows", "process_creation", 0.68, {"concurrent_incident": True, "weak_case_link": True}, {"true_family": "concurrent_oos", "true_boundary": "oos", "benign": False, "oos": True, "expected_techniques": ["T1486"]}),
    ("ambig_oos_c2_01", "Cross-case C2", "ambiguous", "manual", "T1071.001", "command-and-control", "windows", "network_connection", 0.62, {"weak_case_link": True}, {"true_family": "cross_case_c2", "true_boundary": "oos", "benign": False, "oos": True, "expected_techniques": ["T1071.001"]}),
    ("ambig_oos_cloud_01", "Wrong tenant cloud", "ambiguous", "manual", "T1537", "exfiltration", "linux", "cloudtrail_management_event", 0.60, {"weak_case_link": True}, {"true_family": "wrong_tenant", "true_boundary": "oos", "benign": False, "oos": True, "expected_techniques": ["T1537"]}),
    ("ambig_uncertain_ps", "Uncertain dual-use PS", "ambiguous", "manual", "T1059.001", "execution", "windows", "process_creation", 0.50, {}, {"true_family": "dual_use_uncertain", "true_boundary": "uncertain", "benign": False, "oos": False, "expected_techniques": ["T1059.001"]}),
    ("ambig_platform_mismatch", "Platform mismatch alert", "ambiguous", "manual", "T1059.004", "execution", "windows", "process_creation", 0.55, {"weak_case_link": True}, {"true_family": "platform_oos", "true_boundary": "oos", "benign": False, "oos": True, "expected_techniques": ["T1059.004"]}),
    ("tel_gap_ps_script_01", "No script block log", "telemetry-gap", "manual", "T1059.001", "execution", "windows", "process_creation", 0.50, {}, {"true_family": "powershell_download_payload", "true_boundary": "uncertain", "benign": False, "oos": False, "expected_techniques": ["T1059.001"]}),
    ("tel_gap_bash_hist", "Bash history only", "telemetry-gap", "manual", "T1059.004", "execution", "linux", "bash_history", 0.45, {}, {"true_family": "linux_shell", "true_boundary": "uncertain", "benign": False, "oos": False, "expected_techniques": ["T1059.004"]}),
    ("tel_gap_timestamp", "File timestamp only", "telemetry-gap", "manual", "T1070.006", "defense-evasion", "linux", "file_system_timestamp", 0.40, {}, {"true_family": "timestomp", "true_boundary": "uncertain", "benign": False, "oos": False, "expected_techniques": ["T1070.006"]}),
    ("tel_gap_web_only", "Web app log only", "telemetry-gap", "manual", "T1190", "initial-access", "linux", "web_application_log", 0.55, {}, {"true_family": "web_exploit", "true_boundary": "uncertain", "benign": False, "oos": False, "expected_techniques": ["T1190"]}),
    ("tel_gap_sparse_edr", "Sparse EDR coverage", "telemetry-gap", "manual", "T1055", "defense-evasion", "windows", "process_creation", 0.52, {"tenant_profile": {"edr_coverage": "low"}}, {"true_family": "process_injection", "true_boundary": "uncertain", "benign": False, "oos": False, "expected_techniques": ["T1055"]}),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    for row in CASES:
        cid, title, cat, source, tech, tactic, plat, ls, score, attrs, gt = row
        doc = {
            "case_id": cid,
            "title": title,
            "category": cat,
            "source": source,
            "label_quality": "weak_label",
            "alert": {
                "technique_id": tech,
                "tactic": tactic,
                "platform": plat,
                "log_source": ls,
                "anomaly_score": score,
                "attributes": attrs,
            },
            "ground_truth": gt,
            "evaluation": {"calibration_eligible": True},
            "expected_behavior": {"max_max_prior": 0.75, "must_not_hard_veto": True},
        }
        (OUT / f"{cid}.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"written {len(CASES)} labeled fixtures → {OUT}")


if __name__ == "__main__":
    main()
