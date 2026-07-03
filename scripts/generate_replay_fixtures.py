#!/usr/bin/env python3
"""Generate replay fixtures to reach 80-case suite (idempotent — skips existing)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "replay" / "fixtures"

Row = tuple[str, str, str, str, str, str, float, dict]


def _expect(category: str, **kw) -> dict:
    base: dict = {"max_max_prior": 0.55}
    if category == "benign":
        base["benign_anchor_min"] = 0.20
    if category in ("ambiguous", "adversarial"):
        base["oos_anchor_min"] = 0.12
    if category == "telemetry-gap":
        base["must_not_hard_veto"] = True
        base["max_max_prior"] = 0.75
    base.update(kw)
    return base


def write_case(
    cid: str,
    title: str,
    category: str,
    tech: str,
    tactic: str,
    platform: str,
    log_source: str,
    score: float,
    attrs: dict,
    extra_exp: dict | None = None,
) -> bool:
    path = FIX / f"{cid}.json"
    if path.is_file():
        return False
    exp = _expect(category, **(extra_exp or {}))
    doc = {
        "case_id": cid,
        "title": title,
        "category": category,
        "alert": {
            "technique_id": tech,
            "tactic": tactic,
            "platform": platform,
            "log_source": log_source,
            "anomaly_score": score,
            "attributes": attrs,
        },
        "expected_behavior": exp,
    }
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return True


ATTACK: list[Row] = [
    ("phishing_attachment_exec", "Phishing attachment execution", "T1566.001", "initial-access", "windows", "email_gateway", 0.85, {}),
    ("wmi_remote_exec", "WMI remote execution", "T1047", "execution", "windows", "process_creation", 0.78, {}),
    ("rdp_lateral", "RDP lateral movement", "T1021.001", "lateral-movement", "windows", "authentication", 0.80, {}),
    ("credential_dump", "Credential dump LSASS", "T1003.001", "credential-access", "windows", "process_creation", 0.88, {}),
    ("persistence_scheduled_task", "Scheduled task persistence", "T1053.005", "persistence", "windows", "process_creation", 0.75, {}),
    ("defense_evasion_disable_av", "Disable AV", "T1562.001", "defense-evasion", "windows", "process_creation", 0.82, {}),
    ("exfil_dns", "DNS exfiltration", "T1048.003", "exfiltration", "windows", "dns_query", 0.70, {}),
    ("c2_beacon", "C2 beacon", "T1071.001", "command-and-control", "windows", "network_connection", 0.77, {}),
    ("linux_cron_persist", "Linux cron persistence", "T1053.003", "persistence", "linux", "auditd", 0.72, {}),
    ("linux_ssh_bruteforce", "SSH brute force", "T1110.001", "credential-access", "linux", "authentication", 0.68, {}),
    ("cloud_s3_exfil", "Cloud S3 exfil", "T1537", "exfiltration", "linux", "cloudtrail_management_event", 0.74, {}),
    ("kerberoast", "Kerberoasting", "T1558.003", "credential-access", "windows", "authentication", 0.79, {}),
    ("dll_side_load", "DLL sideload", "T1574.002", "defense-evasion", "windows", "module_load", 0.76, {}),
    ("registry_run_key", "Run key persistence", "T1547.001", "persistence", "windows", "registry", 0.73, {}),
    ("discovery_netscan", "Network scan discovery", "T1046", "discovery", "windows", "network_connection", 0.65, {}),
    ("impact_stop_service", "Stop service impact", "T1489", "impact", "windows", "process_creation", 0.81, {}),
]

BENIGN: list[Row] = [
    ("patch_mgmt_wmi", "Patch management WMI", "T1047", "execution", "windows", "process_creation", 0.28, {"admin_baseline": True}),
    ("it_rdp_admin", "IT admin RDP", "T1021.001", "lateral-movement", "windows", "authentication", 0.30, {"known_admin_host": True}),
    ("inventory_scheduled_task", "Inventory scheduled task", "T1053.005", "persistence", "windows", "process_creation", 0.25, {"admin_baseline": True}),
    ("edr_health_check", "EDR health check", "T1059.001", "execution", "windows", "process_creation", 0.22, {"simulation": True}),
    ("dns_cdn_benign", "Benign CDN DNS", "T1071.001", "command-and-control", "windows", "dns_query", 0.20, {}),
    ("linux_package_update", "Linux package update", "T1059.004", "execution", "linux", "auditd", 0.26, {"admin_baseline": True}),
    ("cloud_terraform_apply", "Terraform apply", "T1078.004", "initial-access", "linux", "cloudtrail_management_event", 0.27, {"admin_baseline": True}),
    ("helpdesk_cred_reset", "Helpdesk cred reset", "T1098", "persistence", "windows", "authentication", 0.24, {"known_admin_host": True}),
    ("software_deploy_gpo", "Software deploy GPO", "T1053.005", "persistence", "windows", "process_creation", 0.29, {"backup_baseline": True}),
    ("monitoring_netscan", "Monitoring netscan", "T1046", "discovery", "windows", "network_connection", 0.32, {"simulation": True}),
    ("dev_powershell_test", "Dev PowerShell test", "T1059.001", "execution", "windows", "process_creation", 0.23, {"admin_baseline": True}),
    ("backup_registry_touch", "Backup registry touch", "T1112", "defense-evasion", "windows", "registry", 0.21, {"backup_baseline": True}),
    ("soc_phish_sim", "SOC phish simulation", "T1566.002", "initial-access", "windows", "email_gateway", 0.35, {"simulation": True}),
    ("jenkins_bash_build", "Jenkins bash build", "T1059.004", "execution", "linux", "auditd", 0.24, {"admin_baseline": True}),
    ("vmware_admin_wmi", "VMware admin WMI", "T1047", "execution", "windows", "process_creation", 0.26, {"known_admin_host": True}),
    ("cert_rotation_iam", "Cert rotation IAM", "T1078.004", "initial-access", "linux", "cloudtrail_management_event", 0.22, {}),
]

AMBIG: list[Row] = [
    ("oos_linux_on_windows_alert", "OOS linux technique on windows", "T1059.004", "execution", "windows", "process_creation", 0.55, {"weak_case_link": True}),
    ("weak_parent_no_network", "Weak parent no network", "T1059.001", "execution", "windows", "process_creation", 0.55, {}),
    ("concurrent_ransom_oos", "Concurrent ransom oos", "T1486", "impact", "windows", "process_creation", 0.68, {"concurrent_incident": True}),
    ("cross_case_c2_oos", "Cross case C2 oos", "T1071.001", "command-and-control", "windows", "network_connection", 0.62, {"weak_case_link": True}),
    ("dual_use_rundll32", "Dual use rundll32", "T1218.011", "defense-evasion", "windows", "process_creation", 0.52, {}),
    ("ambiguous_discovery", "Ambiguous discovery", "T1083", "discovery", "windows", "process_creation", 0.48, {}),
    ("oos_cloud_wrong_tenant", "OOS cloud wrong tenant", "T1537", "exfiltration", "linux", "cloudtrail_management_event", 0.60, {"weak_case_link": True}),
    ("uncertain_lateral_smb", "Uncertain lateral SMB", "T1021.002", "lateral-movement", "windows", "network_connection", 0.58, {}),
]

TELEMETRY: list[Row] = [
    ("gap_no_script_log", "Gap no script log", "T1059.001", "execution", "windows", "process_creation", 0.50, {}),
    ("gap_bash_history_only", "Gap bash history only", "T1059.004", "execution", "linux", "bash_history", 0.45, {}),
    ("gap_file_timestamp_only", "Gap file timestamp only", "T1070.006", "defense-evasion", "linux", "file_system_timestamp", 0.40, {}),
    ("gap_web_app_log_only", "Gap web app log only", "T1190", "initial-access", "linux", "web_application_log", 0.55, {}),
    ("gap_single_edr_gap", "Gap single EDR gap", "T1055", "defense-evasion", "windows", "process_creation", 0.52, {}),
    ("gap_no_network_telemetry", "Gap no network telemetry", "T1105", "command-and-control", "windows", "process_creation", 0.48, {}),
    ("gap_cloud_trail_sparse", "Gap cloud trail sparse", "T1078.004", "initial-access", "linux", "cloudtrail_management_event", 0.42, {}),
    ("gap_auth_only", "Gap auth log only", "T1110.003", "credential-access", "windows", "authentication", 0.46, {}),
]

ADVERSARIAL: list[Row] = [
    ("noisy_low_anomaly", "Noisy low anomaly", "T1059.001", "execution", "windows", "process_creation", 0.15, {}),
    ("conflict_platform_linux_win", "Platform conflict", "T1059.001", "execution", "linux", "process_creation", 0.70, {}),
    ("misleading_dual_use_high", "Misleading dual use high score", "T1218.011", "defense-evasion", "windows", "process_creation", 0.90, {"suspicious_parent": True}),
    ("stix_only_weak_tech", "STIX only weak tech", "T1595.001", "reconnaissance", "linux", "network_connection", 0.55, {}),
    ("timestamp_conflict", "Timestamp conflict log", "T1070.006", "defense-evasion", "windows", "file_system_timestamp", 0.65, {}),
    ("simulation_high_score", "Simulation high score", "T1059.003", "execution", "windows", "process_creation", 0.88, {"simulation": True}),
    ("admin_high_anomaly", "Admin high anomaly", "T1059.001", "execution", "windows", "process_creation", 0.95, {"admin_baseline": True, "known_admin_host": True}),
    ("oos_high_impact", "OOS high impact unrelated", "T1486", "impact", "windows", "process_creation", 0.85, {"weak_case_link": True, "concurrent_incident": True}),
]


def main() -> None:
    FIX.mkdir(parents=True, exist_ok=True)
    n = 0
    for cid, title, tech, tactic, plat, ls, score, attrs in ATTACK:
        n += write_case(cid, title, "attack-like", tech, tactic, plat, ls, score, attrs)
    for cid, title, tech, tactic, plat, ls, score, attrs in BENIGN:
        n += write_case(cid, title, "benign", tech, tactic, plat, ls, score, attrs)
    for cid, title, tech, tactic, plat, ls, score, attrs in AMBIG:
        n += write_case(cid, title, "ambiguous", tech, tactic, plat, ls, score, attrs, {"oos_anchor_min": 0.12})
    for cid, title, tech, tactic, plat, ls, score, attrs in TELEMETRY:
        n += write_case(cid, title, "telemetry-gap", tech, tactic, plat, ls, score, attrs)
    for cid, title, tech, tactic, plat, ls, score, attrs in ADVERSARIAL:
        n += write_case(cid, title, "adversarial", tech, tactic, plat, ls, score, attrs)
    print(f"added={n} total={len(list(FIX.glob('*.json')))}")


if __name__ == "__main__":
    main()
