# Prior Replay Report

**Passed:** 80/80 (direct)

## [PASS] admin_high_anomaly — Admin high anomaly
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] admin_powershell_inventory — Admin PowerShell inventory
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] ambiguous_discovery — Ambiguous discovery
- max_prior=0.2602 entropy=1.386 benign=0.45 oos=0.15 contested=8 log_sources=2
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] atomic_red_team_sim — Atomic Red Team sim
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] backup_registry_touch — Backup registry touch
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] backup_smb — Backup SMB access
- max_prior=0.2586 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] c2_beacon — C2 beacon
- max_prior=0.259 entropy=1.386 benign=0.45 oos=0.15 contested=8 log_sources=3
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cert_rotation_iam — Cert rotation IAM
- max_prior=0.2644 entropy=1.3857 benign=0.35 oos=0.25 contested=1 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cicd_bash_curl — CI/CD bash curl
- max_prior=0.263 entropy=1.3859 benign=0.55 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cloud_assume_role_normal — Normal cloud AssumeRole
- max_prior=0.2644 entropy=1.3857 benign=0.35 oos=0.25 contested=1 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cloud_iam_anomaly — Cloud IAM 异常
- max_prior=0.2609 entropy=1.386 benign=0.35 oos=0.15 contested=2 log_sources=1
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cloud_s3_exfil — Cloud S3 exfil
- max_prior=0.5157 entropy=0.6927 benign=0.2 oos=0.25 contested=0 log_sources=1
- checks: {'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cloud_terraform_apply — Terraform apply
- max_prior=0.2644 entropy=1.3857 benign=0.35 oos=0.25 contested=1 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] concurrent_incident_oos — Concurrent incident oos
- max_prior=0.258 entropy=1.386 benign=0.35 oos=0.25 contested=8 log_sources=2
- checks: {'oos_anchor_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] concurrent_miner_ransomware — 挖矿与勒索并发
- max_prior=0.5157 entropy=0.6927 benign=0.2 oos=0.15 contested=0 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] concurrent_ransom_oos — Concurrent ransom oos
- max_prior=0.258 entropy=1.386 benign=0.35 oos=0.25 contested=8 log_sources=2
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] conflict_platform_linux_win — Platform conflict
- max_prior=0.263 entropy=1.3859 benign=0.45 oos=0.25 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] credential_dump — Credential dump LSASS
- max_prior=0.2594 entropy=1.386 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cross_case_c2_oos — Cross case C2 oos
- max_prior=0.259 entropy=1.386 benign=0.45 oos=0.25 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] cross_tenant_oos — Cross tenant oos
- max_prior=0.2644 entropy=1.3857 benign=0.5 oos=0.25 contested=8 log_sources=2
- checks: {'oos_anchor_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] defense_evasion_disable_av — Disable AV
- max_prior=0.2573 entropy=1.3861 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] dev_powershell_test — Dev PowerShell test
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] discovery_netscan — Network scan discovery
- max_prior=0.2602 entropy=1.386 benign=0.35 oos=0.15 contested=6 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] dll_side_load — DLL sideload
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=1 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] dns_cdn_benign — Benign CDN DNS
- max_prior=0.259 entropy=1.386 benign=0.45 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] dual_use_rundll32 — Dual use rundll32
- max_prior=0.2573 entropy=1.3861 benign=0.5 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] dual_use_uncertain — Dual use uncertain
- max_prior=0.2573 entropy=1.3861 benign=0.5 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'boundary_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] edr_health_check — EDR health check
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] edr_test_host — EDR test host
- max_prior=0.263 entropy=1.3859 benign=0.5 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] exfil_dns — DNS exfiltration
- max_prior=0.3451 entropy=1.0983 benign=0.6 oos=0.15 contested=1 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] gap_auth_only — Gap auth log only
- max_prior=0.3463 entropy=1.0982 benign=0.35 oos=0.15 contested=1 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] gap_bash_history_only — Gap bash history only
- max_prior=0.263 entropy=1.3859 benign=0.55 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] gap_cloud_trail_sparse — Gap cloud trail sparse
- max_prior=0.2644 entropy=1.3857 benign=0.35 oos=0.25 contested=1 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] gap_file_timestamp_only — Gap file timestamp only
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=1 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] gap_no_network_telemetry — Gap no network telemetry
- max_prior=0.259 entropy=1.386 benign=0.6 oos=0.15 contested=8 log_sources=3
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] gap_no_script_log — Gap no script log
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] gap_single_edr_gap — Gap single EDR gap
- max_prior=0.2573 entropy=1.3861 benign=0.5 oos=0.15 contested=2 log_sources=3
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] gap_web_app_log_only — Gap web app log only
- max_prior=0.2644 entropy=1.3857 benign=0.35 oos=0.15 contested=8 log_sources=4
- checks: {'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] helpdesk_cred_reset — Helpdesk cred reset
- max_prior=0.2609 entropy=1.386 benign=0.35 oos=0.15 contested=4 log_sources=1
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] impact_stop_service — Stop service impact
- max_prior=0.258 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] inventory_scheduled_task — Inventory scheduled task
- max_prior=0.2609 entropy=1.386 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] it_rdp_admin — IT admin RDP
- max_prior=0.2586 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] jenkins_bash_build — Jenkins bash build
- max_prior=0.263 entropy=1.3859 benign=0.55 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] kerberoast — Kerberoasting
- max_prior=0.2594 entropy=1.386 benign=0.35 oos=0.15 contested=3 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] linux_cron_persist — Linux cron persistence
- max_prior=0.3477 entropy=1.0982 benign=0.45 oos=0.15 contested=2 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] linux_gtfobins — Linux GTFOBins 滥用
- max_prior=0.263 entropy=1.3859 benign=0.55 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'boundary_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] linux_package_update — Linux package update
- max_prior=0.263 entropy=1.3859 benign=0.55 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] linux_ssh_bruteforce — SSH brute force
- max_prior=0.3463 entropy=1.0982 benign=0.35 oos=0.15 contested=2 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] log_clearing — 日志被清理
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=5 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] misleading_dual_use_high — Misleading dual use high score
- max_prior=0.2573 entropy=1.3861 benign=0.5 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] missing_logs_no_attack — Missing logs no attack signal
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] monitoring_netscan — Monitoring netscan
- max_prior=0.2602 entropy=1.386 benign=0.35 oos=0.15 contested=6 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] msiexec_install — Normal msiexec install
- max_prior=0.2573 entropy=1.3861 benign=0.6 oos=0.15 contested=1 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] noisy_low_anomaly — Noisy low anomaly
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] oos_cloud_wrong_tenant — OOS cloud wrong tenant
- max_prior=0.5157 entropy=0.6927 benign=0.2 oos=0.35 contested=0 log_sources=1
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] oos_high_impact — OOS high impact unrelated
- max_prior=0.258 entropy=1.386 benign=0.35 oos=0.25 contested=8 log_sources=2
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] oos_linux_on_windows_alert — OOS linux technique on windows
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.35 contested=8 log_sources=2
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] patch_mgmt_wmi — Patch management WMI
- max_prior=0.263 entropy=1.3859 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] persistence_scheduled_task — Scheduled task persistence
- max_prior=0.2609 entropy=1.386 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] phishing_attachment_exec — Phishing attachment execution
- max_prior=0.2644 entropy=1.3857 benign=0.45 oos=0.15 contested=4 log_sources=4
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] platform_mismatch_oos — Platform mismatch oos
- max_prior=0.263 entropy=1.3859 benign=0.45 oos=0.25 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] powershell_admin — 正常 PowerShell 运维
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] powershell_download_payload — PowerShell 下载 payload
- max_prior=0.259 entropy=1.386 benign=0.6 oos=0.15 contested=8 log_sources=3
- checks: {'entropy_ok': True, 'top_k_hit': True, 'boundary_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] ransomware_chain — Ransomware chain
- max_prior=0.258 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'boundary_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] rdp_lateral — RDP lateral movement
- max_prior=0.2586 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] registry_run_key — Run key persistence
- max_prior=0.2609 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=1
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] simulation_high_score — Simulation high score
- max_prior=0.263 entropy=1.3859 benign=0.5 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] soc_phish_sim — SOC phish simulation
- max_prior=0.2644 entropy=1.3857 benign=0.45 oos=0.15 contested=3 log_sources=4
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] software_deploy_gpo — Software deploy GPO
- max_prior=0.2609 entropy=1.386 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] sparse_telemetry — Sparse telemetry
- max_prior=0.263 entropy=1.3859 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] stix_only_weak_tech — STIX only weak tech
- max_prior=0.505 entropy=0.6931 benign=0.25 oos=0.3 contested=1 log_sources=1
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] suspicious_parent_attack — Suspicious parent attack path
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] timestamp_conflict — Timestamp conflict log
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=2 log_sources=2
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] timestamp_spoofing — 时间戳伪造
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=1 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] uncertain_lateral_smb — Uncertain lateral SMB
- max_prior=0.2586 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] vmware_admin_wmi — VMware admin WMI
- max_prior=0.263 entropy=1.3859 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] vuln_scanner_lateral_look — Vuln scanner lateral-looking
- max_prior=0.2586 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] weak_parent_no_network — Weak parent no network
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] weak_signal_only — Weak signal only
- max_prior=0.2602 entropy=1.386 benign=0.45 oos=0.15 contested=8 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] wmi_remote_exec — WMI remote execution
- max_prior=0.263 entropy=1.3859 benign=0.5 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}
