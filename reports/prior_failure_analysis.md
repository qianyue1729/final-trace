# Prior Failure Analysis

**Total:** 80 | **Failed:** 0 | S1=2 S2=23 S3=0

## Severity ranked (roadmap hints)

- **[S1]** `cloud_s3_exfil` — near max_prior cap (0.5157) — overconfident investigation prior risk → cloud template / exfil L2 coverage, sigma log source mapping / tenant available_log_sources, attack_flow edge or lifecycle template
- **[S1]** `concurrent_miner_ransomware` — near max_prior cap (0.5157) — overconfident investigation prior risk → attack_flow edge or lifecycle template
- **[S2]** `admin_powershell_inventory` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `atomic_red_team_sim` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `backup_registry_touch` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `backup_smb` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `cert_rotation_iam` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `cicd_bash_curl` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `cloud_assume_role_normal` — dual-use boundary on benign case — false attack-chain risk → cloud template / exfil L2 coverage
- **[S2]** `cloud_terraform_apply` — dual-use boundary on benign case — false attack-chain risk → cloud template / exfil L2 coverage
- **[S2]** `dev_powershell_test` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `dns_cdn_benign` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `edr_health_check` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `inventory_scheduled_task` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `it_rdp_admin` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `jenkins_bash_build` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `linux_package_update` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `missing_logs_no_attack` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `monitoring_netscan` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `msiexec_install` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `patch_mgmt_wmi` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `soc_phish_sim` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `software_deploy_gpo` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `vmware_admin_wmi` — dual-use boundary on benign case — false attack-chain risk → —
- **[S2]** `vuln_scanner_lateral_look` — dual-use boundary on benign case — false attack-chain risk → —

## Reliability statement

Investigation prior scores are not calibrated probabilities.