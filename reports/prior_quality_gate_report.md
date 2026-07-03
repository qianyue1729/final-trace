# Prior Quality Gate Report

**Cases passing all gates:** 80/80

## [PASS] admin_high_anomaly
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] admin_powershell_inventory
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] ambiguous_discovery
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2602, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.45, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['insider_misuse_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] atomic_red_team_sim
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] backup_registry_touch
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] backup_smb
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2586, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['authentication', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] c2_beacon
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.259, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.45, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['dns_query', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cert_rotation_iam
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.35, 'null_oos': 0.25, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cicd_bash_curl
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.55, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.55, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cloud_assume_role_normal
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.35, 'null_oos': 0.25, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cloud_iam_anomaly
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2609, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 2, 'log_source_count': 1, 'log_sources': ['process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['cloud_compromise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cloud_s3_exfil
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.5157, 'entropy': 0.6927, 'explanation_count': 2, 'normalized_entropy': 0.9994, 'null_benign': 0.2, 'null_oos': 0.25, 'contested_edge_count': 0, 'log_source_count': 1, 'log_sources': ['process_creation'], 'explanation_ids': ['H1', 'H3'], 'explanation_types': ['lifecycle', 'l1_predecessor'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.2, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cloud_terraform_apply
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.35, 'null_oos': 0.25, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] concurrent_incident_oos
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.258, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.25, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['file_system', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] concurrent_miner_ransomware
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.5157, 'entropy': 0.6927, 'explanation_count': 2, 'normalized_entropy': 0.9994, 'null_benign': 0.2, 'null_oos': 0.15, 'contested_edge_count': 0, 'log_source_count': 3, 'log_sources': ['file_system', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H3'], 'explanation_types': ['lifecycle', 'l1_predecessor'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.2, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] concurrent_ransom_oos
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.258, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.25, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['file_system', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] conflict_platform_linux_win
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.45, 'null_oos': 0.25, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] credential_dump
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2594, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['authentication', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cross_case_c2_oos
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.259, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.45, 'null_oos': 0.25, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['dns_query', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] cross_tenant_oos
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.5, 'null_oos': 0.25, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] defense_evasion_disable_av
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'service_log'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] dev_powershell_test
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] discovery_netscan
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2602, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 6, 'log_source_count': 2, 'log_sources': ['network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['insider_misuse_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] dll_side_load
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] dns_cdn_benign
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.259, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.45, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['dns_query', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] dual_use_rundll32
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['living_off_the_land_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] dual_use_uncertain
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['living_off_the_land_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] edr_health_check
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] edr_test_host
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] exfil_dns
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.3451, 'entropy': 1.0983, 'explanation_count': 3, 'normalized_entropy': 0.9997, 'null_benign': 0.6, 'null_oos': 0.15, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.6, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_auth_only
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.3463, 'entropy': 1.0982, 'explanation_count': 3, 'normalized_entropy': 0.9996, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['authentication', 'process_creation'], 'explanation_ids': ['H1', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_bash_history_only
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.55, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.55, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_cloud_trail_sparse
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.35, 'null_oos': 0.25, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_file_timestamp_only
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_no_network_telemetry
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.259, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.6, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['dns_query', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.6, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_no_script_log
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_single_edr_gap
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 2, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] gap_web_app_log_only
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 4, 'log_sources': ['authentication', 'email_gateway', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] helpdesk_cred_reset
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2609, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 4, 'log_source_count': 1, 'log_sources': ['process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['cloud_compromise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] impact_stop_service
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.258, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['file_system', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] inventory_scheduled_task
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2609, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] it_rdp_admin
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2586, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['authentication', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] jenkins_bash_build
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.55, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.55, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] kerberoast
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2594, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 3, 'log_source_count': 2, 'log_sources': ['authentication', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] linux_cron_persist
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.3477, 'entropy': 1.0982, 'explanation_count': 3, 'normalized_entropy': 0.9996, 'null_benign': 0.45, 'null_oos': 0.15, 'contested_edge_count': 2, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] linux_gtfobins
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.55, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.55, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] linux_package_update
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.55, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.55, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] linux_ssh_bruteforce
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.3463, 'entropy': 1.0982, 'explanation_count': 3, 'normalized_entropy': 0.9996, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 2, 'log_source_count': 2, 'log_sources': ['authentication', 'process_creation'], 'explanation_ids': ['H1', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['credential_theft_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] log_clearing
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 5, 'log_source_count': 2, 'log_sources': ['event_log', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] misleading_dual_use_high
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['living_off_the_land_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] missing_logs_no_attack
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] monitoring_netscan
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2602, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 6, 'log_source_count': 2, 'log_sources': ['network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['insider_misuse_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] msiexec_install
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.6, 'null_oos': 0.15, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.6, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] noisy_low_anomaly
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] oos_cloud_wrong_tenant
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.5157, 'entropy': 0.6927, 'explanation_count': 2, 'normalized_entropy': 0.9994, 'null_benign': 0.2, 'null_oos': 0.35, 'contested_edge_count': 0, 'log_source_count': 1, 'log_sources': ['process_creation'], 'explanation_ids': ['H1', 'H3'], 'explanation_types': ['lifecycle', 'l1_predecessor'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.2, 'oos': 0.35}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] oos_high_impact
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.258, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.25, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['file_system', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] oos_linux_on_windows_alert
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.35, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.35}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] patch_mgmt_wmi
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['living_off_the_land_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] persistence_scheduled_task
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2609, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] phishing_attachment_exec
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.45, 'null_oos': 0.15, 'contested_edge_count': 4, 'log_source_count': 4, 'log_sources': ['authentication', 'email_gateway', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] platform_mismatch_oos
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.45, 'null_oos': 0.25, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.25}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] powershell_admin
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] powershell_download_payload
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.259, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.6, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['dns_query', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.6, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] ransomware_chain
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.258, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['file_system', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] rdp_lateral
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2586, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['authentication', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] registry_run_key
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2609, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 1, 'log_sources': ['process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] simulation_high_score
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] soc_phish_sim
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2644, 'entropy': 1.3857, 'explanation_count': 4, 'normalized_entropy': 0.9996, 'null_benign': 0.45, 'null_oos': 0.15, 'contested_edge_count': 3, 'log_source_count': 4, 'log_sources': ['authentication', 'email_gateway', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] software_deploy_gpo
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2609, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] sparse_telemetry
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['living_off_the_land_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] stix_only_weak_tech
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.505, 'entropy': 0.6931, 'explanation_count': 2, 'normalized_entropy': 0.9999, 'null_benign': 0.25, 'null_oos': 0.3, 'contested_edge_count': 1, 'log_source_count': 1, 'log_sources': ['process_creation'], 'explanation_ids': ['H2', 'H4'], 'explanation_types': ['technique_context', 'dual_use_boundary'], 'lifecycle_templates': [], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.25, 'oos': 0.3}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] suspicious_parent_attack
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] timestamp_conflict
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 2, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] timestamp_spoofing
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2573, 'entropy': 1.3861, 'explanation_count': 4, 'normalized_entropy': 0.9999, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 1, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] uncertain_lateral_smb
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2586, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['authentication', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] vmware_admin_wmi
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['living_off_the_land_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] vuln_scanner_lateral_look
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2586, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['authentication', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['ransomware_enterprise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] weak_parent_no_network
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.35, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['network_connection', 'process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['commodity_malware_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.35, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] weak_signal_only
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.2602, 'entropy': 1.386, 'explanation_count': 4, 'normalized_entropy': 0.9998, 'null_benign': 0.45, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 3, 'log_sources': ['auditd', 'network_connection', 'process_creation'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['cloud_compromise_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.45, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}

## [PASS] wmi_remote_exec
- build_mode=opensource production_eligible=True
- metrics: {'max_prior': 0.263, 'entropy': 1.3859, 'explanation_count': 4, 'normalized_entropy': 0.9997, 'null_benign': 0.5, 'null_oos': 0.15, 'contested_edge_count': 8, 'log_source_count': 2, 'log_sources': ['process_creation', 'script_execution'], 'explanation_ids': ['H1', 'H2', 'H3', 'H4'], 'explanation_types': ['lifecycle', 'technique_context', 'l1_predecessor', 'dual_use_boundary'], 'lifecycle_templates': ['living_off_the_land_v1'], 'entropy_gate_label': 'PASS', 'null_anchor': {'benign': 0.5, 'oos': 0.15}}
- gates: {'max_prior_gate': True, 'entropy_gate': True, 'null_anchor_gate': True, 'explanation_count_gate': True, 'benign_cap_gate': True, 'semantic_firewall': True, 'hard_veto_safe': True, 'telemetry_negative_evidence_gate': True, 'passport_gate': True, 'fallback_production_ban': True, 'all_pass': True}
