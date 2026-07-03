# Prior Replay Report

**Passed:** 8/8 (orchestrator)

## [PASS] cloud_iam_anomaly — Cloud IAM 异常
- max_prior=0.2609 entropy=1.386 benign=0.35 oos=0.15 contested=2 log_sources=1
- checks: {'entropy_ok': True, 'top_k_hit': True, 'expected_hit': True}

## [PASS] concurrent_miner_ransomware — 挖矿与勒索并发
- max_prior=0.5157 entropy=0.6927 benign=0.2 oos=0.15 contested=0 log_sources=3
- checks: {'oos_anchor_ok': True, 'entropy_ok': True, 'top_k_hit': True, 'expected_hit': True}

## [PASS] linux_gtfobins — Linux GTFOBins 滥用
- max_prior=0.263 entropy=1.3859 benign=0.55 oos=0.15 contested=8 log_sources=2
- checks: {'benign_anchor_ok': True, 'boundary_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] log_clearing — 日志被清理
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=5 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] powershell_admin — 正常 PowerShell 运维
- max_prior=0.263 entropy=1.3859 benign=0.35 oos=0.15 contested=8 log_sources=3
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'top_k_hit': True, 'hard_veto_safe': True, 'expected_hit': True}

## [PASS] powershell_download_payload — PowerShell 下载 payload
- max_prior=0.259 entropy=1.386 benign=0.6 oos=0.15 contested=8 log_sources=3
- checks: {'entropy_ok': True, 'top_k_hit': True, 'boundary_ok': True, 'log_source_ok': True, 'expected_hit': True}

## [PASS] ransomware_chain — Ransomware chain
- max_prior=0.258 entropy=1.386 benign=0.35 oos=0.15 contested=8 log_sources=2
- checks: {'entropy_ok': True, 'top_k_hit': True, 'boundary_ok': True, 'expected_hit': True}

## [PASS] timestamp_spoofing — 时间戳伪造
- max_prior=0.2573 entropy=1.3861 benign=0.35 oos=0.15 contested=1 log_sources=2
- checks: {'benign_anchor_ok': True, 'entropy_ok': True, 'top_k_hit': True, 'hard_veto_safe': True, 'expected_hit': True}
