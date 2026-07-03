# 先验产物 JSON Schema

运行时默认路径：`src/trace_agent/data/`（见 `paths.py`）。

---

## L1 — `attack_matrix.json`

```json
{
  "metadata": {
    "version": "2.0",
    "generated_date": "YYYY-MM-DD",
    "data_source": "mitre-cti + attack-flow + reports",
    "total_apt_groups": 167,
    "smoothing": "dirichlet",
    "alpha": 0.5,
    "source_weights": {
      "attack_flow": 1.0,
      "report_explicit_time": 0.9,
      "report_weak_order": 0.6,
      "stix_cooccurrence": 0.2,
      "expert_template": 0.1
    }
  },
  "tactics": ["TA0043", "TA0042", "TA0001", "..."],
  "matrix": {
    "TA0002": {
      "TA0001": {
        "probability": 0.4786,
        "log_odds": 1.24,
        "support": {
          "attack_flow_edges": 18,
          "report_edges": 42,
          "stix_cooccurrence": 133
        },
        "confidence": 0.78
      }
    }
  }
}
```

- **语义**：`matrix[current_tactic][prev_tactic]` = 反向溯源场景下 P(前驱战术 | 当前战术)
- **每行概率和 ≈ 1.0**（Dirichlet 平滑后归一化）
- **support** 字段保留各来源贡献，便于审计
- **校验**：`data_loader.validate_attack_matrix`

---

## L2 — `tech_causal_graph.json`

```json
{
  "metadata": {
    "version": "2.0",
    "generated_date": "YYYY-MM-DD",
    "total_techniques": 97,
    "total_edges": 155,
    "source_priority": ["attack_flow", "report_sequence", "stix_cooccurrence", "sigma_overlap"]
  },
  "nodes": {
    "T1059.001": {
      "name": "PowerShell",
      "tactic": "TA0002",
      "platforms": ["Windows"],
      "log_sources": ["process_creation", "script_execution", "powershell_log"],
      "is_observable": true,
      "tools": {
        "lolbas": ["powershell.exe"],
        "gtfobins": []
      },
      "sigma_rules": [],
      "atomic_tests": []
    }
  },
  "edges": [
    {
      "src": "T1059.001",
      "dst": "T1021.002",
      "probability": 0.18,
      "reverse_prior": 0.22,
      "delay_distribution": {
        "type": "lognormal",
        "p50_seconds": 180,
        "p90_seconds": 3600
      },
      "boundary_prior": {
        "p_in_attack": 0.55,
        "p_benign": 0.30,
        "p_oos": 0.15
      },
      "support": {
        "attack_flow": 7,
        "report_sequence": 19,
        "stix_cooccurrence": 66,
        "sigma_overlap": 3,
        "atomic_available": true
      },
      "confidence": 0.71,
      "description": "PowerShell performs SMB lateral movement"
    }
  ]
}
```

- **语义**：`probability` = P(dst | src)；`reverse_prior` = P(src | dst)（反向溯源用）
- **boundary_prior**：`{p_in_attack, p_benign, p_oos}` 归一化到 1.0——每条候选边的初始三元归属
- **delay_distribution**：分位数比均值更稳；fallback 层级：technique-pair → tactic-pair → lifecycle-stage → global
- **校验**：`data_loader.validate_tech_graph`（节点 ≥80，边 ≥150，boundary_prior 三项和 ≈ 1.0）

---

## L3 — `env_config.json`（租户配置）

模板：`templates/env_config.template.json`

| 字段 | 用途 |
|------|------|
| `os_type` | Windows / Linux / macOS |
| `available_log_sources` | 与 L2 节点 `log_sources` 求交，过滤不可观测战术 |
| `excluded_techniques` | 环境中排除的技术 |
| `high_value_assets` | 域控、核心网段（可接 CMDB） |
| `environment_profiles` | 多站点 profile |

加载：`PriorConfig(env_config_path="...")`

---

## L3 — `log_source_trust.json`（证据信任注册表）

模板：`templates/log_source_trust.template.json`

```json
{
  "edr_kernel_process_event": {
    "integrity": 0.95,
    "tier": "forge-resistant",
    "adversary_controllable_base": false,
    "hard_veto_allowed": true,
    "platforms": ["windows", "linux", "macos"],
    "observes": ["process_creation", "module_load", "network_connection"]
  },
  "cloudtrail_management_event": {
    "integrity": 0.90,
    "tier": "high",
    "adversary_controllable_base": false,
    "hard_veto_allowed": true,
    "platforms": ["aws"],
    "observes": ["cloud_api_call", "iam_change"]
  },
  "windows_event_log_security": {
    "integrity": 0.60,
    "tier": "medium",
    "adversary_controllable_base": "contextual",
    "hard_veto_allowed": false,
    "platforms": ["windows"],
    "observes": ["logon", "privilege_use"]
  },
  "bash_history": {
    "integrity": 0.20,
    "tier": "low",
    "adversary_controllable_base": true,
    "hard_veto_allowed": false,
    "platforms": ["linux", "macos"],
    "observes": ["command_history"]
  }
}
```

- **tier 分级**：`forge-resistant`（抗伪造·可触发 hard VETO）> `high` > `medium` > `low`
- **adversary_controllable_base**：`true` | `false` | `"contextual"`（上下文决定）
- **服务于**：RFC-004-02 §5 EvidenceTrust → `is_forge_resistant()` / 似然降权 / 缺失即信号

---

## L4 — `lifecycle_templates.json`

```json
{
  "metadata": {
    "version": "1.0",
    "total_templates": 6
  },
  "templates": [
    {
      "template_id": "ransomware_enterprise_v1",
      "family": "ransomware",
      "stages": [
        {
          "stage": "initial_access",
          "required": true,
          "expected_tactics": ["initial-access"],
          "expected_techniques": ["T1566", "T1190", "T1133"],
          "debt_policy": "hard_if_no_initial_vector"
        },
        {
          "stage": "execution",
          "required": true,
          "expected_tactics": ["execution"],
          "expected_techniques": ["T1059", "T1204"],
          "debt_policy": "hard"
        },
        {
          "stage": "credential_access",
          "required": "conditional",
          "expected_tactics": ["credential-access"],
          "expected_techniques": ["T1003", "T1555"],
          "debt_policy": "voi_gated"
        },
        {
          "stage": "lateral_movement",
          "required": "conditional",
          "expected_tactics": ["lateral-movement"],
          "expected_techniques": ["T1021", "T1072"],
          "debt_policy": "voi_gated"
        },
        {
          "stage": "impact",
          "required": "conditional",
          "expected_tactics": ["impact"],
          "expected_techniques": ["T1486"],
          "debt_policy": "hard_if_ransomware_claimed"
        }
      ]
    }
  ]
}
```

- **debt_policy 值域**：`"hard"` | `"hard_if_<condition>"` | `"voi_gated"`
- **required 值域**：`true` | `"conditional"` | `false`
- **服务于**：RFC-004-02 §8 LifecycleTemplate → `unexplained_stages(expl, graph)` → 生命周期债务

---

## score_v3 — `score_v3_weights.json`

```json
{
  "version": "2.0",
  "temperature": 2.0,
  "weights": {
    "tactic_fit": 0.18,
    "technique_fit": 0.22,
    "lifecycle_fit": 0.18,
    "environment_fit": 0.12,
    "temporal_fit": 0.12,
    "threat_prevalence": 0.08,
    "boundary_risk": 0.10
  },
  "notes": "threat_prevalence 权重必须低；temperature 保持高熵"
}
```

- **formula**：`P0(H) = softmax(Σ w_i × feature_i(H,E) / τ)`
- **服务于**：`DecisionLedger.seed()` 初始化解释先验

---

## loss_baseline — `loss_baseline.json`

```json
{
  "version": "1.0",
  "lambda_miss": 10,
  "lambda_over": 2,
  "lambda_oos": 4,
  "sensitivity_ranges": {
    "lambda_miss": [8, 20],
    "lambda_over": [1, 5],
    "lambda_oos": [2, 8]
  },
  "profiles": {
    "conservative": {"lambda_miss": 15, "lambda_over": 1, "lambda_oos": 3},
    "boundary": {"lambda_miss": 12, "lambda_over": 4, "lambda_oos": 6},
    "multi_incident": {"lambda_miss": 10, "lambda_over": 2, "lambda_oos": 8}
  },
  "notes": "lambda_over > 0 是治过度归因的真正下限"
}
```

- **服务于**：RFC-004-02 §6 `bayes_risk()` 的边界项 + §7 价值导向停止

---

## DecisionLedger Seed 输出

```json
{
  "decision_ledger_seed": {
    "explanations": [
      {
        "eid": "H1",
        "label": "ransomware_early_execution",
        "is_null": false,
        "null_kind": null,
        "lifecycle_template": "ransomware_enterprise_v1",
        "current_stage": "execution",
        "seed_technique": "T1059.001",
        "log_prior": -1.13,
        "score_v3": {
          "tactic_fit": 0.71,
          "technique_fit": 0.66,
          "lifecycle_fit": 0.74,
          "environment_fit": 0.88,
          "temporal_fit": 0.50,
          "threat_prevalence": 0.42,
          "boundary_risk": 0.55
        }
      }
    ],
    "branch_null_anchor": {
      "benign": {"prior": 0.35, "meaning": "域内良性，剪掉即忘"},
      "oos": {"prior": 0.15, "meaning": "域外真恶意，SPAWN/FEEDBACK"}
    },
    "log_post": {"H1": -1.11, "H2": -1.28, "H3": -1.42, "H4": -1.61},
    "contested": {
      "edge:E": {
        "p_in_attack": 0.45,
        "p_benign": 0.40,
        "p_oos": 0.15
      }
    },
    "entropy": "high",
    "source_version": "prior-bundle-2026.06"
  }
}
```

---

## 加载链

```
attack_matrix.json ──────────────────┐
tech_causal_graph.json ──────────────┤
env_config.json ─────────────────────┤
log_source_trust.json ───────────────┤ → PriorManager (prior_v2.py)
lifecycle_templates.json ────────────┤
score_v3_weights.json ───────────────┤
loss_baseline.json ──────────────────┘
                                     │
                                     ▼
                           DecisionLedger.seed()
                                     │
                                     ▼
                           Orchestrator._initialize()
```

---

## prior_bundle manifest

构建时生成 `manifest.json` 记录所有来源版本，确保可复现：

```json
{
  "version": "2026.06.29",
  "attack_stix_version": "v19.x",
  "attack_flow_version": "v3.2.0",
  "sigma_commit": "...",
  "atomic_red_team_commit": "...",
  "lolbas_commit": "...",
  "gtfobins_commit": "...",
  "generated_at": "2026-06-29",
  "checksums": {
    "l1": "sha256...",
    "l2": "sha256...",
    "l3": "sha256...",
    "l4": "sha256..."
  }
}
```
