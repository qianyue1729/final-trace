# 运行时源码索引

构建产物写入 `src/trace_agent/data/` 后，由下列模块在 **Initialize / Plan / Keep** 阶段消费。阶段汇报见 [README §Phase 2：Runtime MVP](../README.md#phase-2runtime-mvp消费层)。

## 核心模块

| 模块 | 路径 | 职责 |
|------|------|------|
| 数据加载 | `src/trace_agent/data_loader.py` | `load_attack_matrix`, `load_tech_causal_graph`, 校验 |
| 先验引擎 | `src/trace_agent/prior_v2.py` | `PriorManager` L1/L2/L3/L4、战术映射、路径联合概率 |
| 决策账播种 | `src/trace_agent/decision/belief.py` | `DecisionLedger.seed()` — score_v3 + softmax；`MAX_INITIAL_P=0.55` 约束初始分布 |
| 探针（最小） | `src/trace_agent/probe/voi.py` | Sigma visibility + env_config + trust 排序；**非**完整 VOI |
| CLI 演示 | `prior_knowledge/seed_demo.py` | 调用 Runtime MVP，不在 `src/trace_agent/` |
| 算法 trace | `src/trace_agent/loop/compute_trace.py` | `belief_seed_trace` → 前端 algo_trace |
| 调查入口 | `src/trace_agent/agents/orchestrator.py` | `Orchestrator._initialize()` 调用 seed |

## 先验产物

| 产物 | 路径 | 层 |
|------|------|-----|
| 战术转移矩阵 | `src/trace_agent/data/attack_matrix.json` | L1 |
| 技术因果图 | `src/trace_agent/data/tech_causal_graph.json` | L2 |
| 证据信任注册表 | `src/trace_agent/data/log_source_trust.json` | L3 |
| 生命周期模板 | `src/trace_agent/data/lifecycle_templates.json` | L4 |
| 环境配置 | `src/trace_agent/data/env_config.json` | L3（租户） |
| 权重配置 | `prior_knowledge/templates/score_v3_weights.json` | 播种 |
| 损失基线 | `prior_knowledge/templates/loss_baseline.json` | VOI/停止 |
| 构建清单 | `src/trace_agent/data/prior_manifest.json` | 版本追踪 |

## 相关测试

- `tests/runtime/test_decisionledger_seed_with_real_prior.py` — **4** 个 seed / PriorManager 验收（Phase 2 MVP）
- `tests/test_prior_v2.py` — L1/L2 加载与 PriorManager
- `tests/test_compute_trace.py` — `belief_seed_trace`, `seed_from_prior`
- `tests/test_rfc004_acceptance.py` — DecisionLedger seed 验收

## 环境变量

| 变量 | 作用 |
|------|------|
| `PRIOR_DATA_DIR` | 覆盖默认 `src/trace_agent/data/` 目录 |

## 术语映射（RFC-004-02 对齐）

| 旧术语 | 新术语 | 说明 |
|--------|--------|------|
| NarrativeBelief | DecisionLedger | 第四本账 |
| seed_from_prior | DecisionLedger.seed() | 播种决策账 |
| H0/H1/H2 固定三假设 | ≤4-6 竞争解释 + null 锚 | 不再固定数量 |
| 叙事信念态 | 竞争解释后验 | 废弃"叙事"表述 |
| — | BoundaryBelief | 边粒度归属 {in_attack, benign, oos} |
| — | EvidenceTrust | 证据信任向量 |
| — | LifecycleTemplate | 攻击生命周期模板 |
