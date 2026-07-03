# 先验知识 · 开源数据层（Open Source Raw Layer）

> **第一原则**：`prior_knowledge` 的生产产物（L1–L4、score_v3、loss）**必须能追溯到大量公开开源 Raw 快照**，而不是内嵌 50 条 APT 或手工 150 条边。

---

## 为什么必须来自开源数据

| 问题 | 若只用内嵌 fallback | 用开源 Raw |
|------|---------------------|------------|
| 覆盖 APT / technique | ~50 组、~80 节点 | STIX 全量 100+ 组、600+ 技术 |
| 可复现 / 审计 | 「谁编的？」 | `raw/manifest.json` checksum |
| 与 RFC-004-02 一致 | 播种像「编故事」 | 薄先验 = 公开统计的高熵初始化 |
| 分工清晰 | 混在一起 | 各源只干一件事（见下表） |

决策账播种（`DecisionLedger.seed`）需要的是 **P(H) 方向 + boundary_prior + null 锚**——这些都应来自可引用的公开统计，而不是演示硬编码。

---

## 数据流

```
┌─────────────────────────────────────────────────────────────┐
│  Raw Layer（prior_knowledge/raw/）                            │
│  MITRE STIX · ATT&CK Flow · Sigma · Atomic · LOLBAS · …     │
└───────────────────────────┬─────────────────────────────────┘
                            │ fetch_opensource.py
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Normalize / Build                                          │
│  build_attack_matrix.py  → L1                               │
│  build_causal_graph.py   → L2                               │
│  upgrade_to_v2.py        → v2 + boundary_prior + manifest   │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  Runtime（src/trace_agent/data/）                           │
│  attack_matrix · causal_graph · lifecycle · trust · …       │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
                    DecisionLedger.seed(E)
```

---

## 源登记（`raw/sources.json`）

| ID | 源 | 用途 | 权重语义 |
|----|-----|------|----------|
| `mitre_enterprise_attack_stix` | MITRE CTI | L1 战术转移、technique 元数据 | STIX 共现 0.2（非时序） |
| `attack_flow_corpus_sample` | CTID ATT&CK Flow | L1/L2 **时序边**、delay | **1.0** |
| `atomic_enterprise_matrix` | Atomic Red Team | L2 `is_observable` | 覆盖验证 |
| `lolbas_csv` | LOLBAS | L2 `tools.lolbas`、**dual-use boundary signal** | 抬高 benign 竞争，非 benign 判定 |
| `gtfobins_data_functions` | GTFOBins | Linux 双用途 | 同 LOLBAS |
| `sigma_rules_index` | SigmaHQ | L3 log source 映射 | **不当因果** |

**铁律**：STIX 共现 **≠** 攻击时序；时序只认 Flow / 报告显式顺序。

---

## 命令

```powershell
# 1. 拉取 Raw（生产必做）
python prior_knowledge/build/fetch_opensource.py

# 仅 MITRE STIX（最小生产集）
python prior_knowledge/build/fetch_opensource.py --required-only

# 2. 全量构建（默认会先 fetch）
python prior_knowledge/build/run_all.py

# 无网开发（允许 fallback，manifest 标 build_mode=fallback_or_partial）
python prior_knowledge/build/run_all.py --offline
```

---

## 目录约定

```
prior_knowledge/raw/
  sources.json              # 源登记（URL、path、required、used_by）
  manifest.json             # 拉取结果 + STIX 对象统计 + checksum
  mitre/
    enterprise-attack.json  # 必需 · ~数 MB · 数千 STIX objects
  attack_flow/
  atomic/
  lolbas/
  sigma/
  gtfobins/
```

**不要**把 Raw 大文件提交进 git（建议 `.gitignore` + CI 缓存）；**要**提交 `sources.json` 与构建脚本。

---

## 与 fallback 的边界

| 模式 | `prior_manifest.build_mode` | 何时用 |
|------|----------------------------|--------|
| `opensource` | raw STIX 已缓存/拉取成功 | **生产、演示、评测** |
| `fallback_or_partial` | 无 raw/manifest 或 STIX 失败 | 仅离线开发 |

内嵌 `EMBEDDED_APT_TACTICS`（50 组）和手工 `NODES`/`EDGES`（L2）是 **YAGNI 退路**，不是「大量开源数据」的替代品。

---

## 后续集成（Phase 1–3）

1. **L1 加权**：Flow 边 1.0 + 报告 0.9 + STIX 0.2（见 README §L1）
2. **L2 从 STIX + Flow 生成边**，替换手工 150 边
3. **Sigma → log_source_trust** 自动映射
4. **LOLBAS/GTFOBins → boundary_prior** — 抬高 `p_benign` 竞争 / contested；Runtime 再判 benign

详见 `prior_knowledge/README.md` §实施路线。
