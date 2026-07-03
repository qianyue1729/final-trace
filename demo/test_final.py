"""Final attack chain verification via API."""
import urllib.request
import json

r = urllib.request.urlopen("http://localhost:8001/api/session", timeout=60)
s = json.loads(r.read())

print("=" * 70)
print("攻击链完整重构最终验证")
print("=" * 70)

# Get final graph from R5 K phase
r5_k = next(p for p in s["rounds"][4]["phases"] if p["phase"] == "K")
graph = r5_k["graph"]

print(f"\n【最终图统计】")
print(f"  节点: {len(graph['nodes'])}")
print(f"  边: {len(graph['edges'])}")

# Node analysis by kind
kinds = {}
for n in graph["nodes"]:
    kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
print(f"  节点类型分布: {kinds}")

malicious = [n for n in graph["nodes"] if n.get("malicious")]
print(f"  恶意节点: {len(malicious)}/{len(graph['nodes'])}")
for n in malicious:
    print(f"    🔴 {n['id']:15s} kind={n['kind']:8s} label={n['label']}")

# Edge analysis
print(f"\n【因果边】({len(graph['edges'])} 条)")
relation_counts = {}
for e in graph["edges"]:
    relation_counts[e["label"]] = relation_counts.get(e["label"], 0) + 1
print(f"  关系类型: {relation_counts}")

# Growth trajectory
print(f"\n【图增长轨迹】")
for rd in s["rounds"]:
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if not k:
        continue
    n = len(k["graph"]["nodes"])
    e = len(k["graph"]["edges"])
    mal = sum(1 for x in k["graph"]["nodes"] if x.get("malicious"))
    print(f"  R{rd['round']}: {n:2d} nodes ({mal} mal) | {e:2d} edges | margin={k['decisionLedger']['margin']:.4f}")

# Posterior convergence
print(f"\n【后验收敛曲线】")
for rd in s["rounds"]:
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if not k:
        continue
    exps = {e["eid"]: e["posterior"] for e in k["decisionLedger"]["explanations"]}
    h1 = exps.get("H1", 0)
    null = exps.get("null", 0)
    margin = k["decisionLedger"]["margin"]
    bar_h1 = "█" * int(h1 * 40)
    bar_null = "░" * int(null * 40)
    print(f"  R{rd['round']}: H1={h1:.4f} |{bar_h1}| null={null:.4f} |{bar_null}|")

# Final report
print(f"\n【最终报告】")
print(f"  处置决策: {s['report']['action']}")
print(f"  置信度: {s['report']['confidence']}")
print(f"  领先解释: {s['report']['leadingExplanation']}")
print(f"  停止原因: {s['report']['stopReason']}")
print(f"  反事实: {s['report']['counterfactual']}")

# Comprehensive checks
print(f"\n{'='*70}")
print(f"攻击链完整性核查")
print(f"{'='*70}")

checks = []

# 1. Graph growth
final_nodes = len(graph["nodes"])
final_edges = len(graph["edges"])
checks.append(("图节点 ≥ 15", final_nodes >= 15, f"{final_nodes} nodes"))
checks.append(("图边 ≥ 20", final_edges >= 20, f"{final_edges} edges"))

# 2. Malicious nodes found
mal_count = len(malicious)
checks.append(("恶意节点 ≥ 5", mal_count >= 5, f"{mal_count} malicious"))

# 3. Edge diversity
edge_types = len(relation_counts)
checks.append(("边关系多样性 ≥ 2", edge_types >= 2, f"{relation_counts}"))

# 4. H1 confidence reaches very high
final_h1 = next(e for e in r5_k["decisionLedger"]["explanations"] if e.get("leading"))["posterior"]
checks.append(("H1 最终后验 ≥ 0.99", final_h1 >= 0.99, f"H1={final_h1:.4f}"))

# 5. Decision correct
checks.append(("决策 = CONTAIN/ESCALATE", "CONTAIN" in s["report"]["action"], s["report"]["action"]))

# 6. 5 rounds complete
checks.append(("5 轮完整 LOCK", len(s["rounds"]) == 5, f"{len(s['rounds'])} rounds"))

# 7. Each round has 5 phases
all_phases_ok = all(len(rd["phases"]) >= 5 for rd in s["rounds"])
checks.append(("每轮 ≥ 5 拍", all_phases_ok, "L→VETO→O→C→K"))

# 8. Beta grows
r1_beta = len(s["rounds"][0]["phases"][4].get("betaEntries", []))
r5_beta = len(r5_k.get("betaEntries", []))
checks.append(("BetaLedger 增长", r5_beta > r1_beta, f"{r1_beta}→{r5_beta}"))

# 9. Monotone graph growth
node_counts = [len(next(p for p in rd["phases"] if p["phase"]=="K")["graph"]["nodes"]) for rd in s["rounds"]]
grows = all(node_counts[i] <= node_counts[i+1] for i in range(len(node_counts)-1))
checks.append(("图单调增长", grows, f"{node_counts}"))

# 10. Stop signals progress
r5_ss = r5_k["stopSignals"]
checks.append(("R5 budget 触发停止", r5_ss["budget"], str(r5_ss)))

for name, passed, detail in checks:
    icon = "✓" if passed else "✗"
    print(f"  {icon} {name}: {detail}")

all_passed = all(p for _, p, _ in checks)
print(f"\n  {'★ 攻击链路完整重构: 全部通过 ★' if all_passed else '存在未通过项'}")
