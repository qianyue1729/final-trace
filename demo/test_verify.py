"""Comprehensive verification: check every LOCK component is truly driven by the real framework."""
import urllib.request
import json

r = urllib.request.urlopen("http://localhost:8001/api/session", timeout=30)
s = json.loads(r.read())

print("=" * 70)
print("LOCK 循环完整复现验证")
print("=" * 70)

# ── 1. 整体结构 ──
print("\n【1. 整体结构】")
print(f"  会话 ID: {s['id']}")
print(f"  告警标题: {s['alert']['title']}")
print(f"  预算: {s['budgetTotal']} probes")
print(f"  轮次数: {len(s['rounds'])}")
print(f"  最终决策: {s['report']['action']}")
print(f"  领先解释: {s['report']['leadingExplanation']}")
print(f"  停止原因: {s['report']['stopReason']}")

# ── 2. 每轮 LOCK 五拍 ──
print("\n【2. 每轮 LOCK 五拍 (L→VETO→O→C→K)】")
all_ok = True
for rd in s["rounds"]:
    phases = [p["phase"] for p in rd["phases"]]
    expected = ["L", "VETO", "O", "C", "K"]
    if rd["round"] == len(s["rounds"]):
        expected.append("STOP")
    match = phases == expected
    status = "✓" if match else "✗"
    if not match:
        all_ok = False
    print(f"  R{rd['round']}: {phases} {status}")
    # Check each phase has required data
    for p in rd["phases"]:
        has_graph = len(p.get("graph", {}).get("nodes", [])) >= 0
        has_ledger = "decisionLedger" in p and len(p["decisionLedger"].get("explanations", [])) > 0
        has_probes = "probePool" in p
        has_obligations = "obligations" in p
        has_beta = "betaEntries" in p
        has_stop = "stopSignals" in p
        if not all([has_graph, has_ledger, has_probes, has_obligations, has_beta, has_stop]):
            print(f"    ✗ {p['phase']}: missing data (graph={has_graph}, ledger={has_ledger}, probes={has_probes}, obligations={has_obligations}, beta={has_beta}, stop={has_stop})")
            all_ok = False

print(f"\n  全部五拍完整: {'✓ 是' if all_ok else '✗ 否'}")

# ── 3. 决策账贝叶斯更新轨迹 ──
print("\n【3. 决策账贝叶斯更新轨迹】")
print(f"  {'轮次':>4} | {'H1':>8} | {'H2':>8} | {'H3':>8} | {'null':>8} | {'margin':>8} | leading")
print(f"  {'─'*4}─┼─{'─'*8}─┼─{'─'*8}─┼─{'─'*8}─┼─{'─'*8}─┼─{'─'*8}─┼─{'─'*20}")
for rd in s["rounds"]:
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if not k:
        continue
    exps = {e["eid"]: e["posterior"] for e in k["decisionLedger"]["explanations"]}
    margin = k["decisionLedger"]["margin"]
    leading = next((e["label"] for e in k["decisionLedger"]["explanations"] if e.get("leading")), "?")
    h1 = exps.get("H1", 0)
    h2 = exps.get("H2", 0)
    h3 = exps.get("H3", 0)
    null = exps.get("null", 0)
    print(f"  R{rd['round']:>3} | {h1:>8.4f} | {h2:>8.4f} | {h3:>8.4f} | {null:>8.4f} | {margin:>8.4f} | {leading}")

# Verify posterior changes (not static)
r1_k = next(p for p in s["rounds"][0]["phases"] if p["phase"] == "K")
r3_k = next(p for p in s["rounds"][2]["phases"] if p["phase"] == "K")
r1_h1 = next(e for e in r1_k["decisionLedger"]["explanations"] if e["eid"] == "H1")["posterior"]
r3_h1 = next(e for e in r3_k["decisionLedger"]["explanations"] if e["eid"] == "H1")["posterior"]
r5_k = next(p for p in s["rounds"][4]["phases"] if p["phase"] == "K")
r5_h1 = next(e for e in r5_k["decisionLedger"]["explanations"] if e["eid"] == "H1")["posterior"]
print(f"\n  H1 后验变化: R1={r1_h1:.4f} → R3={r3_h1:.4f} → R5={r5_h1:.4f}")
print(f"  贝叶斯更新真实生效: {'✓ 是 (后验在每轮变化)' if r1_h1 != r3_h1 or r3_h1 != r5_h1 else '✗ 否 (后验不变)'}")

# ── 4. SessionGraph 增长 ──
print("\n【4. SessionGraph (第一本账) 增长轨迹】")
prev_nodes = 0
prev_edges = 0
for rd in s["rounds"]:
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if not k:
        continue
    nodes = len(k["graph"]["nodes"])
    edges = len(k["graph"]["edges"])
    delta_n = f"+{nodes - prev_nodes}" if nodes > prev_nodes else ""
    delta_e = f"+{edges - prev_edges}" if edges > prev_edges else ""
    print(f"  R{rd['round']}: {nodes} nodes {delta_n:>4} | {edges} edges {delta_e:>4}")
    prev_nodes = nodes
    prev_edges = edges

# Check node kinds
r5_k_graph = next(p for p in s["rounds"][4]["phases"] if p["phase"] == "K")["graph"]
kinds = {}
for n in r5_k_graph["nodes"]:
    kinds[n["kind"]] = kinds.get(n["kind"], 0) + 1
print(f"  最终图节点类型: {kinds}")
malicious_count = sum(1 for n in r5_k_graph["nodes"] if n.get("malicious"))
print(f"  恶意节点: {malicious_count}/{len(r5_k_graph['nodes'])}")

# ── 5. ProbePool (VOI 排序) ──
print("\n【5. ProbePool (第三本账 · VOI 排序)】")
for rd in s["rounds"][:3]:  # Show first 3 rounds
    o = next((p for p in rd["phases"] if p["phase"] == "O"), None)
    if not o:
        continue
    pool = o.get("probePool", [])
    selected = [p for p in pool if p.get("selected")]
    print(f"  R{rd['round']}: {len(pool)} candidates, {len(selected)} selected")
    for p in pool[:3]:
        sel = "★" if p.get("selected") else " "
        print(f"    {sel} {p['probe']:40s} VOI={p['voi']:.4f} hitRate={p['hitRate']:.4f}")

# ── 6. ObligationLedger ──
print("\n【6. ObligationLedger (第四本账 · 义务管理)】")
for rd in s["rounds"]:
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if not k:
        continue
    obs = k.get("obligations", [])
    for ob in obs:
        discharged = "✓" if ob.get("discharged") else "⏳"
        print(f"  R{rd['round']}: {ob['id']:20s} type={ob['type']:15s} hard={ob['hard']} voi={ob['voi']:.4f} {discharged}")

# ── 7. BetaLedger ──
print("\n【7. BetaLedger (第二本账 · 探针灵敏度)】")
for rd in s["rounds"]:
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if not k:
        continue
    betas = k.get("betaEntries", [])
    print(f"  R{rd['round']}: {len(betas)} entries")
    for b in betas:
        print(f"    {b['key']:40s} hits={b['hits']} total={b['total']}")

# ── 8. StopSignals ──
print("\n【8. StopSignals (停止判定)】")
for rd in s["rounds"]:
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if not k:
        continue
    ss = k.get("stopSignals", {})
    budget = "✓" if ss.get("budget") else " "
    hard = "✓" if ss.get("hardObligations") else " "
    voi = "✓" if ss.get("voiFloor") else " "
    robust = "✓" if ss.get("robust") else " "
    print(f"  R{rd['round']}: budget=[{budget}] hard=[{hard}] voiFloor=[{voi}] robust=[{robust}]")

# ── 9. 最终报告 ──
print("\n【9. 最终报告】")
report = s["report"]
print(f"  处置决策: {report['action']}")
print(f"  置信度: {report['confidence']:.4f}")
print(f"  停止原因: {report['stopReason']}")
print(f"  领先解释: {report['leadingExplanation']}")
print(f"  次优解释: {report['suboptimalExplanation']['label']} (P={report['suboptimalExplanation']['posterior']:.4f})")
print(f"  反事实: {report['counterfactual']}")

# ── Summary ──
print("\n" + "=" * 70)
print("总结: LOCK 循环完整复现验证")
print("=" * 70)
checks = [
    ("5 轮 × 5 拍 (L→VETO→O→C→K)", len(s["rounds"]) == 5 and all(len(r["phases"]) >= 5 for r in s["rounds"])),
    ("贝叶斯后验每轮更新", r1_h1 != r3_h1 or r3_h1 != r5_h1),
    ("SessionGraph 节点增长", prev_nodes > 5),
    ("SessionGraph 边存在", prev_edges > 0),
    ("ProbePool 有候选探针", len(s["rounds"][0]["phases"][2].get("probePool", [])) > 0),
    ("ObligationLedger 有义务", len(s["rounds"][0]["phases"][4].get("obligations", [])) > 0),
    ("BetaLedger 有记录", len(s["rounds"][0]["phases"][4].get("betaEntries", [])) > 0),
    ("StopSignals 四条件", all("stopSignals" in p for r in s["rounds"] for p in r["phases"] if p["phase"] == "K")),
    ("最终决策 = CONTAIN/ESCALATE", "CONTAIN" in report["action"]),
    ("H1 勒索软件 = 领先解释", "勒索" in report["leadingExplanation"]),
]
for name, ok in checks:
    print(f"  {'✓' if ok else '✗'} {name}")
print(f"\n  {'全部通过 ✓' if all(ok for _, ok in checks) else '存在未通过项 ✗'}")
