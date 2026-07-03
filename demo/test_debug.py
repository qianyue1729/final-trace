"""Detailed test: inspect per-phase state to debug stagnant posteriors."""
import sys
sys.path.insert(0, "src")
sys.path.insert(0, "demo")
from server import run_traced_session
import json

session = run_traced_session()
print("Rounds:", len(session["rounds"]))

for r in session["rounds"][:3]:
    print(f"\n=== Round {r['round']}: {r['title']} ===")
    for p in r["phases"]:
        nodes = len(p["graph"]["nodes"])
        edges = len(p["graph"]["edges"])
        probes = len(p["probePool"])
        sel = len([x for x in p["probePool"] if x.get("selected")])
        expls = p["decisionLedger"]["explanations"]
        margin = p["decisionLedger"]["margin"]
        budget = p["budgetUsed"]
        stop = p["stopSignals"]
        print(f"  [{p['phase']}] nodes={nodes} edges={edges} probes={probes}({sel}sel) margin={margin:.3f} budget={budget} stop={stop['budget']}/{stop['hardObligations']}/{stop['voiFloor']}/{stop['robust']}")
        for e in expls:
            print(f"       {e['eid']}: {e['label']} = {e['posterior']:.4f} {'(leading)' if e.get('leading') else ''}")
        if p["probePool"]:
            top = p["probePool"][0]
            print(f"       top probe: {top['probe']} voi={top['voi']:.4f} hit={top.get('hitRate', 0):.3f}")
