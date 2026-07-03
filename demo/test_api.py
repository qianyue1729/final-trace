"""Test the API endpoint."""
import urllib.request
import json

r = urllib.request.urlopen("http://localhost:8001/api/session")
s = json.loads(r.read())

print("=== SESSION OVERVIEW ===")
print(f"Rounds: {len(s['rounds'])}")
print(f"Alert: {s['alert']['title']}")
print(f"Budget total: {s['budgetTotal']}")
print(f"Report action: {s['report']['action']}")
print(f"Report leading: {s['report']['leadingExplanation']}")
print()

for rd in s["rounds"]:
    phases = [p["phase"] for p in rd["phases"]]
    k = next((p for p in rd["phases"] if p["phase"] == "K"), None)
    if k:
        exps = k["decisionLedger"]["explanations"]
        print(f"R{rd['round']}: {rd['title']}")
        print(f"  phases={phases}")
        print(f"  margin={k['decisionLedger']['margin']:.3f}")
        for e in exps:
            tag = " <-- LEADING" if e.get("leading") else ""
            print(f"    {e['eid']:8s} {e.get('label',''):30s} P={e['posterior']:.4f}{tag}")
        print(f"  graph: {len(k['graph']['nodes'])} nodes, {len(k['graph']['edges'])} edges")
        print(f"  probes(O): {len(rd['phases'][2]['probePool'])} candidates")
        print(f"  obligations: {len(k['obligations'])} items")
        print(f"  beta entries: {len(k['betaEntries'])} items")
        print(f"  stopSignals: {k['stopSignals']}")
        print()
