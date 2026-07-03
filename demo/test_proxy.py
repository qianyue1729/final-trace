"""Test Vite proxy -> Python backend end-to-end."""
import urllib.request
import json

# Test through Vite proxy (port 5182) -> Python backend (port 8001)
r = urllib.request.urlopen("http://localhost:5182/api/session", timeout=30)
s = json.loads(r.read())

print("Vite proxy test:")
print(f"  Status: 200")
print(f"  Rounds: {len(s['rounds'])}")
print(f"  Report: {s['report']['action']}")
print(f"  Leading: {s['report']['leadingExplanation']}")

r1_k = s["rounds"][0]["phases"][4]  # R1 K phase
print(f"  R1 K graph: {len(r1_k['graph']['nodes'])} nodes, {len(r1_k['graph']['edges'])} edges")
print(f"  R1 K margin: {r1_k['decisionLedger']['margin']}")

r3_k = s["rounds"][2]["phases"][4]  # R3 K phase
print(f"  R3 K graph: {len(r3_k['graph']['nodes'])} nodes, {len(r3_k['graph']['edges'])} edges")

r5_phases = [p["phase"] for p in s["rounds"][4]["phases"]]
print(f"  R5 phases: {r5_phases}")

# Check stepExplain presence
has_step = any(
    "stepExplain" in p for r in s["rounds"] for p in r["phases"]
)
print(f"  stepExplain present: {has_step}")

# Check probe pool has data
r1_o = s["rounds"][0]["phases"][2]  # R1 O phase
probe_count = len(r1_o.get("probePool", []))
print(f"  R1 O probePool: {probe_count} candidates")

# Check obligations
r1_k_obs = r1_k.get("obligations", [])
print(f"  R1 K obligations: {len(r1_k_obs)} items")

# Check beta entries
r1_k_beta = r1_k.get("betaEntries", [])
print(f"  R1 K beta entries: {len(r1_k_beta)} items")

print("  END-TO-END OK")
