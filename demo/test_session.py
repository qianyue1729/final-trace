"""Test the traced session output."""
import sys
sys.path.insert(0, "src")
sys.path.insert(0, "demo")
from server import run_traced_session
import json

session = run_traced_session()
print("Rounds:", len(session["rounds"]))
print("Report:", json.dumps(session["report"], ensure_ascii=False, indent=2))
for r in session["rounds"]:
    phases = [p["phase"] for p in r["phases"]]
    k_phase = next((p for p in r["phases"] if p["phase"] == "K"), None)
    if k_phase:
        leading = k_phase["decisionLedger"]["explanations"][0] if k_phase["decisionLedger"]["explanations"] else None
        margin = k_phase["decisionLedger"]["margin"]
        if leading:
            print(f"  R{r['round']}: {r['title']} | phases={phases} | margin={margin:.3f} | leading={leading['label']} ({leading['posterior']:.3f})")
        else:
            print(f"  R{r['round']}: {r['title']} | phases={phases} | margin={margin:.3f}")
    else:
        print(f"  R{r['round']}: {r['title']} | phases={phases}")
