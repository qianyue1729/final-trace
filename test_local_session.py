#!/usr/bin/env python3
"""Test local ransomware demo session."""
import httpx
import json

print("Running ransomware_demo...")
r = httpx.get('http://localhost:8001/api/session?scenario=ransomware_demo', timeout=30)
s = r.json()

print(f"\n{'='*60}")
print(f"Total rounds: {len(s.get('rounds', []))}")
print(f"Budget used: {s.get('budgetUsed')}/{s.get('budgetTotal')}")

report = s.get('report', {})
decision = report.get('decision', {})
print(f"\nDecision: {decision.get('action', 'N/A')}")
print(f"Confidence: {report.get('confidence')}")
print(f"Leading explanation: {report.get('leadingExplanation')}")

trace = report.get('traceNarrative', {})
print(f"\nCase ID: {trace.get('caseId')}")
print(f"Alert Summary: {trace.get('alertSummary')}")

kill_chain = trace.get('killChainStages', [])
print(f"\nKill Chain Stages ({len(kill_chain)}):")
for stage in kill_chain[:5]:
    print(f"  - {stage['stage']}: {stage['technique']}")

print(f"\nConclusion preview:")
conclusion = trace.get('conclusion', '')
print(conclusion[:300] if len(conclusion) > 300 else conclusion)

# Show first round details
if s.get('rounds'):
    round1 = s['rounds'][0]
    print(f"\n{'='*60}")
    print(f"Round 1: {round1.get('title')}")
    phases = round1.get('phases', [])
    for p in phases:
        summary = p.get('summary', '')
        print(f"  Phase {p['phase']}: {summary}")

print("\n" + "="*60)
print("✅ Local ransomware demo session completed successfully!")
