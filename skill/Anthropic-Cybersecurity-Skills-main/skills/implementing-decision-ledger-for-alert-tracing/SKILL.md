---
name: implementing-decision-ledger-for-alert-tracing
description: Implement a Decision Ledger that maintains a small set of competing explanations
  (with null anchors) as a Bayesian posterior, enabling principled alert triage decisions
  with calibrated confidence, boundary delineation, and abductive maintenance in SOC
  environments.
domain: cybersecurity
subdomain: soc-operations
tags:
- decision-ledger
- competing-explanations
- bayesian-posterior
- null-anchor
- alert-tracing
- abductive-reasoning
- boundary-belief
- soc
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.AE-02
- DE.AE-06
- RS.AN-03
mitre_attack:
- T1059
- T1078
- T1071
---

# Implementing Decision Ledger for Alert Tracing

## Overview

The Decision Ledger is the fourth ledger in the LOCK cycle (alongside SessionGraph, Beta Ledger, and Obligation Ledger). It maintains a small set (≤4–6) of competing explanations as a normalized log-posterior, including null anchors at two granularities. This enables the SOC engine to produce actionable decisions with calibrated confidence, explicit attack boundaries, runner-up explanations, and counterfactuals — objects that per-probe hit-rate ledgers cannot produce.

The core insight: alert tracing is an **abductive reasoning** problem (effect→cause). The Decision Ledger provides a principled landing surface for competing causal hypotheses, preventing both tunnel vision (missing the true attack) and over-attribution (expanding blast radius with unrelated activity).

## When to Use

- When building a decision-oriented alert triage engine that must output calibrated confidence and attack boundaries
- When existing probe-level hit-rate metrics lead to over-attribution (blast radius expansion)
- When the system must distinguish "this edge doesn't belong to this attack" from "this whole alert is benign"
- When multiple competing explanations exist and the system needs principled disambiguation
- When implementing the LOCK cycle's K-beat update with abductive maintenance

## Prerequisites

- A functioning LOCK cycle with SessionGraph, Beta Ledger, and Obligation Ledger (RFC-003)
- Initial triage / bootstrap chain producing a seed causal subgraph
- A scoring function (e.g., score_v3) for initializing explanation priors
- Evidence trust model capable of producing integrity and adversary-controllability assessments
- Familiarity with Bayesian updating and log-posterior arithmetic

## Workflow

### Step 1: Define the Explanation Data Structure

Each competing explanation represents a coherent causal hypothesis about the observed alert.

```python
@dataclass
class Explanation:
    eid: str                        # unique explanation ID
    label: str                      # human-readable: "ransomware delivery" / "legitimate batch job"
    is_null: bool                   # True = null anchor (session-level or branch-level)
    null_kind: str | None           # "benign" (prune & forget) | "oos" (out-of-scope malicious → SPAWN/FEEDBACK)
    lifecycle_stage: str            # current kill-chain stage this explanation has reached
    subgraph: SessionSubgraph       # the causal subgraph claimed by this explanation

    def likelihood(self, evidence, trust) -> float:
        """P(evidence | this explanation), trust-weighted. See Step 4."""
        log_l = (log_fit_struct(evidence, self.subgraph)
                + log_fit_stage(evidence, self.lifecycle_stage)
                + log_w_trust(evidence, trust))
        return exp(clip(log_l, LOG_MIN, LOG_MAX))
```

### Step 2: Initialize the Decision Ledger (Thin Seeding)

Seeding is analogous to initializing Beta ledger priors — cheap, high-entropy, will be washed out by evidence.

```python
@dataclass
class DecisionLedger:
    explanations: list[Explanation]        # ≤ K_max (hard cap = 6)
    log_post: dict[str, float]            # normalized log-posterior per eid
    contested: dict[str, BoundaryBelief]  # per-edge boundary beliefs

    @classmethod
    def seed(cls, score_v3_output, initial_graph) -> "DecisionLedger":
        """Thin seeding: use score_v3 to initialize priors (high entropy).
        Seeding = giving the ledger an initial value, NOT inventing stories."""
        explanations = []
        for candidate in score_v3_output.top_k(k=3):  # typically 2-4 non-null
            explanations.append(Explanation(
                eid=uuid(), label=candidate.label,
                is_null=False, null_kind=None,
                lifecycle_stage=candidate.initial_stage,
                subgraph=initial_graph.subgraph_for(candidate)
            ))
        # Branch-level null anchor (main workhorse — prevents over-attribution)
        explanations.append(Explanation(
            eid="null-branch", label="not part of this attack",
            is_null=True, null_kind="benign",
            lifecycle_stage="N/A", subgraph=SessionSubgraph.empty()
        ))
        # Initialize high-entropy uniform-ish priors
        log_post = {e.eid: log(1.0 / len(explanations)) for e in explanations}
        return cls(explanations=explanations, log_post=log_post, contested={})
```

### Step 3: Implement Null Anchor Dual-Granularity

| Granularity | Meaning | Prior | Frequency | Downstream Action |
|---|---|---|---|---|
| **Session-level null** | Entire alert is false positive | Low (post initial-triage gate) | Rare fallback | `dismiss-benign` (triple-gated) |
| **Branch-level null** | This edge doesn't belong to this attack | Moderate | Primary workhorse | Prune & delineate boundary |

Branch-level null further splits by `null_kind`:

| null_kind | Semantics | Action on Confirmation |
|---|---|---|
| `benign` | Legitimate activity, domain-internal noise | Prune edge, forget |
| `oos` | Real malicious but out-of-scope (different campaign) | Prune from this story + SPAWN/FEEDBACK to initial triage |

```python
@dataclass
class BoundaryBelief:
    """Per-contested-edge attribution belief (feeds boundary VOI)."""
    edge_id: str
    p_in_attack: float   # P(edge belongs to an attack explanation)
    p_benign: float      # P(edge is benign noise → prune & forget)
    p_oos: float         # P(edge is out-of-scope malicious → SPAWN)
    # Constraint: p_in_attack + p_benign + p_oos == 1.0
```

### Step 4: Implement Bayesian Update (K-beat)

The likelihood uses cheap graph queries (not LLM calls) and only requires ratios, not calibrated absolute densities.

```python
def update_ledger(ledger: DecisionLedger, evidence_batch, trust_model):
    """Called every K-beat. Updates both explanation posteriors and boundary beliefs."""
    for evidence in evidence_batch:
        # Compute log-likelihood ratios across explanations
        log_likelihoods = {}
        for expl in ledger.explanations:
            log_likelihoods[expl.eid] = (
                log_fit_struct(evidence, expl)    # Can this evidence attach to expl's subgraph?
                + log_fit_stage(evidence, expl)   # Does tactic match expl's expected next stage?
                + log_w_trust(evidence, trust_model)  # Trust weight (low integrity → downweight)
            )
        # Bayesian update: log_post += log_likelihood, then renormalize
        for eid in ledger.log_post:
            ledger.log_post[eid] += log_likelihoods[eid]
        ledger._renormalize()

        # Update boundary beliefs for contested edges
        if evidence.edge_id in ledger.contested:
            _update_boundary(ledger, evidence, log_likelihoods, trust_model)

def log_fit_struct(evidence, expl: Explanation) -> float:
    """Can evidence attach to expl's frontier via valid edge + compatible timestamps?
    Reuses ingestion-validation L1 logic. Returns bounded log-score."""
    if expl.subgraph.can_attach(evidence, temporal_tolerance=TAU_TEMPORAL):
        return STRUCT_MATCH_SCORE   # e.g., 0.0 (neutral to positive)
    return STRUCT_MISMATCH_SCORE    # e.g., -2.0 (penalizes but doesn't zero out)

def log_fit_stage(evidence, expl: Explanation) -> float:
    """Does evidence's tactic fall within expl's lifecycle template next-expected stage?"""
    expected = expl.lifecycle_template.next_stages()
    if evidence.tactic in expected:
        return STAGE_MATCH_SCORE
    elif evidence.tactic in expl.lifecycle_template.all_stages():
        return STAGE_PARTIAL_SCORE
    return STAGE_MISMATCH_SCORE

def log_w_trust(evidence, trust_model) -> float:
    """Downweight low-integrity / adversary-controllable evidence."""
    t = trust_model.assess(evidence)
    if t.adversary_controllable:
        return ADVERSARY_CTRL_PENALTY  # e.g., -1.5
    return log(t.integrity)            # high integrity → ~0; low → negative
```

### Step 5: Implement Abductive Maintenance (spawn / merge / cull)

```python
def spawn_merge_cull(ledger: DecisionLedger, evidence_batch, trust, budget):
    """Maintain the explanation set: prevent tunnel vision while keeping set small."""

    # --- SPAWN: new evidence fits no existing explanation ---
    for evidence in evidence_batch:
        max_fit = max(expl.likelihood(evidence, trust)
                      for expl in ledger.explanations if not expl.is_null)
        if max_fit < TAU_SPAWN and evidence_looks_malicious(evidence):
            # Anti-hallucination gate: seed evidence must be forge-resistant or ≥2 independent sources
            if trust.is_forge_resistant(evidence) or trust.corroboration(evidence) >= 2:
                if len(ledger.explanations) >= K_MAX:
                    _force_merge_or_cull(ledger)  # make room
                new_expl = Explanation.from_seed(evidence)
                ledger.explanations.append(new_expl)
                ledger.log_post[new_expl.eid] = LOG_SPAWN_PRIOR  # low prior, must earn its keep

    # --- MERGE: two explanations predict identically on remaining probes ---
    for (e1, e2) in combinations(ledger.non_null_explanations(), 2):
        if prediction_divergence(e1, e2, remaining_probes(ledger)) < TAU_MERGE:
            ledger.merge(e1, e2)  # combine posteriors, union subgraphs

    # --- CULL: posterior too low for too long, obligations resolved ---
    for expl in ledger.non_null_explanations():
        if (ledger.posterior(expl) < EPS_CULL
            and ledger.rounds_below_eps(expl) >= N_CULL_ROUNDS
            and not obligations_pending_for(expl)):
            ledger.cull(expl)
```

### Step 6: Integrate with LOCK Cycle

The Decision Ledger is read by the O-beat (VOI ranking) and stop condition (K-beat exit):

```python
# In the LOCK main loop K-beat:
self.ledger.update(triaged_evidence, self.trust)       # Step 4
self.ledger.spawn_merge_cull(triaged_evidence, self.trust, self.budget)  # Step 5

# O-beat reads ledger for VOI computation (see VOI skill)
# Stop condition reads ledger.margin(), ledger.entropy()
```

## Key Concepts

| Concept | Definition | Role in Decision Ledger |
|---|---|---|
| **Abduction** | Inference from effect to most likely cause | Foundation: alert tracing IS abductive reasoning |
| **Null Anchor** | Explicit "not-attack" hypothesis at two granularities | Prevents over-attribution; provides symmetric landing |
| **BoundaryBelief** | Per-edge `{p_in_attack, p_benign, p_oos}` triple | Edge-granularity object that feeds boundary VOI |
| **Thin Seeding** | Initialize with high-entropy priors from score_v3 | Cheap start; value accrues during cumulative updates |
| **Spawn** | Add new explanation when evidence fits nothing (L3 SPAWN) | Prevents tunnel vision; gated by anti-hallucination |
| **Merge** | Combine explanations with <τ_merge prediction divergence | Keeps set small; no evidence can distinguish them |
| **Cull** | Remove explanation with posterior <ε_cull for N rounds | Garbage collection; requires obligations resolved |
| **K_max=6** | Hard cap on explanation count | Computational tractability + forces maintenance |
| **Log-posterior** | Normalized log P(H\|E) across explanations | Numerically stable; only ratios needed, not absolutes |

## Tools & Systems

- **SessionGraph**: The causal subgraph built by the LOCK cycle (first ledger)
- **Beta Ledger**: Per-probe sensitivity/specificity history (second ledger)
- **Obligation Ledger**: Open investigative obligations (third ledger)
- **EvidenceTrust Model**: Integrity/provenance/adversary-controllability assessments
- **Lifecycle Templates**: Kill-chain stage models for expected attack progression
- **score_v3**: Seven-dimensional scoring for seeding explanation priors

## Common Scenarios

### Scenario 1: Lateral Movement with Benign Noise
An alert shows RDP connections from a compromised host. Some connections are legitimate admin activity. The Decision Ledger maintains H1="ransomware lateral movement" and branch-null="benign admin" for contested edges. Boundary VOI prioritizes probes that disambiguate contested connections.

### Scenario 2: Out-of-Scope Malicious Activity
During ransomware investigation, evidence of cryptomining is found on the same host. The ledger spawns a new explanation (after anti-hallucination gate), then boundary beliefs on shared edges converge to `p_oos` high → SPAWN new investigation, prune from current story.

### Scenario 3: Evidence Tampering
Attacker clears logs on a compromised host. The trust model marks this evidence gap as adversary-controllable. Missing evidence generates anti-forensics obligations rather than being treated as "nothing happened." Likelihood downweighting prevents the attacker from steering the posterior.

## Output Format

The Decision Ledger produces structured output consumed by VOI ranking, stop conditions, and final reporting:

```json
{
  "decision_ledger_state": {
    "round": 7,
    "explanations": [
      {"eid": "h1", "label": "Ransomware delivery via phishing", "posterior": 0.62, "stage": "lateral-movement"},
      {"eid": "h2", "label": "Insider data exfiltration", "posterior": 0.23, "stage": "collection"},
      {"eid": "null-branch", "label": "Not part of this attack", "posterior": 0.15, "null_kind": "benign"}
    ],
    "margin": 0.39,
    "entropy": 1.24,
    "contested_edges": [
      {"edge_id": "e-445", "p_in_attack": 0.71, "p_benign": 0.24, "p_oos": 0.05},
      {"edge_id": "e-512", "p_in_attack": 0.33, "p_benign": 0.58, "p_oos": 0.09}
    ],
    "maintenance_events": ["cull: h3 (posterior < 0.01 for 3 rounds)"]
  }
}
```

## References

- RFC-004-02: LOCK + Decision Ledger (Decision-Oriented Adversarial Abductive Engine)
- RFC-003: Unified Candidate Pool and Graph-Dominant Constraint Layer
- ADR-0001: Graded Veto Hardness
- ADR-0002: Hybrid Constraint Architecture
- Pearl, J. (2009). Causality: Models, Reasoning, and Inference
- Peirce, C.S. — Abductive inference as hypothesis generation
