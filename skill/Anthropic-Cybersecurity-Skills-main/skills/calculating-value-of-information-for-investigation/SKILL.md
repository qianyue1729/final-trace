---
name: calculating-value-of-information-for-investigation
description: Calculate Value of Information (VOI) for investigation probes by estimating
  expected decision-risk reduction, incorporating both session-level and boundary-level
  Bayes risk with asymmetric loss to prioritize probes that resolve ambiguity, delineate
  attack boundaries, and prevent over-attribution.
domain: cybersecurity
subdomain: soc-operations
tags:
- voi
- value-of-information
- bayes-risk
- decision-theory
- probe-prioritization
- boundary-belief
- asymmetric-loss
- soc
version: '1.0'
author: team-cybersecurity
license: Apache-2.0
nist_csf:
- DE.AE-02
- DE.AE-06
- RS.MA-01
mitre_attack:
- T1078
- T1071
- T1059
---

# Calculating Value of Information for Investigation

## Overview

Value of Information (VOI) replaces hit-rate as the probe ranking key in the LOCK cycle's O-beat. It measures each probe's **expected decision-risk reduction minus cost**, unifying "what to investigate next" and "when to stop" into a single framework.

The critical insight: hit-rate ranking implicitly rewards "nailing more edges onto the attack story" — which is exactly **over-attribution** (blast radius expansion). VOI corrects this by pricing both miss-cost AND over-attribution-cost, giving positive scores to probes that **exclude** explanations, **delineate boundaries**, or **disambiguate** competing hypotheses.

VOI requires the Decision Ledger (see `implementing-decision-ledger-for-alert-tracing`) as its primary input — it reads the competing-explanation posterior and per-edge boundary beliefs.

## When to Use

- When prioritizing investigation probes in the LOCK O-beat to maximize decision value
- When the current hit-rate ranking leads to over-attribution (expanding blast radius with weak evidence)
- When negative/boundary probes (confirming an edge is NOT part of the attack) need positive scores
- When deciding whether to continue investigating or stop (VOI floor = stop condition)
- When implementing asymmetric loss that prices both missed attacks AND false attribution

## Prerequisites

- Decision Ledger with competing explanations and boundary beliefs (see Decision Ledger skill)
- Beta Ledger providing per-probe sensitivity priors (P(no_data) estimates)
- Evidence Trust model for cost estimation and trust-weighted likelihoods
- Defined action space: session actions {contain, escalate, monitor, dismiss} + boundary actions {include, prune}
- Asymmetric loss parameters: LAMBDA_MISS, LAMBDA_OVER, LAMBDA_OOS (at minimum two non-zero scalars)

## Workflow

### Step 1: Define the Asymmetric Loss Structure

The loss function encodes organizational risk tolerance. The critical constraint: **LAMBDA_OVER must be non-zero**, otherwise boundary VOI ≈ 0 and over-attribution cannot be priced.

```python
@dataclass
class LossMatrix:
    """Asymmetric loss: missing a real attack is most expensive,
    but over-attributing MUST have non-zero cost — otherwise
    boundary delineation probes can never get positive VOI."""
    LAMBDA_MISS: float = 10.0     # Cost of missing true attack edge/session
    LAMBDA_OVER: float = 1.0      # Cost of including benign edge in attack story
    LAMBDA_OOS: float = 2.0       # Cost of including out-of-scope malicious edge

    def session_loss(self, action: str, true_state: str) -> float:
        """Loss for session-level action given true state."""
        # action ∈ {contain, escalate, monitor, dismiss}
        # true_state derived from explanation: attack, benign, oos
        if action == "dismiss" and true_state == "attack":
            return self.LAMBDA_MISS  # Worst case: dismissing real attack
        if action in ("contain", "escalate") and true_state == "benign":
            return self.LAMBDA_OVER  # Unnecessary containment
        if action == "monitor" and true_state == "attack":
            return self.LAMBDA_MISS * 0.3  # Delayed response, partial cost
        return 0.0  # Correct action

# Critical: LAMBDA_MISS >> LAMBDA_OVER > 0
# If LAMBDA_OVER == 0: confirming "edge not in attack" reduces zero risk → VOI ≈ 0
# → boundary probes never prioritized → over-attribution untreatable
```

### Step 2: Compute Bayes Risk (Dual-Component)

Bayes risk has **two terms**. Missing the boundary term is the most common implementation error — it makes boundary VOI ≈ 0 because session-level P(attack) is already high post-triage.

```python
def bayes_risk(ledger: DecisionLedger, loss: LossMatrix) -> float:
    """Total decision risk = session-level + boundary-level.
    WITHOUT boundary term → boundary VOI ≈ 0 → over-attribution untreatable."""

    # (1) Session-level: optimal expected loss over session actions
    #     (漏报最贵 but post-triage P(attack) high → this term is often small)
    session_risk = min(
        sum(ledger.posterior(H) * loss.session_loss(action, H.true_state_label())
            for H in ledger.explanations)
        for action in SESSION_ACTIONS  # {contain, escalate, monitor, dismiss}
    )

    # (2) Boundary-level: per-contested-edge optimal loss over {include, prune}
    #     THIS IS WHERE OVER-ATTRIBUTION GETS PRICED
    boundary_risk = 0.0
    for edge_id, belief in ledger.contested.items():
        # Cost of INCLUDING this edge (if it's actually benign or oos)
        include_risk = (belief.p_benign * loss.LAMBDA_OVER
                       + belief.p_oos * loss.LAMBDA_OOS)
        # Cost of PRUNING this edge (if it's actually part of the attack)
        prune_risk = belief.p_in_attack * loss.LAMBDA_MISS
        # Optimal boundary action minimizes expected loss
        boundary_risk += min(include_risk, prune_risk)

    return session_risk + boundary_risk
```

### Step 3: Implement VOI Computation (One-Step Lookahead)

```python
def voi(probe: Probe, ledger: DecisionLedger, beta: BetaLedger,
        calib: Calibration, loss: LossMatrix) -> float:
    """VOI = expected decision risk reduction - cost.
    One-step lookahead: for each possible outcome, compute posterior update
    and resulting risk reduction."""

    risk_now = bayes_risk(ledger, loss)
    expected_risk_after = 0.0

    # Enumerate possible outcomes and their probabilities
    for outcome, p_outcome in predict_outcomes(probe, ledger, beta):
        # Hypothetical posterior update (doesn't mutate actual ledger)
        ledger_next = ledger.hypothetical_update(probe, outcome)
        expected_risk_after += p_outcome * bayes_risk(ledger_next, loss)

    risk_reduction = risk_now - expected_risk_after
    cost = calib.cost(probe)  # time, API calls, analyst attention

    return risk_reduction - cost
```

### Step 4: Implement predict_outcomes (Consistency Contract with Likelihood)

The outcome predictor and the likelihood updater **must use the same generative model** — otherwise VOI is computed under a self-contradictory model.

```python
def predict_outcomes(probe: Probe, ledger: DecisionLedger,
                     beta: BetaLedger) -> list[tuple[Outcome, float]]:
    """Predict probe outcome distribution. Consistency contract:
    - Beta ledger provides P(no_data) / sensitivity shrinkage prior
      ("will this probe return signal at all?")
    - Explanation likelihood provides P(outcome|H, probe)
      ("if signal returns, which story does it favor?")
    Beta = "can we dig anything up?" vs Likelihood = "what does it mean for each story?"
    They multiply, not compete."""

    outcomes = []  # outcome ∈ {attributable, benign, oos, no_data}

    # P(no_data) from Beta ledger: historical hit rate for this probe type
    p_no_data = beta.predict_no_data(probe.learning_key())

    # P(outcome | data exists) from explanation likelihoods
    p_signal = 1.0 - p_no_data
    for outcome in [Outcome.ATTRIBUTABLE, Outcome.BENIGN, Outcome.OOS]:
        # Marginalize over explanations: P(outcome|probe) = Σ_H P(H) · P(outcome|H,probe)
        p_outcome_given_signal = sum(
            ledger.posterior(H) * explanation_predicts(H, probe, outcome)
            for H in ledger.explanations
        )
        outcomes.append((outcome, p_signal * p_outcome_given_signal))

    outcomes.append((Outcome.NO_DATA, p_no_data))

    # Normalize (outcomes should sum to 1.0)
    total = sum(p for _, p in outcomes)
    return [(o, p / total) for o, p in outcomes]

def explanation_predicts(expl: Explanation, probe: Probe, outcome: Outcome) -> float:
    """P(outcome | H, probe) — uses SAME likelihood model as ledger.update().
    fit_struct × fit_stage × w_trust (cheap graph queries, ratios only)."""
    if expl.is_null and expl.null_kind == "benign":
        # Null-benign predicts: mostly no_data or benign outcome
        return {Outcome.ATTRIBUTABLE: 0.05, Outcome.BENIGN: 0.70,
                Outcome.OOS: 0.05, Outcome.NO_DATA: 0.20}[outcome]
    # Non-null explanation: likelihood that this probe yields this outcome
    return expl.predicted_outcome_distribution(probe)[outcome]
```

### Step 5: Understand Why VOI Cures Multiple Diseases

| Disease | How Hit-Rate Fails | How VOI Cures |
|---|---|---|
| **Over-attribution** | "Edge not in attack" = miss = 0 reward | Boundary term + LAMBDA_OVER>0 → boundary probes get positive score |
| **Confirmation bias** | Only rewards evidence FOR the leading hypothesis | Probes that EXCLUDE an explanation reduce risk → positive VOI |
| **Ignoring negative info** | "No data" = miss = 0 reward | Absence narrows posteriors → risk reduction → positive VOI |
| **Lack of discrimination** | Doesn't distinguish high-ambiguity from low-ambiguity cases | VOI peaks where margin is small (explanations diverge on predictions) |
| **No principled stopping** | Arbitrary convergence threshold | Stop when maxVOI < cost (same framework) |
| **No exploration** | Pure exploitation of leading hypothesis | Thompson sampling preserved; Beta provides exploration via uncertainty |

### Step 6: Implement the Upgrade Path (Minimal Core → Full VOI)

```python
# === MINIMAL CORE (Phase 1): Add boundary decision term to existing acquisition ===
def acquisition_with_boundary(probe, ledger, beta, loss) -> float:
    """Minimum viable: RFC-003 acquisition + boundary risk reduction term.
    Does NOT require full one-step lookahead."""
    base_score = rfc003_acquisition(probe, beta)  # existing hit-rate score

    # Boundary decision term: how much does this probe reduce boundary uncertainty?
    boundary_value = 0.0
    for edge_id, belief in ledger.contested.items():
        if probe.targets_edge(edge_id):
            # Current boundary risk for this edge
            include_risk = belief.p_benign * loss.LAMBDA_OVER + belief.p_oos * loss.LAMBDA_OOS
            prune_risk = belief.p_in_attack * loss.LAMBDA_MISS
            current_edge_risk = min(include_risk, prune_risk)
            # Expected risk reduction (simplified: assume probe resolves this edge)
            expected_resolved_risk = current_edge_risk * probe.expected_resolution_factor(beta)
            boundary_value += current_edge_risk - expected_resolved_risk

    return base_score + WEIGHT_BOUNDARY * boundary_value

# === FULL VOI (Phase 2): Complete one-step lookahead ===
# Use voi() function from Step 3 — requires predict_outcomes and hypothetical_update
```

### Step 7: Connect VOI to Stop Condition

VOI unifies "what to investigate" and "when to stop" — they're two sides of the same optimal stopping problem.

```python
def should_stop(ledger, beta, budget, obligations, loss) -> StopDecision:
    """Value-directed stopping: same VOI framework as probe ranking."""
    if budget.exhausted():
        return STOP("budget")

    # Hard obligations (structural/anti-forensics) block stopping unconditionally
    if obligations.open_hard():
        return CONTINUE

    # Soft obligations (lifecycle/discriminative) only block if their VOI ≥ EPS
    max_voi_value = max(
        voi(probe, ledger, beta, Calibration(), loss)
        for probe in candidate_pool(ledger, beta, obligations)
    ) if candidate_pool(ledger, beta, obligations) else 0.0

    if max_voi_value < EPS_VOI:
        return STOP("voi_floor")  # No probe can reduce risk enough to justify cost

    if decision_robust(ledger, loss):
        return STOP("robust")  # Decision won't flip under posterior perturbation

    return CONTINUE

def decision_robust(ledger, loss) -> bool:
    """Optimal action doesn't change under credible posterior perturbation."""
    optimal_action = ledger.optimal_action(loss)
    for perturbation in posterior_perturbations(ledger, delta=ROBUSTNESS_DELTA):
        if perturbation.optimal_action(loss) != optimal_action:
            return False
    return True
```

## Key Concepts

| Concept | Definition | Why It Matters |
|---|---|---|
| **VOI** | Expected decision risk reduction minus cost | Unified ranking + stopping criterion |
| **Bayes Risk (session)** | Min expected loss over session actions {contain, escalate, monitor, dismiss} | Prices missed attacks at session level |
| **Bayes Risk (boundary)** | Σ per-contested-edge min(include_risk, prune_risk) | Prices over-attribution at edge level |
| **LAMBDA_MISS** | Cost of missing a true attack edge | Must be >> LAMBDA_OVER (asymmetric) |
| **LAMBDA_OVER** | Cost of including benign edge in attack story | **Must be > 0** or boundary VOI ≈ 0 |
| **predict_outcomes** | P(outcome\|probe) marginalizing over explanations | Uses same generative model as likelihood |
| **Beta-Likelihood Split** | Beta = "will probe return data?" / Likelihood = "what does data mean?" | They multiply, not compete |
| **One-step lookahead** | Hypothetical update per outcome, weighted by probability | Tractable VOI approximation |
| **Thompson sampling** | Exploration via posterior sampling from Beta | Preserved within VOI framework |
| **Decision robustness** | Optimal action unchanged under posterior perturbation | Stop condition: robust = safe to decide |

## Tools & Systems

- **Decision Ledger**: Source of competing-explanation posteriors and boundary beliefs
- **Beta Ledger**: Provides P(no_data) and sensitivity priors per probe type
- **Calibration Module**: Tracks prediction accuracy and provides cost estimates
- **Loss Matrix**: Organizational risk tolerance parameters (LAMBDA_MISS, LAMBDA_OVER, LAMBDA_OOS)
- **Obligation Ledger**: Hard vs. soft obligation classification for stop condition
- **SessionGraph**: Provides structural context for fit_struct computation

## Common Scenarios

### Scenario 1: Boundary Delineation Probe
A lateral movement investigation has 3 contested edges (RDP connections that might be admin activity). Hit-rate gives these "confirm benign" probes 0 score. With VOI + LAMBDA_OVER=1.0, each boundary probe reduces boundary risk by ~0.8 units → gets prioritized, preventing blast radius expansion.

### Scenario 2: Discriminative Probe
Two explanations (H1: ransomware delivery, H2: legitimate file transfer) have similar posteriors (margin=0.12). A probe checking for encryption behavior is predicted to produce divergent outcomes under H1 vs H2. VOI is maximal here because risk reduction is highest where ambiguity is greatest.

### Scenario 3: Negative Information Value
A probe that checks process ancestry might return "clean" (no malicious parent). Under hit-rate this is worthless (miss). Under VOI, "clean" would eliminate H1 → massive risk reduction → positive VOI. The system correctly prioritizes this exclusionary probe.

### Scenario 4: VOI-Based Stopping
After 5 rounds, the leading explanation has posterior 0.89, all contested edges converged (max boundary entropy < 0.3), and the best remaining probe has VOI = 0.02 < EPS_VOI = 0.05. System stops: further investigation cannot meaningfully change the decision.

## Output Format

```json
{
  "voi_ranking": {
    "round": 5,
    "current_bayes_risk": {
      "session_risk": 0.42,
      "boundary_risk": 1.73,
      "total": 2.15
    },
    "top_probes": [
      {"probe_id": "p-112", "target": "edge-445", "voi": 0.89, "type": "boundary-delineation",
       "expected_outcomes": {"attributable": 0.35, "benign": 0.45, "oos": 0.08, "no_data": 0.12}},
      {"probe_id": "p-087", "target": "host-C", "voi": 0.72, "type": "discriminative",
       "expected_outcomes": {"attributable": 0.55, "benign": 0.10, "oos": 0.05, "no_data": 0.30}},
      {"probe_id": "p-201", "target": "edge-512", "voi": 0.61, "type": "exclusionary",
       "expected_outcomes": {"attributable": 0.15, "benign": 0.60, "oos": 0.10, "no_data": 0.15}}
    ],
    "stop_assessment": {
      "max_voi": 0.89,
      "eps_voi": 0.05,
      "decision_robust": false,
      "hard_obligations_open": 1,
      "recommendation": "CONTINUE"
    }
  }
}
```

## References

- RFC-004-02: LOCK + Decision Ledger — §6 (VOI Ranking) and §7 (Value-Directed Stopping)
- RFC-003: Unified Candidate Pool — acquisition function and Beta ledger
- ADR-0003: Value-Urgency-Obligation Scheduling
- Howard, R.A. (1966). Information Value Theory
- DeGroot, M.H. (1970). Optimal Statistical Decisions — Bayes risk framework
- Raiffa & Schlaifer (1961). Applied Statistical Decision Theory
