---
name: implementing-value-oriented-stopping-criteria
description: 'Implements formal stopping criteria for automated alert triage and incident
  investigations based on Value of Information (VOI) thresholds, decision robustness
  checks, and obligation fulfillment. Defines three session-level exits (contain,
  dismiss-benign, monitor), branch-level pruning, and provably-terminating conditions.
  Activates for requests involving investigation termination logic, over-attribution
  prevention, VOI-based decision making, or formal convergence guarantees in
  automated security analysis.

  '
domain: cybersecurity
subdomain: soc-operations
tags:
- stopping-criteria
- value-oriented
- decision-robustness
- voi-threshold
- investigation-closure
- over-attribution
mitre_attack:
- T1078
- T1071
- T1059
version: '1.0'
author: mahipal
license: Apache-2.0
nist_csf:
- RS.MA-01
- RS.MA-02
- DE.AE-06
---

# Implementing Value-Oriented Stopping Criteria

## When to Use

- Determining when an automated investigation has gathered sufficient evidence to act
- Preventing over-investigation that consumes SOC resources without improving decision quality
- Enforcing formal termination guarantees so investigations cannot loop indefinitely
- Distinguishing between branch-level pruning (frequent, lightweight) and session-level closure (rare, gated)
- Implementing the dismiss-benign pathway with appropriate safeguards against false negatives
- Balancing completeness (resolving all obligations) against cost (budget/time constraints)

**Do not use** for simple threshold-based alerting (e.g., "if score > X, escalate"). This framework is for multi-step investigations requiring formal convergence.

## Prerequisites

- Bayesian hypothesis scoring engine producing posterior probabilities for each candidate explanation
- VOI (Value of Information) estimator for remaining investigative actions
- Obligation ledger (see `managing-investigation-obligations-with-mandate`) tracking outstanding debts
- Evidence trust model (see `implementing-evidence-trust-model`) for forge-resistance evaluation
- Defined loss function mapping incorrect decisions to organizational impact
- Budget allocation system with step-counting or time-based limits

## Workflow

### Step 1: Define the Three Session-Level Exits and Branch-Level Operations

```python
from enum import Enum
from dataclasses import dataclass
from typing import Optional

class SessionExit(Enum):
    CONTAIN_ESCALATE = "contain_escalate"  # Confirmed attack, take action
    DISMISS_BENIGN = "dismiss_benign"      # Confirmed false positive (rare, heavy gate)
    MONITOR = "monitor"                     # Uncertain but VOI < cost, passive watch

class BranchOperation(Enum):
    CONFIRM_AND_PRUNE = "confirm_and_prune"  # Eliminate hypothesis branch (frequent)

@dataclass
class StopDecision:
    action: SessionExit | BranchOperation
    confidence: float
    rationale: str
    obligations_status: str
    robustness_check: bool
```

Exit characteristics:

```
SESSION-LEVEL EXITS vs BRANCH-LEVEL OPERATIONS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Type                    Frequency   Gate Strength   Effect
──────────────────────────────────────────────────────────────────────
contain/escalate        Common      Medium          Trigger containment + escalate to IR
dismiss-benign          Rare        Heavy (4 gates) Close case as false positive
monitor                 Moderate    Light           Move to passive observation queue
confirm-and-prune       Frequent    Light           Remove one hypothesis branch
                        (branch)                    (does NOT end investigation)
```

### Step 2: Implement the should_stop() Decision Function

```python
EPS_VOI = 0.05           # VOI threshold below which investigation adds no value
BUDGET_HARD_LIMIT = 50   # absolute maximum investigation steps
CONFIDENCE_THRESHOLD = 0.90  # posterior confidence for action

def should_stop(state) -> tuple[bool, Optional[SessionExit], str]:
    """
    Core stopping logic. Evaluates conditions in strict priority order.

    Returns: (should_stop, exit_type, reason)
    """
    # Priority 1: Budget exhaustion → unconditional hard stop
    if state.budget_remaining <= 0:
        return True, determine_best_exit(state), "Budget exhausted (hard stop)"

    # Priority 2: Hard obligations unresolved → unconditional continue
    hard_obligations = [m for m in state.obligations if
                        not m.resolved and m.blocking_level == BlockingLevel.HARD]
    if hard_obligations:
        return False, None, f"Hard obligations pending: {len(hard_obligations)}"

    # Priority 3: VOI below threshold → investigation adds no value
    max_voi = compute_max_voi(state)
    if max_voi < EPS_VOI:
        return True, determine_best_exit(state), f"maxVOI={max_voi:.4f} < EPS={EPS_VOI}"

    # Priority 4: Decision robustness → action stable under perturbation
    if decision_robust(state):
        exit_type = determine_best_exit(state)
        if exit_type == SessionExit.DISMISS_BENIGN:
            # Additional gates for dismiss-benign (Step 4)
            if dismiss_benign_gates_pass(state):
                return True, SessionExit.DISMISS_BENIGN, "Robust benign + all gates pass"
            else:
                return False, None, "Dismiss-benign gates not satisfied"
        return True, exit_type, "Decision robust under perturbation"

    return False, None, "Investigation ongoing: VOI available, decision not yet robust"
```

### Step 3: Implement Decision Robustness Check

Verify that the optimal action does not flip under posterior perturbation:

```python
import numpy as np

def decision_robust(state, perturbation_range=0.10, n_samples=1000) -> bool:
    """
    Check whether the current best action remains optimal under
    plausible perturbations to the posterior distribution.

    Method: Monte Carlo perturbation of posterior confidence interval.
    """
    current_best = determine_best_exit(state)
    posteriors = state.hypothesis_posteriors  # dict: hypothesis → probability

    flip_count = 0
    for _ in range(n_samples):
        # Perturb each posterior by uniform noise within perturbation_range
        perturbed = {}
        for h, p in posteriors.items():
            noise = np.random.uniform(-perturbation_range, perturbation_range)
            perturbed[h] = max(0.001, min(0.999, p + noise))

        # Renormalize
        total = sum(perturbed.values())
        perturbed = {h: p / total for h, p in perturbed.items()}

        # Check if best action changes under perturbed posteriors
        perturbed_best = determine_best_exit_from_posteriors(perturbed, state.loss_function)
        if perturbed_best != current_best:
            flip_count += 1

    flip_rate = flip_count / n_samples
    return flip_rate < 0.05  # robust if < 5% of perturbations cause flip


def expected_loss(posteriors, action, loss_function):
    """
    Compute expected loss for a given action under current posteriors.
    E[L] = sum over hypotheses: P(h) * L(action | h is true)
    """
    return sum(
        p * loss_function(action, h)
        for h, p in posteriors.items()
    )
```

### Step 4: Implement Dismiss-Benign Heavy Gate

The dismiss-benign exit requires four simultaneous conditions (prevent false negatives):

```python
def dismiss_benign_gates_pass(state) -> bool:
    """
    Dismiss-benign is the rarest and most dangerous exit.
    All four gates must pass simultaneously.
    """
    # Gate 1: Null hypothesis dominates posterior
    null_posterior = state.hypothesis_posteriors.get('benign', 0)
    if null_posterior < CONFIDENCE_THRESHOLD:
        return False  # Null not dominant enough

    # Gate 2: Decision robustness (already checked, but re-verify with tighter bound)
    if not decision_robust(state, perturbation_range=0.15):
        return False  # Not robust under wider perturbation

    # Gate 3: Lifecycle obligations fully resolved
    lifecycle_obligations = [m for m in state.obligations
                            if m.type == ObligationType.LIFECYCLE and not m.resolved]
    if lifecycle_obligations:
        return False  # Unexplained kill-chain phases remain

    # Gate 4: Anti-forensics obligations fully resolved
    af_obligations = [m for m in state.obligations
                      if m.type == ObligationType.ANTI_FORENSICS and not m.resolved]
    if af_obligations:
        return False  # Evidence tampering unresolved

    return True  # All four gates pass → safe to dismiss
```

### Step 5: Implement Branch-Level Pruning (High-Frequency Operation)

```python
def confirm_and_prune(state, hypothesis_id: str) -> bool:
    """
    Branch-level operation: eliminate a single hypothesis from consideration.
    This is the high-frequency workhorse of the LOCK loop.

    Much lighter gate than session-level dismiss:
    - Only needs VETO or posterior < pruning threshold
    - Does NOT end the investigation
    - Does NOT require obligation resolution
    """
    PRUNE_THRESHOLD = 0.01  # posterior below which hypothesis is irrelevant

    h_posterior = state.hypothesis_posteriors.get(hypothesis_id, 0)

    # Condition A: Hard VETO applied (forge-resistant evidence contradicts)
    if hypothesis_id in state.vetoed_hypotheses:
        state.prune_hypothesis(hypothesis_id)
        return True

    # Condition B: Posterior collapsed below threshold
    if h_posterior < PRUNE_THRESHOLD:
        state.prune_hypothesis(hypothesis_id)
        return True

    return False  # Cannot prune yet
```

### Step 6: Guarantee Provable Termination

Ensure the investigation always terminates in finite steps:

```python
def termination_proof():
    """
    The investigation provably terminates because:

    1. Budget hard-stop: budget_remaining decrements monotonically per step.
       When budget_remaining <= 0, investigation MUST stop regardless of state.

    2. Obligation finiteness: obligations are bounded by graph size.
       - Structural: <= |nodes| + |edges| in attack graph
       - Lifecycle: <= |phases| in kill-chain template (typically 7-10)
       - Anti-forensics: <= |evidence_sources| in scope
       - Discriminative: <= |hypotheses| * (|hypotheses|-1) / 2

    3. VOI monotonic trigger: as evidence accumulates, remaining uncertainty
       decreases. maxVOI < EPS_VOI is eventually triggered because:
       - Each step resolves at least one information bit
       - Finite hypothesis space means finite information content

    4. Obligation resolution: each obligation is resolved in at most K steps
       (bounded by probe complexity). Unresolved past deadline → escalated
       (removed from blocking set).

    Formal bound: T_max = min(BUDGET_HARD_LIMIT, |obligations_max| * K + convergence_steps)
    """
    pass  # This is a proof sketch, not executable code
```

```
TERMINATION GUARANTEE DIAGRAM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Step 1──Step 2──...──Step N
  │        │            │
  ▼        ▼            ▼
Budget:  B-1      B-2      ... → 0 (HARD STOP)
maxVOI:  0.8      0.6      ... → <EPS (SOFT STOP)
Obligations:  created → resolved/escalated (finite)

Three independent stopping triggers, any one sufficient:
  1. budget=0           → unconditional stop
  2. maxVOI < EPS       → value-based stop
  3. decision_robust()  → confidence-based stop
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Session-Level Exit** | Final disposition of an investigation: contain/escalate, dismiss-benign, or monitor |
| **Branch-Level Pruning** | Elimination of a single hypothesis without ending the investigation; the high-frequency operation in LOCK |
| **VOI (Value of Information)** | Expected improvement in decision quality from executing an additional investigative step |
| **maxVOI** | Maximum VOI across all remaining candidate actions; when below EPS, no action justifies its cost |
| **Decision Robustness** | Property that the optimal action does not change under plausible perturbations to posterior beliefs |
| **Dismiss-Benign Gate** | Four-condition heavy gate preventing false negatives: null dominant + robust + lifecycle clear + anti-forensics clear |
| **Provable Termination** | Formal guarantee that investigation halts in finite steps via budget bound + VOI monotonicity + obligation finiteness |
| **EPS_VOI** | Minimum value threshold; below this, continuing investigation costs more than the expected decision improvement |

## Tools & Systems

- **Bayesian Inference Engine**: Computes posterior probabilities and expected losses for each candidate action
- **VOI Estimator**: Calculates expected information gain for each available investigative probe
- **Obligation Ledger**: Tracks blocking obligations that gate stopping decisions (see MANDATE skill)
- **SOAR Orchestrator**: Executes the chosen exit action (containment playbook, case closure, monitoring rule)
- **Decision Audit Trail**: Records every stopping evaluation for post-incident review and tuning

## Common Scenarios

### Scenario: Automated Triage Reaches VOI Exhaustion

**Context**: An automated investigation has executed 8 steps analyzing a suspicious login alert. The leading hypothesis is "legitimate VPN from new device" (P=0.72). Remaining probes (check device enrollment, call user) have VOI estimates of 0.03 and 0.02 respectively.

**Approach**:
1. Evaluate should_stop(): budget remaining = 12 (not exhausted)
2. Check hard obligations: none outstanding
3. Compute maxVOI = max(0.03, 0.02) = 0.03 < EPS_VOI (0.05) → value exhausted
4. Determine best exit: P(benign)=0.72, not high enough for dismiss-benign gate (needs 0.90)
5. Select MONITOR exit: move to passive observation with low-cost monitoring rule
6. Configure monitor: "Alert if same user authenticates from >2 new devices in 7 days"

**Pitfalls**:
- Continuing to investigate past VOI exhaustion (wasting analyst/automation budget)
- Jumping to dismiss-benign without meeting the four-gate requirement
- Not configuring an appropriate monitoring rule when selecting the MONITOR exit

### Scenario: Dismiss-Benign Blocked by Anti-Forensics Obligation

**Context**: Investigation of a malware alert has P(benign)=0.93 after static analysis confirms the file is a legitimate admin tool. However, the evidence trust model detected an EDR silence gap on the host during the relevant time window.

**Approach**:
1. Evaluate should_stop(): maxVOI still above EPS (EDR gap investigation has VOI=0.35)
2. Decision appears robust: 95% of perturbations still select dismiss-benign
3. Check dismiss-benign gates: Gate 1 (null dominant) ✓, Gate 2 (robust) ✓
4. Gate 4 (anti-forensics clear) FAILS: EDR silence obligation OBL-007 unresolved
5. Cannot dismiss → must resolve OBL-007 first
6. Execute probe: verify EDR agent health → agent crashed (non-adversary cause) → resolve OBL-007
7. Re-evaluate: all four gates now pass → dismiss-benign

**Pitfalls**:
- Bypassing the anti-forensics gate because static analysis "looks clean" (exactly what anti-forensics achieves)
- Not distinguishing between EDR silence from agent crash vs. adversary tampering
- Treating branch-level evidence (file is clean) as sufficient for session-level dismiss (whole case is benign)

## Output Format

```
STOPPING CRITERIA EVALUATION
============================
Investigation ID:     INV-2025-0042
Step Count:           15 / 50 (budget)
Hypothesis Count:     3 active, 2 pruned

POSTERIOR DISTRIBUTION
Hypothesis              Posterior    Trend
────────────────────────────────────────────
H1: APT lateral move    0.61         ↑ (+0.08 last step)
H2: Insider misuse      0.24         ↓ (-0.05 last step)
H3: Benign automation   0.15         ↓ (-0.03 last step)
[pruned] H4: Red team   0.00         VETOED (step 7)
[pruned] H5: Worm       0.00         Collapsed (step 9)

VOI ASSESSMENT
Probe                           VOI      Cost    Net Value
────────────────────────────────────────────────────────────
Check lateral credentials       0.18     1 step  +0.17
Analyze C2 beacon interval      0.12     1 step  +0.11
Interview user                  0.04     1 step  +0.03
────────────────────────────────────────────────────────────
maxVOI = 0.18 (above EPS=0.05)

OBLIGATION STATUS
Hard blockers:     0 (all structural/anti-forensics resolved)
Value-gated:       1 (lifecycle: impact phase, VOI=0.09)

ROBUSTNESS CHECK
Best action: CONTAIN_ESCALATE (H1 dominant)
Perturbation range: ±0.10
Flip rate: 8.2% (> 5% threshold → NOT ROBUST)

DECISION: CONTINUE INVESTIGATION
Reason: Decision not yet robust (flip rate 8.2% > 5%)
Next action: Execute "Check lateral credentials" (highest VOI)
```
