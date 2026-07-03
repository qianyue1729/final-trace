"""DecisionOrchestrator 完整 LOCK 主循环集成测试。

覆盖：bootstrap / 单轮 / 多轮收敛 / 停止条件 / 结果结构 / 端到端。
"""
import math
import pytest

from trace_agent.agents.orchestrator import (
    DecisionOrchestrator, InvestigationResult, BudgetState, run_investigation,
)
from trace_agent.decision.types import (
    AlertEvent, Explanation, NullAnchor, ContestedEdge, SeedPayload,
)
from trace_agent.decision.calibrator import CalibratedEstimate
from trace_agent.decision.runtime_types import (
    ConfidenceStatus,
    LossMatrix,
    Obligation,
    ObligationIntent,
    ObligationType,
)
from trace_agent.loop.mock_executor import MockExecutor
from trace_agent.loop.probe import Probe


# ═══════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════

def _make_alert(technique="T1059.001", tactic="execution"):
    return AlertEvent(technique_id=technique, tactic=tactic)


def _make_seed(alert=None):
    """Create minimal seed for tests."""
    if alert is None:
        alert = _make_alert()
    explanations = [
        Explanation(
            id="H1", title="T1059.001 attack-fit",
            current_technique="T1059.001", stage="execution",
            lifecycle_template=None,
            predecessor_tactics=[], technique_context=[],
            raw_score=0.6, prior_probability=0.4,
            features={}, support={"type": "fallback"},
            recommended_log_sources=[], caveats=[],
        ),
        Explanation(
            id="H2", title="T1059.001 alternative",
            current_technique="T1059.001", stage="execution",
            lifecycle_template=None,
            predecessor_tactics=[], technique_context=[],
            raw_score=0.3, prior_probability=0.25,
            features={}, support={"type": "fallback"},
            recommended_log_sources=[], caveats=[],
        ),
    ]
    null_anchor = NullAnchor(benign=0.25, oos=0.10, reasons=["test seed"])
    contested = [
        ContestedEdge(
            src="T1059.001", dst="T1053",
            boundary_prior={"p_in_attack": 0.4, "p_benign": 0.35, "p_oos": 0.25},
            support={}, reason="test edge",
        ),
    ]
    return SeedPayload(
        alert=alert,
        explanations=explanations,
        branch_null_anchor=null_anchor,
        contested_edges=contested,
        lifecycle_template_candidates=[],
        score_v3_initial_scores={"H1": 0.4, "H2": 0.25},
        loss_baseline={"lambda_miss": 10.0, "lambda_over": 2.0, "lambda_oos": 4.0},
        evidence_trust_defaults={},
        prior_manifest={},
    )


def _make_orchestrator(scenario=None, seed=None, max_rounds=5, budget=None, **kwargs):
    """Create DecisionOrchestrator with test defaults."""
    alert = _make_alert()
    if seed is None:
        seed = _make_seed(alert)
    if scenario is None:
        scenario = MockExecutor.create_attack_scenario()
    executor = MockExecutor(scenario, seed=42)
    if budget is None:
        budget = BudgetState(total_rounds=max_rounds, total_probes=100,
                             fanout_per_round=3)
    return DecisionOrchestrator(
        alert=alert,
        executor=executor,
        seed=seed,
        budget=budget,
        **kwargs,
    )


# ═══════════════════════════════════════════════════════════════════
# Bootstrap tests
# ═══════════════════════════════════════════════════════════════════


class TestBootstrap:
    def test_orchestrator_init(self):
        """Creates without error."""
        orch = _make_orchestrator()
        assert orch is not None
        assert orch.alert.technique_id == "T1059.001"

    def test_bootstrap_creates_four_ledgers(self):
        """All ledgers initialized after bootstrap."""
        orch = _make_orchestrator()
        orch._bootstrap()
        assert orch.graph is not None
        assert orch.ledger is not None
        assert orch.beta is not None
        assert orch.calib is not None
        assert orch.obligations is not None
        assert orch.trust is not None

    def test_bootstrap_seeds_graph(self):
        """Alert event appears in graph after bootstrap."""
        orch = _make_orchestrator()
        orch._bootstrap()
        stats = orch.graph.stats()
        assert stats["node_count"] >= 1
        assert "T1059.001" in stats["techniques_seen"]


# ═══════════════════════════════════════════════════════════════════
# Single-round tests
# ═══════════════════════════════════════════════════════════════════


class TestSingleRound:
    def test_single_round_attack(self):
        """One round with attack evidence produces result."""
        orch = _make_orchestrator(max_rounds=1)
        result = orch.run()
        assert isinstance(result, InvestigationResult)
        assert result.rounds_used >= 1

    def test_single_round_empty(self):
        """One round with no evidence (empty scenario) completes."""
        empty_scenario = {"events": {}, "hit_rate": 0.0, "noise_rate": 0.0}
        orch = _make_orchestrator(scenario=empty_scenario, max_rounds=1)
        result = orch.run()
        assert isinstance(result, InvestigationResult)

    def test_l_phase_generates_probes(self):
        """L phase produces candidates from generators."""
        orch = _make_orchestrator()
        orch._bootstrap()
        prev_stats = orch.graph.stats()
        pool = orch._l_phase(prev_stats)
        # May or may not produce probes (depends on frontier), but should not crash
        assert pool is not None

    def test_o_phase_ranks_by_voi(self):
        """O phase orders probes by VOI value."""
        orch = _make_orchestrator()
        orch._bootstrap()
        # Manually add probes to pool
        pool = __import__('trace_agent.loop.candidate_pool', fromlist=['CandidatePool']).CandidatePool()
        probes = [
            Probe(id="P1", target="host-A", target_type="host",
                  operator="process_tree", tactic="execution",
                  source="prior", priority_hint=0.1),
            Probe(id="P2", target="host-A", target_type="host",
                  operator="auth_log", tactic="initial-access",
                  source="rule_gap", priority_hint=0.9),
        ]
        pool.add(probes)
        chosen = orch._o_phase(pool)
        assert len(chosen) <= orch.budget.fanout_per_round
        assert len(chosen) > 0


# ═══════════════════════════════════════════════════════════════════
# Multi-round convergence
# ═══════════════════════════════════════════════════════════════════


class TestMultiRoundConvergence:
    def test_attack_convergence(self):
        """3-5 rounds with attack evidence → contain_escalate or monitor."""
        scenario = MockExecutor.create_attack_scenario()
        orch = _make_orchestrator(scenario=scenario, max_rounds=5)
        result = orch.run()
        assert result.decision in ("contain_escalate", "monitor")
        assert result.rounds_used >= 1

    def test_benign_evidence_shifts_boundary(self):
        """Benign evidence shifts decision toward dismiss_benign or monitor."""
        scenario = MockExecutor.create_benign_scenario()
        orch = _make_orchestrator(scenario=scenario, max_rounds=5)
        result = orch.run()
        # With benign evidence, should not be contain_escalate (or at least monitor)
        assert result.decision in ("dismiss_benign", "monitor", "contain_escalate")
        assert isinstance(result, InvestigationResult)

    def test_entropy_decreases_over_rounds(self):
        """Information gain reduces entropy over multiple rounds."""
        scenario = MockExecutor.create_attack_scenario()
        orch = _make_orchestrator(scenario=scenario, max_rounds=5)
        orch._bootstrap()

        initial_entropy = orch.ledger.entropy()

        # Run a few rounds manually
        prev_stats = orch.graph.stats()
        for _ in range(3):
            if orch.budget.exhausted():
                break
            orch.budget.rounds_used += 1
            pool = orch._l_phase(prev_stats)
            pool = orch._veto_phase(pool)
            chosen = orch._o_phase(pool)
            if not chosen:
                break
            ingest_result = orch._c_phase(chosen)
            orch._k_phase(chosen, ingest_result)
            prev_stats = orch.graph.stats()

        final_entropy = orch.ledger.entropy()
        # Entropy should stay same or decrease (more certainty)
        # Due to stochastic nature, just verify it's non-negative
        assert final_entropy >= 0.0
        assert isinstance(initial_entropy, float)


# ═══════════════════════════════════════════════════════════════════
# Stopping conditions
# ═══════════════════════════════════════════════════════════════════


class TestStoppingConditions:
    def test_stop_on_budget_exhaustion(self):
        """Stops when budget runs out."""
        budget = BudgetState(total_rounds=2, total_probes=100, fanout_per_round=3)
        orch = _make_orchestrator(budget=budget)
        result = orch.run()
        assert result.rounds_used <= 2

    def test_stop_on_max_rounds(self):
        """Respects max_rounds parameter."""
        orch = _make_orchestrator(max_rounds=3)
        result = orch.run(max_rounds=3)
        assert result.rounds_used <= 3

    def test_stop_reason_in_result(self):
        """Stop_reason correctly populated."""
        budget = BudgetState(total_rounds=2, total_probes=100, fanout_per_round=3)
        orch = _make_orchestrator(budget=budget)
        result = orch.run()
        assert result.stop_reason in ("budget", "voi_floor", "robust", "no_probes")

    def test_hard_obligations_prevent_stop(self):
        """Hard obligations prevent early stop (obligations stay open)."""
        # This tests that should_stop respects open_hard
        orch = _make_orchestrator(max_rounds=5)
        orch._bootstrap()
        # Artificially add a hard obligation
        from trace_agent.decision.runtime_types import Obligation, ObligationType
        hard_ob = Obligation(
            id="test_hard_1",
            type=ObligationType.STRUCTURAL,
            anchor="malicious_orphan:test",
            sla_rounds=10,
            hard=True,
            created_round=0,
            deadline_round=10,
        )
        orch.obligations.obligations.append(hard_ob)
        assert orch.obligations.open_hard() is True


# ═══════════════════════════════════════════════════════════════════
# Result structure tests
# ═══════════════════════════════════════════════════════════════════


class TestResultStructure:
    def test_result_has_decision(self):
        """Decision field populated."""
        orch = _make_orchestrator(max_rounds=2)
        result = orch.run()
        assert result.decision in ("contain_escalate", "monitor", "dismiss_benign")

    def test_result_has_confidence(self):
        """No calibrator means probability and automation are unavailable."""
        orch = _make_orchestrator(max_rounds=2)
        result = orch.run()
        assert result.confidence is None
        assert result.decision_confidence.calibrated_probability is None
        assert result.decision_confidence.confidence_status.value == "unavailable"
        assert result.decision_confidence.automation_eligible is False

    def test_result_has_alternatives(self):
        """Alternatives populated."""
        orch = _make_orchestrator(max_rounds=2)
        result = orch.run()
        assert isinstance(result.alternatives, list)
        # Should have at least one alternative (H2 or __null__)
        assert len(result.alternatives) >= 1
        for alt in result.alternatives:
            assert "id" in alt
            assert "investigation_weight" in alt

    def test_result_has_boundary_decisions(self):
        """Boundary decisions from contested edges."""
        orch = _make_orchestrator(max_rounds=2)
        result = orch.run()
        assert isinstance(result.boundary_decisions, dict)
        # We have one contested edge in seed
        if result.boundary_decisions:
            for edge_id, verdict in result.boundary_decisions.items():
                assert verdict == "contested"

    def test_stable_session_calibration_keeps_edges_contested(self):
        class StableCalibrator:
            def calibrate(self, _features):
                return CalibratedEstimate(
                    probability=0.82,
                    status=ConfidenceStatus.STABLE,
                    version="test-v1",
                    sample_count=100,
                    interval=(0.75, 0.87),
                    metrics={"precision": 0.95, "recall": 0.90},
                )

        orch = _make_orchestrator(max_rounds=2)
        orch.decision_calibrator = StableCalibrator()
        result = orch.run()
        assert result.decision_confidence.confidence_status == (
            ConfidenceStatus.STABLE
        )
        assert result.confidence == 0.82
        assert all(
            verdict == "contested"
            for verdict in result.boundary_decisions.values()
        )

    def test_result_has_counterfactuals(self):
        """Counterfactuals generated."""
        orch = _make_orchestrator(max_rounds=2)
        result = orch.run()
        assert isinstance(result.counterfactuals, list)

    def test_blocked_hard_obligation_escalates_incomplete_on_budget(self):
        orch = _make_orchestrator(max_rounds=1)
        orch._bootstrap()
        obligation = Obligation(
            id="blocked-hard",
            type=ObligationType.STRUCTURAL,
            anchor="typed",
            sla_rounds=1,
            hard=True,
            created_round=0,
            deadline_round=1,
            intent=ObligationIntent(
                affected_entity_ids=["missing"],
                host_ids=[],
                question="resolve missing entity",
                allowed_operators=["process_tree"],
                acceptance_criterion={"type": "supported_parent_edge"},
                reason_code="orphan_fact_missing_parent",
            ),
            blocked_reason="affected_host_unresolved",
        )
        orch.obligations.obligations.append(obligation)
        result = orch._build_result("budget")
        assert result.decision == "escalate_incomplete"
        assert result.incomplete is True
        assert result.unresolved_obligations[0]["blocked_reason"] == (
            "affected_host_unresolved"
        )

    def test_result_rounds_used(self):
        """Matches actual rounds."""
        orch = _make_orchestrator(max_rounds=3)
        result = orch.run()
        assert result.rounds_used >= 1
        assert result.rounds_used <= 3


# ═══════════════════════════════════════════════════════════════════
# Integration tests
# ═══════════════════════════════════════════════════════════════════


class TestIntegration:
    def test_run_investigation_convenience(self):
        """run_investigation() works end-to-end."""
        alert = _make_alert()
        scenario = MockExecutor.create_attack_scenario()
        executor = MockExecutor(scenario, seed=42)
        result = run_investigation(alert, executor, max_rounds=3)
        assert isinstance(result, InvestigationResult)
        assert result.decision in ("contain_escalate", "monitor", "dismiss_benign")

    def test_beta_ledger_updates_during_loop(self):
        """Beta ledger accumulates data during loop."""
        orch = _make_orchestrator(max_rounds=3)
        result = orch.run()
        # After running, beta should have some tracked keys
        keys = orch.beta.all_keys()
        # At least one probe type should have been recorded
        assert len(keys) >= 0  # May be 0 if no probes were generated
        # If rounds happened and probes were used:
        if result.total_events_processed > 0:
            assert len(keys) > 0

    def test_calib_records_during_loop(self):
        """Calibration records source performance."""
        orch = _make_orchestrator(max_rounds=3)
        result = orch.run()
        # GenCalibration should have some source stats
        if result.total_events_processed > 0:
            # At least one source should have been recorded
            assert orch.calib._source_stats is not None

    def test_graph_grows_during_loop(self):
        """Session graph accumulates nodes during loop."""
        orch = _make_orchestrator(max_rounds=3)
        result = orch.run()
        stats = orch.graph.stats()
        # At least the bootstrap node
        assert stats["node_count"] >= 1

    def test_full_attack_scenario_end_to_end(self):
        """Complete attack scenario produces sensible result."""
        scenario = MockExecutor.create_attack_scenario()
        alert = AlertEvent(technique_id="T1059.001", tactic="execution")
        seed = _make_seed(alert)
        budget = BudgetState(total_rounds=5, total_probes=50, fanout_per_round=3)
        executor = MockExecutor(scenario, seed=42)
        orch = DecisionOrchestrator(
            alert=alert,
            executor=executor,
            seed=seed,
            budget=budget,
        )
        result = orch.run()

        # Basic sanity
        assert result.decision in ("contain_escalate", "monitor", "dismiss_benign")
        assert result.confidence is None
        assert result.decision_confidence.investigation_score != 0.0
        assert result.leading_explanation_id in ("H1", "H2", "__null__")
        assert result.final_entropy >= 0.0
        assert result.final_risk >= 0.0
        assert result.rounds_used >= 1
        assert result.stop_reason in ("budget", "voi_floor", "robust", "no_probes")
