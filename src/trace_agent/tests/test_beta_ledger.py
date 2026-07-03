"""Tests for BetaLedger — 探针灵敏度台账."""
import random

import pytest

from trace_agent.loop.beta_ledger import BetaLedger


class TestBetaLedger:
    """Unit tests for BetaLedger."""

    def test_initial_sensitivity_uniform(self):
        """Cold start returns 0.5 (uniform prior)."""
        ledger = BetaLedger()
        assert ledger.sensitivity("unseen|key|here") == pytest.approx(0.5)

    def test_update_increases_sensitivity(self):
        """Hits increase sensitivity above 0.5."""
        ledger = BetaLedger()
        key = BetaLedger.learning_key("grep", "process", "execution")
        ledger.update(key, success=5, fail=0)
        assert ledger.sensitivity(key) > 0.5

    def test_update_decreases_sensitivity(self):
        """Misses decrease sensitivity below 0.5."""
        ledger = BetaLedger()
        key = BetaLedger.learning_key("grep", "process", "execution")
        ledger.update(key, success=0, fail=5)
        assert ledger.sensitivity(key) < 0.5

    def test_p_no_data_complement(self):
        """p_no_data = 1 - sensitivity always."""
        ledger = BetaLedger()
        key = BetaLedger.learning_key("netstat", "network", "lateral_movement")
        ledger.update(key, success=3, fail=2)
        assert ledger.p_no_data(key) == pytest.approx(1.0 - ledger.sensitivity(key))

    def test_thompson_sample_range(self):
        """Thompson sample always in [0, 1]."""
        ledger = BetaLedger()
        key = BetaLedger.learning_key("ps", "process", "discovery")
        ledger.update(key, success=10, fail=3)
        random.seed(42)
        for _ in range(100):
            sample = ledger.thompson_sample(key)
            assert 0.0 <= sample <= 1.0

    def test_thompson_distribution_shift(self):
        """After many hits, samples cluster high."""
        ledger = BetaLedger()
        key = BetaLedger.learning_key("ps", "process", "discovery")
        ledger.update(key, success=100, fail=1)
        random.seed(42)
        samples = [ledger.thompson_sample(key) for _ in range(200)]
        mean_sample = sum(samples) / len(samples)
        assert mean_sample > 0.9

    def test_get_params_cold_start(self):
        """Returns (alpha0, beta0) for unseen key."""
        ledger = BetaLedger(alpha0=2.0, beta0=3.0)
        assert ledger.get_params("never|seen|key") == (2.0, 3.0)

    def test_get_params_after_updates(self):
        """Correct accumulation of alpha and beta."""
        ledger = BetaLedger(alpha0=1.0, beta0=1.0)
        key = "op|type|tactic"
        ledger.update(key, success=3, fail=2)
        ledger.update(key, success=1, fail=1)
        assert ledger.get_params(key) == (5.0, 4.0)

    def test_learning_key_format(self):
        """Standardized pipe-separated format."""
        key = BetaLedger.learning_key("grep", "file", "collection")
        assert key == "grep|file|collection"

    def test_learning_key_normalization(self):
        """Case and whitespace handling."""
        key = BetaLedger.learning_key("  GReP  ", " File ", " Collection ")
        assert key == "grep|file|collection"

    def test_variance_decreases_with_data(self):
        """More data = less uncertainty."""
        ledger = BetaLedger()
        key = "op|type|tactic"
        var_before = ledger.variance(key)
        ledger.update(key, success=10, fail=10)
        var_after = ledger.variance(key)
        assert var_after < var_before

    def test_serialization_roundtrip(self):
        """to_dict -> from_dict preserves state."""
        ledger = BetaLedger(alpha0=2.0, beta0=3.0)
        k1 = BetaLedger.learning_key("op1", "type1", "tactic1")
        k2 = BetaLedger.learning_key("op2", "type2", "tactic2")
        ledger.update(k1, success=5, fail=2)
        ledger.update(k2, success=1, fail=8)

        data = ledger.to_dict()
        restored = BetaLedger.from_dict(data)

        assert restored.get_params(k1) == ledger.get_params(k1)
        assert restored.get_params(k2) == ledger.get_params(k2)
        assert restored.sensitivity(k1) == pytest.approx(ledger.sensitivity(k1))

    def test_total_observations(self):
        """Tracks cumulative count."""
        ledger = BetaLedger()
        key = "op|type|tactic"
        assert ledger.total_observations(key) == 0
        ledger.update(key, success=3, fail=2)
        assert ledger.total_observations(key) == 5
        ledger.update(key, success=1, fail=1)
        assert ledger.total_observations(key) == 7

    def test_multiple_keys_independent(self):
        """Different keys don't interfere."""
        ledger = BetaLedger()
        k1 = BetaLedger.learning_key("op1", "type1", "tactic1")
        k2 = BetaLedger.learning_key("op2", "type2", "tactic2")
        ledger.update(k1, success=10, fail=0)
        ledger.update(k2, success=0, fail=10)
        assert ledger.sensitivity(k1) > 0.8
        assert ledger.sensitivity(k2) < 0.2
        assert ledger.get_params(k1) != ledger.get_params(k2)
