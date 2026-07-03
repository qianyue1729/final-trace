"""Scenario registry Wazuh scope resolution."""
from trace_engine.scenario_registry import resolve_wazuh_scope


def test_pipeline_18_resolves_incident_attack_chain_scope():
    scope = resolve_wazuh_scope("pipeline_18")
    assert scope is not None
    assert scope.incident_prefix == "INC-PIPELINE_18"
    assert scope.scope_field == "incident"
    assert scope.attacks_only is True
    assert scope.indexed_attack_chain is True
    assert scope.scenario_slug == "pipeline_18"


def test_unknown_scenario_returns_none():
    assert resolve_wazuh_scope("nonexistent_xyz") is None
