"""MockExecutor — 基于预设场景的模拟取证执行器"""
from __future__ import annotations
import random
import time
import uuid
from typing import Any, Optional
from .probe import Probe
from .executor import ProbeExecutor


class MockExecutor(ProbeExecutor):
    """基于预设场景的模拟执行器，用于测试和演示。

    Scenario format:
    {
        "events": {
            "(target, operator)": [  # key is tuple-like string
                {"technique": "T1059.001", "tactic": "execution", ...},
                ...
            ]
        },
        "hit_rate": 0.7,        # probability of returning events (default 0.7)
        "noise_rate": 0.1,      # probability of adding noise events (default 0.1)
    }

    If no scenario provided, generates synthetic events based on probe parameters.
    """

    def __init__(self, scenario: Optional[dict] = None, seed: Optional[int] = None):
        """
        Args:
            scenario: Pre-configured event mappings
            seed: Random seed for reproducibility
        """
        self._scenario = scenario or {"events": {}, "hit_rate": 0.7, "noise_rate": 0.1}
        self._rng = random.Random(seed)
        self._event_counter = 0

    def execute_fanout(self, probes: list[Probe]) -> list[dict]:
        """Execute probes against scenario, return matching events.

        For each probe:
        1. Look up (target, operator) in scenario events
        2. Apply hit_rate probability (may return empty for this probe)
        3. Optionally inject noise events (unrelated to probe)
        4. Tag each event with probe_id for tracing
        """
        if not probes:
            return []

        hit_rate = self._scenario.get("hit_rate", 0.7)
        noise_rate = self._scenario.get("noise_rate", 0.1)
        events_map = self._scenario.get("events", {})
        results: list[dict] = []

        for probe in probes:
            # Apply hit_rate: may miss
            if self._rng.random() > hit_rate:
                continue

            key = f"({probe.target}, {probe.operator})"
            scenario_events = events_map.get(key, [])

            if scenario_events:
                # Return pre-configured events
                for ev_template in scenario_events:
                    event = self._materialize_event(ev_template, probe)
                    results.append(event)
            else:
                # Generate synthetic event from probe parameters
                event = self._synthesize_event(probe)
                results.append(event)

            # Possibly inject noise
            if self._rng.random() < noise_rate:
                noise_event = self._generate_noise(probe)
                results.append(noise_event)

        return results

    def available(self) -> bool:
        return True

    def _materialize_event(self, template: dict, probe: Probe) -> dict:
        """Create a concrete event from a scenario template."""
        self._event_counter += 1
        event = {
            "id": template.get("id", f"EVT-{self._event_counter:04d}"),
            "technique": template.get("technique", "T0000"),
            "tactic": template.get("tactic", probe.tactic),
            "timestamp": template.get("timestamp", time.time()),
            "source": template.get("source", "mock-source"),
            "target": template.get("target", probe.target),
            "probe_id": probe.id,
            "raw_data": template.get("raw_data", {}),
            "attributes": template.get("attributes", {}),
        }
        return event

    def _synthesize_event(self, probe: Probe) -> dict:
        """Generate a synthetic event when no scenario match."""
        self._event_counter += 1
        return {
            "id": f"EVT-{self._event_counter:04d}",
            "technique": f"T{self._rng.randint(1000, 1999):04d}",
            "tactic": probe.tactic,
            "timestamp": time.time() + self._rng.uniform(-60, 60),
            "source": f"synth-{probe.operator}",
            "target": probe.target,
            "probe_id": probe.id,
            "raw_data": {"synthetic": True, "operator": probe.operator},
            "attributes": {"target_type": probe.target_type},
        }

    def _generate_noise(self, probe: Probe) -> dict:
        """Generate a noise event unrelated to the probe's intent."""
        self._event_counter += 1
        noise_tactics = ["discovery", "collection", "reconnaissance"]
        return {
            "id": f"NOISE-{self._event_counter:04d}",
            "technique": f"T{self._rng.randint(1000, 1999):04d}",
            "tactic": self._rng.choice(noise_tactics),
            "timestamp": time.time() + self._rng.uniform(-300, 300),
            "source": "noise-source",
            "target": f"noise-entity-{self._rng.randint(1, 100)}",
            "probe_id": probe.id,
            "raw_data": {"noise": True},
            "attributes": {"is_noise": True},
        }

    @staticmethod
    def create_attack_scenario(rounds: int = 3) -> dict:
        """Create a multi-round attack scenario for integration testing.

        Simulates a typical attack progression:
        Round 1: initial-access → execution (T1566 → T1059)
        Round 2: persistence → privilege-escalation (T1053 → T1068)
        Round 3: lateral-movement → exfiltration (T1021 → T1048)

        Returns scenario dict compatible with MockExecutor.__init__
        """
        base_time = time.time()
        events: dict[str, list[dict]] = {}

        attack_chain = [
            # (target, operator, technique, tactic, time_offset)
            ("host-A", "email_log", "T1566.001", "initial-access", 0),
            ("host-A", "process_tree", "T1059.001", "execution", 60),
            ("host-A", "scheduled_task", "T1053.005", "persistence", 180),
            ("host-A", "privilege_check", "T1068", "privilege-escalation", 300),
            ("host-B", "auth_log", "T1021.001", "lateral-movement", 420),
            ("host-B", "network_flow", "T1048.003", "exfiltration", 600),
        ]

        for target, operator, technique, tactic, offset in attack_chain:
            key = f"({target}, {operator})"
            ev = {
                "technique": technique,
                "tactic": tactic,
                "timestamp": base_time + offset,
                "source": f"sysmon-{target}",
                "target": target,
                "raw_data": {"command": f"simulated-{technique}"},
                "attributes": {"round": (offset // 200) + 1},
            }
            events.setdefault(key, []).append(ev)

        return {
            "events": events,
            "hit_rate": 0.9,
            "noise_rate": 0.05,
        }

    @staticmethod
    def create_benign_scenario() -> dict:
        """Create a scenario that produces mostly benign/noise events.
        Good for testing boundary convergence and dismiss paths.
        """
        base_time = time.time()
        events: dict[str, list[dict]] = {}

        benign_activities = [
            ("workstation-1", "process_tree", "T1204.002", "execution", "user-click"),
            ("workstation-1", "auth_log", "T1078", "initial-access", "normal-login"),
            ("server-1", "network_flow", "T1071.001", "command-and-control", "web-browse"),
        ]

        for target, operator, technique, tactic, label in benign_activities:
            key = f"({target}, {operator})"
            ev = {
                "technique": technique,
                "tactic": tactic,
                "timestamp": base_time,
                "source": f"audit-{target}",
                "target": target,
                "raw_data": {"benign_label": label},
                "attributes": {"benign": True, "confidence_malicious": 0.1},
            }
            events.setdefault(key, []).append(ev)

        return {
            "events": events,
            "hit_rate": 1.0,
            "noise_rate": 0.3,
        }
