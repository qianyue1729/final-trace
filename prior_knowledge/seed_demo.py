#!/usr/bin/env python3
"""Demo: generate DecisionLedger seed from real L1–L4 prior products."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from trace_agent.data_loader import load_prior_bundle  # noqa: E402
from trace_agent.decision.belief import DecisionLedger  # noqa: E402
from trace_agent.decision.types import AlertEvent  # noqa: E402
from trace_agent.prior_v2 import PriorManager, reset_prior_manager  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed DecisionLedger from prior knowledge (L1-L4)")
    parser.add_argument("--technique", default="T1059.001", help="Entry ATT&CK technique")
    parser.add_argument("--tactic", default="execution", help="Entry tactic short name")
    parser.add_argument("--platform", default="windows", help="Platform")
    parser.add_argument("--log-source", default="process_creation", help="Observed log source")
    parser.add_argument("--anomaly", type=float, default=0.85, help="Entry anomaly_score")
    parser.add_argument("--data-dir", default=None, help="Override prior data directory")
    args = parser.parse_args()

    reset_prior_manager()
    bundle = load_prior_bundle(args.data_dir)
    prior = PriorManager(bundle)
    ledger = DecisionLedger(prior)

    alert = AlertEvent(
        technique_id=args.technique,
        tactic=args.tactic,
        platform=args.platform,
        log_source=args.log_source,
        anomaly_score=args.anomaly,
    )

    seed = ledger.seed(alert)
    print(json.dumps(seed.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
