"""Live agent demo — the real LLM strategist driving the hunt.

    TPIHUNTER_LIVE=1 python3 -m tpihunter.live_agent_demo

Guarded by the TPIHUNTER_LIVE env var so it never makes a paid API call during the
ordinary green-check (without it, this prints setup instructions and exits 0). When
enabled it needs `pip install anthropic` and credentials (ANTHROPIC_API_KEY or an
`ant auth login` profile), then runs the agent against the mock with a small budget —
the model proposes the probes, the oracle judges, dedup reports the distinct bugs.
"""
from __future__ import annotations

import os
import sys

from .agent import AgentHunter, LLMStrategist
from .enumerator import ACTIONS
from .mock_target import MockAdapter
from .types import Principal


def main() -> None:
    if os.environ.get("TPIHUNTER_LIVE") != "1":
        print("\nLive agent demo is gated (no paid call during the normal test run).")
        print("To run the real LLM strategist against the mock:")
        print("  1. pip install anthropic")
        print("  2. export ANTHROPIC_API_KEY=...   (or `ant auth login`)")
        print("  3. TPIHUNTER_LIVE=1 python3 -m tpihunter.live_agent_demo")
        print("\nFor the offline demo of the same loop: python3 -m tpihunter.agent_demo\n")
        return

    try:
        import anthropic  # noqa: F401
    except ImportError:
        print("The `anthropic` package is not installed. Run: pip install anthropic")
        sys.exit(1)

    from .llm import make_complete_fn

    attacker, victim = Principal("attacker"), Principal("victim")
    email = "victim@corp.example"
    control = {victim.name: {email}}

    def adapter_factory():
        return MockAdapter(patched=False, control=control)

    print("\nTPI-HUNTER  -  LIVE agent (Claude Opus 5 strategist) on the mock\n")
    hunter = AgentHunter(adapter_factory, attacker, victim, email, specs=ACTIONS, budget=24)
    result = hunter.hunt(LLMStrategist(make_complete_fn(), max_rounds=3))

    print(f" probes used: {result.probes_used}")
    print(f" distinct bugs: {len(result.bugs)}")
    for i, cl in enumerate(result.bugs, 1):
        repro = "  ->  ".join(f"{r}:{a}" for r, a in cl.representative)
        print(f"   [{i}] {cl.clause_id}: {repro}")
    print()


if __name__ == "__main__":
    main()
