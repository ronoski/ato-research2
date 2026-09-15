"""Agent-as-hunter self-test: the same target, two strategies.

    python3 -m tpihunter.agent_demo

1. The mechanical `EnumeratorStrategist` brute-forces every interleaving.
2. A `LLMStrategist` driven by a *fake* completion function proposes the two
   effective probes directly and finds the same distinct bugs in a handful of
   probes — the point of agent-as-hunter: adapt, don't brute-force.

The fake completion stands in for a model; swap it for a real one (prompt in, text
out) to get a live agent. The prompt it receives is printed so the tool contract is
tangible.
"""
from __future__ import annotations

import json

from .agent import AgentHunter, EnumeratorStrategist, HuntState, LLMStrategist
from .enumerator import ACTIONS
from .mock_target import MockAdapter
from .types import Principal


def _print_bugs(bugs) -> None:
    for i, cl in enumerate(bugs, 1):
        repro = "  ->  ".join(f"{r}:{a}" for r, a in cl.representative)
        print(f"       [{i}] {cl.clause_id}: {repro}")


def _fake_llm(prompt: str) -> str:
    """Stand-in for a model. A real agent would read `prompt` (printed below) and
    reason; this canned reply proposes the two effective TPI probes."""
    return json.dumps([
        {"steps": [["attacker", "register"], ["victim", "sso_login"]]},
        {"steps": [["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]]},
    ])


def main() -> None:
    attacker, victim = Principal("attacker"), Principal("victim")
    email = "victim@corp.example"
    control = {victim.name: {email}}

    def adapter_factory():
        return MockAdapter(patched=False, control=control)

    print("\nTPI-HUNTER  -  agent as hunter: two strategies, one target\n")

    # 1) mechanical baseline
    h1 = AgentHunter(adapter_factory, attacker, victim, email, specs=ACTIONS, budget=300)
    r1 = h1.hunt(EnumeratorStrategist())
    print(f" [enumerator strategist]  {r1.probes_used} probes -> {len(r1.bugs)} distinct bug(s):")
    _print_bugs(r1.bugs)

    # 2) the agent's tool contract (what an LLM strategist is handed)
    fresh = HuntState(ACTIONS, attacker, victim, email, budget=300)
    print("\n ---- the prompt an LLM strategist receives (its tool contract) ----")
    for line in LLMStrategist(_fake_llm).render_prompt(fresh).splitlines():
        print("   " + line)
    print(" ------------------------------------------------------------------")

    # 3) agent strategist (fake model) — adapts instead of brute-forcing
    h2 = AgentHunter(adapter_factory, attacker, victim, email, specs=ACTIONS, budget=300)
    r2 = h2.hunt(LLMStrategist(_fake_llm, max_rounds=1))
    print(f"\n [LLM strategist (fake)]  {r2.probes_used} probes -> {len(r2.bugs)} distinct bug(s):")
    _print_bugs(r2.bugs)

    print("\n " + "=" * 74)
    print(f" same 2 bugs. enumerator: {r1.probes_used} probes.  agent: {r2.probes_used} probes.")
    print(" The deterministic tools (adapter + oracle + dedup) give ground truth;")
    print(" the strategist supplies the hypotheses. Swap _fake_llm for a real model")
    print(" completion (prompt in, text out) and this loop becomes a live agent.")
    print(" " + "=" * 74 + "\n")


if __name__ == "__main__":
    main()
