"""Situational-awareness self-test: the agent reasons about coverage and stops on its own.

    python3 -m tpihunter.coverage_demo

M8 showed the agent *finds* the bugs in few probes. But to hunt a REAL target well it also
needs to know WHY each probe landed, WHAT it has covered, and WHEN to stop — otherwise it burns
probes (and, live, real requests) re-testing settled surface. This demo shows the three signals
now fed back to the strategist:

  * a per-probe REASON code — new_bug / duplicate / enforced / unbound_action / incomplete;
  * a COVERAGE map — distinct bugs, clauses with evidence, effect-combinations tried, untried
    frontier in the known alphabet;
  * a principled STOP — `patience`: halt after N rounds with no new distinct bug.

No API key: a scripted `complete_fn` plays a plausible adaptive session so the seam is exercised
end to end (render_prompt now carries the coverage block the model would read).
"""
from __future__ import annotations

import json

from .agent import AgentHunter, EnumeratorStrategist, LLMStrategist
from .mock_target import MockAdapter
from .types import Principal

EMAIL = "victim@corp.example"


def _scripted_agent():
    """Round 1: try the two laundering shapes, a verb the target lacks, and a lone seed.
    Round 2: only a padded rerun of a bug already found (no new ground). It would keep going,
    but `patience` stops it once a round adds nothing."""
    rounds = [
        json.dumps({
            "new_actions": [{"id": "device_pair", "effect": "raise", "needs_control": False}],
            "probes": [
                {"steps": [["attacker", "register"], ["victim", "sso_login"]]},
                {"steps": [["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]]},
                {"steps": [["attacker", "register"], ["victim", "device_pair"]]},
                {"steps": [["attacker", "register"]]},
            ],
        }),
        json.dumps({"probes": [
            {"steps": [["attacker", "register"], ["attacker", "login"], ["victim", "sso_login"]]},
        ]}),
        json.dumps({"probes": [{"steps": [["victim", "sso_login"], ["attacker", "register"]]}]}),
    ]
    box = {"i": 0}

    def complete(_prompt: str) -> str:
        r = rounds[min(box["i"], len(rounds) - 1)]
        box["i"] += 1
        return r
    return complete


def main() -> None:
    attacker, victim = Principal("attacker"), Principal("victim")
    control = {victim.name: {EMAIL}}
    print("\nTPI-HUNTER  -  agent situational awareness (reason codes, coverage, stopping)\n")

    hunter = AgentHunter(lambda: MockAdapter(patched=False, control=control),
                         attacker, victim, EMAIL, budget=50)
    res = hunter.hunt(LLMStrategist(_scripted_agent(), max_rounds=4), patience=1)

    print(" per-probe feedback the agent now gets back (the [reason] steers the next move):")
    for a in res.attempts:
        probe = "  ->  ".join(f"{r}:{x}" for r, x in a.merged)
        tag = a.severity + (f" {a.clause_id}" if a.clause_id else "")
        print(f"   [{a.reason:14}] {tag:16} {probe}")

    c = res.coverage
    print("\n coverage map the agent can query at any point:")
    print(f"   distinct bugs        : {c.distinct_bugs}  ({', '.join(c.clauses_found)})")
    print("   effect-combos tried  : "
          + ", ".join("{" + "+".join(sorted(x)) + "}" for x in c.effect_combos_tried))
    print(f"   frontier untried     : ~{c.frontier_remaining} known-alphabet probes")
    print(f"   probes used          : {c.probes_used}")
    print(f"   stopped because      : {res.stop_reason}")

    base = AgentHunter(lambda: MockAdapter(patched=False, control=control),
                       attacker, victim, EMAIL, budget=300).hunt(EnumeratorStrategist())
    print("\n " + "=" * 72)
    print(f" adaptive agent : {c.distinct_bugs} bugs in {res.probes_used} probes, stopped on '{res.stop_reason}'")
    print(f" enumerator     : {len(base.bugs)} bugs in {base.probes_used} probes (fires the whole space)")
    print(" => reason codes + coverage + patience are what let the agent stop early instead of")
    print("    re-testing settled surface — the difference that matters on a real target, where")
    print("    every probe is a live request.\n")


if __name__ == "__main__":
    main()
