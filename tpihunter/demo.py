"""Self-test: run the pre-hijacking probe against the built-in mock, on both the
vulnerable and patched targets, and print the oracle's verdicts.

    python3 -m tpihunter.demo
"""
from __future__ import annotations

from .harness import run_plan
from .oracle import AtoOracle
from .mock_target import MockAdapter
from .probes import pre_hijacking_plan
from .types import Principal


def _hr(c: str = "-", n: int = 74) -> str:
    return c * n


def _print_trace(trace) -> None:
    for s in trace.steps:
        who = s.principal.name if s.principal else "--"
        proof = f"   emits {s.obs.proof}" if (s.obs and s.obs.proof) else ""
        print(f"    {who:8} {s.action:14} ok={str(s.obs.ok):5}{proof}")


def run(patched: bool) -> None:
    attacker, victim = Principal("attacker"), Principal("victim")
    email = "victim@corp.example"
    # The victim genuinely controls their email (IdP + inbox); the attacker does not.
    adapter = MockAdapter(patched=patched, control={victim.name: {email}})
    oracle = AtoOracle(adapter, attacker, victim)
    plan = pre_hijacking_plan(attacker, victim, email)
    verdict, trace = run_plan(adapter, plan, oracle)

    label = "PATCHED    (revoke-on-rebind enforced)" if patched else "VULNERABLE (as shipped)"
    print(_hr("="))
    print(f" TARGET : {label}")
    print(f" PROBE  : {plan.name}  ->  targets {plan.targets_clause}")
    print(_hr())
    print(" alphabet trace (two principals, one shared store):")
    _print_trace(trace)
    print(_hr())
    icon = {"takeover": "[TAKEOVER]", "suspect": "[SUSPECT]", "safe": "[SAFE]"}[verdict.severity.value]
    print(f" VERDICT: {icon}   confidence={verdict.confidence:.2f}")
    if verdict.clause_id:
        print(f" CLAUSE : {verdict.clause_id}  ({verdict.failure_mode})")
    if verdict.laundered_proof:
        print(f" LAUNDERED PROOF: {verdict.laundered_proof}")
    if verdict.evidence:
        print(" EVIDENCE:")
        for e in verdict.evidence:
            print(f"    [{e.strength}] {e.kind}: {e.detail}")
    print(" ", verdict.narrative)
    print()


def main() -> None:
    print("\nTPI-HUNTER  -  black-box account-takeover loop")
    print("self-test on the built-in mock (no live target)\n")
    run(patched=False)
    run(patched=True)
    print(_hr("="))
    print(" Same probe: TAKEOVER on the vulnerable target, SAFE on the patched one")
    print(" -> the oracle discriminates. Swap MockAdapter for a real httpx-backed")
    print(" TargetAdapter (see README) to hunt a live target.\n")


if __name__ == "__main__":
    main()
