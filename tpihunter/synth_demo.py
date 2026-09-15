"""End-to-end: learn -> synthesize -> enumerate, with nothing hand-coded.

    python3 -m tpihunter.synth_demo

This is the M3 acceptance demo. It (1) learns the mock's auth machine from black-box
queries, (2) synthesizes the enumerator's action model from that machine, (3) shows
the synthesized effects match the hand-coded ACTIONS, and (4) runs the enumerator on
the *synthesized* model and confirms it reproduces the same findings (TPI-1 and
TPI-4), all closing under the patch. The static action table is no longer trusted —
generation now rides on observed behaviour.
"""
from __future__ import annotations

from .enumerator import ACTIONS, enumerate_plans
from .harness import run_plan
from .learner import LStar
from .oracle import AtoOracle
from .mock_target import MockAdapter
from .sul import MockSUL
from .synthesis import specs_from_machine
from .types import Principal


def _findings(specs, actions, attacker, victim, email, control):
    cands = enumerate_plans(attacker, victim, email, specs=specs, actions=actions)
    fired = []
    patch_gaps = 0
    for c in cands:
        av = MockAdapter(patched=False, control=control)
        vv = run_plan(av, c.plan, AtoOracle(av, attacker, victim))[0]
        if vv.severity.value != "takeover":
            continue
        ap = MockAdapter(patched=True, control=control)
        vp = run_plan(ap, c.plan, AtoOracle(ap, attacker, victim))[0]
        fired.append(vv.clause_id)
        if vp.severity.value == "takeover":
            patch_gaps += 1
    return len(cands), fired, patch_gaps


def main() -> None:
    attacker, victim = Principal("attacker"), Principal("victim")
    email = "victim@corp.example"
    control = {victim.name: {email}}

    # 1) learn
    learner = LStar(MockSUL(patched=False), seed=1, eq_tests=1500)
    machine = learner.learn()

    # 2) synthesize the action model
    specs = specs_from_machine(machine)

    print("\nTPI-HUNTER  -  learn -> synthesize -> enumerate")
    print(f"learned {len(machine.states)}-state machine in {learner.mq_count} queries; "
          f"synthesized {len(specs)} action specs\n")

    # 3) compare synthesized vs hand-coded
    print(f"   {'action':16} {'synthesized':30} {'hand-coded (ACTIONS)'}")
    print("   " + "-" * 74)
    all_match = True
    for name in sorted(set(specs) | set(ACTIONS)):
        s = specs.get(name)
        h = ACTIONS.get(name)
        s_desc = f"{s.effect.value:8} req={s.requires}" if s else "(absent)"
        h_desc = f"{h.effect.value:8} req={h.requires}" if h else "(absent)"
        match = bool(s) and bool(h) and s.effect == h.effect
        all_match = all_match and match
        flag = "" if match else "   <-- differs"
        print(f"   {name:16} {s_desc:30} {h_desc}{flag}")
    print(f"\n   effects match hand-coded model: {all_match}")

    # 4) enumerate from the synthesized model and check findings
    actions = list(specs.keys())
    n, fired, gaps = _findings(specs, actions, attacker, victim, email, control)
    clauses = sorted(set(fired))
    print("\n " + "=" * 74)
    print(f" enumerated {n} probes from the LEARNED model; {len(fired)} fired, "
          f"distinct clauses: {', '.join(clauses)}")
    if gaps:
        print(f" WARNING: {gaps} finding(s) still fire on the patched target.")
    else:
        print(" All findings close under the patch -> real bugs, not detector artifacts.")
    print(" " + "=" * 74)
    ok = (clauses == ["TPI-1", "TPI-4"]) and gaps == 0 and all_match
    print(f" M3 acceptance: {'PASS' if ok else 'FAIL'} "
          "(learned model reproduces the hand-coded findings)\n")


if __name__ == "__main__":
    main()
