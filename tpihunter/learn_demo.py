"""Automata-learning self-test: learn the mock's single-account auth state machine
from black-box queries and print it.

    python3 -m tpihunter.learn_demo

The recovered Mealy machine is the *implemented* protocol state machine — e.g. it
shows that RESET_USE only yields a session after a RESET_REQ, and that LOGIN is
denied until an account exists. This is the de Ruiter & Poll move: learn what the
server really does, then diff against intent or feed the alphabet to the enumerator.
"""
from __future__ import annotations

from .learner import LStar, Mealy
from .sul import MockSUL


def _fmt_word(w) -> str:
    return "ε" if len(w) == 0 else ">".join(w)


def print_machine(m: Mealy) -> None:
    for st in m.states:
        acc = m.access.get(st, ())
        print(f"  {st}  (access: {_fmt_word(acc)})")
        for a in m.alphabet:
            nxt, out = m.trans[(st, a)]
            arrow = "self" if nxt == st else nxt
            print(f"      {a:10} / {out:12} -> {arrow}")


def main() -> None:
    sul = MockSUL(patched=False)
    learner = LStar(sul, seed=1)
    machine = learner.learn()

    print("\nTPI-HUNTER  -  automata learning (black-box L*)")
    print(f"learned the mock's single-account auth FSM from {learner.mq_count} membership queries\n")
    print(f"alphabet: {', '.join(machine.alphabet)}")
    print(f"states:   {len(machine.states)}  (initial: {machine.initial})\n")
    print_machine(machine)

    # A couple of read-offs a hunter cares about.
    print("\n read-offs:")
    reg_out = machine.run(("REGISTER",))
    pre_reset = machine.run(("RESET_USE",))
    post_reset = machine.run(("REGISTER", "RESET_REQ", "RESET_USE"))
    print(f"   REGISTER from start                 -> {reg_out}")
    print(f"   RESET_USE with no prior RESET_REQ    -> {pre_reset}   (no outstanding token)")
    print(f"   REGISTER>RESET_REQ>RESET_USE         -> {post_reset}   (token consumed -> session)")
    print("\n Next (M3 cont.): map these learned transitions to the enumerator's")
    print(" effect classes so generation runs on learned behaviour, not the static")
    print(" ACTIONS table.\n")


if __name__ == "__main__":
    main()
