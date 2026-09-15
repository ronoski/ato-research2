"""Automata-learning self-test: learn the mock's single-account auth state machine
from black-box queries and print it.

    python3 -m tpihunter.learn_demo

The recovered Mealy machine is the *implemented* protocol state machine — e.g. it
shows that reset_consume only yields a session after a reset_request, and that
sso_login yields a *verified* session (OK_VERIFIED) that plain register/login do
not. This is the de Ruiter & Poll move: learn what the server really does, then
diff against intent or feed the alphabet to synthesis + the enumerator.
"""
from __future__ import annotations

from .learner import LStar, Mealy


def _fmt_word(w) -> str:
    return "ε" if len(w) == 0 else ">".join(w)


def print_machine(m: Mealy) -> None:
    for st in m.states:
        acc = m.access.get(st, ())
        print(f"  {st}  (access: {_fmt_word(acc)})")
        for a in m.alphabet:
            nxt, out = m.trans[(st, a)]
            arrow = "self" if nxt == st else nxt
            print(f"      {a:14} / {out:12} -> {arrow}")


def main() -> None:
    from .sul import MockSUL
    sul = MockSUL(patched=False)
    learner = LStar(sul, seed=1, eq_tests=1500)
    machine = learner.learn()

    print("\nTPI-HUNTER  -  automata learning (black-box L*)")
    print(f"learned the mock's single-account auth FSM from {learner.mq_count} membership queries\n")
    print(f"alphabet: {', '.join(machine.alphabet)}")
    print(f"states:   {len(machine.states)}  (initial: {machine.initial})\n")
    print_machine(machine)

    # A few read-offs a hunter cares about.
    print("\n read-offs:")
    reg = machine.run(("register",))
    sso = machine.run(("sso_login",))
    pre_reset = machine.run(("reset_consume",))
    post_reset = machine.run(("register", "reset_request", "reset_consume"))
    print(f"   register from start                      -> {reg}")
    print(f"   sso_login from start                     -> {sso}   (verified session — a trust-raise)")
    print(f"   reset_consume with no prior reset_request -> {pre_reset}   (no outstanding token)")
    print(f"   register>reset_request>reset_consume      -> {post_reset}   (token consumed -> session)")
    print("\n Next: synthesis.specs_from_machine turns this into the enumerator's")
    print(" action model — see `python3 -m tpihunter.synth_demo`.\n")


if __name__ == "__main__":
    main()
