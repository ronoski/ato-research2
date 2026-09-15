"""Synthesis: turn a *learned* Mealy machine into the enumerator's action model.

This closes the black-box loop. `learner.py` recovers the machine a target really
implements; this module reads that machine and emits the `ActionSpec` dict the
enumerator generates from — so probe generation runs on observed behaviour instead
of the hand-coded `ACTIONS` table.

Two things are derived, and one is declared:

  * requires (ordering)  — DERIVED, soundly, from the FSM: an action's immediate
    precondition is the last action on the shortest path that first enables it.
  * effect (SEED/RAISE/CRED/REQUEST) — DERIVED from the output signature: a verified
    session (`OK_VERIFIED`) is a RAISE; a token (`SENT`) is a REQUEST; a session that
    is only reachable after a token-producing action is a CRED; any other session is
    a SEED.
  * needs_control — DECLARED per channel. Single-account learning always controls
    the identifier, so control-denial is unobservable from these traces; it is a
    property of the channel, not of the trace.

The result is validated in `synth_demo` and `tests/`: for the mock, the synthesized
effects match the hand-coded `ACTIONS`, and the enumerator reproduces the same
findings from them.
"""
from __future__ import annotations

from collections import deque
from typing import Optional

from .enumerator import ActionSpec, Effect
from .learner import Mealy
from .sul import DENIED, LOGGED_OUT, NOSESS, OK_SESSION, OK_VERIFIED, SENT

# Outputs that mean "the action did something" (used to derive enabledness/ordering).
SUCCESS_OUTPUTS = {OK_SESSION, OK_VERIFIED, SENT}
# Outputs that carry no attack-relevant effect (pure session control).
NEUTRAL_OUTPUTS = {LOGGED_OUT, NOSESS}

# Channels whose action requires control of the target identifier. Domain knowledge:
# not learnable from single-account traces, where the actor always controls it.
CONTROL_REQUIRING = {"sso_login", "reset_consume"}


def _outputs_of(machine: Mealy, symbol: str) -> set[str]:
    """Every output `symbol` can produce, across all states of the machine."""
    return {machine.trans[(s, symbol)][1] for s in machine.states}


def _shortest_enabling(machine: Mealy, symbol: str) -> Optional[list[str]]:
    """Shortest input word from the initial state after which `symbol` first yields a
    success output. [] if already enabled at start; None if never enabled."""
    start = machine.initial
    if machine.trans[(start, symbol)][1] in SUCCESS_OUTPUTS:
        return []
    seen = {start}
    q: deque[tuple[str, list[str]]] = deque([(start, [])])
    while q:
        s, path = q.popleft()
        for a in machine.alphabet:
            ns, _out = machine.trans[(s, a)]
            npath = path + [a]
            if machine.trans[(ns, symbol)][1] in SUCCESS_OUTPUTS:
                return npath
            if ns not in seen:
                seen.add(ns)
                q.append((ns, npath))
    return None


def classify_effect(machine: Mealy, symbol: str) -> Optional[Effect]:
    """Label a symbol's effect from its output signature. None = neutral (e.g. logout)."""
    outs = _outputs_of(machine, symbol)
    if OK_VERIFIED in outs:
        return Effect.RAISE
    if SENT in outs:
        return Effect.REQUEST
    if OK_SESSION in outs:
        path = _shortest_enabling(machine, symbol)
        if path:  # enabled only after some prior action
            req = path[-1]
            if SENT in _outputs_of(machine, req):   # gated behind a token -> credential change
                return Effect.CRED
        return Effect.SEED
    return None


def synth_spec(machine: Mealy, symbol: str) -> Optional[ActionSpec]:
    effect = classify_effect(machine, symbol)
    if effect is None:
        return None
    path = _shortest_enabling(machine, symbol)
    requires = (path[-1],) if path else ()
    return ActionSpec(symbol, effect, requires=requires,
                      needs_control=(symbol in CONTROL_REQUIRING))


def specs_from_machine(machine: Mealy) -> dict[str, ActionSpec]:
    """The enumerator-ready action model derived from a learned machine. Neutral
    symbols (no attack-relevant effect) are dropped, so the enumerator never spends
    interleavings on them."""
    specs: dict[str, ActionSpec] = {}
    for sym in machine.alphabet:
        spec = synth_spec(machine, sym)
        if spec is not None:
            specs[sym] = spec
    return specs
