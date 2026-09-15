"""System-Under-Learning (SUL) interface for active automata learning.

A SUL is a black box the learner can (a) reset to a known start state and (b) step
with one input symbol, observing one output symbol. Wrapping a target this way
turns "learn the auth state machine" into standard Mealy-machine learning (L*) —
the de Ruiter & Poll protocol-state-fuzzing move from Section 7 of the paper:
recover the machine the server *actually* implements, then diff it against intent
or feed its alphabet to the enumerator.

The input alphabet is the adapter's own action names, so a learned machine plugs
straight into `synthesis.specs_from_machine` and then the enumerator with no
translation layer. Outputs are abstracted to a small observation vocabulary; note
`sso_login` yields a distinct `OK_VERIFIED` — the observable trust-raise the
synthesis step keys on to label a RAISE action.

`MockSUL` drives the built-in vulnerable target for a single account. A real
target implements the same tiny interface over its live endpoints.
"""
from __future__ import annotations

from typing import Protocol

from .mock_target import MockAdapter
from .types import Principal

# Abstract input alphabet == adapter action names (one account, one controlling actor).
REGISTER = "register"
LOGIN = "login"
SSO_LOGIN = "sso_login"
RESET_REQ = "reset_request"
RESET_USE = "reset_consume"
LOGOUT = "logout"

ALPHABET = [REGISTER, LOGIN, SSO_LOGIN, RESET_REQ, RESET_USE, LOGOUT]

# Output vocabulary.
OK_SESSION = "OK_SESSION"      # a session, identifier still unverified
OK_VERIFIED = "OK_VERIFIED"    # a session AND the identifier is now verified (trust-raise)
SENT = "SENT"                  # an outstanding token was created
DENIED = "DENIED"              # the action was refused in this state
LOGGED_OUT = "LOGGED_OUT"      # a live session was ended
NOSESS = "NOSESS"             # nothing to end


class SUL(Protocol):
    @property
    def alphabet(self) -> list[str]: ...
    def reset(self) -> None: ...
    def step(self, symbol: str) -> str: ...


class MockSUL:
    """Single-account view of the mock, as a deterministic Mealy SUL."""

    def __init__(self, patched: bool = False, email: str = "user@corp.example") -> None:
        self.patched = patched
        self.email = email
        self.actor = Principal("learner")
        self._pw = "pw0"
        self._a: MockAdapter | None = None
        self.reset()

    @property
    def alphabet(self) -> list[str]:
        return list(ALPHABET)

    def reset(self) -> None:
        # A fresh target instance; the actor controls this email's IdP + inbox.
        self._a = MockAdapter(patched=self.patched, control={self.actor.name: {self.email}})
        self._pw = "pw0"

    def step(self, symbol: str) -> str:
        a, p, e = self._a, self.actor, self.email
        if symbol == REGISTER:
            return OK_SESSION if a.register(p, e, self._pw).ok else DENIED
        if symbol == LOGIN:
            return OK_SESSION if a.login(p, e, self._pw).ok else DENIED
        if symbol == SSO_LOGIN:
            # proves control of the email AND verifies it -> a distinct, observable raise
            return OK_VERIFIED if a.sso_login(p, e).ok else DENIED
        if symbol == RESET_REQ:
            return SENT if a.reset_request(p, e).ok else DENIED
        if symbol == RESET_USE:
            # reset keeps the password at self._pw, so LOGIN stays valid afterwards
            return OK_SESSION if a.reset_consume(p, e, self._pw).ok else DENIED
        if symbol == LOGOUT:
            had_session = a.whoami(p).ok
            a.logout(p)
            return LOGGED_OUT if had_session else NOSESS
        raise ValueError(f"unknown input symbol: {symbol}")
