"""System-Under-Learning (SUL) interface for active automata learning.

A SUL is a black box the learner can (a) reset to a known start state and (b) step
with one input symbol, observing one output symbol. Wrapping a target this way
turns "learn the auth state machine" into standard Mealy-machine learning (L*) —
the de Ruiter & Poll protocol-state-fuzzing move from Section 7 of the paper:
recover the machine the server *actually* implements, then diff it against intent
or feed its alphabet to the enumerator.

`MockSUL` drives the built-in vulnerable target for a single account, over an
abstract alphabet with deterministic outputs, so the learner has something
concrete to recover. A real target implements the same tiny interface.
"""
from __future__ import annotations

from typing import Protocol

from .mock_target import MockAdapter
from .types import Principal

# Abstract input alphabet (one account, one actor who controls its email).
REGISTER = "REGISTER"
LOGIN = "LOGIN"
RESET_REQ = "RESET_REQ"
RESET_USE = "RESET_USE"
LOGOUT = "LOGOUT"


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
        return [REGISTER, LOGIN, RESET_REQ, RESET_USE, LOGOUT]

    def reset(self) -> None:
        # A fresh target instance; the actor controls this email's IdP + inbox.
        self._a = MockAdapter(patched=self.patched, control={self.actor.name: {self.email}})
        self._pw = "pw0"

    def step(self, symbol: str) -> str:
        a, p, e = self._a, self.actor, self.email
        if symbol == REGISTER:
            return "OK_SESSION" if a.register(p, e, self._pw).ok else "DENIED"
        if symbol == LOGIN:
            return "OK_SESSION" if a.login(p, e, self._pw).ok else "DENIED"
        if symbol == RESET_REQ:
            return "SENT" if a.reset_request(p, e).ok else "DENIED"
        if symbol == RESET_USE:
            # reset keeps the password at self._pw, so LOGIN stays valid afterwards
            return "OK_SESSION" if a.reset_consume(p, e, self._pw).ok else "DENIED"
        if symbol == LOGOUT:
            had_session = a.whoami(p).ok
            a.logout(p)
            return "LOGGED_OUT" if had_session else "NOSESS"
        raise ValueError(f"unknown input symbol: {symbol}")
