"""A lossy adapter wrapper for exercising oracle confirmation.

A real target is not the deterministic mock: it rate-limits, times out, and returns
transient errors, so a single observation can MISS evidence that is genuinely present
(a read that should return the canary fails this once). This wrapper models exactly that
failure — it drops the *attacker's* read observations (`whoami`, `read_marker`) with
probability `drop`, deterministically under `seed` — so the value of oracle confirmation
(re-probe, then require a stable majority; see `oracle.AtoOracle(confirm=k)`) can be
demonstrated and regression-tested against the mock.

The asymmetry is the point: this wrapper can only *remove* evidence, never fabricate it.
A flaky target can hide a real takeover (a false negative the confirmation loop recovers),
but it cannot invent an identity confluence or a canary read — so it can never turn the
patched target into a false positive. Confirmation buys back the recall lost to flakiness
without ever weakening the load-bearing invariant.

Only the attacker's *read/identity* surface is made flaky; the plan's setup actions and
the oracle's victim-side restore run through untouched, so state is never left corrupted.
"""
from __future__ import annotations

import random
from typing import Optional

from .types import Observation, Principal


class FlakyAdapter:
    """Wrap `inner` and drop the attacker's observations with probability `drop`.

    Everything not overridden here passes straight through to `inner`, so a FlakyAdapter
    is a drop-in for any adapter (MockAdapter today, a real TargetAdapter later)."""

    def __init__(self, inner, attacker: str, drop: float = 0.5, seed: int = 0) -> None:
        self._inner = inner
        self._attacker = attacker
        self._drop = drop
        self._rng = random.Random(seed)

    def __getattr__(self, name):
        # only reached for attributes not defined on this wrapper -> the real adapter
        return getattr(self._inner, name)

    def _flap(self) -> bool:
        return self._rng.random() < self._drop

    def whoami(self, p: Principal) -> Observation:
        if p.name == self._attacker and self._flap():
            return Observation(False, identity=None, note="transient identity read (flaky target)")
        return self._inner.whoami(p)

    def read_marker(self, p: Principal, ref: Optional[str] = None) -> Observation:
        if p.name == self._attacker and self._flap():
            return Observation(False, extracted={"value": None},
                               note="transient read failure (flaky target)")
        return self._inner.read_marker(p, ref=ref)
