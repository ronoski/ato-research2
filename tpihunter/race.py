"""Concurrency — the failure the engine could not express, though the theory names it.

A single-use proof consumed twice yields two bindings from one proof. That is a
provenance violation in the plainest sense, and Trust-Provenance Integrity has always
covered it. The *engine* could not: `run_plan` walks steps strictly in order, so the only
interleaving it can produce is an ordering. Real token double-spend is not an ordering. It
is two requests inside one check-then-act window, and no permutation of sequential steps
reaches it.

So this mode fires the same action N times at once and asks whether an invariant that
holds sequentially still holds concurrently.

THREE CONTROLS, because a race is unusually easy to fake in both directions:

  SEQUENTIAL   fired twice in sequence, exactly one attempt must succeed. If two do, the
               action was never single-use and a race would prove nothing; if none do, the
               setup is broken. Either way the cell measured nothing.
  OVERLAP      the attempts must actually have overlapped in time. Requests that serialise
               — behind a connection pool, a lock, a rate limiter — are a sequential run
               wearing a concurrent costume, and "no race found" from one is a false
               negative. Measured from the recorded windows, never assumed.
  NEGATIVE     a never-valid input must fail in every racer, so "two succeeded" cannot be
               an endpoint that accepts anything.

    v = run_race(RaceSpec("reset token double-spend",
                          invariant="a single-use reset token is consumed at most once"),
                 prepare=mint_token, fire=consume_token)
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional

from .types import Observation


class RaceOutcome(str, Enum):
    ATOMIC = "atomic"                # concurrency changed nothing — correct behaviour
    RACE = "race"                    # the invariant held in sequence and broke under load
    INCONCLUSIVE = "inconclusive"    # a control failed; the cell measured nothing


@dataclass(frozen=True)
class RaceSpec:
    name: str
    invariant: str                   # what must remain true, in words
    parallelism: int = 8
    clause_id: str = "TPI-2"         # a proof consumed more than once is pinned-proof failure


@dataclass
class Attempt:
    index: int
    ok: bool
    started: float
    ended: float
    note: str = ""


@dataclass
class RaceVerdict:
    spec: RaceSpec
    outcome: RaceOutcome
    sequential_successes: int = 0
    concurrent_successes: int = 0
    attempts: list = field(default_factory=list)
    controls: dict = field(default_factory=dict)
    note: str = ""

    @property
    def is_finding(self) -> bool:
        return self.outcome is RaceOutcome.RACE

    def render(self) -> str:
        head = f"[{self.outcome.value.upper()}] {self.spec.name}"
        if self.outcome is RaceOutcome.RACE:
            return (f"{head}: {self.concurrent_successes} of {self.spec.parallelism} "
                    f"concurrent attempts succeeded where exactly one succeeds in sequence. "
                    f"Invariant broken: {self.spec.invariant}")
        return f"{head}: {self.note}"


def max_overlap(attempts: list) -> int:
    """How many attempts were in flight at once, from the recorded windows."""
    edges = []
    for a in attempts:
        edges.append((a.started, 1))
        edges.append((a.ended, -1))
    edges.sort()
    cur = best = 0
    for _t, d in edges:
        cur += d
        best = max(best, cur)
    return best


def run_race(spec: RaceSpec, *, prepare: Callable[[], Any],
             fire: Callable[[Any, int], Observation],
             negative: Optional[Callable[[Any, int], Observation]] = None) -> RaceVerdict:
    """`prepare()` builds a fresh racing context; `fire(ctx, i)` makes one attempt."""
    v = RaceVerdict(spec=spec, outcome=RaceOutcome.INCONCLUSIVE)

    # -- SEQUENTIAL control: the invariant must hold when nothing is concurrent ----
    ctx = prepare()
    seq = [fire(ctx, i) for i in range(2)]
    v.sequential_successes = sum(1 for o in seq if getattr(o, "ok", False))
    v.controls["sequential_single_use"] = v.sequential_successes == 1
    if v.sequential_successes != 1:
        v.note = (f"fired twice in sequence, {v.sequential_successes} succeeded — the "
                  f"action is not single-use even without concurrency, so a race would "
                  f"prove nothing")
        return v

    # -- NEGATIVE control ----------------------------------------------------------
    if negative is not None:
        nctx = prepare()
        bad = negative(nctx, 0)
        v.controls["negative_rejected"] = not getattr(bad, "ok", False)
        if getattr(bad, "ok", False):
            v.note = ("a never-valid input succeeded; this endpoint accepts anything and "
                      "'two succeeded' would mean nothing")
            return v

    # -- the concurrent trial ------------------------------------------------------
    ctx = prepare()
    barrier = threading.Barrier(spec.parallelism)

    def one(i: int) -> Attempt:
        try:
            barrier.wait(timeout=30)     # release together, so the windows really overlap
        except Exception:
            pass
        t0 = time.monotonic()
        try:
            obs = fire(ctx, i)
        except Exception as e:
            return Attempt(i, False, t0, time.monotonic(), f"{type(e).__name__}: {e}")
        return Attempt(i, bool(getattr(obs, "ok", False)), t0, time.monotonic(),
                       getattr(obs, "note", "") or "")

    with ThreadPoolExecutor(max_workers=spec.parallelism) as pool:
        v.attempts = sorted(pool.map(one, range(spec.parallelism)), key=lambda a: a.index)

    overlap = max_overlap(v.attempts)
    v.controls["max_in_flight"] = overlap
    v.controls["overlapped"] = overlap >= 2
    v.concurrent_successes = sum(1 for a in v.attempts if a.ok)

    if overlap < 2:
        v.note = (f"the attempts never overlapped (max {overlap} in flight) — they "
                  f"serialised, so this was a sequential run in disguise and 'no race' "
                  f"is not a result")
        return v
    if v.concurrent_successes > 1:
        v.outcome = RaceOutcome.RACE
        v.note = (f"{v.concurrent_successes} concurrent successes with {overlap} in "
                  f"flight, against exactly 1 in sequence")
        return v
    v.outcome = RaceOutcome.ATOMIC
    v.note = (f"{v.concurrent_successes} success with {overlap} attempts in flight — the "
              f"check-and-act is atomic under this much concurrency")
    return v
