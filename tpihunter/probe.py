"""Bounded, hypothesis-led enumeration — the legitimate half of "try things".

A rules-of-engagement document usually says two things at once: *no scanners, no
wordlists, nothing generating significant volume*, and *structured input probing is fine,
bounded and hypothesis-led, ≤N values per argument*. The difference between the two is not
the number of requests. It is whether each value was chosen for a reason.

So this makes the reason mandatory and the bound structural:

  * every candidate carries a `hypothesis` — what it would mean if it worked. A candidate
    without one cannot be constructed, which is the difference between probing and fuzzing;
  * `Budget` caps values per argument and total requests, and refuses rather than trims;
  * a rate-limit or challenge response HALTS the probe, as an ROE requires, and the halt
    is recorded — a probe that stopped early is not a probe that found nothing.

    b = Budget(per_argument=12, total=60)
    out = run_probe(b, [Candidate("shape", {"login_id": x}, "the field the SPA sends")],
                    send=lambda c: adapter_call(c.value))
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


class BudgetExceeded(RuntimeError):
    """The probe would have gone past its ceiling. Raised, never silently trimmed."""


class Halted(RuntimeError):
    """The target asked us to stop (429 / challenge). Recorded, and the probe ends."""


@dataclass(frozen=True)
class Candidate:
    argument: str
    value: Any
    hypothesis: str

    def __post_init__(self) -> None:
        if not (self.hypothesis or "").strip():
            raise ValueError(
                "a candidate needs a hypothesis — what it would mean if it worked. "
                "Values chosen without one are a wordlist, which is the thing every "
                "programme's rules forbid.")


@dataclass
class Budget:
    per_argument: int = 40
    total: int = 200
    halt_statuses: frozenset = frozenset({429, 503})
    used: int = 0
    per: dict = field(default_factory=dict)
    halted: Optional[str] = None

    def take(self, argument: str) -> None:
        if self.halted:
            raise Halted(self.halted)
        n = self.per.get(argument, 0)
        if n >= self.per_argument:
            raise BudgetExceeded(f"{self.per_argument} values already tried for "
                                 f"{argument!r}; widen the hypothesis rather than the list")
        if self.used >= self.total:
            raise BudgetExceeded(f"probe budget of {self.total} requests is spent")
        self.per[argument] = n + 1
        self.used += 1

    def note_response(self, status: Optional[int], text: str = "") -> None:
        if status in self.halt_statuses:
            self.halted = f"target returned {status}; halting as the rules of engagement require"
        elif "captcha" in (text or "").lower() or "challenge" in (text or "").lower():
            self.halted = "target presented a challenge; halting rather than working around it"
        if self.halted:
            raise Halted(self.halted)


@dataclass
class Outcome:
    candidate: Candidate
    status: Optional[int]
    detail: str
    interesting: bool = False


@dataclass
class ProbeResult:
    outcomes: list = field(default_factory=list)
    halted: Optional[str] = None
    exhausted: Optional[str] = None

    @property
    def complete(self) -> bool:
        """False when the probe stopped early — then 'nothing found' means nothing."""
        return self.halted is None and self.exhausted is None

    def interesting(self) -> list:
        return [o for o in self.outcomes if o.interesting]

    def summary(self) -> str:
        head = f"{len(self.outcomes)} probed, {len(self.interesting())} interesting"
        if self.halted:
            return f"{head} — HALTED: {self.halted} (this is not a clean negative)"
        if self.exhausted:
            return f"{head} — STOPPED: {self.exhausted} (this is not a clean negative)"
        return head


def run_probe(budget: Budget, candidates: list,
              send: Callable[[Candidate], tuple]) -> ProbeResult:
    """`send(candidate) -> (status, detail, interesting)`."""
    res = ProbeResult()
    for c in candidates:
        try:
            budget.take(c.argument)
        except Halted as e:
            res.halted = str(e); break
        except BudgetExceeded as e:
            res.exhausted = str(e); break
        try:
            status, detail, interesting = send(c)
        except Halted as e:
            res.halted = str(e); break
        res.outcomes.append(Outcome(c, status, detail, bool(interesting)))
        try:
            budget.note_response(status, detail)
        except Halted as e:
            res.halted = str(e); break
    return res
