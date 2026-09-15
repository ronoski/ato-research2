"""W-method conformance testing as an L* equivalence oracle (Chow, 1978).

The random-walk oracle in `learner.py` only *samples* the target: it can fail to find a
counterexample but never certify its absence, so a learned machine can be incomplete for a
larger alphabet. The W-method instead builds a FINITE test suite that is guaranteed to expose
any discrepancy between the hypothesis and the true machine, provided the true machine has at
most `n + extra_states` states (n = hypothesis states). That bound is the "soundness within a
bound" this module adds.

The suite is  P · M · W :
  P  transition cover     = state_cover ∪ state_cover·Σ  — reach every hypothesis state, and
                            take every one-step extension of every state
  M  middle sequences     = Σ^0 ∪ Σ^1 ∪ … ∪ Σ^{extra_states}  — the guard for up to
                            `extra_states` states the hypothesis has not yet split out
  W  characterization set = input words that tell every pair of distinct hypothesis states
                            apart by their output

Each test word is run on both the hypothesis and the SUL; the first position at which their
OUTPUT TRACES differ yields a minimal counterexample (the prefix up to and including that
position), directly usable by L* — its last output differs there. Comparing full traces (not
just the last symbol) means a distinguishing output at any interior position is still caught.
"""
from __future__ import annotations

from collections import deque
from typing import Callable, Iterator, Optional

Word = tuple


# --- hypothesis-side helpers ------------------------------------------------
def _hyp_trace(hyp, state: str, word: Word) -> tuple:
    """The output trace produced by running `word` from `state` of the hypothesis."""
    s, outs = state, []
    for a in word:
        s, o = hyp.trans[(s, a)]
        outs.append(o)
    return tuple(outs)


def _dedupe(words) -> list:
    seen, out = set(), []
    for w in words:
        w = tuple(w)
        if w not in seen:
            seen.add(w)
            out.append(w)
    return out


def state_cover(hyp) -> list:
    """One shortest access word per reachable hypothesis state (ε first) — a BFS spanning
    tree over the transition function."""
    access = {hyp.initial: ()}
    order = [()]
    q = deque([hyp.initial])
    while q:
        s = q.popleft()
        for a in hyp.alphabet:
            ns, _ = hyp.trans[(s, a)]
            if ns not in access:
                access[ns] = access[s] + (a,)
                order.append(access[ns])
                q.append(ns)
    return order


def transition_cover(hyp) -> list:
    """State cover, plus every one-step extension of every covered state."""
    sc = state_cover(hyp)
    cover = list(sc)
    for acc in sc:
        for a in hyp.alphabet:
            cover.append(acc + (a,))
    return _dedupe(cover)


def _distinguish(hyp, s: str, t: str) -> Optional[Word]:
    """Shortest input word whose output differs when run from states `s` vs `t`
    (a product-BFS over state pairs)."""
    q = deque([(s, t, ())])
    seen = {(s, t)}
    while q:
        p, r, path = q.popleft()
        for a in hyp.alphabet:
            np_, op = hyp.trans[(p, a)]
            nr, orr = hyp.trans[(r, a)]
            if op != orr:
                return path + (a,)
            key = (np_, nr)
            if key not in seen:
                seen.add(key)
                q.append((np_, nr, path + (a,)))
    return None


def characterization_set(hyp) -> list:
    """A set W that separates every pair of distinct hypothesis states: for each pair not yet
    told apart by some word already in W, add a shortest distinguishing word."""
    states = list(hyp.states)
    W: list = []

    def separated(s: str, t: str) -> bool:
        return any(_hyp_trace(hyp, s, w) != _hyp_trace(hyp, t, w) for w in W)

    for i in range(len(states)):
        for j in range(i + 1, len(states)):
            s, t = states[i], states[j]
            if separated(s, t):
                continue
            w = _distinguish(hyp, s, t)
            if w and w not in W:
                W.append(w)
    if not W:                                  # single-state hypothesis: probe each symbol
        W = [(a,) for a in hyp.alphabet]
    return W


def _middles(alphabet, extra_states: int) -> list:
    """Σ^0 ∪ … ∪ Σ^{extra_states}."""
    out = [()]
    cur = [()]
    for _ in range(max(0, extra_states)):
        cur = [m + (a,) for m in cur for a in alphabet]
        out.extend(cur)
    return out


def w_method_suite(hyp, extra_states: int = 0) -> Iterator[Word]:
    """Yield every distinct, non-empty test word of the P · M · W suite."""
    P = transition_cover(hyp)
    W = characterization_set(hyp)
    M = _middles(hyp.alphabet, extra_states)
    seen: set = set()
    for p in P:
        for m in M:
            for w in W:
                t = tuple(p) + tuple(m) + tuple(w)
                if t and t not in seen:
                    seen.add(t)
                    yield t


def sul_trace_factory(sul) -> Callable[[Word], list]:
    """A cached full-output-trace function over a (deterministic) SUL: reset, then step the
    whole word, collecting the output at each step. Caching is valid because the SUL is
    deterministic and reset for every query; it is shared across learning rounds."""
    cache: dict = {}

    def trace(word: Word) -> list:
        word = tuple(word)
        if word not in cache:
            sul.reset()
            cache[word] = [sul.step(a) for a in word]
        return cache[word]

    return trace


def find_counterexample(hyp, sul, extra_states: int = 0,
                        trace_fn: Optional[Callable[[Word], list]] = None) -> Optional[Word]:
    """Run the W-method suite against `sul` and return the first (minimal) counterexample —
    the prefix up to and including the first position where the output traces differ — or
    None if the hypothesis conforms within the `extra_states` bound."""
    trace = trace_fn or sul_trace_factory(sul)
    for t in w_method_suite(hyp, extra_states):
        h = _hyp_trace(hyp, hyp.initial, t)
        s = trace(t)
        for i in range(min(len(h), len(s))):
            if h[i] != s[i]:
                return t[:i + 1]
        if len(h) != len(s):                   # a partial machine diverged in length
            return t
    return None
