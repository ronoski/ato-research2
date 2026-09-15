"""Angluin's L* for Mealy machines, with a W-method (or random-walk) equivalence oracle.

Learns the deterministic Mealy machine a SUL implements from:
  * membership queries  — run a word from reset, observe the last output;
  * equivalence queries — by default the **W-method** conformance oracle (`wmethod.py`):
    a finite test suite that *certifies* the hypothesis against the true machine up to a
    state bound (n + `extra_states`), so the learned machine is sound within that bound —
    unlike the random-walk oracle (`eq_method="random"`), which only samples and can miss
    states. The random walk is kept as a cheaper, unsound fallback.

This is the active-learning core of the black-box track. The recovered machine is
the *implemented* auth state machine; diffing it against the intended one, or
handing its alphabet to the enumerator, is what makes the hunt run on real
behaviour instead of an assumed action set.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

Word = tuple


@dataclass
class Mealy:
    states: list[str]
    initial: str
    trans: dict            # (state, input) -> (next_state, output)
    alphabet: list[str]
    access: dict = field(default_factory=dict)   # state -> access word

    def run(self, word) -> Optional[str]:
        s, out = self.initial, None
        for a in word:
            s, out = self.trans[(s, a)]
        return out


class LStar:
    def __init__(self, sul, seed: int = 0, eq_tests: int = 500, eq_maxlen: int = 14,
                 eq_method: str = "wmethod", extra_states: int = 2) -> None:
        self.sul = sul
        self.Sigma = list(sul.alphabet)
        self.S: list[Word] = [()]                       # access prefixes (ordered, ε first)
        self.E: list[Word] = [(a,) for a in self.Sigma]  # distinguishing suffixes
        self.T: dict[Word, str] = {}                    # memoized last-output per word
        self.rng = random.Random(seed)
        self.eq_tests = eq_tests
        self.eq_maxlen = eq_maxlen
        # equivalence oracle: "wmethod" (conformance-tested, sound up to n+extra_states states)
        # or "random" (random-walk sampling, unsound). extra_states is the W-method state margin.
        self.eq_method = eq_method
        self.extra_states = extra_states
        self.mq_count = 0
        self.eq_count = 0                               # conformance queries the eq-oracle made
        # a full-output-trace function over the SUL, cached across rounds (W-method only)
        self._trace_fn = None

    # --- queries -------------------------------------------------------------
    def _mq(self, word: Word) -> str:
        if word in self.T:
            return self.T[word]
        self.sul.reset()
        out = "-"
        for a in word:
            out = self.sul.step(a)
        self.mq_count += 1
        self.T[word] = out
        return out

    def _cell(self, u: Word, e: Word) -> str:
        return self._mq(tuple(u) + tuple(e))

    def _row(self, u: Word) -> Word:
        return tuple(self._cell(u, e) for e in self.E)

    @staticmethod
    def _add_unique(seq: list, item) -> None:
        if item not in seq:
            seq.append(item)

    # --- closure / consistency ----------------------------------------------
    def _closed(self) -> Optional[Word]:
        rows_S = {self._row(s) for s in self.S}
        for s in self.S:
            for a in self.Sigma:
                ua = tuple(s) + (a,)
                if self._row(ua) not in rows_S:
                    return ua
        return None

    def _consistent(self) -> Optional[Word]:
        for i in range(len(self.S)):
            for j in range(i + 1, len(self.S)):
                if self._row(self.S[i]) != self._row(self.S[j]):
                    continue
                for a in self.Sigma:
                    si, sj = tuple(self.S[i]) + (a,), tuple(self.S[j]) + (a,)
                    for e in self.E:
                        if self._cell(si, e) != self._cell(sj, e):
                            return (a,) + e
        return None

    # --- hypothesis ----------------------------------------------------------
    def _build(self) -> Mealy:
        rows: dict[Word, Word] = {}
        for s in self.S:                       # first access word wins (ε first -> s0)
            rows.setdefault(self._row(s), s)
        name = {r: f"s{i}" for i, r in enumerate(rows)}
        access = {name[r]: rows[r] for r in rows}
        trans = {}
        for r, acc in rows.items():
            for a in self.Sigma:
                trans[(name[r], a)] = (name[self._row(tuple(acc) + (a,))], self._cell(acc, (a,)))
        return Mealy(list(name.values()), name[self._row(())], trans, list(self.Sigma), access)

    def _find_counterexample(self, hyp: Mealy) -> Optional[Word]:
        if self.eq_method == "wmethod":
            return self._find_counterexample_wmethod(hyp)
        for _ in range(self.eq_tests):
            length = self.rng.randint(1, self.eq_maxlen)
            word = tuple(self.rng.choice(self.Sigma) for _ in range(length))
            if hyp.run(word) != self._mq(word):
                return word
        return None

    def _find_counterexample_wmethod(self, hyp: Mealy) -> Optional[Word]:
        from . import wmethod
        if self._trace_fn is None:                     # shared cache across rounds
            base = wmethod.sul_trace_factory(self.sul)

            def counted(word):
                self.eq_count += 1
                return base(word)

            self._trace_fn = counted
        return wmethod.find_counterexample(hyp, self.sul, extra_states=self.extra_states,
                                           trace_fn=self._trace_fn)

    def learn(self, max_rounds: int = 100) -> Mealy:
        for _ in range(max_rounds):
            while True:
                ua = self._closed()
                if ua is not None:
                    self._add_unique(self.S, ua)
                    continue
                e = self._consistent()
                if e is not None:
                    self._add_unique(self.E, e)
                    continue
                break
            hyp = self._build()
            ce = self._find_counterexample(hyp)
            if ce is None:
                return hyp
            for i in range(1, len(ce) + 1):    # add all prefixes of the counterexample
                self._add_unique(self.S, ce[:i])
        return self._build()
