"""Semantic dedup: collapse near-duplicate findings to the distinct bugs.

The enumerator over-generates on purpose — it explores every interleaving and every
padding of the action pool, so one real bug shows up as dozens of findings that
differ only in irrelevant order or extra steps. A hunter wants the *distinct* bugs,
each with a minimal repro, not 106 variants of two.

Two steps, both driven by the authoritative oracle verdict (never by the
enumerator's guess):

  1. Causal minimization (delta debugging). Greedily drop steps from a fired probe
     as long as the verdict stays a takeover *of the same clause*. What survives is
     the causal core — the minimal repro. This strips padding (a stray reset_request
     in a TPI-1 finding) and redundant seeds (a login on top of a register).

  2. Causal signature. Two minimal cores are the same bug iff they violate the same
     clause via the same multiset of (role, effect) events — e.g. TPI-1 is always
     "attacker SEED + victim RAISE", regardless of which concrete seed or how the
     independent steps interleave. Findings are grouped by that signature.

Dedup is decoupled from the target: pass a `verdict_fn(plan) -> Verdict` that runs a
plan against the (vulnerable) system and returns the oracle's verdict.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from .enumerator import ACTIONS, ActionSpec, Candidate, build_plan, is_wellformed
from .harness import Plan
from .types import Principal

VerdictFn = Callable[[Plan], object]   # plan -> Verdict (has .severity.value, .clause_id, .laundered_proof)

Merged = tuple  # tuple[tuple[str, str], ...] of (role, action)


@dataclass
class Cluster:
    """One distinct bug: a set of enumerator findings that share a causal signature."""
    clause_id: Optional[str]
    signature: tuple
    representative: list                      # minimal (role, action) repro
    laundered_proof: Optional[str] = None
    members: list = field(default_factory=list)   # the raw Candidates collapsed here

    @property
    def size(self) -> int:
        return len(self.members)

    def render(self) -> str:
        return "  ->  ".join(f"{role}:{action}" for role, action in self.representative)


def _takeover_of(v, clause_id: Optional[str]) -> bool:
    return getattr(v, "severity", None) is not None \
        and v.severity.value == "takeover" and v.clause_id == clause_id


def minimize(merged: Merged, clause_id: Optional[str], attacker: Principal,
             victim: Principal, email: str, specs: dict[str, ActionSpec],
             verdict_fn: VerdictFn) -> list:
    """Shrink `merged` to a causal core that still yields a takeover of `clause_id`.
    Standard 1-minimal delta debugging: remove one step at a time, restart on success."""
    current = list(merged)
    changed = True
    while changed:
        changed = False
        for i in range(len(current)):
            trial = current[:i] + current[i + 1:]
            if not trial or not is_wellformed(tuple(trial), specs):
                continue
            v = verdict_fn(build_plan(tuple(trial), attacker, victim, email, specs))
            if _takeover_of(v, clause_id):
                current = trial
                changed = True
                break
    return current


def _signature(min_merged: list, specs: dict[str, ActionSpec], clause_id: Optional[str]) -> tuple:
    """The causal identity: clause + the SET of effect-classes causally present in the
    minimal core. Deliberately abstracts away role, count, and interleaving:

      * the clause (from the oracle's diagnosis) already encodes the who/what — e.g.
        an attacker-consumed credential is TPI-2, a victim-consumed one TPI-4 — so
        re-encoding role here only splits one bug into its exploitation paths;
      * a REQUEST is a setup sub-step of a CRED, and who initiates it is incidental;
      * count and order are exploitation detail, not bug identity.

    So "attacker seeds, victim raises" is one TPI-1 bug however it interleaves, and a
    session surviving a reset is one TPI-4 bug whoever requested the reset.

    The one endpoint distinction kept: the *trigger* actions (effect raise/cred — the
    laundering step), so a bug via `sso_login` and one via a synthesized `magic_link`
    are separate findings (different flows to fix), while padding/order variants of each
    still merge. The minimal repro kept on the cluster shows one concrete path."""
    effects = frozenset(specs[a].effect.value for _role, a in min_merged)
    triggers = frozenset(a for _role, a in min_merged
                         if specs[a].effect.value in ("raise", "cred"))
    return (clause_id, effects, triggers)


def deduplicate(cands: list[Candidate], attacker: Principal, victim: Principal,
                email: str, verdict_fn: VerdictFn,
                specs: Optional[dict[str, ActionSpec]] = None) -> list[Cluster]:
    """Group fired candidates into distinct bugs, each with a minimal repro."""
    specs = specs if specs is not None else ACTIONS
    clusters: dict[tuple, Cluster] = {}
    for c in cands:
        v = verdict_fn(c.plan)
        if getattr(v, "severity", None) is None or v.severity.value != "takeover":
            continue
        clause = v.clause_id
        core = minimize(tuple(c.merged), clause, attacker, victim, email, specs, verdict_fn)
        sig = _signature(core, specs, clause)
        cl = clusters.get(sig)
        if cl is None:
            clusters[sig] = Cluster(clause_id=clause, signature=sig, representative=list(core),
                                    laundered_proof=getattr(v, "laundered_proof", None),
                                    members=[c])
        else:
            cl.members.append(c)
            if len(core) < len(cl.representative):   # keep the shortest repro seen
                cl.representative = list(core)
    out = list(clusters.values())
    out.sort(key=lambda k: (k.clause_id or "~", -k.size))
    return out
