"""The scope matrix — consent as a provenance level (TPI-6 at the token layer).

A token carries the scopes its user consented to. If a resource serves data the token was
never granted, consent is decorative: a client approved for `openid` alone reads the
birthday, the wallet, the wishlist. TPI-6 says a privileged action must not accept
provenance below the level its own flow demands, and a scope is exactly such a level.

The matrix is scope-set x resource. What makes it work is the **field witness**, and that
is not a detail — it is the whole mode:

    "served" means the specific field this scope governs came back.
    NOT "HTTP 200", and NOT "the account id appeared somewhere in the response".

Both weaker predicates were tried live and both said "scope not enforced" about a surface
that enforces it correctly:

  * `openid` legitimately grants the subject identifier, so an id in the body means only
    that the token worked at all;
  * an error body commonly echoes the request URL, and on this surface that URL *contains*
    the account id — so a 403 refusing the request scored as a disclosure.

So a `Resource` must name the field whose disclosure requires the scope, and a cell counts
as served only when that field is present. Nothing here performs I/O: the caller supplies
`fetch`.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Served(str, Enum):
    SERVED = "served"              # the governed field came back
    REFUSED = "refused"            # denied, as an under-scoped request should be
    ABSENT = "absent"              # request succeeded but the governed field was withheld
    INCONCLUSIVE = "inconclusive"  # no verdict; never evidence of a disclosure


@dataclass(frozen=True)
class ScopeSet:
    id: str
    scopes: frozenset

    @staticmethod
    def of(id: str, scopes: str) -> "ScopeSet":
        return ScopeSet(id, frozenset(scopes.split()))


@dataclass(frozen=True)
class Resource:
    """A resource, and the field whose disclosure the scope is supposed to gate."""
    id: str
    requires: str          # the scope that governs `witness_field`
    witness_field: str     # the field that must be absent without `requires`


@dataclass
class Cell:
    scope_set: ScopeSet
    resource: Resource
    served: Served
    evidence: str = ""


@dataclass
class ScopeFinding:
    clause_id: str
    detail: str

    def render(self) -> str:
        return f"{self.clause_id} (scope not enforced)\n    {self.detail}"


@dataclass
class ScopeResult:
    cells: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    withheld: list = field(default_factory=list)

    def render(self) -> str:
        w = max([len(c.scope_set.id) for c in self.cells] + [9])
        out = [f"{'scope set'.ljust(w)}  {'resource':<18} {'result':<14} evidence"]
        for c in self.cells:
            out.append(f"{c.scope_set.id.ljust(w)}  {c.resource.id:<18} "
                       f"{c.served.value:<14} {c.evidence[:56]}")
        for f in self.findings:
            out.append("\n" + f.render())
        for n in self.withheld:
            out.append(f"\n[withheld] {n}")
        if not self.findings and not self.withheld:
            out.append("\nno finding: every resource withheld what its scope governs")
        return "\n".join(out)


def run_scope_matrix(scope_sets: list, resources: list,
                     fetch: Callable[[ScopeSet, Resource], object],
                     full: Optional[ScopeSet] = None,
                     never_valid: Optional[ScopeSet] = None) -> ScopeResult:
    """`fetch(scope_set, resource) -> Presentation-like` with `.served` and `.evidence`.

    `full` is the scope set granted everything: its cell is the positive control. If it
    does not obtain the governed field, the resource is excluded — a 404 or a moved
    endpoint would otherwise read as perfect enforcement.
    """
    res = ScopeResult()
    full = full or (scope_sets[0] if scope_sets else None)

    def _fetch(ss, r):
        try:
            return fetch(ss, r)
        except Exception as exc:
            class _E:
                served = Served.INCONCLUSIVE
                evidence = f"{type(exc).__name__}: {exc}"
            return _E()

    usable = {}
    for r in resources:
        ctl = _fetch(full, r)
        usable[r.id] = ctl.served is Served.SERVED
        if not usable[r.id]:
            res.withheld.append(
                f"'{r.id}': the fully-scoped token did not obtain '{r.witness_field}' "
                f"({ctl.evidence}) — the resource is gone or changed shape, so a refusal "
                f"for a narrower scope shows nothing")
        if never_valid is not None:
            neg = _fetch(never_valid, r)
            if neg.served is Served.SERVED:
                usable[r.id] = False
                res.findings.append(ScopeFinding(
                    "SCOPE-0", f"'{r.id}' served '{r.witness_field}' to a never-valid "
                               f"credential — it is not authenticating at all, which "
                               f"subsumes every scope question here"))

    for ss in scope_sets:
        for r in resources:
            out = _fetch(ss, r)
            res.cells.append(Cell(ss, r, out.served, getattr(out, "evidence", "")))

    for c in res.cells:
        r = c.resource
        if not usable.get(r.id) or c.served is not Served.SERVED:
            continue
        if r.requires in c.scope_set.scopes:
            continue                                  # entitled to it
        res.findings.append(ScopeFinding(
            "TPI-6", f"'{r.id}' returned '{r.witness_field}' to a token granted "
                     f"{sorted(c.scope_set.scopes)}, which does not include "
                     f"'{r.requires}' — consent is not being enforced"))
    return res
