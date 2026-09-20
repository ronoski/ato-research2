"""The authority matrix — the target's own capability flags as the oracle.

Most modes have to argue about what *should* happen. This one does not, because the
surface says so itself. Rendering a family member's page, the server ships its own verdict
next to the links it is describing:

    canSeeFamilyMemberLoginHistory: false     familyMemberLoginHistoryActionUri: .../login_history
    canTransferAdmin:               false     familyTransferAdminRequestFormActionUri: ...
    canChangeChildProfileOfMember:  false     familyChildProfileEditFormActionUri: ...

Those flags exist to hide buttons. The question is whether the server that computed them
also *enforces* them, or whether they were only advice to the client. A flag reading false
beside a route that serves is a declared-versus-enforced mismatch — the clearest form of
object-level authorization failure, and one where the target has already told you the
expected result, so there is nothing to argue about.

The direction matters. `granted=false` + SERVED is a finding. `granted=true` + REFUSED is
not: that is a surface being stricter than its own UI, which is a bug report for someone
else.

Three controls, because the failure modes here are all about the session, not the routes:

  * **Positive.** At least one route whose flag is `true` must actually serve. Otherwise
    the session is dead, every route refuses, and the clean sweep is meaningless.
  * **Bystander.** The same route addressed to a principal with no relationship to the
    actor must be refused. Without it you cannot tell "scoped to this relationship" from
    "not scoped at all" — and those have very different severities.
  * **Conclusiveness.** A timeout is not a refusal. Routes that never answered stay
    inconclusive and are listed, so a sweep that silently lost half its probes cannot read
    as a pass.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Outcome(str, Enum):
    SERVED = "served"              # the route answered with the thing it governs
    REFUSED = "refused"            # denied, as a false flag says it should be
    INCONCLUSIVE = "inconclusive"  # no answer; never evidence of enforcement


@dataclass(frozen=True)
class Capability:
    """A capability the server declared, and the route it governs.

    `subject` is the principal the route addresses, and it is what makes a bystander test
    well defined. A route like `/family/members/me` names no one, so substituting an
    unrelated principal into it is impossible — and a bystander probe that silently fails
    to substitute just re-fetches the actor's OWN resource, which serves, and reads as
    "this route is not scoped at all". That false AUTHZ-1 fired on the first live run.
    """
    flag: str
    granted: bool
    route: str
    label: str = ""
    subject: Optional[str] = None


@dataclass
class Cell:
    capability: Capability
    outcome: Outcome
    evidence: str = ""

    @property
    def mismatch(self) -> bool:
        return (not self.capability.granted) and self.outcome is Outcome.SERVED


@dataclass
class AuthorityFinding:
    clause_id: str
    detail: str

    def render(self) -> str:
        return f"{self.clause_id} (declared authority not enforced)\n    {self.detail}"


@dataclass
class AuthorityResult:
    cells: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    withheld: list = field(default_factory=list)
    enforced: list = field(default_factory=list)

    def render(self) -> str:
        w = max([len(c.capability.flag) for c in self.cells] + [12])
        out = [f"{'declared flag'.ljust(w)}  {'granted':<8} {'outcome':<14} route"]
        for c in sorted(self.cells, key=lambda x: x.capability.flag):
            out.append(f"{c.capability.flag.ljust(w)}  {str(c.capability.granted):<8} "
                       f"{c.outcome.value:<14} {c.capability.route[:48]}")
        for f in self.findings:
            out.append("\n" + f.render())
        for n in self.enforced:
            out.append(f"\n[enforced] {n}")
        for n in self.withheld:
            out.append(f"\n[withheld] {n}")
        return "\n".join(out)


def run_authority_matrix(capabilities: list,
                         probe: Callable[[Capability], object],
                         bystander: Optional[Callable[[Capability], object]] = None
                         ) -> AuthorityResult:
    """`probe(capability) -> object with .outcome and .evidence`.

    `bystander` runs the same route against a principal that has no relationship to the
    actor at all; it separates "scoped to this relationship" from "not scoped".
    """
    res = AuthorityResult()

    def _run(fn, cap):
        try:
            return fn(cap)
        except Exception as exc:
            class _E:
                outcome = Outcome.INCONCLUSIVE
                evidence = f"{type(exc).__name__}: {exc}"
            return _E()

    for cap in capabilities:
        out = _run(probe, cap)
        res.cells.append(Cell(cap, out.outcome, getattr(out, "evidence", "")))

    granted_served = [c for c in res.cells if c.capability.granted and c.outcome is Outcome.SERVED]
    if not granted_served:
        res.withheld.append(
            "no route whose flag is `true` actually served — the session may simply be "
            "dead, in which case every refusal below is meaningless")

    unread = [c.capability.flag for c in res.cells if c.outcome is Outcome.INCONCLUSIVE]
    if unread:
        res.withheld.append(
            f"never answered, so not evidence of enforcement: {', '.join(sorted(unread))}")

    if granted_served:
        for c in res.cells:
            if c.mismatch:
                res.findings.append(AuthorityFinding(
                    "AUTHZ-1",
                    f"the surface declared '{c.capability.flag}' = false and then served "
                    f"'{c.capability.route}' anyway ({c.evidence}). The check that computed "
                    f"the flag is not the check that guards the route."))

    if bystander is not None:
        skipped = [c.flag for c in capabilities
                   if not (c.subject and c.subject in c.route)]
        if skipped:
            res.withheld.append(
                f"no bystander probe possible for {', '.join(sorted(skipped))}: the route "
                f"does not address a named subject, so an unrelated principal cannot be "
                f"substituted into it")
        for cap in capabilities:
            if not (cap.subject and cap.subject in cap.route):
                continue
            out = _run(bystander, cap)
            if out.outcome is Outcome.SERVED:
                res.findings.append(AuthorityFinding(
                    "AUTHZ-1",
                    f"'{cap.route}' served a principal with no relationship to the actor "
                    f"({getattr(out, 'evidence', '')}) — the route is not scoped at all, "
                    f"which subsumes any question about {cap.flag}"))

    refused = [c.capability.flag for c in res.cells
               if not c.capability.granted and c.outcome is Outcome.REFUSED]
    if granted_served and refused and not res.findings:
        res.enforced.append(
            f"every flag declared false was refused at its own route "
            f"({len(refused)} of them), while a granted route served — declared authority "
            f"matches enforced authority here")
    return res
