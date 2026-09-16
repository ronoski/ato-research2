"""The Trust-Provenance Integrity clause catalog.

These are the operational form of Invariant TPI from the paper. A verdict cites
one, so a detected takeover *names the invariant it broke* rather than reporting
a bare "ATO". The three failure modes (gap / forgery / laundering) are the whole
surface over which `justifies(prov(B), B)` can be negated (Fig. 3).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FailureMode(str, Enum):
    GAP = "gap"                 # a binding with no proof at all
    FORGERY = "forgery"         # a proof of the wrong resource
    LAUNDERING = "laundering"   # a weaker / older / other-principal fact upgraded


@dataclass(frozen=True)
class Clause:
    id: str
    title: str
    statement: str
    mode: FailureMode


CLAUSES: dict[str, Clause] = {
    "TPI-1": Clause(
        "TPI-1", "revoke-on-rebind",
        "An identity-mutating transition (email/phone change, verification, or "
        "account merge) must re-assert justification for every binding on the "
        "row and revoke those it can no longer justify.",
        FailureMode.LAUNDERING),
    "TPI-2": Clause(
        "TPI-2", "proof-pinned-to-resource",
        "A proof event justifies a binding only if it demonstrates control of "
        "exactly the resource the binding privileges — same identifier, same "
        "account.",
        FailureMode.FORGERY),
    "TPI-3": Clause(
        "TPI-3", "no-upgrade-off-claimed",
        "A binding may not be raised to 'verified' on the strength of an "
        "unproven ('claimed') fact.",
        FailureMode.LAUNDERING),
    "TPI-4": Clause(
        "TPI-4", "session-kill-on-credential-change",
        "A credential change or password reset must invalidate every session "
        "and outstanding token whose provenance predates it.",
        FailureMode.LAUNDERING),
    "TPI-6": Clause(
        "TPI-6", "step-up-not-bypassable",
        "A privileged action must not accept provenance below the session level "
        "its own flow demands. If any flow refuses a credential as insufficient "
        "for a transition, every flow reaching that transition must refuse it.",
        FailureMode.GAP),
    "TPI-5": Clause(
        "TPI-5", "authenticated-transition",
        "A privileged action must carry provenance empowering the acting "
        "principal for the target resource (no provenance gap).",
        FailureMode.GAP),
}
