"""The step-up matrix — TPI-6 measured across live flows.

Sibling to `stepup.py`, which models the same clause *inside the state machine*: partial
sessions, a multi-phase login, and a recovery flow that accepts an intermediate credential
the login flow refuses. That one needs a modelled target. This one needs only a session
and a list of URLs, which is what you have on a live engagement at 17:00.

`matrix.py` asks, over time: does a mutation revoke the bindings that predate it?
This asks the sibling question, across flows, at one instant:

    for each privileged transition T,
    what provenance does the surface demand before it will perform T?

TPI-6: *"If any flow refuses a credential as insufficient for a transition, every flow
reaching that transition must refuse it."* So the bug is never "T needs no step-up" on
its own — it is two transitions of **equal privilege** disagreeing. A surface that
re-authenticates before a password change and does not before enrolling a new passkey
has not made a policy choice; it has left a flow behind. Whoever holds a session cookie
takes the flow that does not ask.

Found live: on one aged session, `/login_id/edit` and `/login_method` answered `302
/reauthenticate` while `/passkey`, `/2fa/authenticator` and `/phone_number` rendered
their mutation forms directly. Every one of those changes *who can authenticate as this
account*, which is what makes them comparable at all.

Five controls, because the naive version of this mode is a false-positive generator —
and the fifth was learned the hard way, by this mode producing a false positive on its
first live run. `/passkey` rendered its page on an aged session while `/login_id/edit`
answered `302 /reauthenticate`, which looked exactly like the clause being broken. It was
not. `/passkey` is an *index*: its primary control points at `/passkey/register`, and that
route redirects to re-authentication like the others. An index page compared against a
mutation route manufactures an asymmetry out of nothing.

  * **Liveness (positive).** A logged-out page also shows no password prompt. So a
    reading counts only if the response carried a value that only an authenticated view
    of *this* principal shows. Absence of a step-up is not evidence; presence of the
    principal is. This is the control that makes the mode sound.
  * **Age.** A session minted a minute ago may legitimately skip step-up — most surfaces
    run a freshness window. A verdict is refused below `min_age`, so the finding is about
    the provenance level, not about being freshly logged in.
  * **Equal privilege.** Transitions are compared only inside a declared class. Without
    it the mode "discovers" that editing a nickname needs less proof than changing a
    password, which is not a bug and is not what the clause says.
  * **Conclusiveness.** An asymmetry needs at least one refusal and one acceptance, all
    conclusive. Errors and unknowns never become evidence of an absence.
  * **Route kind.** Only a route that *performs* the mutation may be compared. A page that
    merely links to one proves nothing by rendering, and the config blob that names these
    URIs does not distinguish the two — so the caller must, and an unmarked route is
    excluded rather than assumed.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .clauses import CLAUSES

# A privileged transition is worth comparing only against ones that move the same
# capability. `LOGIN_CREDENTIAL` is the class that matters for takeover: every member
# changes who can authenticate as the account.
LOGIN_CREDENTIAL = "login-credential"
RECOVERY_CHANNEL = "recovery-channel"
ACCOUNT_LIFECYCLE = "account-lifecycle"
PROFILE_DATA = "profile-data"

DEFAULT_MIN_AGE = 900.0          # 15 minutes; below this a freshness window explains it


class Kind(str, Enum):
    """Whether a route performs the mutation or only links to it."""
    MUTATION = "mutation"     # the route that performs the change — the only comparable kind
    INDEX = "index"           # a page listing the capability; rendering proves nothing
    UNKNOWN = "unknown"       # not established — excluded, never assumed


class Level(str, Enum):
    DEMANDED = "demanded"            # the surface refused this provenance and asked for more
    NOT_DEMANDED = "not-demanded"    # the surface performed/offered the transition as-is
    INCONCLUSIVE = "inconclusive"    # could not tell — never evidence of an absence


@dataclass(frozen=True)
class Transition:
    """One privileged action, tagged with the capability class it moves."""
    id: str
    label: str
    privilege: str
    note: str = ""
    kind: Kind = Kind.UNKNOWN


@dataclass
class Reading:
    """What a probe observed for one transition. `principal_seen` is the positive control."""
    level: Level
    evidence: str
    principal_seen: bool = False


@dataclass
class Cell:
    transition: Transition
    level: Level
    evidence: str
    withheld: Optional[str] = None

    @property
    def conclusive(self) -> bool:
        return self.level is not Level.INCONCLUSIVE


@dataclass
class Asymmetry:
    """Two equally-privileged transitions disagreeing about required provenance."""
    privilege: str
    demanded: list
    accepted: list
    session_age: float
    clause_id: str = "TPI-6"

    def render(self) -> str:
        c = CLAUSES.get(self.clause_id)
        return (f"{self.clause_id} ({c.title if c else '?'}) in class '{self.privilege}', "
                f"session age {int(self.session_age)}s\n"
                f"    refuses this provenance : {', '.join(self.demanded)}\n"
                f"    accepts it              : {', '.join(self.accepted)}\n"
                f"    -> the same capability is reachable through a flow that asks for less")


@dataclass
class StepUpResult:
    cells: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    withheld: list = field(default_factory=list)

    def render(self) -> str:
        w = max([len(c.transition.id) for c in self.cells] + [10])
        out = [f"{'transition'.ljust(w)}  {'privilege':<18} {'step-up':<14} evidence"]
        for c in sorted(self.cells, key=lambda x: (x.transition.privilege, x.transition.id)):
            out.append(f"{c.transition.id.ljust(w)}  {c.transition.privilege:<18} "
                       f"{c.level.value:<14} {c.evidence[:60]}")
        for f in self.findings:
            out.append("\n" + f.render())
        for note in self.withheld:
            out.append(f"\n[withheld] {note}")
        if not self.findings and not self.withheld:
            out.append("\nno asymmetry: every conclusive transition in each class agrees")
        return "\n".join(out)


def run_stepup(transitions: list, probe: Callable[[Transition], Reading],
               session_age: float, min_age: float = DEFAULT_MIN_AGE) -> StepUpResult:
    """Read each transition's demanded provenance and report same-class disagreement."""
    res = StepUpResult()
    for t in transitions:
        try:
            r = probe(t)
        except Exception as exc:                       # a probe that blew up proves nothing
            res.cells.append(Cell(t, Level.INCONCLUSIVE, f"probe raised {type(exc).__name__}: {exc}"))
            continue
        if not r.principal_seen and r.level is Level.NOT_DEMANDED:
            # The control that stops the mode lying: a logged-out page demands no step-up
            # either, and would otherwise read as the most exploitable cell on the board.
            res.cells.append(Cell(t, Level.INCONCLUSIVE, r.evidence,
                                  withheld="no authenticated marker for this principal — "
                                           "'no step-up' is indistinguishable from 'logged out'"))
            continue
        res.cells.append(Cell(t, r.level, r.evidence))

    for note in {c.withheld for c in res.cells if c.withheld}:
        res.withheld.append(note)

    if session_age < min_age:
        res.withheld.append(
            f"session is {int(session_age)}s old (< {int(min_age)}s): a freshness window "
            f"would explain any asymmetry, so no TPI-6 verdict is issued")
        return res

    # Only an excluded route that ACCEPTED needs explaining: that is the one that would
    # have manufactured a false asymmetry. An index that refuses adds nothing either way.
    skipped = sorted({c.transition.id for c in res.cells
                      if c.conclusive and c.transition.kind is not Kind.MUTATION
                      and c.level is Level.NOT_DEMANDED})
    if skipped:
        res.withheld.append(
            f"excluded from comparison (not established as mutation routes): {', '.join(skipped)} "
            f"— an index page proves nothing by rendering; probe the route its primary control targets")

    classes: dict = {}
    for c in res.cells:
        if c.conclusive and c.transition.kind is Kind.MUTATION:
            classes.setdefault(c.transition.privilege, []).append(c)
    for priv, cells in sorted(classes.items()):
        dem = [c.transition.id for c in cells if c.level is Level.DEMANDED]
        acc = [c.transition.id for c in cells if c.level is Level.NOT_DEMANDED]
        if dem and acc:
            res.findings.append(Asymmetry(priv, sorted(dem), sorted(acc), session_age))
    return res


def nintendo_account_transitions() -> list:
    """The account-surface transitions recovered from the authenticated page's own config.

    A worked example of both tags that make the mode sound. `privilege` says what may be
    compared with what; `kind` says whether the route is even a transition. The config blob
    hands over `passkey` and `2fa/authenticator`, but those are index pages — the routes
    that mutate are one link deeper, and marking them MUTATION on the strength of the
    config alone is how this mode produced its first false positive.
    """
    L = LOGIN_CREDENTIAL
    M, I = Kind.MUTATION, Kind.INDEX
    return [
        Transition("password/edit", "change password", L, kind=M),
        Transition("login_id/edit", "change login id", L, kind=M),
        Transition("login_method", "change login method", L, kind=M),
        Transition("email/edit", "rebind email", L, "email owns the reset flow", kind=M),
        Transition("passkey/register", "enrol a passkey", L,
                   "a resident passkey logs in on its own", kind=M),
        Transition("passkey", "passkey list", L, "index only — links to passkey/register", kind=I),
        Transition("2fa/authenticator", "TOTP settings", L, "index only", kind=I),
        Transition("phone_number", "phone settings", RECOVERY_CHANNEL, "index only", kind=I),
        Transition("withdraw/confirm", "delete account", ACCOUNT_LIFECYCLE, kind=M),
        Transition("profile/edit", "edit profile", PROFILE_DATA, kind=M),
    ]
