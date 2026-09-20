"""The revocation matrix — a second hunting mode, built on the paper's core thesis.

The oracle in `oracle.py` hunts *confluence*: two principals, does the attacker read
the victim's data. That is the pre-hijacking shape. But the sharpest expression of
Composition-Blindness is a different, single-principal, over-time question:

    for each binding B minted before a credential-mutating transition M,
    does M revoke B?

A binding that survives a mutation that should have killed it is TPI-4 laundering —
the stolen session that outlives the owner's logout, the reset token that works after
the row was rebound. This is exactly the matrix that proved to be the valuable artifact
against a real engagement (see `~/singularity/grab/ato/TPI_LENS.md`): mutation × predating
binding, each cell a measured `revoked | survived`.

Two properties make this mode matter:

  * **Single-principal, own-account, reversible.** Mint B on an account you own, capture
    it, perform the mutation, re-present B. No second principal, no reading anyone else's
    data — the ROE-friendly shape real bug-bounty engagements require.
  * **Complete.** Every (mint, mutation) pair is a cell, so the untested joins are visible
    as blanks, not hidden in an interleaving. A fix on one flow that a parallel flow lacks
    shows up as one red cell in an otherwise green row.

Each cell carries its own controls: a POSITIVE (B authenticated before M) and a NEGATIVE
(a never-valid handle is rejected), so a `survived` verdict cannot be a false positive
from a broken check, and a `revoked` verdict cannot be a mint that never worked.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

from .creds import password
from .harness import execute_action
from .types import Principal

AdapterFactory = Callable[[], object]
_NEVER_VALID = "__never_valid_binding_handle__"


class Survival(str, Enum):
    REVOKED = "revoked"          # good: the mutation killed the predating binding on every plane
    SURVIVED = "survived"        # bad: TPI-4 laundering — the binding outlived the mutation everywhere
    SPLIT = "split"              # bad: revoked on some planes, survived on others — plane-local
                                 #      revocation, the subtle cross-plane bug a same-plane test misses
    NOT_APPLICABLE = "n/a"       # the mutation is not obliged to revoke this binding kind (a passkey
                                 #      is not expected to die on logout) — measured but never a finding
    INCONCLUSIVE = "inconclusive"  # a control failed; the cell measured nothing


@dataclass(frozen=True)
class MintSpec:
    """A short sequence that establishes a durable binding on the acting account.
    `kind` is what sort of binding it is — "session" (a bearer token, plane-scoped) or
    "factor" (an enrolled authenticator, plane-independent). The kind decides how the
    binding is captured and which mutations are obliged to revoke it."""
    id: str
    steps: tuple          # ((action, params), ...)
    label: str = ""
    kind: str = "session"


@dataclass(frozen=True)
class MutationSpec:
    """A credential-mutating transition. `revokes_kinds` names the binding kinds it is
    *obliged* to revoke — logout ends sessions but not passkeys; a remediation password
    reset should end both. A binding of a kind the mutation need not revoke is measured
    but marked NOT_APPLICABLE, never a finding — so a passkey surviving a logout is not
    a false positive, while a passkey surviving a password reset is the real bug."""
    id: str
    steps: tuple
    label: str = ""
    revokes_kinds: frozenset = frozenset({"session"})
    # OPTIONAL mutation control: verify(adapter, principal) -> True (it took effect),
    # False (it did not), None (cannot tell). Without it a cell can only check that the
    # mutation's steps reported success, which is not the same thing — see run_cell.
    verify: Optional[object] = None
    # STRONGER mutation control, and the one to prefer: witness(adapter, principal) returns
    # an observable that the mutation MUST change — the account's email after a rebind, the
    # count of live devices after a sign-out-all. run_cell reads it before and after and
    # requires the two to differ.
    #
    # Why this rather than `verify`: a boolean is a claim, and a claim can be made by code
    # that did not look. Both false SURVIVED verdicts this framework has produced against a
    # real target came from a caller asserting "the mutation happened" — once from a /logout
    # page that only *offered* to log out, once from a flag that overrode a control which had
    # already reported failure. A witness cannot be asserted; it has to be read twice, and
    # an unchanged reading is indistinguishable from a mutation that never ran, which is
    # exactly the verdict the cell should give.
    witness: Optional[object] = None


@dataclass
class CellVerdict:
    mint_id: str
    mutation_id: str
    survival: Survival
    confidence: float
    clause_id: Optional[str]
    evidence: list = field(default_factory=list)
    note: str = ""
    per_plane: dict = field(default_factory=dict)   # plane -> Survival (REVOKED/SURVIVED)
    expected_revoke: bool = True                    # was the mutation obliged to revoke this kind?
    binding_kind: str = "session"                   # "session" | "factor"
    mutation_verified: str = "not measured"         # did the mutation demonstrably happen?

    @property
    def is_finding(self) -> bool:
        return self.expected_revoke and self.survival in (Survival.SURVIVED, Survival.SPLIT)


# --------------------------------------------------------------------------- #
def default_mints(email: str) -> list[MintSpec]:
    """Ways to establish a durable binding on a fresh own account — two session kinds
    and one factor. The factor is the durable one: it can mint new sessions long after
    the session that enrolled it is gone, so a mutation that fails to revoke it is the
    durable-takeover bug."""
    return [
        MintSpec("password_session", (("register", {"email": email, "password": password("owner:account")}),),
                 "a password session (register)", kind="session"),
        MintSpec("sso_session", (("sso_login", {"email": email}),),
                 "a federated session (SSO)", kind="session"),
        MintSpec("passkey_factor",
                 (("register", {"email": email, "password": password("owner:account")}), ("enroll_factor", {})),
                 "an enrolled passkey/biometric factor", kind="factor"),
    ]


def default_mutations(email: str) -> list[MutationSpec]:
    """Credential-mutating transitions across the account lifecycle, each declaring the
    binding kinds it is obliged to revoke."""
    return [
        MutationSpec("logout", (("logout", {}),), "logout",
                     revokes_kinds=frozenset({"session"}),
                     # witness: the acting context's own identity must stop resolving
                     witness=lambda a, p: a.whoami(p).identity),
        # NOTE on `factor` here, learned on a live target. A passkey surviving a password
        # change is STANDARD WebAuthn behaviour — the credential is deliberately independent
        # of the password — so asserting it as an obligation makes this cell fire on every
        # passkey-supporting target. It is kept only because a reset is a REMEDIATION action
        # and the pairing is a real gap when the target's own compromise guidance says
        # "change your password" and nothing else. Read a finding here as "the remediation
        # story is incomplete", not "the authenticator is broken", and check what the target
        # actually tells a compromised user to do before reporting it.
        MutationSpec("password_reset",
                     (("reset_request", {"email": email}),
                      ("reset_consume", {"email": email, "new_password": password("owner:reset")})),
                     "password reset", revokes_kinds=frozenset({"session", "factor"})),
        MutationSpec("email_change", (("email_change", {"new_email": "rebound@corp.example"}),),
                     "email change", revokes_kinds=frozenset({"session"})),
    ]


_WITNESS_ERROR = object()


def _read_witness(mutation: MutationSpec, adapter, principal):
    if mutation.witness is None:
        return None
    try:
        return mutation.witness(adapter, principal)
    except Exception:
        return _WITNESS_ERROR


def run_cell(adapter_factory: AdapterFactory, mint: MintSpec, mutation: MutationSpec,
             principal: Principal) -> CellVerdict:
    """Measure one (mint, mutation) cell, per plane, with in-cell positive and negative
    controls on each plane. The credential is checked on every verify-point plane after
    the mutation, so a plane-local revocation (revoked where the mutation was issued,
    alive elsewhere) surfaces as a SPLIT rather than hiding behind a same-plane test."""
    expected = mint.kind in getattr(mutation, "revokes_kinds", frozenset({"session"}))
    if not expected:
        # a passkey is not obliged to die on logout — measure nothing, never a finding
        return CellVerdict(mint.id, mutation.id, Survival.NOT_APPLICABLE, 0.0, None,
                           note=f"'{mutation.label or mutation.id}' is not obliged to revoke a "
                                f"'{mint.kind}' binding", expected_revoke=False)

    a = adapter_factory()
    planes = list(a.planes()) if hasattr(a, "planes") else [None]

    def inconclusive(note):
        return CellVerdict(mint.id, mutation.id, Survival.INCONCLUSIVE, 0.0, None, note=note,
                           binding_kind=mint.kind)

    # 1. mint the binding and capture a durable handle to it (of the mint's kind)
    for action, params in mint.steps:
        execute_action(a, principal, action, params)
    handle = a.capture_binding(principal, mint.kind)
    if not handle:
        return inconclusive(f"mint '{mint.id}' established no binding")

    # 2/3. per-plane controls — B authenticates before M, a never-valid handle does not
    readable = []
    for plane in planes:
        if a.present_binding(handle, plane).ok and not a.present_binding(_NEVER_VALID, plane).ok:
            readable.append(plane)
    if not readable:
        return inconclusive("no plane had both a firing positive control and a rejecting "
                            "negative control — cannot read a survival")

    # 4. perform the mutation as the account owner — and CHECK IT HAPPENED.
    #
    # This is the control the cell was missing, and a live run is what exposed it: a real
    # target's /logout is a CONFIRMATION page, so navigating to it returns HTTP 200 and
    # logs nobody out. The binding then "survives" a mutation that never occurred, and
    # every cell reads SURVIVED — a false Critical, produced by a measurement that never
    # ran. A cell may only report on a mutation it can show took effect.
    # Read the witness BEFORE the mutation runs — an unchanged reading is only meaningful
    # if the "before" was taken before. (Getting this order wrong makes every cell
    # INCONCLUSIVE, which the suite caught immediately.)
    witness_before = _read_witness(mutation, a, principal)
    outs = [execute_action(a, principal, action, params) for action, params in mutation.steps]
    failed = [o for o in outs if o is not None and not getattr(o, "ok", True)]
    if failed:
        return inconclusive(
            f"the mutation '{mutation.id}' did not execute ("
            + "; ".join((o.note or "step failed")[:80] for o in failed) + ")")
    verified = None
    if mutation.verify is not None:
        try:
            verified = mutation.verify(a, principal)
        except Exception as e:                      # a broken verifier is not a finding
            return inconclusive(f"the mutation control for '{mutation.id}' raised "
                                f"{type(e).__name__}; the cell measured nothing")
        if verified is False:
            return inconclusive(
                f"'{mutation.id}' reported success but did not take effect — the cell "
                f"cannot distinguish a surviving binding from a mutation that never "
                f"happened")

    if mutation.witness is not None:
        witness_after = _read_witness(mutation, a, principal)
        if witness_before is _WITNESS_ERROR or witness_after is _WITNESS_ERROR:
            return inconclusive(f"the witness for '{mutation.id}' could not be read; the "
                                f"cell cannot show the mutation happened")
        if witness_before == witness_after:
            return inconclusive(
                f"'{mutation.id}' left the witness unchanged ({witness_before!r}) — on this "
                f"evidence the mutation did not happen, and a surviving binding cannot be "
                f"told apart from a mutation that never ran")
        verified = True

    # 5. re-present the captured binding on each readable plane
    per_plane = {p: (Survival.SURVIVED if a.present_binding(handle, p).ok else Survival.REVOKED)
                 for p in readable}
    survived = [p for p, s in per_plane.items() if s is Survival.SURVIVED]
    revoked = [p for p, s in per_plane.items() if s is Survival.REVOKED]

    def names(ps):
        return ", ".join(str(p) for p in ps)

    def tag(v: CellVerdict) -> CellVerdict:
        v.mutation_verified = ("witnessed" if mutation.witness is not None and verified is True
                               else "verified" if verified is True else
                               "unverified — steps succeeded but the mutation's effect "
                               "was not independently confirmed")
        return v

    if survived and revoked:
        ev = [f"binding minted by '{mint.id}' was REVOKED on plane(s) [{names(revoked)}] "
              f"but SURVIVED on [{names(survived)}] after '{mutation.id}'",
              "the mutation's revocation is plane-local — a same-plane test would call this fixed",
              "per-plane positive and negative controls held on every plane read"]
        return tag(CellVerdict(mint.id, mutation.id, Survival.SPLIT, 0.95, "TPI-4", ev,
                           note=f"'{mutation.label or mutation.id}' revoked the "
                                f"'{mint.label or mint.id}' binding on [{names(revoked)}] but not "
                                f"[{names(survived)}] — plane-local revocation",
                           per_plane=per_plane, binding_kind=mint.kind))
    if survived:
        ev = [f"binding minted by '{mint.id}' still authenticates after '{mutation.id}' "
              f"on plane(s) [{names(survived)}]",
              "per-plane positive control fired and the negative control was rejected"]
        return tag(CellVerdict(mint.id, mutation.id, Survival.SURVIVED, 0.95, "TPI-4", ev,
                           note=f"'{mutation.label or mutation.id}' did not revoke the "
                                f"'{mint.label or mint.id}' binding",
                           per_plane=per_plane, binding_kind=mint.kind))
    return tag(CellVerdict(mint.id, mutation.id, Survival.REVOKED, 0.95, None,
                       note=f"'{mutation.label or mutation.id}' revoked the "
                            f"'{mint.label or mint.id}' binding",
                       per_plane=per_plane, binding_kind=mint.kind))


@dataclass
class RevocationMatrix:
    principal: Principal
    mints: list
    mutations: list

    def run(self, adapter_factory: AdapterFactory) -> dict:
        """Return {(mint_id, mutation_id): CellVerdict} for the full grid."""
        return {(m.id, x.id): run_cell(adapter_factory, m, x, self.principal)
                for m in self.mints for x in self.mutations}

    def findings(self, results: dict) -> list:
        """The SURVIVED cells — the laundering bugs, most-confident first."""
        return sorted((v for v in results.values() if v.is_finding),
                      key=lambda v: -v.confidence)

    def render(self, results: dict) -> str:
        """A text grid: mutations as columns, mints as rows."""
        sym = {Survival.REVOKED: "revoked ", Survival.SURVIVED: "SURVIVED",
               Survival.SPLIT: "SPLIT ⚠", Survival.NOT_APPLICABLE: "  n/a   ",
               Survival.INCONCLUSIVE: "  --    "}
        w = max([len(m.id) for m in self.mints] + [8])
        head = " " * (w + 2) + "  ".join(f"{x.id:^14}" for x in self.mutations)
        lines = [head, " " * (w + 2) + "  ".join("-" * 14 for _ in self.mutations)]
        for m in self.mints:
            row = f"{m.id:<{w}}  "
            for x in self.mutations:
                v = results[(m.id, x.id)]
                row += f"{sym[v.survival]:^14}  "
            lines.append(row.rstrip())
        return "\n".join(lines)
