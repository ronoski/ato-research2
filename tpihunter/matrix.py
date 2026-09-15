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

from .harness import execute_action
from .types import Principal

AdapterFactory = Callable[[], object]
_NEVER_VALID = "__never_valid_binding_handle__"


class Survival(str, Enum):
    REVOKED = "revoked"          # good: the mutation killed the predating binding
    SURVIVED = "survived"        # bad: TPI-4 laundering — the binding outlived the mutation
    INCONCLUSIVE = "inconclusive"  # a control failed; the cell measured nothing


@dataclass(frozen=True)
class MintSpec:
    """A short sequence that establishes a durable binding on the acting account."""
    id: str
    steps: tuple          # ((action, params), ...)
    label: str = ""


@dataclass(frozen=True)
class MutationSpec:
    """A credential-mutating transition that *ought* to revoke predating bindings."""
    id: str
    steps: tuple
    label: str = ""


@dataclass
class CellVerdict:
    mint_id: str
    mutation_id: str
    survival: Survival
    confidence: float
    clause_id: Optional[str]
    evidence: list = field(default_factory=list)
    note: str = ""

    @property
    def is_finding(self) -> bool:
        return self.survival is Survival.SURVIVED


# --------------------------------------------------------------------------- #
def default_mints(email: str) -> list[MintSpec]:
    """Two ways to mint a passenger-style session, on a fresh own account."""
    return [
        MintSpec("password_session", (("register", {"email": email, "password": "OwnPw!1"}),),
                 "a password session (register)"),
        MintSpec("sso_session", (("sso_login", {"email": email}),),
                 "a federated session (SSO)"),
    ]


def default_mutations(email: str) -> list[MutationSpec]:
    """Two credential-mutating transitions that should each end prior sessions."""
    return [
        MutationSpec("logout", (("logout", {}),), "logout"),
        MutationSpec("password_reset",
                     (("reset_request", {"email": email}),
                      ("reset_consume", {"email": email, "new_password": "NewPw!2"})),
                     "password reset"),
    ]


def run_cell(adapter_factory: AdapterFactory, mint: MintSpec, mutation: MutationSpec,
             principal: Principal) -> CellVerdict:
    """Measure one (mint, mutation) cell with in-cell positive and negative controls."""
    a = adapter_factory()

    # 1. mint the binding and capture a durable handle to it
    for action, params in mint.steps:
        execute_action(a, principal, action, params)
    handle = a.capture_binding(principal)
    if not handle:
        return CellVerdict(mint.id, mutation.id, Survival.INCONCLUSIVE, 0.0, None,
                           note=f"mint '{mint.id}' established no binding")

    # 2. POSITIVE control — the binding authenticates before the mutation
    before = a.present_binding(handle)
    if not before.ok:
        return CellVerdict(mint.id, mutation.id, Survival.INCONCLUSIVE, 0.0, None,
                           note="captured binding did not authenticate before the mutation")

    # 3. NEGATIVE control — a never-valid handle is rejected (the check discriminates)
    if a.present_binding(_NEVER_VALID).ok:
        return CellVerdict(mint.id, mutation.id, Survival.INCONCLUSIVE, 0.0, None,
                           note="present_binding accepts a never-valid handle — cannot read a survival")

    # 4. perform the mutation as the account owner
    for action, params in mutation.steps:
        execute_action(a, principal, action, params)

    # 5. re-present the captured binding
    after = a.present_binding(handle)
    if after.ok:
        ev = [f"binding minted by '{mint.id}' still authenticates as {after.identity} "
              f"after '{mutation.id}'",
              "positive control: it authenticated before the mutation",
              "negative control: a never-valid handle was rejected"]
        return CellVerdict(mint.id, mutation.id, Survival.SURVIVED, 0.95, "TPI-4", ev,
                           note=f"'{mutation.label or mutation.id}' did not revoke the "
                                f"'{mint.label or mint.id}' binding")
    return CellVerdict(mint.id, mutation.id, Survival.REVOKED, 0.95, None,
                       note=f"'{mutation.label or mutation.id}' revoked the "
                            f"'{mint.label or mint.id}' binding")


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
