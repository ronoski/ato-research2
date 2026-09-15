"""Revocation-matrix self-test: the single-principal, own-account hunting mode.

    python3 -m tpihunter.matrix_demo

Runs the mutation × predating-binding matrix against the *patched* mock — the target
whose pre-hijacking bugs are all fixed. The point it makes: even there, the fix did not
propagate uniformly. The password-reset flow revokes predating sessions; the parallel
logout flow does not (a plane-local logout that clears client state but leaves the token
alive). That asymmetry — one red cell in an otherwise green column — is Composition-
Blindness made visible, and it is exactly the shape a real engagement surfaces
(cf. ~/singularity/grab/ato/TPI_LENS.md, T-ATO-05).

Every cell is own-account and reversible; no second principal, no reading anyone's data.
"""
from __future__ import annotations

from .matrix import RevocationMatrix, Survival, default_mints, default_mutations
from .mock_target import MockAdapter
from .types import Principal


def _run(label: str, patched: bool, revokes: set) -> None:
    owner = Principal("owner")
    email = "owner@corp.example"
    control = {owner.name: {email}}

    def factory():
        return MockAdapter(patched=patched, control=control, revokes=revokes)

    matrix = RevocationMatrix(owner, default_mints(email), default_mutations(email))
    results = matrix.run(factory)
    findings = matrix.findings(results)

    print(f"\n {label}")
    print(" " + "-" * 60)
    print(matrix.render(results))
    if findings:
        print(f"\n  {len(findings)} laundering cell(s) — a binding outlived a mutation that should kill it:")
        for v in findings:
            print(f"   [{v.clause_id}] {v.note}")
    else:
        print("\n  no laundering: every mint is revoked by every mutation.")


def main() -> None:
    print("\nTPI-HUNTER  -  revocation matrix (own-account, over-time hunting mode)")
    print(" question per cell: does the mutation revoke a binding minted before it?")

    _run("TARGET: mock-patched  (pre-hijacking bugs fixed — but is the fix uniform?)",
         patched=True, revokes=set())
    _run("TARGET: fully patched (revoke-on-mutation enforced on every flow)",
         patched=True, revokes={"logout"})

    print("\n " + "=" * 60)
    print(" The first grid finds SURVIVED cells on a 'patched' target: the reset flow")
    print(" revokes, the parallel logout flow does not. The second grid — with logout")
    print(" revocation added — is clean. Same discriminating discipline as the oracle:")
    print(" a matrix that was red on both would be worthless.\n")


if __name__ == "__main__":
    main()
