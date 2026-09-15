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


def _run(label: str, **cfg) -> None:
    owner = Principal("owner")
    email = "owner@corp.example"
    control = {owner.name: {email}}

    def factory():
        return MockAdapter(control=control, **cfg)

    matrix = RevocationMatrix(owner, default_mints(email), default_mutations(email))
    results = matrix.run(factory)
    findings = matrix.findings(results)

    print(f"\n {label}")
    print(" " + "-" * 62)
    print(matrix.render(results))
    if findings:
        print(f"\n  {len(findings)} laundering cell(s) — a binding outlived a mutation that should kill it:")
        for v in findings:
            print(f"   [{v.clause_id}] {v.note}")
    else:
        print("\n  no laundering: every mint is revoked by every mutation, on every plane.")


def main() -> None:
    print("\nTPI-HUNTER  -  revocation matrix (own-account, over-time hunting mode)")
    print(" question per cell: does the mutation revoke a binding minted before it?")

    _run("TARGET: mock-patched  (pre-hijacking bugs fixed — but is the fix uniform?)",
         patched=True)
    _run("TARGET: mock-plane-split  (multi-plane estate — logout revokes only its own plane)",
         patched=True, planes=("auth", "mts"), revokes={"logout"}, plane_local={"logout"})
    _run("TARGET: fully patched (revoke-on-mutation enforced on every flow, every plane)",
         patched=True, planes=("auth", "mts"), revokes={"logout"})

    print("\n " + "=" * 62)
    print(" Grid 1: on a 'patched' single-plane target the reset flow revokes but the")
    print("         parallel logout flow does not — SURVIVED.")
    print(" Grid 2: ⭐ the subtle one. logout DOES revoke — but only on the plane it is")
    print("         issued on ('mts'); the credential lives on 'auth' — a SPLIT. A")
    print("         same-plane test would have called this fixed. This is the exact shape")
    print("         of the open cross-plane cell on the real engagement (Grab T-ATO-05).")
    print(" Grid 3: logout revokes globally — clean. A matrix red on every target would")
    print("         be worthless; the discipline is that a fix shows as green.\n")


if __name__ == "__main__":
    main()
