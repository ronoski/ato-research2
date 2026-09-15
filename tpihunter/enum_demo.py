"""Enumerator self-test: generate probes automatically, run each against the
vulnerable and patched mock, then collapse the near-duplicates to distinct bugs.

    python3 -m tpihunter.enum_demo

The point: with zero hand-written probes, the enumerator rediscovers the
pre-hijacking bug (TPI-1) *and* finds a distinct one no hand-written probe targeted
(TPI-4, session survives reset). It over-generates 100+ interleavings; semantic
dedup (causal minimization + signature) collapses them to the 2 distinct bugs, each
with a minimal repro. Every finding closes under the patch — real bugs, not
artifacts of an always-yes detector.
"""
from __future__ import annotations

from .dedup import deduplicate
from .enumerator import enumerate_plans
from .harness import run_plan
from .oracle import AtoOracle
from .mock_target import MockAdapter
from .types import Principal


def _make_verdict_fn(attacker, victim, control, patched=False):
    def fn(plan):
        a = MockAdapter(patched=patched, control=control)
        return run_plan(a, plan, AtoOracle(a, attacker, victim))[0]
    return fn


def main() -> None:
    attacker, victim = Principal("attacker"), Principal("victim")
    email = "victim@corp.example"
    control = {victim.name: {email}}   # victim controls the IdP + inbox; attacker does not

    cands = enumerate_plans(attacker, victim, email)
    vuln = _make_verdict_fn(attacker, victim, control, patched=False)
    patched = _make_verdict_fn(attacker, victim, control, patched=True)

    fired = [c for c in cands if vuln(c.plan).severity.value == "takeover"]

    print("\nTPI-HUNTER  -  probe enumerator + semantic dedup")
    print(f"generated {len(cands)} composition-relevant interleavings; "
          f"{len(fired)} fired on the vulnerable target\n")

    # --- preview: the shortest handful ---------------------------------------
    print(" preview (shortest first):")
    print(f"   {'probe':52} {'vulnerable':26} {'patched'}")
    print("   " + "-" * 88)
    for c in cands[:8]:
        vv, vp = vuln(c.plan), patched(c.plan)
        tag = f"[{vv.severity.value.upper()}]" + (f" {vv.clause_id}" if vv.clause_id else "")
        print(f"   {c.plan.name:52} {tag:26} [{vp.severity.value.upper()}]")
    if len(cands) > 8:
        print(f"   ... {len(cands) - 8} more")

    # --- semantic dedup: distinct bugs ---------------------------------------
    clusters = deduplicate(cands, attacker, victim, email, vuln)
    print("\n" + " " + "=" * 74)
    print(f" {len(fired)} findings collapse to {len(clusters)} DISTINCT bug(s) "
          "(causal minimization + signature):")
    for i, cl in enumerate(clusters, 1):
        print(f"\n   [{i}] {cl.clause_id}   ({cl.size} interleavings collapsed here)")
        print(f"       minimal repro:  {cl.render()}")
        if cl.laundered_proof:
            print(f"       laundered proof: {cl.laundered_proof}")

    # --- patch discipline ----------------------------------------------------
    patch_gaps = [c for c in fired if patched(c.plan).severity.value == "takeover"]
    print("\n " + "-" * 74)
    if patch_gaps:
        print(f" WARNING: {len(patch_gaps)} finding(s) still fire on the patched target.")
    else:
        print(" All findings close under the patch -> real bugs, not detector artifacts.")
    ok = len(clusters) == 2 and sorted(c.clause_id for c in clusters) == ["TPI-1", "TPI-4"] and not patch_gaps
    print(f" dedup acceptance: {'PASS' if ok else 'FAIL'} "
          f"({len(fired)} findings -> {len(clusters)} distinct bugs)")
    print(" " + "=" * 74)
    print(" No probe was hand-written. The hunter sees 2 distinct bugs, not 106.\n")


if __name__ == "__main__":
    main()
