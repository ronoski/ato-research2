"""Enumerator self-test: generate probes automatically, run each against the
vulnerable and patched mock, and report which fire.

    python3 -m tpihunter.enum_demo

The point: with zero hand-written probes, the enumerator rediscovers the
pre-hijacking bug (TPI-1) *and* finds a distinct one no hand-written probe
targeted (TPI-4, session-survives-reset) — reported as a minimal witness per
clause, and every witness closes under the patch (real bugs, not artifacts of
an always-yes detector).
"""
from __future__ import annotations

from .enumerator import enumerate_plans
from .harness import run_plan
from .oracle import AtoOracle
from .mock_target import MockAdapter
from .types import Principal


def _verdict_for(plan, patched, attacker, victim, control):
    adapter = MockAdapter(patched=patched, control=control)
    oracle = AtoOracle(adapter, attacker, victim)
    verdict, _ = run_plan(adapter, plan, oracle)
    return verdict


def _render_steps(plan) -> str:
    parts = []
    for s in plan.steps:
        if s.principal is None:      # oracle checkpoint
            continue
        parts.append(f"{s.principal.name}:{s.action}")
    return "  ->  ".join(parts)


def main() -> None:
    attacker, victim = Principal("attacker"), Principal("victim")
    email = "victim@corp.example"
    control = {victim.name: {email}}   # victim controls the IdP + inbox; attacker does not

    cands = enumerate_plans(attacker, victim, email)
    rows = [(c, _verdict_for(c.plan, False, attacker, victim, control),
                _verdict_for(c.plan, True, attacker, victim, control)) for c in cands]

    takeovers = [(c, vv, vp) for c, vv, vp in rows if vv.severity.value == "takeover"]
    patch_gaps = [(c, vv, vp) for c, vv, vp in takeovers if vp.severity.value == "takeover"]

    print("\nTPI-HUNTER  -  probe enumerator")
    print(f"generated {len(cands)} composition-relevant interleavings; "
          f"{len(takeovers)} fired on the vulnerable target\n")

    # --- preview: the shortest dozen candidates -----------------------------
    print(" preview (shortest first):")
    print(f"   {'probe':52} {'vulnerable':26} {'patched'}")
    print("   " + "-" * 88)
    for c, vv, vp in rows[:12]:
        vuln = f"[{vv.severity.value.upper()}]" + (f" {vv.clause_id}" if vv.clause_id else "")
        print(f"   {c.plan.name:52} {vuln:26} [{vp.severity.value.upper()}]")
    if len(rows) > 12:
        print(f"   ... {len(rows) - 12} more")

    # --- minimal witness per distinct clause --------------------------------
    clauses = sorted({vv.clause_id for _c, vv, _vp in takeovers if vv.clause_id})
    print("\n" + " " + "=" * 74)
    print(f" FINDINGS: {len(takeovers)} takeover(s), distinct clauses: {', '.join(clauses)}")
    print(" minimal witness per clause (shortest confirmed repro):")
    for clause in clauses:
        hits = [(c, vv, vp) for c, vv, vp in takeovers if vv.clause_id == clause]
        c, vv, vp = min(hits, key=lambda r: r[0].length)
        closes = "closes under patch" if vp.severity.value != "takeover" else "STILL OPEN under patch"
        print(f"   {clause} ({vv.failure_mode})  [{closes}]")
        print(f"       {_render_steps(c.plan)}")
        if vv.laundered_proof:
            print(f"       laundered proof: {vv.laundered_proof}")

    # --- patch discipline ---------------------------------------------------
    print(" " + "-" * 74)
    if patch_gaps:
        print(f" WARNING: {len(patch_gaps)} finding(s) still fire on the patched target:")
        for c, _vv, _vp in patch_gaps[:5]:
            print(f"     {c.plan.name}")
    else:
        print(" All findings close under the patch -> real bugs, not detector artifacts.")
    print(" " + "=" * 74)
    print(" No probe here was hand-written. TPI-4 was found by the enumerator, not")
    print(" seeded by a human. Point the same generator at a real TargetAdapter's")
    print(" learned alphabet to hunt live.\n")


if __name__ == "__main__":
    main()
