"""Safety self-test: what stops this tool from doing the wrong thing to a real system.

    python3 -m tpihunter.safety_demo

Every other demo shows the loop finding bugs. This one shows the two properties that
have to hold before the loop is allowed near a live target:

  1. THE ORACLE'S CONTROLS. A verdict is a measurement, and a measurement without
     controls is an anecdote. Three probes that used to produce confident, wrong answers
     now produce honest ones — and the real bug still fires at full confidence beside them.

  2. THE DIAGNOSIS CONTROL. A takeover is not automatically a *provenance* takeover. An
     uninvolved third account tells the two apart, so a plain authorization bug is not
     reported as laundering with a remediation that would never close it.

  3. THE ENGAGEMENT POLICY. Rules of engagement live in data and are enforced per action
     by `policy.guard()`, so an out-of-scope account or an unbudgeted run is refused by
     the tool rather than by the operator remembering.

Nothing here touches a network: the "target" is the in-memory mock, as everywhere else.
"""
from __future__ import annotations

from .adapter import Trace
from .enumerator import make_candidate
from .harness import run_plan
from .mock_target import MockAdapter
from .oracle import AtoOracle
from .policy import BudgetExhausted, EngagementPolicy, ScopeViolation, guard, policy_report
from .types import Observation, Principal

ATTACKER, VICTIM = Principal("attacker"), Principal("victim")
EMAIL = "pentest-v@acme.example"


def _probe(control, merged, patched=False, **oracle_kw):
    a = MockAdapter(patched=patched, control=control)
    cand = make_candidate(merged, ATTACKER, VICTIM, EMAIL)
    return run_plan(a, cand.plan, AtoOracle(a, ATTACKER, VICTIM, resource=EMAIL, **oracle_kw))[0]


def _line(label: str, v) -> None:
    tag = f"{v.severity.value.upper():<13}"
    extra = f"  withheld={v.withheld}" if v.withheld else ""
    print(f"  {tag} conf={v.confidence:<5} {label}{extra}")


def part_one() -> None:
    print("1. THE ORACLE'S CONTROLS — the same three probes that used to lie\n")

    # (a) a legitimately shared account: two co-owners, both proving control of the identifier
    v = _probe({VICTIM.name: {EMAIL}, ATTACKER.name: {EMAIL}},
               (("attacker", "sso_login"), ("victim", "sso_login")))
    _line("a shared/tenant account — both principals own it", v)

    # (b) a probe where the victim never establishes a session, so no canary is ever planted
    v = _probe({VICTIM.name: {EMAIL}}, (("attacker", "register"), ("victim", "reset_request")))
    _line("the canary was never planted — the probe did not run", v)

    # (c) two principals wired to one context — the classic mis-built live adapter
    a = MockAdapter(patched=False, control={VICTIM.name: {EMAIL}})
    a.sso_login(VICTIM, EMAIL)
    a.sess[ATTACKER.name] = a.sess[VICTIM.name]          # one session, two "principals"
    o = AtoOracle(a, ATTACKER, VICTIM, resource=EMAIL).arm(Trace())
    _line("two principals sharing one context — a harness bug", o.plant().assess(Trace()))

    # (d) and the finding the whole tool exists for, undiminished
    v = _probe({VICTIM.name: {EMAIL}}, (("attacker", "register"), ("victim", "sso_login")))
    _line(f"REAL laundering ({v.clause_id}) — attacker seeds, victim raises", v)
    print("\n  Each of (a)-(c) graded TAKEOVER at 0.90-0.99 before the controls existed.")
    print("  A false Critical is a bogus report; a false SAFE tells the agent to stop looking.\n")


class _FlatIdor(MockAdapter):
    """Correct auth, correct revocation — object reads simply are not scoped to the owner.
    A reachability model finds this in one principal; it is not a provenance failure."""

    def read_marker(self, p, ref=None):
        if ref is None:
            return super().read_marker(p)
        acc = self.t.accounts.get(ref)
        return Observation(acc is not None, extracted={"value": acc.marker if acc else None})


def part_two() -> None:
    print("2. THE DIAGNOSIS CONTROL — is this access provenance-specific, or can anyone do it?\n")
    probe = (("attacker", "register"), ("victim", "sso_login"))
    for label, cls, patched, bystander in (
            ("a genuinely laundering target", MockAdapter, False, True),
            ("a target with flat IDOR instead", _FlatIdor, True, True),
            ("...the same target, control off", _FlatIdor, True, False)):
        a = cls(patched=patched, control={VICTIM.name: {EMAIL}})
        kw = {} if bystander else {"bystander": None}
        v = run_plan(a, make_candidate(probe, ATTACKER, VICTIM, EMAIL).plan,
                     AtoOracle(a, ATTACKER, VICTIM, resource=EMAIL, **kw))[0]
        print(f"  {v.severity.value.upper():<9} {str(v.clause_id):<8} {label:<34} "
              f"bystander={v.controls['bystander']}")
    print("\n  The third line is what the tool used to do on every target of the second kind:")
    print("  a real bug, reported under a provenance clause whose remediation cannot fix it.\n")


def part_three() -> None:
    print("3. THE ENGAGEMENT POLICY — rules of engagement the tool enforces itself\n")
    policy = EngagementPolicy(
        name="acme-bugbounty",
        authorized_by="security@acme.example, ticket SEC-1421, 2026-09-20",
        identifiers=frozenset({EMAIL}),          # the ONLY account in scope
        hosts=frozenset({"staging.acme.example"}),
        allow_credential_change=True,
        max_actions=64,
    )
    merged = (("attacker", "register"), ("victim", "sso_login"))

    a = guard(MockAdapter(patched=False, control={VICTIM.name: {EMAIL}}), policy)
    v = run_plan(a, make_candidate(merged, ATTACKER, VICTIM, EMAIL).plan,
                 AtoOracle(a, ATTACKER, VICTIM, resource=EMAIL))[0]
    print(f"  in scope        -> {v.severity.value} ({v.clause_id}), {a.actions_used} actions audited")

    other = "ceo@acme.example"        # a real account, not one we were given
    b = guard(MockAdapter(patched=False, control={VICTIM.name: {other}}), policy)
    try:
        run_plan(b, make_candidate(merged, ATTACKER, VICTIM, other).plan,
                 AtoOracle(b, ATTACKER, VICTIM, resource=other))
        print("  out of scope    -> NOT REFUSED (this is a bug)")
    except ScopeViolation as e:
        print(f"  out of scope    -> refused: {str(e).splitlines()[0][:66]}...")

    c = guard(MockAdapter(patched=False, control={VICTIM.name: {EMAIL}}),
              EngagementPolicy(name="tiny", authorized_by="x", identifiers=frozenset({EMAIL}),
                               max_actions=3))
    try:
        for _ in range(10):
            c.whoami(VICTIM)
        print("  budget          -> NOT STOPPED (this is a bug)")
    except BudgetExhausted:
        print(f"  budget          -> stopped after {c.actions_used} actions, as instructed")

    d = guard(MockAdapter(patched=False, control={VICTIM.name: {EMAIL}}),
              EngagementPolicy(name="review", authorized_by="x", identifiers=frozenset({EMAIL}),
                               dry_run=True))
    run_plan(d, make_candidate(merged, ATTACKER, VICTIM, EMAIL).plan,
             AtoOracle(d, ATTACKER, VICTIM, resource=EMAIL))
    print(f"  dry run         -> {d.audit.counts()}, target untouched "
          f"({len(d._inner.t.accounts)} accounts created)")
    print()
    print(policy_report(a).split("Audit trail:")[0].rstrip())
    print("  Audit trail (first 4 of "
          f"{len(a.audit.records)}):")
    for r in a.audit.records[:4]:
        print("   ", r.render())


def main() -> None:
    print("=" * 78)
    print("TPI-Hunter — safety self-test")
    print("=" * 78, "\n")
    part_one()
    part_two()
    part_three()
    print("\n" + "=" * 78)
    print("Controls hold, scope holds, the real bug still fires. "
          "Live use still needs M4 + an authorized target.")
    print("=" * 78)


if __name__ == "__main__":
    main()
