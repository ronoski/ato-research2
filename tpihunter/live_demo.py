"""The live path, end to end: a target described as data, proved, then hunted over HTTP.

    python3 -m tpihunter.live_demo

Every other demo drives the in-memory mock through a Python adapter someone wrote. This
one starts a real HTTP server on loopback, describes it with a `TargetProfile` — the kind
an agent authors through `set_target()` — proves the description works, and then runs the
ordinary hunt against it through sockets, cookies and JSON.

The point it makes is not that HTTP works. It is that the loop finds **the same TPI-1 and
TPI-4, with the same minimal repros**, with nobody writing an adapter — which is what has
to be true before an agent in an MCP session can hunt anything that is not this mock.

Nothing leaves the machine: the server binds to 127.0.0.1 and the engagement authorizes
that host and nothing else.
"""
from __future__ import annotations

from dataclasses import replace

from .agent import AgentHunter, EnumeratorStrategist
from .http_mock import VICTIM_EMAIL, engagement_for, profile_for, serve
from .live import live_adapter
from .policy import EngagementPolicy, ScopeViolation
from .profile import ProfileError, TargetProfile
from .types import Principal
from .validate import validate_target

ATTACKER, VICTIM = Principal("attacker"), Principal("victim")
RULE = "=" * 78


def _hunt(profile, policy):
    def factory():
        return live_adapter(profile, policy, control={VICTIM.name: {VICTIM_EMAIL}})
    return AgentHunter(factory, ATTACKER, VICTIM, VICTIM_EMAIL, budget=300).hunt(
        EnumeratorStrategist(max_attacker=1, max_victim=2))


def main() -> None:
    print(RULE)
    print("TPI-Hunter — hunting a real HTTP target from a profile")
    print(RULE)

    with serve(patched=False) as url:
        policy = EngagementPolicy.from_dict(engagement_for(url))
        raw = profile_for(url)

        print(f"\n THE OPERATOR authorizes the engagement (out of band, on disk):")
        print(f"   host       : {sorted(policy.hosts)[0]}")
        print(f"   accounts   : {len(policy.identifiers)} test identifiers")
        print(f"   authorized : {policy.authorized_by}")

        print(f"\n THE AGENT describes the target (no Python, just data):")
        profile = TargetProfile.from_dict(raw)
        d = profile.describe()
        print(f"   base_url   : {d['base_url']}")
        print(f"   actions    : {', '.join(d['actions'])}")
        print(f"   oracle     : {', '.join(d['oracle'])}")

        print("\n" + "-" * 78)
        print(" 1. PROVE THE DESCRIPTION WORKS  (validate_target)")
        print("-" * 78)
        v = validate_target(profile, policy)
        print(v.render())
        print("\n    left on the target:")
        for a in v.artifacts:
            print(f"      - {a}")

        print("\n" + "-" * 78)
        print(" 2. HUNT IT  (the ordinary loop, over HTTP)")
        print("-" * 78)
        res = _hunt(profile, policy)
        print(f"\n   {res.probes_used} probes -> {len(res.bugs)} distinct bug(s)")
        for b in res.bugs:
            print(f"     {b.clause_id}  {b.render()}")

    print("\n" + "-" * 78)
    print(" 3. THE SAME PROBES AGAINST THE PATCHED BUILD")
    print("-" * 78)
    with serve(patched=True) as url:
        policy = EngagementPolicy.from_dict(engagement_for(url))
        profile = TargetProfile.from_dict(profile_for(url))
        res = _hunt(profile, policy)
        print(f"\n   {res.probes_used} probes -> {len(res.bugs)} bug(s) "
              f"— the invariant holds through the live stack")

    print("\n" + "-" * 78)
    print(" 4. WHAT THE GUARDRAILS REFUSE")
    print("-" * 78)
    with serve() as url:
        policy = EngagementPolicy.from_dict(engagement_for(url))
        raw = profile_for(url)

        bad = dict(raw)
        bad["actions"] = dict(raw["actions"])
        bad["actions"]["login"] = {**raw["actions"]["login"],
                                   "path": "https://elsewhere.example/api/login"}
        try:
            TargetProfile.from_dict(bad)
            print("   an action pointing off-origin        : NOT REFUSED (bug)")
        except ProfileError:
            print("   an action pointing off-origin        : refused at parse time")

        narrow = replace(policy, identifiers=frozenset({VICTIM_EMAIL}))
        try:
            live_adapter(TargetProfile.from_dict(raw), narrow)
            print("   an account outside the engagement    : NOT REFUSED (bug)")
        except ScopeViolation:
            print("   an account outside the engagement    : refused before any request")

        from .live import ScopedTransport
        from .policy import AuditLog
        t = ScopedTransport(policy, AuditLog())
        try:
            t.send("GET", url + "/testing/redirect?to=http://example.invalid/x", {}, None)
            print("   a redirect out of scope              : NOT REFUSED (bug)")
        except ScopeViolation:
            print("   a redirect out of scope              : refused mid-request")

    print("\n" + RULE)
    print(" Same bugs, same repros, no adapter written. An agent reaches a real target")
    print(" through set_target() / validate_target() — see the tool README.")
    print(RULE)


if __name__ == "__main__":
    main()
