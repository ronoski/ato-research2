"""Prove the profile works before trusting a single verdict.

The oracle already refuses to call a probe SAFE when its own controls did not hold. One
level up, the same failure is unguarded and much worse: a profile with a wrong field —
the login endpoint returning 200 on failure, `identity` extracted from a field that is
null, a marker route that silently does nothing — produces confident SAFE verdicts across
the *entire* surface. An agent reads that as "this target is secure" and stops. Nothing in
the transcript looks wrong.

So a profile is not usable until it has been shown to work, against ground truth the tool
can check for itself:

    can each principal get a session?          — otherwise nothing runs
    do two principals resolve to two accounts? — otherwise every verdict is void
    can the victim read back what it planted?  — the oracle's positive control
    is a foreign reference refused at baseline? — the oracle's negative control
    is there a third account for the bystander? — the diagnosis control
    does the channel deliver a token?           — otherwise the reset flows are unreachable

Each check reports `pass`, `fail` or `skip` with a one-line `fix`, so an agent can repair
one field and re-run instead of guessing at a whole profile. `ready` is true only when
nothing blocking failed.

This performs real writes on the engagement's own accounts (it registers, plants a marker
and reads it back), so it is subject to the same policy as a hunt and shows up in the same
audit trail.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Optional

from .live import LiveAdapter, live_adapter
from .oracle import NEVER_VALID_REF
from .policy import AuditLog, EngagementPolicy, PolicyViolation
from .profile import TargetProfile
from .redact import redact, untrusted
from .types import Principal

VICTIM, ATTACKER, BYSTANDER = (Principal("victim"), Principal("attacker"),
                               Principal("bystander"))


@dataclass
class Check:
    name: str
    status: str                  # pass | fail | skip
    detail: str = ""
    fix: str = ""
    blocking: bool = True

    def as_dict(self) -> dict:
        out = {"check": self.name, "status": self.status, "detail": self.detail}
        if self.status != "pass" and self.fix:
            out["fix"] = self.fix
        if self.status == "fail":
            out["blocking"] = self.blocking
        return out


@dataclass
class Validation:
    checks: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)   # what this left on the target

    @property
    def ready(self) -> bool:
        return not any(c.status == "fail" and c.blocking for c in self.checks)

    def as_dict(self, profile: Optional[TargetProfile] = None) -> dict:
        out = {
            "ready": self.ready,
            "checks": [c.as_dict() for c in self.checks],
            "blocking_failures": [c.name for c in self.checks
                                  if c.status == "fail" and c.blocking],
            "warnings": [c.name for c in self.checks
                         if c.status == "fail" and not c.blocking],
            "artifacts_left_on_target": self.artifacts,
        }
        if profile is not None:
            out["profile"] = profile.describe()
        if not self.ready:
            out["next"] = ("Fix the blocking failures above — each check's `fix` says which "
                           "profile field — then call validate_target() again. Verdicts from "
                           "an unvalidated profile are not evidence of anything.")
        return out

    def render(self) -> str:
        mark = {"pass": "PASS", "fail": "FAIL", "skip": "skip"}
        lines = [f"  {mark[c.status]}  {c.name}" + (f" — {c.detail}" if c.detail else "")
                 for c in self.checks]
        lines.append("")
        lines.append(f"  ready = {self.ready}")
        return "\n".join(lines)


def _check_natural_canary(inner, profile, v) -> tuple:
    """Natural mode: the ground truth is a value the account already holds, so the three
    properties a planted secret has for free are measured here instead of assumed.

    Reported as separate checks rather than one, because each failure has a different fix:
    an unstable field is the wrong field, a low-entropy one is the wrong field, and a
    constant one means the route is not returning per-account state at all."""
    from .oracle import MIN_CANARY_BITS, MIN_CANARY_LEN, canary_bits
    first = inner.read_marker(VICTIM)
    value = first.extracted.get("value")
    ref = first.extracted.get("ref") or inner.whoami(VICTIM).identity
    if not isinstance(value, str) or not value.strip():
        v.checks.append(Check("canary", "fail",
                              "the victim's private field returned no value",
                              "Fix oracle.read_marker: point it at a private per-account "
                              "field and make extract.value select it."))
        return None, ref
    value = value.strip()

    bits = canary_bits(value)
    if len(value) < MIN_CANARY_LEN or bits < MIN_CANARY_BITS:
        v.checks.append(Check("canary", "fail",
                              f"the value carries ~{bits:.0f} bits — too little to tell one "
                              f"account from another, so a match would be coincidence",
                              "Point oracle.read_marker at a higher-entropy private field "
                              "(an account id, a handle) rather than a flag or a count."))
        return None, ref
    if inner.read_marker(VICTIM).extracted.get("value") != value:
        v.checks.append(Check("canary", "fail",
                              "the value changed between two reads by its own owner",
                              "That field is a nonce or a timestamp. Point "
                              "oracle.read_marker at a stable private field."))
        return None, ref
    v.checks.append(Check("canary", "pass",
                          f"observed a stable private value (~{bits:.0f} bits), no write issued"))
    return value, ref


def validate_target(profile: TargetProfile, policy: EngagementPolicy,
                    audit: Optional[AuditLog] = None) -> Validation:
    """Run the profile against the target and report what works."""
    v = Validation()
    log = audit if audit is not None else AuditLog()

    try:
        adapter = live_adapter(profile, policy, control={VICTIM.name: profile.identifiers()},
                               audit=log)
    except PolicyViolation as e:
        v.checks.append(Check("engagement", "fail", untrusted(str(e), 300),
                              "Name every identifier and host the profile uses in the "
                              "engagement policy, and record who authorized the test."))
        return v
    v.checks.append(Check("engagement", "pass",
                          f"policy '{policy.name}' authorizes {len(policy.identifiers)} "
                          f"identifier(s) and host {profile.host}"))

    # 1. reachable at all
    inner: LiveAdapter = adapter._inner            # the transport lives on the unguarded one
    probe = inner._t(VICTIM).send("GET", profile.base_url + "/", {}, None)
    if probe.status == 0:
        v.checks.append(Check("reachable", "fail", "no HTTP response from base_url",
                              "Check base_url, DNS, TLS and that the host is reachable "
                              "from here."))
        return v
    v.checks.append(Check("reachable", "pass", f"base_url answered HTTP {probe.status}"))

    # 2/3. each principal can establish its own session, on its own account
    ids = {}
    for p in (VICTIM, ATTACKER):
        acct = profile.accounts.get(p.name)
        obs = inner.login(p, acct.email, acct.password)
        how = "login"
        if not obs.ok:
            obs = inner.register(p, acct.email, acct.password)
            how = "register"
            if obs.ok:
                v.artifacts.append(f"account {acct.email} (created by validation)")
        if not obs.ok:
            v.checks.append(Check(f"session:{p.name}", "fail",
                                  untrusted(redact(obs.note), 200),
                                  f"Fix actions.login / actions.register: the request must "
                                  f"establish a session for {acct.email} and return one of "
                                  f"its `expect` statuses."))
            continue
        who = inner.whoami(p)
        if not who.ok or not who.identity:
            v.checks.append(Check(f"identity:{p.name}", "fail",
                                  f"{how} succeeded but whoami returned no identity",
                                  "Fix oracle.whoami.extract.identity — it must pull a "
                                  "stable per-account value (an id) from the response."))
            continue
        ids[p.name] = who.identity
        v.checks.append(Check(f"session:{p.name}", "pass",
                              f"{how} -> session, identity {untrusted(who.identity, 60)}"))

    if len(ids) < 2:
        v.checks.append(Check("independence", "skip",
                              "needs a session for both principals"))
        return v

    # 4. the two contexts are genuinely two accounts
    if ids[VICTIM.name] == ids[ATTACKER.name]:
        v.checks.append(Check("independence", "fail",
                              f"both principals resolve to {untrusted(ids[VICTIM.name], 60)}",
                              "Give each principal its own account in `accounts`, and make "
                              "sure the session is carried per principal (cookie jar or "
                              "bearer token), not shared."))
    else:
        v.checks.append(Check("independence", "pass",
                              "the two principals resolve to two different accounts"))

    # 5. positive control: there is a ground truth to compare against at all
    if profile.canary == "natural":
        canary, ref = _check_natural_canary(inner, profile, v)
    else:
        canary = "tpihunter-validate-" + secrets.token_hex(12)
        planted = inner.plant_marker(VICTIM, canary)
        ref = planted.extracted.get("ref")
        back = inner.read_marker(VICTIM)
        if back.extracted.get("value") != canary:
            v.checks.append(Check("canary", "fail",
                                  "the victim could not read back what it just planted",
                                  "Fix oracle.plant_marker / oracle.read_marker: they must "
                                  "write and read the SAME private per-account field, and "
                                  "read_marker.extract.value must point at it."))
            canary = None
        else:
            v.artifacts.append(f"marker on {profile.accounts[VICTIM.name].email} "
                               f"(left holding a validation canary)")
            v.checks.append(Check("canary", "pass", "planted and read back by the owner"))

    # 6. the by-reference route works for its owner, and is refused for anyone else
    if canary is None or ref is None or "read_marker_by_ref" not in profile.oracle:
        v.checks.append(Check("by_ref", "skip",
                              "profile declares no read_marker_by_ref",
                              "Add oracle.read_marker_by_ref to let the oracle ask the "
                              "direct-object question; without it a whole bug class is "
                              "invisible.", blocking=False))
    else:
        own = inner.read_marker(VICTIM, ref=ref)
        if own.extracted.get("value") != canary:
            v.checks.append(Check("by_ref", "fail",
                                  "the owner cannot read its own resource by reference",
                                  "Fix oracle.read_marker_by_ref — {ref} must name the "
                                  "resource that plant_marker's extract.ref returned."))
        else:
            v.checks.append(Check("by_ref", "pass", "the owner can read its own resource"))
            leak = inner.read_marker(ATTACKER, ref=ref)
            if leak.extracted.get("value") == canary:
                v.checks.append(Check("baseline_scoping", "fail",
                                      "a SECOND account can already read the victim's "
                                      "resource before any attack — this target has an "
                                      "object-level authorization bug (AUTHZ-1) independent "
                                      "of anything this tool does",
                                      "This is a finding, not a profile error. Report it; "
                                      "expect the bystander control to reclassify "
                                      "confluence findings here as AUTHZ-1.",
                                      blocking=False))
            else:
                v.checks.append(Check("baseline_scoping", "pass",
                                      "a second account is refused the victim's resource"))
            never = inner.read_marker(ATTACKER, ref=NEVER_VALID_REF)
            if never.extracted.get("value") is not None:
                v.checks.append(Check("negative_control", "fail",
                                      "a reference that names nothing still returned data",
                                      "The read endpoint is unscoped; by-reference reads "
                                      "cannot be used as evidence until it is fixed."))
            else:
                v.checks.append(Check("negative_control", "pass",
                                      "an invalid reference is refused"))

    # 7a. natural mode only: the value must not be a constant every account shares
    if profile.canary == "natural" and canary is not None:
        if "bystander" not in profile.accounts:
            v.checks.append(Check("canary_distinct", "skip",
                                  "no bystander account — a constant cannot be ruled out",
                                  "Add a third account; in natural mode it is what proves "
                                  "the field holds per-account state.", blocking=False))
        else:
            enrolled = inner.enrol_bystander(BYSTANDER)
            other = (inner.read_marker(BYSTANDER).extracted.get("value")
                     if enrolled.ok else None)
            if other is not None and str(other).strip() == canary:
                v.checks.append(Check("canary_distinct", "fail",
                                      "an uninvolved account's copy of the same field holds "
                                      "the SAME value — it is a constant, not private state",
                                      "Point oracle.read_marker at a field that differs "
                                      "between accounts."))
            else:
                v.checks.append(Check("canary_distinct", "pass",
                                      "the value differs from an uninvolved account's"))

    # 7. the diagnosis control
    if "bystander" not in profile.accounts:
        v.checks.append(Check("bystander", "skip",
                              "no 'bystander' account in the profile",
                              "Add a third account. Without it the oracle can detect a "
                              "takeover but cannot tell laundering from a plain "
                              "authorization bug.", blocking=False))
    else:
        obs = inner.enrol_bystander(BYSTANDER)
        who = inner.whoami(BYSTANDER) if obs.ok else None
        if not obs.ok or not who or not who.identity:
            v.checks.append(Check("bystander", "fail", untrusted(redact(obs.note), 200),
                                  "The bystander account must be able to log in (or "
                                  "register) like any other.", blocking=False))
        elif who.identity in ids.values():
            v.checks.append(Check("bystander", "fail",
                                  "the bystander resolves to a principal's account",
                                  "Give the bystander its own, separate account.",
                                  blocking=False))
        else:
            v.checks.append(Check("bystander", "pass", "third account enrolled, independent"))

    # 8. the out-of-band channel
    if profile.channel is None or "reset_request" not in profile.actions:
        v.checks.append(Check("channel", "skip",
                              "no channel and/or no reset_request declared",
                              "Wire `channel` to a mailbox you control so reset and "
                              "magic-link flows can be driven; they are where much of "
                              "the ATO surface lives.", blocking=False))
    else:
        email = profile.accounts[VICTIM.name].email
        inner.reset_request(VICTIM, email)
        token = inner._channel_token(VICTIM, email)
        if not token:
            v.checks.append(Check("channel", "fail",
                                  "reset_request sent, but no token came back from the channel",
                                  "Fix `channel` (path/extract.token): it must fetch the "
                                  "message delivered to {email} and pull the token out.",
                                  blocking=False))
        else:
            v.artifacts.append(f"an outstanding password-reset token for {email}")
            v.checks.append(Check("channel", "pass", "a reset token was delivered and read"))

    return v
