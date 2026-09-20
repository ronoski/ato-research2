"""Rules of engagement, enforced in the tool rather than trusted to the operator.

Everything else in this package is aimed at a mock. The moment it is aimed at a real
system it becomes an offensive tool driven by a model that is choosing its own next
action from the target's own responses, and the interesting failure is no longer a bad
verdict — it is a correct verdict about the wrong account, a password reset on a
production user, or a run that keeps going after it was supposed to stop.

Those are not things to leave to a careful adapter author. `EngagementPolicy` states the
engagement in data, `guard()` wraps any adapter so every action is checked against it
before it reaches the target, and `AuditLog` records what was actually done. The wrapper
is an adapter like any other, so it composes with everything already here:

    policy = EngagementPolicy(
        name="acme-bugbounty",
        authorized_by="security@acme.example, ticket SEC-1421, 2026-09-20",
        identifiers={"pentest-a@acme.example", "pentest-v@acme.example"},
        hosts={"staging.acme.example"},
    )
    adapter = guard(AcmeAdapter(...), policy)     # now every call is checked
    verdict, trace = run_plan(adapter, plan, AtoOracle(adapter, attacker, victim))
    print(policy_report(adapter))                 # what the run actually did

What it enforces, and why each one is a mistake someone has actually made:

  * **Explicit authorization.** A policy with no `authorized_by` refuses every action.
    There is no default-permissive mode and no "just this once" flag; the datum that
    says a human authorized this is the same datum the tool checks.
  * **Identifier allowlist.** Every account identifier an action touches must be one
    named in the policy. This is the control that stops a probe — or a model that read
    a real address out of a response — from acting on a bystander's account. A breach
    here raises `ScopeViolation`: it is never handled by continuing.
  * **Host allowlist.** Same, for adapters that talk HTTP: `check_url()` refuses a URL
    whose host is not in scope, which is what a redirect, a link in a delivered email,
    or a model-proposed endpoint can otherwise walk you into.
  * **Destructive-action gates.** Credential changes (password reset, email change) and
    cross-principal writes are off unless the policy turns them on, because they are the
    actions that cannot be undone from outside the system.
  * **A hard action budget and a rate limit.** A hunting loop that has lost the plot
    should stop, not saturate someone's login endpoint. The budget fails closed.
  * **Dry run.** `dry_run=True` executes nothing and records what *would* have run, so a
    live plan can be reviewed before it is a live plan.
  * **An audit trail.** Every action, with a redacted parameter record and the outcome.
    An engagement that cannot say what it did has no answer when asked.

None of this makes an unauthorized test legitimate. It makes an authorized one
accountable, and it makes the common accidents impossible rather than unlikely.
"""
from __future__ import annotations

import functools
import inspect
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlsplit

from .redact import redact
from .types import Observation, Principal

# Param names whose value is an account identifier, so it must be in scope.
IDENTIFIER_PARAMS = frozenset({"email", "alias", "new_email", "username", "phone",
                               "identifier", "account", "address", "recovery_email"})

# Actions that change a credential or an identity binding on the account.
CREDENTIAL_ACTIONS = frozenset({"reset_consume", "email_change", "email_change_confirm",
                                "password_change", "enroll_factor", "add_alias"})


class PolicyViolation(RuntimeError):
    """Base class for a refusal the operator has to know about."""


class ScopeViolation(PolicyViolation):
    """An action would touch an identifier or host outside the authorized scope."""


class BudgetExhausted(PolicyViolation):
    """The engagement's action budget is spent; the run stopped rather than continued."""


@dataclass(frozen=True)
class EngagementPolicy:
    """The rules of one engagement, as data.

    `identifiers` is the whole allowlist of accounts the tool may act on — the test
    accounts you created for this engagement, and nothing else. `hosts` is the
    equivalent for network destinations. Both are exact matches; `hosts` additionally
    admits subdomains of a listed host, which is how in-scope estates are usually
    written, and never a suffix match on a bare string (so `acme.example` in scope does
    not put `notacme.example` in scope).
    """
    name: str
    authorized_by: str = ""                      # who authorized this, and where it is recorded
    identifiers: frozenset = frozenset()         # account identifiers in scope
    hosts: frozenset = frozenset()               # hostnames in scope (for an HTTP adapter)
    allow_credential_change: bool = False        # resets, email changes, factor enrolment
    allow_cross_principal_write: bool = False    # the oracle's destructive write probe
    max_actions: int = 500                       # hard cap; fails closed
    min_interval: float = 0.0                    # seconds between actions (be a good citizen)
    dry_run: bool = False                        # record what would run; execute nothing

    @property
    def authorized(self) -> bool:
        return bool(self.authorized_by.strip())


    # -- checks ---------------------------------------------------------------
    def preflight(self) -> list[str]:
        """Problems that must be fixed before this policy may be used. Empty == ready."""
        problems = []
        if not self.authorized:
            problems.append("authorized_by is empty: no action will be permitted until it "
                            "names who authorized this engagement and where that is recorded")
        if not self.identifiers:
            problems.append("identifiers is empty: no account is in scope, so every action "
                            "would be refused")
        if self.max_actions <= 0:
            problems.append("max_actions must be positive")
        return problems

    def check_identifier(self, value: str) -> Optional[str]:
        return None if value in self.identifiers else (
            f"identifier {value!r} is not in the authorized scope for '{self.name}' "
            f"({len(self.identifiers)} identifier(s) in scope)")

    def check_host(self, host: str) -> Optional[str]:
        host = (host or "").lower().rstrip(".")
        for allowed in self.hosts:
            a = allowed.lower().rstrip(".")
            if host == a or host.endswith("." + a):
                return None
        return f"host {host!r} is not in the authorized scope for '{self.name}'"

    def check_url(self, url: str) -> Optional[str]:
        """Refuse a URL outside scope — the check a redirect or an emailed link needs."""
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return f"refusing non-HTTP URL scheme {parts.scheme!r}"
        return self.check_host(parts.hostname or "")


# The policy a mock target runs under: everything permitted, because nothing is real.
# It exists so the guard can be exercised in tests and demos; never copy it for a target.
MOCK_POLICY = EngagementPolicy(
    name="built-in-mock",
    authorized_by="in-memory mock target owned by this process",
    identifiers=frozenset(),         # see `for_mock()`, which fills in the run's identifiers
    allow_credential_change=True,
    allow_cross_principal_write=True,
    max_actions=100_000,
)


def for_mock(*identifiers: str) -> EngagementPolicy:
    """A permissive policy scoped to the given mock identifiers."""
    from dataclasses import replace
    return replace(MOCK_POLICY, identifiers=frozenset(identifiers))


@dataclass
class AuditRecord:
    t: float
    principal: Optional[str]
    action: str
    params: dict
    outcome: str          # ok | failed | refused | dry-run
    note: str = ""

    def render(self) -> str:
        stamp = time.strftime("%H:%M:%S", time.gmtime(self.t))
        args = " ".join(f"{k}={v}" for k, v in sorted(self.params.items()))
        tail = f"  — {self.note}" if self.note else ""
        return f"{stamp}  {self.outcome:<8} {self.principal or '-':<10} {self.action}({args}){tail}"


@dataclass
class AuditLog:
    records: list = field(default_factory=list)

    def add(self, **kw) -> None:
        self.records.append(AuditRecord(t=time.time(), **kw))

    def render(self) -> str:
        return "\n".join(r.render() for r in self.records)

    def counts(self) -> dict:
        out: dict = {}
        for r in self.records:
            out[r.outcome] = out.get(r.outcome, 0) + 1
        return out


class GuardedAdapter:
    """Wrap a `TargetAdapter` so every action is checked against an `EngagementPolicy`.

    Anything not defined here passes through to the inner adapter, so the wrapper is a
    drop-in for the alphabet, the oracle surface, and the matrix's binding surface alike.
    """

    # The oracle's and the matrix's measurement surface: reads that carry no account
    # identifier. They are still budgeted and audited — a read is a request against
    # someone's service — but not gated as destructive, because they *are* the experiment.
    # `read_marker(ref=...)` is included: the only refs the oracle ever presents are one it
    # planted itself and a deliberately-invalid sentinel, never a value the target supplied.
    _READ_ONLY = frozenset({"whoami", "read_marker", "planes", "capture_binding",
                            "present_binding"})

    def __init__(self, inner, policy: EngagementPolicy, audit: Optional[AuditLog] = None) -> None:
        self._inner = inner
        self._policy = policy
        self._audit = audit if audit is not None else AuditLog()
        self._used = 0
        self._last = 0.0

    # -- introspection --------------------------------------------------------
    @property
    def policy(self) -> EngagementPolicy:
        return self._policy

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def actions_used(self) -> int:
        return self._used

    # -- the gate -------------------------------------------------------------
    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        target = getattr(self._inner, name)
        if not callable(target):
            return target

        @functools.wraps(target)      # keeps the inner signature visible to the dispatcher
        def guarded(*args, **kwargs):
            params = _bind(target, args, kwargs)
            principal = next((v for v in list(args) + list(kwargs.values())
                              if isinstance(v, Principal)), None)
            return self._dispatch(name, target, principal, params, args, kwargs)
        return guarded

    def _dispatch(self, action, target, principal, params, args, kwargs):
        try:
            refusal = self._refusal(action, params)
        except PolicyViolation as e:
            # a breach is recorded before it is raised: the audit trail has to show the
            # attempt, or the engagement record is missing the one event that mattered
            self._audit.add(principal=str(principal) if principal else None, action=action,
                            params=redact(_stringify(params)), outcome="refused",
                            note=f"{type(e).__name__}: {e}")
            raise
        if refusal is not None:
            self._audit.add(principal=str(principal) if principal else None, action=action,
                            params=redact(_stringify(params)), outcome="refused", note=refusal)
            return Observation(False, note=f"refused by engagement policy: {refusal}")

        if self._policy.dry_run:
            self._audit.add(principal=str(principal) if principal else None, action=action,
                            params=redact(_stringify(params)), outcome="dry-run",
                            note="not executed (policy.dry_run)")
            return Observation(False, note="dry run: not executed")

        self._throttle()
        self._used += 1
        result = target(*args, **kwargs)
        ok = bool(getattr(result, "ok", True))
        self._audit.add(principal=str(principal) if principal else None, action=action,
                        params=redact(_stringify(params)),
                        outcome="ok" if ok else "failed",
                        note=redact(getattr(result, "note", "") or ""))
        return result

    def _refusal(self, action: str, params: dict) -> Optional[str]:
        """A reason to refuse, or None. Scope breaches and budget exhaustion raise instead:
        continuing past either is not a decision this wrapper is entitled to make."""
        if not self._policy.authorized:
            raise ScopeViolation(
                f"engagement policy '{self._policy.name}' has no authorized_by; refusing "
                f"every action. Record who authorized this test before running it.")

        for key, value in params.items():
            if key in IDENTIFIER_PARAMS and isinstance(value, str):
                problem = self._policy.check_identifier(value)
                if problem:
                    raise ScopeViolation(f"{action}: {problem}")

        # The budget is checked before the read-only exemption: a read is still a request
        # against someone's service, and a loop that has lost the plot reads in a tight loop.
        if self._used >= self._policy.max_actions:
            raise BudgetExhausted(
                f"engagement '{self._policy.name}' hit its budget of "
                f"{self._policy.max_actions} actions; stopping rather than continuing")

        if action in self._READ_ONLY:
            return None
        if action in CREDENTIAL_ACTIONS and not self._policy.allow_credential_change:
            return (f"'{action}' changes a credential and the policy does not allow it "
                    f"(set allow_credential_change=True once the owner has agreed)")
        if action == "write_marker" and params.get("ref") is not None \
                and not self._policy.allow_cross_principal_write:
            return ("write_marker targets another principal's resource and the policy does "
                    "not allow cross-principal writes (set allow_cross_principal_write=True)")
        return None

    def _throttle(self) -> None:
        gap = self._policy.min_interval
        if gap <= 0:
            return
        wait = self._last + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()


def _bind(target, args, kwargs) -> dict:
    """Name every argument, positional ones included.

    The built-in alphabet is dispatched positionally (`a.register(p, email, password)`),
    so a guard that only inspected keyword arguments would check nothing on exactly the
    calls that matter. Binding to the inner signature is what makes the identifier
    allowlist real rather than decorative."""
    try:
        bound = inspect.signature(target).bind_partial(*args, **kwargs)
        return {k: v for k, v in bound.arguments.items() if not isinstance(v, Principal)}
    except (TypeError, ValueError):
        out = {f"arg{i}": a for i, a in enumerate(args) if not isinstance(a, Principal)}
        out.update({k: v for k, v in kwargs.items() if not isinstance(v, Principal)})
        return out


def _stringify(params: dict) -> dict:
    return {k: (v if isinstance(v, (str, int, float, bool, type(None))) else repr(v))
            for k, v in params.items()}


def guard(adapter, policy: EngagementPolicy, audit: Optional[AuditLog] = None) -> GuardedAdapter:
    """Wrap `adapter` so every action is checked against `policy`. Refuses to construct a
    guard around a policy that is not ready, so the failure is at setup, not mid-run."""
    problems = policy.preflight()
    if problems:
        raise ScopeViolation("engagement policy is not ready:\n  - " + "\n  - ".join(problems))
    return GuardedAdapter(adapter, policy, audit)


def policy_report(guarded: GuardedAdapter) -> str:
    """What the run actually did, for the engagement record."""
    p = guarded.policy
    counts = guarded.audit.counts()
    lines = [f"Engagement: {p.name}",
             f"Authorized by: {p.authorized_by}",
             f"Scope: {len(p.identifiers)} identifier(s), {len(p.hosts)} host(s)",
             f"Actions: {guarded.actions_used}/{p.max_actions} used  {counts}",
             f"Credential changes: {'allowed' if p.allow_credential_change else 'refused'}; "
             f"cross-principal writes: {'allowed' if p.allow_cross_principal_write else 'refused'}",
             "", "Audit trail:", guarded.audit.render()]
    return "\n".join(lines)
