"""The two-principal adapter interface — the surface an autonomous hunter drives.

Laundering (the dominant ATO class) is invisible with a single session, because
it needs two principals interleaving through one shared store row. So the adapter
keeps an *independent* authenticated context per principal, and every action is
executed *as* a named principal. Each method is one symbol of the alphabet Sigma;
each returns a structured `Observation` (including any `ProofEvent` it emitted).

To hunt a real target, implement `TargetAdapter` with an httpx client per
principal: back `register/login/sso_login/reset_*` with the app's real endpoints,
pull tokens and links from responses and the channel providers, and back the
oracle surface (`whoami / plant_marker / read_marker / write_marker`) with a
"my account" endpoint plus a private per-account resource (a note, a profile
field) that holds the canary.

**Wrap it.** A live adapter is never used bare: `policy.guard(adapter, policy)`
checks every action against the engagement's rules of engagement — the identifier
allowlist, the host allowlist, the destructive-action gates, the request budget —
and records what was actually done. The guard is itself an adapter, so it composes
with everything here. Three rules that are the adapter author's to keep, because
nothing outside the adapter can:

  * **One transport per principal.** Separate cookie jars / token stores, no shared
    default client. Two principals sharing one context is not a subtle bug: it makes
    the oracle's independence control fail and voids every verdict in the run.
  * **Never infer scope from the target.** A redirect, a link in a delivered email, or
    an endpoint a model proposed are all target-controlled. Pass them through
    `policy.check_url()` before following them.
  * **Own accounts only.** Everything here assumes both principals are accounts you
    created for this engagement. The oracle plants a canary and (with `mutate=True`)
    writes; neither is acceptable against a real user's account.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from .types import Observation, Principal, ProofEvent

# The alphabet Sigma, each symbol tagged conceptually with <principal, channel, resource>.
ALPHABET = [
    "register", "login", "sso_login",
    "reset_request", "reset_consume",
    "email_change_request", "email_change_confirm",
    "logout",
    # oracle surface
    "whoami", "plant_marker", "read_marker", "write_marker",
]


@dataclass
class TraceStep:
    principal: Optional[Principal]
    action: str
    params: dict
    obs: Observation


@dataclass
class Trace:
    """The ordered record of a probe: what each principal did and what came back.
    The oracle reads this to diagnose *which* TPI clause failed."""
    steps: list[TraceStep] = field(default_factory=list)

    def record(self, principal, action, params, obs) -> None:
        self.steps.append(TraceStep(principal, action, params, obs))

    def proofs(self) -> list[ProofEvent]:
        return [s.obs.proof for s in self.steps if s.obs and s.obs.proof]

    def by_principal(self, p: Principal) -> list[TraceStep]:
        return [s for s in self.steps if s.principal == p]


@runtime_checkable
class TargetAdapter(Protocol):
    """Implement one per target. The adapter owns per-principal session state."""

    # --- alphabet Sigma: identity lifecycle ---------------------------------
    def register(self, p: Principal, email: str, password: str) -> Observation: ...
    def login(self, p: Principal, email: str, password: str) -> Observation: ...
    def sso_login(self, p: Principal, email: str) -> Observation: ...
    def reset_request(self, p: Principal, email: str) -> Observation: ...
    def reset_consume(self, p: Principal, email: str, new_password: str) -> Observation: ...
    def logout(self, p: Principal) -> Observation: ...

    # --- oracle surface: ground-truth probes --------------------------------
    def whoami(self, p: Principal) -> Observation:
        """Which account does p's current context resolve to? identity in obs.identity."""
        ...

    def plant_marker(self, p: Principal, value: str) -> Observation:
        """Store a secret in p's own private resource; obs.extracted['ref'] = its id."""
        ...

    def read_marker(self, p: Principal, ref: Optional[str] = None) -> Observation:
        """Read p's own marker (ref=None) or a specific resource `ref`;
        value in obs.extracted['value']. A correctly-scoped app denies a `ref`
        that p's session does not own."""
        ...

    def write_marker(self, p: Principal, value: str, ref: Optional[str] = None) -> Observation:
        """Mutate p's own resource, or a specific `ref` if the app allows it."""
        ...

    # --- optional: the bystander control ------------------------------------
    def enrol_bystander(self, p: Principal) -> Observation:
        """OPTIONAL. Authenticate `p` as an account that takes NO part in the probe.

        The oracle uses it as a control on its own diagnosis: if an uninvolved account can
        read the victim's resource just as well as the attacker can, the access is not
        provenance-specific and the finding is an object-level authorization bug, not
        laundering (`clauses.BROAD_AUTHORIZATION`). Without it the oracle still detects the
        takeover — it just cannot tell the two classes apart, and says so in
        `Verdict.controls`.

        Implement it by logging in a THIRD account you created for the engagement; its
        identifier must be in the engagement policy's allowlist like any other. Return a
        failed `Observation` if no such account is available.
        """
        ...
