"""Core domain types for TPI-based account-takeover hunting.

These mirror the objects in the working paper *Provenance, Not Reachability*:
principals, identifiers, channels, proof events, bindings, and the observations
the harness returns. Everything the oracle reasons about is expressed in these
terms, so a verdict can always be traced back to the Trust-Provenance Integrity
(TPI) invariant it violates.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Channel(str, Enum):
    """The medium over which control of a resource is demonstrated."""
    KNOWLEDGE = "knowledge"   # a password / shared secret
    EMAIL = "email"           # control of an inbox
    SMS = "sms"               # control of a phone number
    TOTP = "totp"             # possession of an authenticator
    WEBAUTHN = "webauthn"     # possession of a hardware credential
    IDP = "idp"               # control of a federated account
    NONE = "none"             # an assertion carrying no proof at all


class TrustLevel(str, Enum):
    """The identifier-trust lattice (Fig. 2, top)."""
    UNKNOWN = "unknown"
    CLAIMED = "claimed"       # asserted, never proven -> attacker-settable
    PENDING = "pending"
    VERIFIED = "verified"


class SessionLevel(str, Enum):
    """The session-trust lattice (Fig. 2, bottom)."""
    ANON = "anon"
    PARTIAL = "partial"
    FULL = "full"
    STEP_UP = "step_up"


@dataclass(frozen=True)
class Principal:
    """An actor with its own, independent authenticated context."""
    name: str

    def __str__(self) -> str:
        return self.name


@dataclass(frozen=True)
class Identifier:
    kind: str    # "email" | "phone" | "username" | "oauth_sub" | "credential"
    value: str

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


@dataclass(frozen=True)
class ProofEvent:
    """P = <p, r, c, t>: principal p demonstrated control of resource r over
    channel c at time t (Definition 2)."""
    principal: Principal
    resource: Identifier
    channel: Channel
    t: float = field(default_factory=time.time)

    def __str__(self) -> str:
        return f"P<{self.principal}, {self.resource}, {self.channel.value}>"


@dataclass
class Binding:
    """A privileged fact the system holds: a session->account binding, an
    identifier->account 'verified' binding, or a capability->session grant
    (Definition 1). `provenance` is the proof events the system actually used
    to justify it."""
    kind: str                 # "session" | "identifier_verified" | "credential"
    account_id: str
    empowers: Principal
    resource: str
    provenance: list = field(default_factory=list)

    def __str__(self) -> str:
        prov = ", ".join(str(p) for p in self.provenance) or "(none)"
        return f"B[{self.kind} acct={self.account_id} empowers={self.empowers} prov={prov}]"


@dataclass
class Observation:
    """The structured result of one alphabet action, executed as one principal."""
    ok: bool
    status: Optional[int] = None
    identity: Optional[str] = None          # account the context resolved to, if any
    extracted: dict = field(default_factory=dict)   # tokens, links, codes, refs, marker values
    proof: Optional[ProofEvent] = None      # the proof event this action emitted, if any
    session: Optional["SessionLevel"] = None  # the session-trust level this action left the
                                              # context at. Without this the lattice in Fig. 2
                                              # is unobservable, so no probe can distinguish a
                                              # first-factor (PARTIAL) context from a FULL one.
    note: str = ""
