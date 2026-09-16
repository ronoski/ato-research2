"""Partial sessions and step-up — making the session-trust lattice testable.

WHY THIS EXISTS
---------------
`types.SessionLevel` declares ANON / PARTIAL / FULL / STEP_UP (Fig. 2, bottom), but
until now nothing in the package produced, observed, or reasoned about anything
between ANON and FULL: the alphabet's `login` was atomic, so every probe could only
ask "is there a session?". An entire ATO class is invisible to that view.

The class: a **multi-phase login**. Factor one (a texted code, a password) yields an
*intermediate credential* — a partial session — which the login flow then refuses to
upgrade without a second factor. That intermediate credential has its own provenance,
and the bug is a *sibling* flow that accepts it for a privileged transition the login
flow would have refused.

This is not hypothetical. It is the shape measured on a live authorized target
(Grab, 2026-09-16): `grabid/v1/phone/token` mints a `preAuthToken` from an SMS code;
`phone/login` refuses to turn it into a session without a `GOOGLE_AUTH` step-up, and
every MFA verify route refuses it too with a flow-scoped error. A recovery route
(`phone/reset/pin`) accepts the same credential into business logic. Login says the
provenance is insufficient; recovery does not ask.

That is TPI-6 (`step-up-not-bypassable`), a provenance GAP: the privileged transition
is reachable with provenance its own primary flow rejects.

The mock below is the smallest target exhibiting it, so the scaffold stays
self-validating: `StepUpTarget(patched=False)` leaks, `patched=True` does not, and
the detector must separate them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .clauses import CLAUSES
from .types import Channel, Identifier, Observation, Principal, ProofEvent, SessionLevel

# ── alphabet extension ────────────────────────────────────────────────────────
# Splitting the atomic `login` into its two real phases is the whole point: a
# learner given only `login` can never visit PARTIAL, so it can never find TPI-6.
FIRST_FACTOR = "login_first_factor"   # ANON -> PARTIAL, mints the intermediate credential
STEPUP_SATISFY = "stepup_satisfy"     # PARTIAL -> FULL, the second factor
SESSION_UPGRADE = "session_upgrade"   # PARTIAL -> FULL *without* a second factor (the login flow)
RECOVERY_MUTATE = "recovery_mutate"   # the privileged sibling transition (reset a factor)

STEPUP_ALPHABET = [FIRST_FACTOR, STEPUP_SATISFY, SESSION_UPGRADE, RECOVERY_MUTATE]

# Output vocabulary, extending sul.py's.
OK_PARTIAL = "OK_PARTIAL"     # an intermediate credential exists; not a session
STEPUP_REQ = "STEPUP_REQ"     # the flow demands a second factor before upgrading
OK_FULL = "OK_FULL"           # a full session
MUTATED = "MUTATED"           # a privileged credential-changing transition completed
DENIED = "DENIED"


@dataclass
class _Acct:
    aid: str
    second_factor: bool = True     # the account has a step-up factor enrolled
    pin: Optional[str] = "pin-original"


@dataclass
class StepUpTarget:
    """Smallest target with a two-phase login and a recovery sibling.

    `patched=False` reproduces the measured shape: `recovery_mutate` accepts a
    PARTIAL credential that `session_upgrade` refuses.
    """
    patched: bool = False
    acct: _Acct = field(default_factory=lambda: _Acct("acct-1"))
    _partial: set = field(default_factory=set)
    _full: set = field(default_factory=set)
    _n: int = 0

    def _mint(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n}"

    # ── phase 1: a texted code buys an intermediate credential, not a session ──
    def first_factor(self) -> Observation:
        t = self._mint("preauth")
        self._partial.add(t)
        return Observation(ok=True, status=200, extracted={"token": t},
                           session=SessionLevel.PARTIAL,
                           proof=ProofEvent(principal=Principal("actor"),
                                            resource=Identifier("phone", "+10000000000"),
                                            channel=Channel.SMS),
                           note="intermediate credential minted from factor one")

    # ── the login flow: refuses to upgrade a PARTIAL credential ───────────────
    def session_upgrade(self, token: Optional[str]) -> Observation:
        if token in self._full:
            return Observation(ok=True, status=200, session=SessionLevel.FULL, note="already full")
        if token in self._partial:
            if self.acct.second_factor:
                # This refusal is the ground truth: the system ITSELF declares this
                # provenance insufficient for a privileged transition.
                return Observation(ok=False, status=401, session=SessionLevel.PARTIAL,
                                   extracted={"authz_req": "STEP_UP"},
                                   note="step-up required; provenance insufficient to upgrade")
            self._partial.discard(token); self._full.add(token)
            return Observation(ok=True, status=200, session=SessionLevel.FULL, note="upgraded")
        return Observation(ok=False, status=401, session=SessionLevel.ANON, note="unknown credential")

    def stepup_satisfy(self, token: Optional[str]) -> Observation:
        if token in self._partial:
            self._partial.discard(token); self._full.add(token)
            return Observation(ok=True, status=200, session=SessionLevel.FULL,
                               proof=ProofEvent(principal=Principal("actor"),
                                                resource=Identifier("oauth_sub", "sub-1"),
                                                channel=Channel.IDP),
                               note="second factor satisfied")
        return Observation(ok=False, status=401, session=SessionLevel.ANON, note="no partial credential")

    # ── the sibling: a privileged, credential-MUTATING transition ─────────────
    def recovery_mutate(self, token: Optional[str], new_pin: str = "pin-attacker") -> Observation:
        full = token in self._full
        partial = token in self._partial
        if not (full or partial):
            return Observation(ok=False, status=401, session=SessionLevel.ANON, note="invalid token")
        if partial and self.patched:
            # The fix: recovery asks the same question login asks.
            return Observation(ok=False, status=401, session=SessionLevel.PARTIAL,
                               extracted={"authz_req": "STEP_UP"},
                               note="step-up required for a credential change")
        self.acct.pin = new_pin
        return Observation(ok=True, status=200, session=SessionLevel.FULL if full else SessionLevel.PARTIAL,
                           extracted={"pin": new_pin},
                           note="second factor rewritten")


# ── the detector ──────────────────────────────────────────────────────────────
@dataclass
class StepUpVerdict:
    severity: str                 # "TAKEOVER" | "SAFE" | "INCONCLUSIVE"
    clause_id: Optional[str]
    evidence: list
    narrative: str


def probe_stepup(target: StepUpTarget) -> StepUpVerdict:
    """Differential probe. The refusal by the PRIMARY flow is the control: without it
    we cannot claim the provenance was insufficient, only that two routes differ."""
    ev: list[str] = []
    o1 = target.first_factor()
    if o1.session is not SessionLevel.PARTIAL:
        return StepUpVerdict("INCONCLUSIVE", None, ev,
                             "factor one did not yield a PARTIAL session; nothing to test.")
    tok = o1.extracted["token"]
    ev.append(f"factor one -> PARTIAL credential ({o1.note})")

    # CONTROL: the primary flow must refuse this exact credential. If it upgrades,
    # the account has no step-up and there is no insufficiency to exploit.
    up = target.session_upgrade(tok)
    if up.ok:
        return StepUpVerdict("INCONCLUSIVE", None, ev,
                             "primary flow upgraded the partial credential; no step-up is enforced, "
                             "so a sibling accepting it proves nothing.")
    ev.append(f"CONTROL FIRED: primary flow refused the same credential "
              f"(status={up.status}, {up.note})")

    # ARM: the privileged sibling, with the credential the primary flow just refused.
    mut = target.recovery_mutate(tok)
    if mut.ok:
        ev.append(f"ARM: privileged sibling ACCEPTED it and mutated the factor ({mut.note})")
        c = CLAUSES["TPI-6"]
        return StepUpVerdict(
            "TAKEOVER", "TPI-6", ev,
            f"A credential the primary flow refused as insufficient (status {up.status}) was "
            f"accepted by a privileged sibling, which rewrote the account's second factor. "
            f"Diagnosis: {c.id} ({c.title}) — {c.mode.value}.")
    ev.append(f"ARM: sibling refused it too (status={mut.status}, {mut.note})")
    return StepUpVerdict("SAFE", None, ev,
                         "every flow reaching the privileged transition refused the partial "
                         "credential; the session lattice is enforced consistently.")
