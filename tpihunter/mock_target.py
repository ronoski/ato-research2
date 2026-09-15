"""A deliberately vulnerable in-memory auth system + its adapter.

This lets the oracle be exercised end-to-end without a live target. It implements
the pre-account-hijacking laundering bug from Section 6 of the paper: an attacker
registers the victim's future email (an unproven 'claimed' binding, plus a
credential and a session), the victim later signs in via SSO which marks the email
'verified' but — the bug — does not revoke the attacker's pre-existing binding.

Set patched=True to get the TPI-1 (revoke-on-rebind) fix and confirm the oracle
reports SAFE. That toggle is the oracle's own regression test: a detector that
fired on both would be worthless.
"""
from __future__ import annotations

import secrets
from typing import Optional

from .channels import InMemoryInbox
from .types import Channel, Identifier, Observation, Principal, ProofEvent


class _Account:
    def __init__(self, account_id: str, email: str) -> None:
        self.id = account_id
        self.email = email
        self.email_verified = False
        self.password: Optional[str] = None      # one credential bound to the row
        self.marker: Optional[str] = None        # the private resource that holds a canary
        self.sessions: set[str] = set()


class VulnerableTarget:
    def __init__(self, patched: bool = False, revokes: Optional[set] = None) -> None:
        self.patched = patched
        # Which credential-mutating transitions actually revoke predating sessions.
        # This is the revocation-matrix substrate: real systems fix one flow and forget
        # a parallel one (e.g. a reset revokes but a plane-local logout does not). Empty
        # default => logout leaves captured tokens alive (a T-ATO-05-shaped latent bug).
        self.revokes: set = set(revokes or ())
        self.accounts: dict[str, _Account] = {}
        self.by_email: dict[str, str] = {}
        self.sessions: dict[str, str] = {}        # token -> account_id
        self.reset_tokens: dict[str, tuple[str, str]] = {}   # token -> (account_id, email_at_request)
        self._n = 0

    def _new_id(self) -> str:
        self._n += 1
        return f"acct_{self._n}"

    def _issue(self, aid: str) -> str:
        tok = secrets.token_hex(8)
        self.sessions[tok] = aid
        self.accounts[aid].sessions.add(tok)
        return tok

    def _get_or_create(self, email: str) -> _Account:
        aid = self.by_email.get(email)
        if aid is None:
            aid = self._new_id()
            self.accounts[aid] = _Account(aid, email)
            self.by_email[email] = aid
        return self.accounts[aid]

    def register(self, email: str, password: str) -> tuple[Optional[str], Optional[str]]:
        if self.by_email.get(email) is not None and self.patched:
            # correct behaviour: registration cannot attach a fresh credential/session
            # to an email that already has an account (closes the victim-first ordering
            # where the attacker registers *onto* an account the victim already owns).
            return None, None
        acc = self._get_or_create(email)
        acc.password = password       # 'claimed' email + a knowledge credential
        return self._issue(acc.id), acc.id

    def login(self, email: str, password: str) -> tuple[Optional[str], Optional[str]]:
        aid = self.by_email.get(email)
        if aid and self.accounts[aid].password == password:
            return self._issue(aid), aid
        return None, None

    def sso_login(self, email: str) -> tuple[str, str]:
        acc = self._get_or_create(email)
        if self.patched:
            # TPI-1 revoke-on-rebind: sever every binding we can no longer justify
            # before attaching the freshly-proven identity.
            for tok in list(acc.sessions):
                self.sessions.pop(tok, None)
            acc.sessions.clear()
            acc.password = None
        acc.email_verified = True      # the victim's IdP proof upgrades the row
        return self._issue(acc.id), acc.id

    def magic_link(self, email: str) -> tuple[str, str]:
        # A passwordless email login: proving inbox control also verifies the row.
        # NOTE: the revoke-on-rebind fix (see sso_login) was NEVER applied here — a
        # realistic "fixed one flow, forgot the parallel one" gap. So this launders
        # even on the patched target, and only reachable if the agent knows to try it.
        acc = self._get_or_create(email)
        acc.email_verified = True
        return self._issue(acc.id), acc.id

    def reset_request(self, email: str) -> Optional[str]:
        aid = self.by_email.get(email)
        if aid is None:
            return None
        tok = secrets.token_hex(8)
        self.reset_tokens[tok] = (aid, email)
        return tok

    def reset_consume(self, token: str, new_password: str) -> tuple[Optional[str], Optional[str]]:
        rec = self.reset_tokens.pop(token, None)
        if rec is None:
            return None, None
        aid, _email_at_request = rec
        acc = self.accounts[aid]
        if self.patched or "reset_consume" in self.revokes:
            # TPI-4 session-kill-on-credential-change: a reset invalidates every
            # session whose provenance predates it.
            for tok in list(acc.sessions):
                self.sessions.pop(tok, None)
            acc.sessions.clear()
        acc.password = new_password
        return self._issue(aid), aid

    def logout(self, token: Optional[str]) -> bool:
        """End a session. Whether it actually revokes the *credential* (removes the
        token server-side) depends on `revokes` — a plane-local logout that only clears
        client state leaves the token alive, which is the laundering the matrix hunts."""
        if not token:
            return False
        acc = self.account_of(token)
        if "logout" in self.revokes:
            self.sessions.pop(token, None)
            if acc:
                acc.sessions.discard(token)
        return acc is not None

    def account_of(self, token: Optional[str]) -> Optional[_Account]:
        aid = self.sessions.get(token) if token else None
        return self.accounts.get(aid) if aid else None


class MockAdapter:
    """Binds the alphabet Sigma to the mock, keeping one session per principal."""

    def __init__(self, patched: bool = False, control: Optional[dict[str, set[str]]] = None,
                 revokes: Optional[set] = None) -> None:
        self.t = VulnerableTarget(patched=patched, revokes=revokes)
        self.inbox = InMemoryInbox()
        self.sess: dict[str, Optional[str]] = {}     # principal name -> session token
        # Who genuinely controls which identifier (IdP account / inbox). Channel-proof
        # actions (sso_login, reset_consume) only succeed for a principal who controls
        # the identifier — modelling the C in a ProofEvent <p, r, c, t>.
        self.control: dict[str, set[str]] = {k: set(v) for k, v in (control or {}).items()}

    def _controls(self, p: Principal, ident: str) -> bool:
        return ident in self.control.get(p.name, set())

    # -- identity lifecycle ---------------------------------------------------
    def register(self, p: Principal, email: str, password: str) -> Observation:
        tok, aid = self.t.register(email, password)
        if tok:
            self.sess[p.name] = tok
        proof = ProofEvent(p, Identifier("credential", email), Channel.KNOWLEDGE) if tok else None
        return Observation(tok is not None, identity=aid, proof=proof,
                           note=f"{p} registered {email} (email still 'claimed')")

    def login(self, p: Principal, email: str, password: str) -> Observation:
        tok, aid = self.t.login(email, password)
        if tok:
            self.sess[p.name] = tok
        proof = ProofEvent(p, Identifier("credential", email), Channel.KNOWLEDGE)
        return Observation(tok is not None, identity=aid, proof=proof)

    def sso_login(self, p: Principal, email: str) -> Observation:
        if not self._controls(p, email):
            return Observation(False, note=f"{p} does not control {email} at the IdP")
        tok, aid = self.t.sso_login(email)
        self.sess[p.name] = tok
        proof = ProofEvent(p, Identifier("email", email), Channel.IDP)
        return Observation(True, identity=aid, proof=proof,
                           note=f"{p} proved control of {email} via IdP; row now 'verified'")

    def magic_link(self, p: Principal, email: str) -> Observation:
        # A passwordless email-login flow, outside the default alphabet. Needs inbox
        # control, like a reset. The agent must know such flows exist to try it.
        if not self._controls(p, email):
            return Observation(False, note=f"{p} cannot read the {email} inbox")
        tok, aid = self.t.magic_link(email)
        self.sess[p.name] = tok
        proof = ProofEvent(p, Identifier("email", email), Channel.EMAIL)
        return Observation(True, identity=aid, proof=proof,
                           note=f"{p} logged in via magic link; row now 'verified'")

    def reset_request(self, p: Principal, email: str) -> Observation:
        tok = self.t.reset_request(email)
        if tok:
            self.inbox.deliver(email, f"Reset your password: http://target/reset?token={tok}")
        return Observation(tok is not None, extracted={"token": tok},
                           note=f"{p} requested a password reset for {email} (token emailed)")

    def reset_consume(self, p: Principal, email: str, new_password: str) -> Observation:
        if not self._controls(p, email):
            return Observation(False, note=f"{p} cannot read the {email} inbox")
        link = self.inbox.latest_link(email, "http")
        token = link.split("token=")[-1] if link else None
        tok, aid = self.t.reset_consume(token, new_password) if token else (None, None)
        if tok:
            self.sess[p.name] = tok
        proof = ProofEvent(p, Identifier("email", email), Channel.EMAIL)
        return Observation(tok is not None, identity=aid, proof=proof,
                           note=f"{p} consumed the reset token from the {email} inbox and set a new password")

    def logout(self, p: Principal) -> Observation:
        token = self.sess.get(p.name)
        self.t.logout(token)
        self.sess[p.name] = None
        return Observation(True, note=f"{p} logged out")

    # -- oracle surface -------------------------------------------------------
    def whoami(self, p: Principal) -> Observation:
        acc = self.t.account_of(self.sess.get(p.name))
        return Observation(acc is not None, identity=(acc.email if acc else None))

    # -- binding lifecycle surface (revocation matrix) ------------------------
    def capture_binding(self, p: Principal) -> Optional[str]:
        """Snapshot the principal's current durable credential (its session token), so
        it can be re-presented later — the analogue of capturing a bearer token to test
        whether a mutation revokes it."""
        return self.sess.get(p.name)

    def present_binding(self, handle: Optional[str]) -> Observation:
        """Present a previously-captured credential directly (not via a principal's live
        session) and report whether it still authenticates, and to what identity."""
        acc = self.t.account_of(handle)
        return Observation(acc is not None, identity=(acc.email if acc else None))

    def plant_marker(self, p: Principal, value: str) -> Observation:
        acc = self.t.account_of(self.sess.get(p.name))
        if acc:
            acc.marker = value
        return Observation(acc is not None, extracted={"ref": acc.id if acc else None})

    def read_marker(self, p: Principal, ref: Optional[str] = None) -> Observation:
        acc = self.t.account_of(self.sess.get(p.name))
        my_id = acc.id if acc else None
        if ref is not None and ref != my_id:
            # a correctly-scoped app denies reading a resource this session doesn't own
            return Observation(False, extracted={"value": None}, note="cross-account read denied")
        target = ref if ref is not None else my_id
        val = self.t.accounts[target].marker if target in self.t.accounts else None
        return Observation(val is not None, extracted={"value": val})

    def write_marker(self, p: Principal, value: str, ref: Optional[str] = None) -> Observation:
        acc = self.t.account_of(self.sess.get(p.name))
        my_id = acc.id if acc else None
        if ref is not None and ref != my_id:
            return Observation(False, note="cross-account write denied")
        target = ref if ref is not None else my_id
        if target in self.t.accounts:
            self.t.accounts[target].marker = value
            return Observation(True)
        return Observation(False)
