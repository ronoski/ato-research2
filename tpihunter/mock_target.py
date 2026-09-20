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
import time
from typing import Optional

from .channels import InMemoryInbox
from .creds import password as _password
from .creds import session_id
from .types import Channel, Identifier, Observation, Principal, ProofEvent


class _Account:
    def __init__(self, account_id: str, email: str) -> None:
        self.id = account_id
        self.email = email
        self.email_verified = False
        self.password: Optional[str] = None      # one credential bound to the row
        self.marker: Optional[str] = None        # the private resource that holds a canary
        # A private, stable, high-entropy value the SERVER generates at account creation —
        # a wallet handle, a loyalty id. Nothing plants it, so it is what an engagement
        # that authorises reads and not writes has to use as ground truth (a "natural
        # canary"; see oracle._observe_natural_canary).
        self.handle: str = secrets.token_hex(12)
        self.sessions: set[str] = set()
        self.factors: set[str] = set()           # enrolled 2nd-factor ids (passkey/biometric)
        self.aliases: set[str] = set()           # recovery/secondary emails that resolve here


class VulnerableTarget:
    def __init__(self, patched: bool = False, revokes: Optional[set] = None,
                 planes: Optional[tuple] = None, plane_local: Optional[set] = None,
                 mutation_planes: Optional[dict] = None, revoke_factors: Optional[set] = None,
                 revoke_aliases: bool = False, racy_reset: float = 0.0) -> None:
        self.patched = patched
        # A check-then-act window in reset_consume. Zero (the default) consumes the token
        # atomically; a positive value opens the window a token double-spend needs. This is
        # the race mode's discriminator, the role `patched` plays for the oracle: a detector
        # that fired on both the bug and its fix would be worthless.
        self.racy_reset = float(racy_reset)
        # Whether the revoke-on-rebind fix (patched sso_login) ALSO drops recovery emails an
        # attacker added before the rebind. Default False models the common gap: the fix
        # revoked sessions/password but forgot the parallel recovery-email data, so an
        # attacker-added alias survives and still resolves to the account (a second-identifier
        # laundering only reachable if a probe can pass that non-email identifier).
        self.revoke_aliases = revoke_aliases
        # Which credential-mutating transitions actually revoke predating sessions.
        # This is the revocation-matrix substrate: real systems fix one flow and forget
        # a parallel one (e.g. a reset revokes but a plane-local logout does not). Empty
        # default => logout leaves captured tokens alive (a T-ATO-05-shaped latent bug).
        self.revokes: set = set(revokes or ())
        # Verify-point planes: a credential is checked on several route surfaces owned by
        # different lineages. Revocation may be per-plane state (Grab T-ATO-05). Default is
        # one plane, so the estate behaves globally and legacy behaviour is unchanged.
        self.planes: tuple = tuple(planes) if planes else ("default",)
        # Mutations that revoke ONLY the plane they are issued on (a plane-local logout
        # clears client state on its own plane while the token lives on the others).
        self.plane_local: set = set(plane_local or ())
        self.mutation_planes: dict = dict(mutation_planes or {"logout": "mts", "reset_consume": "auth"})
        # Mutations that revoke enrolled FACTORS (default empty: a factor an attacker
        # enrolled survives the victim's password reset — the durable takeover, Grab T-ATO-22).
        self.revoke_factors: set = set(revoke_factors or ())
        self.accounts: dict[str, _Account] = {}
        self.by_email: dict[str, str] = {}
        self.sessions: dict[str, str] = {}        # token -> account_id (global bookkeeping)
        self.plane_sessions: dict[str, set] = {p: set() for p in self.planes}  # per-plane validity
        self.factors: dict[str, str] = {}         # factor_id -> account_id
        self.reset_tokens: dict[str, tuple[str, str]] = {}   # token -> (account_id, email_at_request)
        self._n = 0

    def _new_id(self) -> str:
        self._n += 1
        return f"acct_{self._n}"

    def _issue(self, aid: str) -> str:
        tok = secrets.token_hex(8)
        self.sessions[tok] = aid
        self.accounts[aid].sessions.add(tok)
        for p in self.planes:                     # a fresh session authenticates everywhere
            self.plane_sessions[p].add(tok)
        return tok

    def _issuing_plane(self, action: str) -> str:
        p = self.mutation_planes.get(action)
        return p if p in self.planes else self.planes[0]

    def _revoke_global(self, token: str, acc: "_Account") -> None:
        self.sessions.pop(token, None)
        acc.sessions.discard(token)
        for p in self.planes:
            self.plane_sessions[p].discard(token)

    def _revoke_sessions(self, acc: "_Account", action: str) -> None:
        """Revoke every session on the account, respecting plane-locality of `action`."""
        for tok in list(acc.sessions):
            if action in self.plane_local:
                self.plane_sessions[self._issuing_plane(action)].discard(tok)
            else:
                self._revoke_global(tok, acc)

    def token_valid_on_plane(self, token: Optional[str], plane: str) -> bool:
        return bool(token) and token in self.plane_sessions.get(plane, set())

    # -- factor bindings ------------------------------------------------------
    def enroll_factor(self, aid: str) -> str:
        fid = "fac_" + secrets.token_hex(6)
        self.factors[fid] = aid
        self.accounts[aid].factors.add(fid)
        return fid

    def factor_account(self, fid: Optional[str]) -> Optional["_Account"]:
        aid = self.factors.get(fid) if fid else None
        return self.accounts.get(aid) if aid else None

    def change_email(self, token: str, new_email: str) -> Optional[str]:
        acc = self.account_of(token)
        if acc is None:
            return None
        self.by_email.pop(acc.email, None)
        acc.email = new_email
        self.by_email[new_email] = acc.id
        if self.patched:            # an identity rebind should end sessions minted under the old email
            self._revoke_sessions(acc, "email_change")
        return acc.id

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
            if self.revoke_aliases:
                # the complete fix also drops recovery emails added under the old (unproven)
                # binding; by default it does NOT — the attacker's alias survives the rebind.
                for a in list(acc.aliases):
                    self.by_email.pop(a, None)
                acc.aliases.clear()
        acc.email_verified = True      # the victim's IdP proof upgrades the row
        return self._issue(acc.id), acc.id

    def add_alias(self, token: Optional[str], alias: str) -> Optional[str]:
        """Add a recovery/secondary email to the acting session's account. The bug: it is not
        re-validated on a later rebind, so it can outlive the binding that created it."""
        acc = self.account_of(token)
        if acc is None:
            return None
        acc.aliases.add(alias)
        self.by_email[alias] = acc.id     # the alias now resolves to this account
        return acc.id

    def alias_login(self, alias: str) -> tuple[Optional[str], Optional[str]]:
        """Log in via a recovery email. Succeeds only if `alias` is a registered recovery
        email of some account (else it does not create one), so a finding is genuine."""
        aid = self.by_email.get(alias)
        if aid is None or alias not in self.accounts[aid].aliases:
            return None, None
        return self._issue(aid), aid

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
        if self.racy_reset > 0:
            rec = self.reset_tokens.get(token)          # CHECK
            if rec is None:
                return None, None
            time.sleep(self.racy_reset)                 # ...the window...
            self.reset_tokens.pop(token, None)          # ACT
        else:
            rec = self.reset_tokens.pop(token, None)    # atomic
        if rec is None:
            return None, None
        aid, _email_at_request = rec
        acc = self.accounts[aid]
        if self.patched or "reset_consume" in self.revokes:
            # TPI-4 session-kill-on-credential-change: a reset invalidates every session
            # whose provenance predates it.
            self._revoke_sessions(acc, "reset_consume")
        if "reset_consume" in self.revoke_factors:
            # A remediation reset should also invalidate an attacker-enrolled factor;
            # by default it does NOT (the durable-takeover bug, Grab T-ATO-22).
            for fid in list(acc.factors):
                self.factors.pop(fid, None)
            acc.factors.clear()
        acc.password = new_password
        return self._issue(aid), aid

    def logout(self, token: Optional[str]) -> bool:
        """End a session. Whether it revokes the *credential* (removes the token
        server-side), and on WHICH planes, depends on `revokes` / `plane_local` — a
        plane-local logout clears its own plane while the token lives on the others, the
        cross-plane laundering the matrix hunts (Grab T-ATO-05)."""
        if not token:
            return False
        acc = self.account_of(token)
        if "logout" in self.revokes and acc is not None:
            if "logout" in self.plane_local:
                self.plane_sessions[self._issuing_plane("logout")].discard(token)
            else:
                self._revoke_global(token, acc)
        return acc is not None

    def account_of(self, token: Optional[str]) -> Optional[_Account]:
        aid = self.sessions.get(token) if token else None
        return self.accounts.get(aid) if aid else None


class MockAdapter:
    """Binds the alphabet Sigma to the mock, keeping one session per principal."""

    def __init__(self, patched: bool = False, control: Optional[dict[str, set[str]]] = None,
                 revokes: Optional[set] = None, planes: Optional[tuple] = None,
                 plane_local: Optional[set] = None, mutation_planes: Optional[dict] = None,
                 revoke_factors: Optional[set] = None, revoke_aliases: bool = False,
                 bystander_email: Optional[str] = None, racy_reset: float = 0.0) -> None:
        # the account the oracle's bystander control runs on — separate from the contended
        # one, and tagged with this run so an artefact it leaves is attributable
        self.bystander_email = bystander_email or f"bystander-{session_id()}@corp.example"
        self.t = VulnerableTarget(patched=patched, revokes=revokes, planes=planes,
                                  plane_local=plane_local, mutation_planes=mutation_planes,
                                  revoke_factors=revoke_factors, revoke_aliases=revoke_aliases,
                                  racy_reset=racy_reset)
        self.inbox = InMemoryInbox()
        self.factor_of: dict[str, Optional[str]] = {}   # principal -> its most-recent factor id
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

    def add_alias(self, p: Principal, alias: str) -> Observation:
        # Add a recovery email to the acting session's account. Needs control of the alias
        # (you prove the recovery inbox), so the finding is not an all-permissive artifact.
        if not self._controls(p, alias):
            return Observation(False, note=f"{p} does not control the recovery email {alias}")
        aid = self.t.add_alias(self.sess.get(p.name), alias)
        return Observation(aid is not None, identity=aid,
                           note=f"{p} added {alias} as a recovery email on the account")

    def alias_login(self, p: Principal, alias: str) -> Observation:
        # Log in via a recovery email the actor controls. Resolves to whatever account the
        # alias is registered on — the takeover vector when an attacker's alias survives a rebind.
        if not self._controls(p, alias):
            return Observation(False, note=f"{p} cannot read the {alias} inbox")
        tok, aid = self.t.alias_login(alias)
        if tok:
            self.sess[p.name] = tok
        proof = ProofEvent(p, Identifier("email", alias), Channel.EMAIL) if tok else None
        return Observation(tok is not None, identity=aid, proof=proof,
                           note=f"{p} logged in via the recovery email {alias}")

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

    def enroll_factor(self, p: Principal) -> Observation:
        """Enrol a second factor (passkey/biometric) on the acting session's account —
        a durable binding independent of the session that minted it."""
        acc = self.t.account_of(self.sess.get(p.name))
        if acc is None:
            return Observation(False, note=f"{p} has no session to enrol a factor on")
        fid = self.t.enroll_factor(acc.id)
        self.factor_of[p.name] = fid
        return Observation(True, identity=acc.email, extracted={"factor": fid},
                           note=f"{p} enrolled a passkey/biometric factor on {acc.email}")

    def email_change(self, p: Principal, new_email: str) -> Observation:
        token = self.sess.get(p.name)
        aid = self.t.change_email(token, new_email)
        return Observation(aid is not None, identity=new_email,
                           note=f"{p} changed the account email to {new_email}")

    def enrol_bystander(self, p: Principal) -> Observation:
        """Authenticate `p` on a fresh account of its own — an uninvolved third party.

        A real adapter logs in the engagement's third test account instead of creating one,
        and that account's identifier belongs in the policy allowlist."""
        email = self.bystander_email
        tok, aid = self.t.register(email, _password("bystander:account"))
        if tok is None:
            tok, aid = self.t.login(email, _password("bystander:account"))
        if tok:
            self.sess[p.name] = tok
        return Observation(tok is not None, identity=aid,
                           note=f"{p} enrolled as an uninvolved bystander on {email}")

    # -- oracle surface -------------------------------------------------------
    def whoami(self, p: Principal) -> Observation:
        acc = self.t.account_of(self.sess.get(p.name))
        return Observation(acc is not None, identity=(acc.email if acc else None))

    # -- binding lifecycle surface (revocation matrix) ------------------------
    def capture_binding(self, p: Principal, kind: str = "session") -> Optional[str]:
        """Snapshot a durable credential the principal holds, so it can be re-presented
        later. `kind` "session" captures the session token; "factor" captures the id of
        the factor the principal most recently enrolled."""
        if kind == "factor":
            return self.factor_of.get(p.name)
        return self.sess.get(p.name)

    def planes(self) -> tuple:
        """The verify-point planes this target exposes. Revocation may be per-plane, so
        a binding must be checked on each — a mutation that revokes on one plane may
        leave the credential alive on another. (Factor bindings are plane-independent.)"""
        return self.t.planes

    def present_binding(self, handle: Optional[str], plane: Optional[str] = None) -> Observation:
        """Present a previously-captured credential and report whether it still grants
        access. A factor handle is checked for enrolment (plane-independent); a session
        handle is checked on a specific `plane` when given, else globally."""
        if handle in self.t.factors:
            acc = self.t.factor_account(handle)
            return Observation(acc is not None, identity=(acc.email if acc else None))
        acc = self.t.account_of(handle)
        if plane is None:
            return Observation(acc is not None, identity=(acc.email if acc else None))
        valid = self.t.token_valid_on_plane(handle, plane) and acc is not None
        return Observation(valid, identity=(acc.email if valid else None))

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
