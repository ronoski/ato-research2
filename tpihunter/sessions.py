"""Sessions as a scarce, degrading resource — the constraint that ended an engagement.

On this project's first live engagement the hunt did not stop because the target was
clean or the methodology was thin. It stopped because **no session could be obtained any
more**. Sixteen scripts each minted their own login, eight sessions were captured and
thrown away when their browser closed, and roughly a dozen authentications ran through
one account estate in a day. By evening every account answered the login form with an
error page, including one rested for seven hours.

None of that was necessary. Almost every one of those logins was re-establishing a session
that already existed and was still valid.

A session is not free and it is not renewable on demand:

  * each authentication spends a one-time code from a real mailbox;
  * each one raises a behavioural risk score that does not reset when you stop;
  * a credential change invalidates every session, including the ones held aside;
  * and the failure is silent — a throttled login returns the same error page as a wrong
    password, so "I could not log in" never distinguishes exhaustion from a bad credential.

So this treats a session as inventory: **check before you spend**, spend against a budget,
and record the spend so the exhaustion is visible while it is still recoverable.

    store = SessionStore(path, validate=is_still_live)
    s = store.acquire("victim", login=do_browser_login)   # reuses if it can
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Optional


class NoSessionAvailable(RuntimeError):
    """No live session, and the login budget for this principal is spent."""


@dataclass
class Session:
    principal: str
    cookies: dict = field(default_factory=dict)
    token: str = ""
    acquired_at: float = 0.0
    source: str = "login"          # login | reused | supplied

    def age(self) -> float:
        return time.time() - (self.acquired_at or 0.0)


@dataclass
class LoginLedger:
    """What has been spent, per principal, so exhaustion is visible early."""
    attempts: dict = field(default_factory=dict)      # principal -> [(ts, ok)]
    max_per_principal: int = 4
    max_total: int = 12

    def record(self, principal: str, ok: bool) -> None:
        self.attempts.setdefault(principal, []).append((time.time(), bool(ok)))

    def spent(self, principal: str) -> int:
        return len(self.attempts.get(principal, ()))

    def total(self) -> int:
        return sum(len(v) for v in self.attempts.values())

    def recent_failures(self, principal: str, n: int = 3) -> int:
        rows = self.attempts.get(principal, [])[-n:]
        return sum(1 for _ts, ok in rows if not ok)

    def may_login(self, principal: str) -> Optional[str]:
        """None if a login is permitted, else why not."""
        if self.spent(principal) >= self.max_per_principal:
            return (f"{principal}: {self.spent(principal)} logins already spent "
                    f"(cap {self.max_per_principal}). Each one costs a mailbox code and "
                    f"raises a risk score that does not reset — get a session out of band "
                    f"rather than trying again.")
        if self.total() >= self.max_total:
            return (f"{self.total()} logins spent across the engagement (cap "
                    f"{self.max_total}); stopping before the estate is unusable")
        if self.recent_failures(principal) >= 2:
            return (f"{principal}: the last two login attempts failed. On a real target "
                    f"that reads as throttling or a degraded risk score, and retrying is "
                    f"what deepens it. Wait, or supply a session captured out of band.")
        return None


class SessionStore:
    """Sessions persisted across runs, validated before reuse, minted only as a last resort."""

    def __init__(self, path: str, validate: Optional[Callable[[Session], bool]] = None,
                 ledger: Optional[LoginLedger] = None, max_age: float = 3600.0) -> None:
        self.path = path
        self.validate = validate
        self.ledger = ledger or LoginLedger()
        self.max_age = max_age
        self._sessions: dict = {}
        self.load()

    # -- persistence ----------------------------------------------------------
    def load(self) -> None:
        try:
            raw = json.load(open(self.path))
        except (OSError, ValueError):
            return
        for name, d in (raw.get("sessions") or {}).items():
            self._sessions[name] = Session(**d)
        led = raw.get("ledger") or {}
        if led:
            self.ledger.attempts = {k: [tuple(x) for x in v]
                                    for k, v in (led.get("attempts") or {}).items()}

    def save(self) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w") as fh:
            json.dump({"sessions": {k: asdict(v) for k, v in self._sessions.items()},
                       "ledger": {"attempts": self.ledger.attempts}}, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # -- the point of the whole module ----------------------------------------
    def acquire(self, principal: str,
                login: Optional[Callable[[], Optional[Session]]] = None) -> Session:
        """Return a live session, minting one only if there is genuinely no other way."""
        held = self._sessions.get(principal)
        if held is not None:
            # A validator is the only real evidence. Without one, age is the only signal
            # left, and a stale session must NOT be handed back: a dead cookie fails the
            # same way a refused request does, so reusing one silently turns every verdict
            # downstream into an INCONCLUSIVE dressed up as a result.
            if self.validate is not None:
                live = bool(self.validate(held))
            else:
                live = not (self.max_age and held.age() > self.max_age)
            if live:
                held.source = "reused"
                return held
            del self._sessions[principal]              # it was dead; do not keep it around

        blocked = self.ledger.may_login(principal)
        if blocked:
            raise NoSessionAvailable(blocked)
        if login is None:
            raise NoSessionAvailable(f"no live session for {principal} and no way to mint one")

        s = login()
        self.ledger.record(principal, s is not None)
        self.save()
        if s is None:
            raise NoSessionAvailable(
                f"{principal}: login attempt failed. It is now "
                f"{self.ledger.spent(principal)} of {self.ledger.max_per_principal} spent.")
        s.principal, s.acquired_at, s.source = principal, time.time(), "login"
        self._sessions[principal] = s
        self.save()
        return s

    def put(self, principal: str, session: Session) -> None:
        """Record a session captured out of band — the path that costs nothing."""
        session.principal = principal
        session.acquired_at = session.acquired_at or time.time()
        session.source = "supplied"
        self._sessions[principal] = session
        self.save()

    def status(self) -> str:
        rows = [f"  {n:<10} age {int(s.age())}s  source={s.source}"
                for n, s in sorted(self._sessions.items())]
        led = [f"  {p:<10} {len(v)} login(s), {sum(1 for _t, ok in v if not ok)} failed"
               for p, v in sorted(self.ledger.attempts.items())]
        return ("held sessions:\n" + ("\n".join(rows) or "  none") +
                "\nlogin ledger:\n" + ("\n".join(led) or "  none") +
                f"\n  total spent: {self.ledger.total()}/{self.ledger.max_total}")
