"""Driving a target through its UI, with the framework's controls still applying.

Some auth surface has no API you can drive: the flow is a rendered page, a modal, a
multi-step wizard. This engagement's evidence is blunt about what happens then — every
wrong answer it produced came from an ad-hoc browser script hand-rolling a check the
framework already does properly:

    three "logins succeeded" that were /cdn/display_error
    two SURVIVED verdicts on mutations that never happened

The framework's controls only protect the code paths that go through the framework, and
none of the browser work did. So this module makes a browser flow an ordinary
`TargetAdapter`: `validate_target`, `AtoOracle` and `matrix.run_cell` then apply to UI
flows exactly as they do to HTTP ones, and there is nothing left to hand-roll.

**The schema cannot express an absence check.** `Expect` offers `url_contains`,
`text_contains`, `cookie` and `selector` — positive evidence that something is true. It
deliberately has no `url_not_contains`: "we did not land on the error page" is precisely
the check that reported success on `/cdn/display_error` three times, and a schema that
cannot say it cannot get it wrong. A flow whose final step carries no `Expect` is refused
when the profile is built, not when it silently returns the wrong answer.

The browser itself is injected as a `PageDriver`, so the logic here is tested without a
browser at all and `playwright` is imported only by `PlaywrightDriver`.

    adapter = BrowserAdapter(profile, policy, driver_factory=playwright_driver_factory())
    verdict, trace = run_plan(adapter, plan, AtoOracle(adapter, attacker, victim))
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from .policy import EngagementPolicy, ScopeViolation
from .profile import PLACEHOLDERS, ProfileError, render
from .redact import redact, untrusted
from .types import Channel, Identifier, Observation, Principal, ProofEvent

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


# --------------------------------------------------------------------------- #
#  The browser, behind an interface.
# --------------------------------------------------------------------------- #
class PageDriver(Protocol):
    """One independent browsing context. One per principal, never shared."""

    def goto(self, url: str) -> None: ...
    def fill(self, selector: str, value: str) -> bool: ...
    def click(self, target: str) -> bool: ...
    def url(self) -> str: ...
    def text(self) -> str: ...
    def cookies(self) -> dict: ...
    def set_cookies(self, cookies: dict) -> None: ...
    def has(self, selector: str) -> bool: ...
    def close(self) -> None: ...


# --------------------------------------------------------------------------- #
#  Expectations: positive evidence only.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Expect:
    """What must be TRUE for a step to count as having worked.

    There is no negative form on purpose. An absence check ("the URL does not contain
    'login'") passes on any page the author did not think of, including the error page,
    and that is exactly how three logins in this engagement were reported as successful
    while sitting on /cdn/display_error.
    """
    url_contains: Optional[str] = None
    text_contains: Optional[str] = None
    cookie: Optional[str] = None
    selector: Optional[str] = None

    def __post_init__(self) -> None:
        if not any((self.url_contains, self.text_contains, self.cookie, self.selector)):
            raise ProfileError("Expect needs at least one positive condition "
                               "(url_contains / text_contains / cookie / selector)")

    def check(self, driver: PageDriver, vars: dict) -> tuple[bool, str]:
        """(met, why). Every condition given must hold."""
        misses = []
        if self.url_contains is not None:
            want = render(self.url_contains, vars)
            if want not in driver.url():
                misses.append(f"url lacks {want!r} (at {untrusted(driver.url(), 90)})")
        if self.text_contains is not None:
            want = render(self.text_contains, vars)
            if want not in driver.text():
                misses.append(f"page text lacks {want!r}")
        if self.cookie is not None and self.cookie not in driver.cookies():
            misses.append(f"cookie {self.cookie!r} absent")
        if self.selector is not None and not driver.has(self.selector):
            misses.append(f"selector {self.selector!r} not present")
        return (not misses), ("; ".join(misses) or "all conditions met")


@dataclass(frozen=True)
class UiStep:
    """One interaction. `expect`, where given, is checked immediately after."""
    goto: Optional[str] = None
    fill: tuple = ()                    # ((selector, value-template), ...)
    click: Optional[str] = None
    expect: Optional[Expect] = None

    def describe(self) -> str:
        bits = []
        if self.goto: bits.append(f"goto {self.goto}")
        if self.fill: bits.append("fill " + ",".join(s for s, _ in self.fill))
        if self.click: bits.append(f"click {self.click!r}")
        return " / ".join(bits) or "(no-op)"


@dataclass(frozen=True)
class Flow:
    """A named sequence of steps. The LAST step must carry an `Expect`.

    Without that a flow reports success whenever nothing raised, which is not a
    measurement — it is the absence of a crash."""
    name: str
    steps: tuple
    proof: Optional[Channel] = None     # the proof event a successful run emits

    def __post_init__(self) -> None:
        if not self.steps:
            raise ProfileError(f"flow {self.name!r} has no steps")
        if self.steps[-1].expect is None:
            raise ProfileError(
                f"flow {self.name!r}: the final step must carry an Expect. A flow that "
                f"asserts nothing reports success whenever nothing raised, which is how a "
                f"login onto an error page gets recorded as a login.")


@dataclass(frozen=True)
class BrowserProfile:
    """A target's UI surface, as data."""
    name: str
    base_url: str
    accounts: dict                       # role -> {"email": ..., "password": ...}
    flows: dict                          # action name -> Flow
    identity_from: Optional[str] = None  # regex with one group, read off the page
    marker_from: Optional[str] = None    # regex with one group: the private value
    session_cookie: str = ""             # the cookie that carries the session

    def describe(self) -> dict:
        return {"name": self.name, "base_url": self.base_url,
                "accounts": {r: a.get("email") for r, a in self.accounts.items()},
                "flows": sorted(self.flows), "session_cookie": self.session_cookie,
                "identity_from": self.identity_from is not None,
                "marker_from": self.marker_from is not None}


# --------------------------------------------------------------------------- #
class BrowserAdapter:
    """A `TargetAdapter` whose actions are UI flows."""

    def __init__(self, profile: BrowserProfile, policy: EngagementPolicy,
                 driver_factory: Callable[[], PageDriver],
                 control: Optional[dict] = None) -> None:
        problems = policy.preflight()
        if problems:
            raise ScopeViolation("engagement policy is not ready:\n  - " + "\n  - ".join(problems))
        self.profile = profile
        self.policy = policy
        self._factory = driver_factory
        self.control: dict = {k: set(v) for k, v in (control or {}).items()}
        self._drivers: dict = {}

    # -- one independent context per principal --------------------------------
    def driver(self, p: Principal) -> PageDriver:
        if p.name not in self._drivers:
            self._drivers[p.name] = self._factory()
        return self._drivers[p.name]

    def close(self) -> None:
        for d in self._drivers.values():
            try: d.close()
            except Exception: pass
        self._drivers.clear()

    def _controls(self, p: Principal, ident: str) -> bool:
        return ident in self.control.get(p.name, set())

    def _vars(self, p: Principal, params: dict) -> dict:
        acct = self.profile.accounts.get(p.name, {})
        out = {k: "" for k in PLACEHOLDERS}
        out.update({"role": p.name, "base_url": self.profile.base_url,
                    "email": params.get("email") or acct.get("email", ""),
                    "password": params.get("password") or acct.get("password", "")})
        out.update({k: v for k, v in params.items() if isinstance(v, str)})
        return out

    # -- running a flow -------------------------------------------------------
    def run_flow(self, p: Principal, action: str, **params) -> Observation:
        flow = self.profile.flows.get(action)
        if flow is None:
            return Observation(False, note=f"action '{action}' has no binding on this target")
        vars = self._vars(p, params)
        d = self.driver(p)
        met, why = False, "flow did not run"
        for i, step in enumerate(flow.steps, 1):
            if step.goto:
                url = render(step.goto, vars)
                if not url.startswith(("http://", "https://")):
                    url = self.profile.base_url.rstrip("/") + "/" + url.lstrip("/")
                problem = self.policy.check_url(url)
                if problem:
                    # the UI path gets the same scope gate as the HTTP one
                    raise ScopeViolation(f"{action} step {i}: {problem}")
                d.goto(url)
            for sel, val in step.fill:
                if not d.fill(sel, render(val, vars)):
                    return Observation(False, note=f"{action} step {i}: field {sel!r} not found")
            if step.click and not d.click(render(step.click, vars)):
                return Observation(False, note=f"{action} step {i}: control "
                                               f"{step.click!r} not found or not clickable")
            if step.expect is not None:
                met, why = step.expect.check(d, vars)
                if not met:
                    return Observation(False, note=f"{action} step {i} ({step.describe()}): {why}")
        proof = None
        if met and flow.proof is not None:
            kind = "credential" if flow.proof is Channel.KNOWLEDGE else "email"
            proof = ProofEvent(p, Identifier(kind, vars.get("email", "")), flow.proof)
        return Observation(met, identity=self._identity(d), proof=proof,
                           note=f"{action}: {untrusted(redact(why), 160)}")

    def _identity(self, d: PageDriver) -> Optional[str]:
        if not self.profile.identity_from:
            return None
        m = re.search(self.profile.identity_from, d.text())
        return m.group(1) if m else None

    # -- alphabet -------------------------------------------------------------
    def register(self, p, email=None, password=None):
        return self.run_flow(p, "register", email=email, password=password)

    def login(self, p, email=None, password=None):
        return self.run_flow(p, "login", email=email, password=password)

    def sso_login(self, p, email=None):
        ident = email or self.profile.accounts.get(p.name, {}).get("email", "")
        if not self._controls(p, ident):
            return Observation(False, note=f"{p} does not control {ident} — not attempted")
        return self.run_flow(p, "sso_login", email=email)

    def reset_request(self, p, email=None):
        return self.run_flow(p, "reset_request", email=email)

    def reset_consume(self, p, email=None, new_password=None):
        ident = email or self.profile.accounts.get(p.name, {}).get("email", "")
        if not self._controls(p, ident):
            return Observation(False, note=f"{p} cannot read the {ident} inbox — not attempted")
        return self.run_flow(p, "reset_consume", email=email, new_password=new_password)

    def logout(self, p):
        return self.run_flow(p, "logout")

    def __getattr__(self, name):
        """Any other flow the profile declares — a passkey enrolment, an email rebind."""
        flows = self.__dict__.get("profile")
        if name.startswith("_") or flows is None or name not in flows.flows:
            raise AttributeError(name)

        def action(p: Principal, **params):
            return self.run_flow(p, name, **params)
        return action

    # -- oracle surface -------------------------------------------------------
    def whoami(self, p: Principal) -> Observation:
        d = self.driver(p)
        ident = self._identity(d)
        return Observation(ident is not None, identity=ident)

    def read_marker(self, p: Principal, ref: Optional[str] = None) -> Observation:
        """Read the private per-account value off the page. There is no by-reference form
        in a UI: a browser shows you your own account, so a `ref` cannot be honoured and
        is reported as such rather than answered."""
        if ref is not None:
            return Observation(False, extracted={"value": None},
                               note="a UI flow has no by-reference read")
        if not self.profile.marker_from:
            return Observation(False, extracted={"value": None},
                               note="profile declares no marker_from")
        m = re.search(self.profile.marker_from, self.driver(p).text())
        return Observation(m is not None, extracted={"value": m.group(1) if m else None})

    def plant_marker(self, p: Principal, value: str) -> Observation:
        return Observation(False, note="a browser profile is natural-canary only; "
                                       "it does not write")

    def write_marker(self, p: Principal, value: str, ref: Optional[str] = None) -> Observation:
        return Observation(False, note="a browser profile is natural-canary only; "
                                       "it does not write")

    # -- binding lifecycle (the revocation matrix) ----------------------------
    def capture_binding(self, p: Principal, kind: str = "session") -> Optional[str]:
        c = self.driver(p).cookies()
        return c.get(self.profile.session_cookie) if self.profile.session_cookie else None

    def present_binding(self, handle: Optional[str], plane: Optional[str] = None) -> Observation:
        """Re-present a captured session in a FRESH context — never the one that made it,
        which would answer a different question."""
        if not handle:
            return Observation(False)
        d = self._factory()
        try:
            d.set_cookies({self.profile.session_cookie: handle})
            url = self.profile.base_url
            if self.policy.check_url(url) is None:
                d.goto(url)
            ident = self._identity(d)
            return Observation(ident is not None, identity=ident)
        finally:
            try: d.close()
            except Exception: pass


# --------------------------------------------------------------------------- #
def playwright_driver_factory(headless: bool = False, **context_kw):
    """A `PageDriver` factory backed by Playwright. Imported lazily, like every other
    optional integration here, so the core stays stdlib-only."""
    def factory() -> PageDriver:
        from .playwright_driver import PlaywrightDriver   # local: keeps the import lazy
        return PlaywrightDriver(headless=headless, **context_kw)
    return factory
