"""Driving a real target from a profile — the adapter an agent can configure.

`profile.TargetProfile` says what a target's auth surface looks like; `LiveAdapter`
turns that description into the alphabet the rest of the package already drives. One
independent transport per principal (its own cookie jar, its own bearer token), because
two principals sharing a context voids every verdict the oracle produces.

Security posture, since this module is the only one that touches a network and the
description it follows was written by a model reading the target's own responses:

  * **The policy is not optional.** A `LiveAdapter` cannot be constructed without an
    `EngagementPolicy`, and every URL — including every redirect hop — is re-checked
    against it. A target that answers a probe with a 302 to somewhere else does not get
    to decide what this tool connects to.
  * **The transport enforces what an action-level guard cannot see:** URL scope, TLS
    verification, a per-request timeout, a response size cap, a minimum interval between
    requests, and a hard request budget. `policy.guard()` layers the action-level gates
    (credential changes, cross-principal writes) on top; `live_adapter()` builds both
    together over one shared audit log, which is how you should normally construct one.
  * **The tool does not authenticate.** Consumer auth is gated by CAPTCHA, device checks
    or push approvals, and defeating any of those is a hard stop on every programme worth
    testing — so `sessions={"victim": "<credential>"}` takes sessions a human captured in
    a real browser and drives everything after that. `login`/`register` for such a
    principal are satisfied without a request, and the trace says so.
  * **Channel control is the hunter's, not the target's.** Whether a principal can
    complete an IdP or inbox flow is a fact about the world, so it is enforced here,
    exactly as `MockAdapter` does it. A probe that would need the attacker to read the
    victim's inbox fails locally instead of being sent.

    adapter = live_adapter(profile, policy, control={"victim": {victim_email}})
    verdict, trace = run_plan(adapter, plan, AtoOracle(adapter, attacker, victim,
                                                       resource=victim_email))
"""
from __future__ import annotations

import http.cookiejar
import json as _json
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .policy import AuditLog, BudgetExhausted, EngagementPolicy, ScopeViolation, guard
from .profile import Request, TargetProfile, render, render_path
from .redact import redact, untrusted
from .types import Channel, Identifier, Observation, Principal, ProofEvent

# action name -> the proof channel it demonstrates, when the profile does not say.
_DEFAULT_PROOF = {
    "register": Channel.KNOWLEDGE, "login": Channel.KNOWLEDGE,
    "sso_login": Channel.IDP, "magic_link": Channel.EMAIL,
    "reset_consume": Channel.EMAIL, "alias_login": Channel.EMAIL,
}
# actions only the principal controlling the identifier can complete
_DEFAULT_NEEDS_CONTROL = frozenset({"sso_login", "reset_consume", "magic_link"})

_USER_AGENT = "tpihunter (authorized security testing)"


@dataclass
class Response:
    status: int
    headers: dict
    cookies: dict
    text: str
    truncated: bool = False
    _parsed: object = field(default=None, repr=False)

    def json(self):
        if self._parsed is None:
            try:
                self._parsed = _json.loads(self.text or "null")
            except ValueError:
                self._parsed = {}
        return self._parsed


class ScopedTransport:
    """One HTTP client for one principal, with the engagement's limits enforced in it."""

    def __init__(self, policy: EngagementPolicy, audit: AuditLog,
                 verify_tls: bool = True, timeout: float = 10.0,
                 max_bytes: int = 262_144, label: str = "") -> None:
        self.policy = policy
        self.audit = audit
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.label = label
        self.requests = 0
        self._last = 0.0
        self.jar = http.cookiejar.CookieJar()
        ctx = ssl.create_default_context()
        if not verify_tls:
            # Explicit, and recorded: an unverified channel means every observation here
            # is attributable to whoever is on the path, not necessarily to the target.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            audit.add(principal=label or None, action="tls", params={}, outcome="refused",
                      note="TLS verification DISABLED for this engagement")
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(self.jar),
            _ScopedRedirect(policy))

    def send(self, method: str, url: str, headers: dict, body: Optional[bytes]) -> Response:
        problem = self.policy.check_url(url)
        if problem:
            self.audit.add(principal=self.label or None, action=f"{method} {url}",
                           params={}, outcome="refused", note=problem)
            raise ScopeViolation(problem)
        if self.requests >= self.policy.max_actions:
            raise BudgetExhausted(
                f"engagement '{self.policy.name}' hit its budget of "
                f"{self.policy.max_actions} requests; stopping rather than continuing")
        self._throttle(self.policy.rules_for(url).get("min_interval", 0.0))
        req = urllib.request.Request(url, data=body, method=method)
        req.add_header("User-Agent", _USER_AGENT)
        for k, v in headers.items():
            req.add_header(k, v)
        self.requests += 1
        try:
            with self._opener.open(req, timeout=self.timeout) as raw:
                return self._read(raw, method, url)
        except urllib.error.HTTPError as e:              # a status is a result, not a crash
            return self._read(e, method, url)
        except ScopeViolation:
            raise
        except Exception as e:                            # timeout, DNS, TLS, reset
            self.audit.add(principal=self.label or None, action=f"{method} {url}",
                           params={}, outcome="failed", note=f"{type(e).__name__}: {e}")
            return Response(0, {}, {}, "", False)

    def _read(self, raw, method: str, url: str) -> Response:
        body = raw.read(self.max_bytes + 1)
        truncated = len(body) > self.max_bytes
        text = body[:self.max_bytes].decode("utf-8", "replace")
        headers = {k.lower(): v for k, v in raw.headers.items()}
        cookies = {c.name: c.value for c in self.jar}
        status = getattr(raw, "status", None) or raw.getcode()
        self.audit.add(principal=self.label or None, action=f"{method} {url}", params={},
                       outcome="ok" if 200 <= status < 400 else "failed",
                       note=f"{status}" + (" (response truncated)" if truncated else ""))
        return Response(status, headers, cookies, text, truncated)

    def _throttle(self, gap: float = 0.0) -> None:
        """`gap` is the per-asset minimum from the policy, already merged with the global
        one — an asset that asked for 100 requests/minute gets 0.6s whatever the rest of
        the engagement runs at."""
        if gap <= 0:
            return
        wait = self._last + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is the target choosing the next URL. It gets the same check as the first."""

    def __init__(self, policy: EngagementPolicy) -> None:
        self.policy = policy

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        problem = self.policy.check_url(newurl)
        if problem:
            raise ScopeViolation(f"refusing to follow a redirect out of scope: {problem}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# --------------------------------------------------------------------------- #
class LiveAdapter:
    """The alphabet, driven over HTTP from a `TargetProfile`."""

    def __init__(self, profile: TargetProfile, policy: EngagementPolicy,
                 control: Optional[dict] = None, audit: Optional[AuditLog] = None,
                 sessions: Optional[dict] = None) -> None:
        problems = policy.preflight()
        if problems:
            raise ScopeViolation("engagement policy is not ready:\n  - " + "\n  - ".join(problems))
        missing = profile.identifiers() - set(policy.identifiers)
        if missing:
            raise ScopeViolation(
                f"profile '{profile.name}' uses identifiers the policy does not authorize: "
                f"{sorted(missing)}")
        if policy.check_host(profile.host):
            raise ScopeViolation(f"profile host {profile.host!r} is not in the policy's scope")
        rules = policy.rules_for(profile.base_url + "/")
        if rules.get("no_registration") and "register" in profile.actions:
            # Refused at construction, not at request time: an asset whose instructions say
            # "do not register for accounts as this is a production site" must not be
            # reachable by a probe that opens with `register`, and noticing that mid-hunt
            # is one request too late.
            raise ScopeViolation(
                f"the engagement forbids account registration on {profile.host!r} "
                f"({rules.get('note') or 'per-asset instruction'}); remove the `register` "
                f"action from the profile, or point it at an asset that permits it")
        self.profile = profile
        self.policy = policy
        self.audit = audit if audit is not None else AuditLog()
        self.control: dict = {k: set(v) for k, v in (control or {}).items()}
        self._transports: dict = {}
        self._tokens: dict = {}      # principal -> bearer token, when session.kind == "header"
        # Sessions captured OUTSIDE this tool and handed to it: {principal name -> token}.
        # Real consumer auth is gated by a CAPTCHA, a device check or a push approval, and
        # defeating any of those is out of scope on every programme worth testing. So the
        # framework does not log in — a human does, and passes the resulting credential
        # here. Everything after authentication is still driven normally.
        self._supplied: dict = dict(sessions or {})

    # -- per-principal transport ---------------------------------------------
    def _t(self, p: Principal) -> ScopedTransport:
        if p.name not in self._transports:
            self._transports[p.name] = ScopedTransport(
                self.policy, self.audit, verify_tls=self.profile.verify_tls,
                timeout=self.profile.timeout, max_bytes=self.profile.max_bytes, label=p.name)
        return self._transports[p.name]

    def _controls(self, p: Principal, ident: str) -> bool:
        return ident in self.control.get(p.name, set())

    def _account(self, p: Principal):
        return self.profile.accounts.get(p.name)

    # -- the one call that does everything ------------------------------------
    def _call(self, p: Principal, spec: Request, vars: dict) -> tuple[Response, dict]:
        url = self.profile.base_url + render_path(spec.path, vars)
        headers = {k: render(v, vars) for k, v in spec.headers.items()}
        body = None
        if spec.json_body is not None:
            headers["Content-Type"] = "application/json"
            body = _json.dumps(render(spec.json_body, vars)).encode()
        elif spec.form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urllib.parse.urlencode(render(spec.form, vars)).encode()
        token = self._supplied.get(p.name) or self._tokens.get(p.name)
        if token:
            if self.profile.session.kind == "header":
                headers[self.profile.session.header] = render(
                    self.profile.session.format, {"token": token})
            elif p.name in self._supplied:
                # a cookie jar cannot be handed over, so a supplied cookie is sent verbatim
                headers["Cookie"] = token
        resp = self._t(p).send(spec.method, url, headers, body)
        got = {name: ex.apply(resp) for name, ex in spec.extract.items()}
        if spec.session_from is not None:
            tok = spec.session_from.apply(resp)
            if tok:
                self._tokens[p.name] = tok
        return resp, got

    def _observe(self, p: Principal, action: str, spec: Request, resp: Response,
                 got: dict, ident: str) -> Observation:
        ok = resp.status in spec.expect
        proof = None
        if ok:
            ch = _DEFAULT_PROOF.get(action)
            if ch is not None and ch is not Channel.NONE:
                kind = "credential" if ch is Channel.KNOWLEDGE else "email"
                proof = ProofEvent(p, Identifier(kind, ident), ch)
        note = f"{action} -> HTTP {resp.status}"
        if not ok:
            note += f" (expected {list(spec.expect)}): {untrusted(redact(resp.text), 160)}"
        return Observation(ok, status=resp.status, identity=got.get("identity"),
                           extracted={k: v for k, v in got.items() if v is not None},
                           proof=proof, note=note)

    # -- alphabet -------------------------------------------------------------
    def has_supplied_session(self, p: Principal) -> bool:
        return p.name in self._supplied

    def _run_action(self, p: Principal, action: str, **params) -> Observation:
        if action in ("login", "register") and p.name in self._supplied:
            # The principal is already authenticated by a credential captured out of band.
            # Re-authenticating would mean driving the very flow we are not permitted to
            # automate, so the step is satisfied without a request — and says so, because
            # a probe whose `register` did not actually register means something different.
            return Observation(True, note=f"{p} is using a supplied session; '{action}' "
                                          f"not performed by this tool")
        spec = self.profile.actions.get(action)
        if spec is None:
            return Observation(False, note=f"action '{action}' has no binding on this target")
        acct = self._account(p)
        ident = params.get("email") or (acct.email if acct else "")
        needs_control = action in _DEFAULT_NEEDS_CONTROL
        if needs_control and not self._controls(p, ident):
            return Observation(False, note=f"{p} does not control {ident} "
                                           f"(inbox/IdP) — not sent")
        vars = {"email": ident, "role": p.name, "base_url": self.profile.base_url,
                "password": params.get("password") or (acct.password if acct else ""),
                "new_password": params.get("new_password", ""),
                "new_email": params.get("new_email", ""),
                "alias": params.get("alias", ""),
                "code": params.get("code", ""), "token": params.get("token", "")}
        if action == "reset_consume" and not vars["token"]:
            tok = self._channel_token(p, ident)
            if not tok:
                return Observation(False, note=f"no token delivered to {ident} — the "
                                               f"channel returned nothing")
            vars["token"] = tok
        resp, got = self._call(p, spec, vars)
        return self._observe(p, action, spec, resp, got, ident)

    def _channel_token(self, p: Principal, email: str) -> Optional[str]:
        """Read the out-of-band channel as the principal that controls the address."""
        if self.profile.channel is None:
            return None
        _resp, got = self._call(p, self.profile.channel, {"email": email, "role": p.name})
        return got.get("token")

    def register(self, p, email=None, password=None):
        return self._run_action(p, "register", email=email, password=password)

    def login(self, p, email=None, password=None):
        return self._run_action(p, "login", email=email, password=password)

    def sso_login(self, p, email=None):
        return self._run_action(p, "sso_login", email=email)

    def reset_request(self, p, email=None):
        return self._run_action(p, "reset_request", email=email)

    def reset_consume(self, p, email=None, new_password=None):
        return self._run_action(p, "reset_consume", email=email, new_password=new_password,
                                password=new_password)

    def logout(self, p):
        return self._run_action(p, "logout")

    def __getattr__(self, name):
        """Serve any OTHER action the profile declares — a magic link, a device pairing,
        an org invite — so `register_action` in the agent's alphabet is backed by a real
        request. Only profile-declared names: never an arbitrary attribute."""
        profile = self.__dict__.get("profile")     # never getattr: that recurses here
        if name.startswith("_") or profile is None or name not in profile.actions:
            raise AttributeError(name)

        def action(p: Principal, **params):
            return self._run_action(p, name, **params)
        return action

    # -- oracle surface -------------------------------------------------------
    def whoami(self, p: Principal) -> Observation:
        spec = self.profile.oracle["whoami"]
        resp, got = self._call(p, spec, {"role": p.name})
        ok = resp.status in spec.expect
        return Observation(ok, status=resp.status,
                           identity=(got.get("identity") if ok else None))

    def plant_marker(self, p: Principal, value: str) -> Observation:
        spec = self.profile.oracle.get("plant_marker") or self.profile.oracle.get("write_marker")
        if spec is None:
            return Observation(False, note="profile declares no plant_marker/write_marker")
        resp, got = self._call(p, spec, {"value": value, "role": p.name})
        ok = resp.status in spec.expect
        ref = got.get("ref")
        if ref is None:                       # fall back to the identity as the resource ref
            ref = self.whoami(p).identity
        return Observation(ok, status=resp.status, extracted={"ref": ref})

    def read_marker(self, p: Principal, ref: Optional[str] = None) -> Observation:
        key = "read_marker_by_ref" if ref is not None else "read_marker"
        spec = self.profile.oracle.get(key)
        if spec is None:
            # A profile with no by-ref read cannot answer the direct-object question. Say
            # so as "no value", never as a value: a missing probe is not a denied one.
            return Observation(False, extracted={"value": None},
                               note=f"profile declares no {key}")
        resp, got = self._call(p, spec, {"ref": ref or "", "role": p.name})
        ok = resp.status in spec.expect
        return Observation(ok, status=resp.status,
                           extracted={"value": got.get("value") if ok else None})

    def write_marker(self, p: Principal, value: str, ref: Optional[str] = None) -> Observation:
        key = "write_marker_by_ref" if ref is not None else "write_marker"
        spec = self.profile.oracle.get(key) or self.profile.oracle.get("write_marker")
        if spec is None:
            return Observation(False, note=f"profile declares no {key}")
        resp, _got = self._call(p, spec, {"value": value, "ref": ref or "", "role": p.name})
        return Observation(resp.status in spec.expect, status=resp.status)

    def enrol_bystander(self, p: Principal) -> Observation:
        """Log in the engagement's third account — the oracle's diagnosis control."""
        acct = self.profile.accounts.get("bystander")
        if acct is None:
            return Observation(False, note="profile declares no 'bystander' account")
        obs = self._run_action(p, "login", email=acct.email, password=acct.password)
        if not obs.ok and "register" in self.profile.actions:
            obs = self._run_action(p, "register", email=acct.email, password=acct.password)
        return obs


def live_adapter(profile: TargetProfile, policy: EngagementPolicy,
                 control: Optional[dict] = None, audit: Optional[AuditLog] = None,
                 sessions: Optional[dict] = None):
    """Build a policy-enforced live adapter: transport-level scope, TLS, timeout, size,
    rate and budget limits, plus `policy.guard()`'s action-level gates and audit trail,
    over one shared log. This is how a live adapter should be constructed."""
    log = audit if audit is not None else AuditLog()
    return guard(LiveAdapter(profile, policy, control=control, audit=log,
                             sessions=sessions), policy, log)
