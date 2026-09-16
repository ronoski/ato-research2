"""GrabID adapter — the first LIVE target, mapping a real multi-phase login.

RUNG 2. `READINESS.md` puts this project on rung 1: everything validated only
against a mock it authored itself, with the whole remaining distance being "live
validation on an authorized target". This module is that bridge for one authorized
target (Grab's public bug-bounty programme, open since 2015).

WHY GRABID IS THE RIGHT FIRST TARGET
------------------------------------
Its login is genuinely multi-phase, so it exercises the session-trust lattice that
`stepup.py` made expressible:

    POST grabid/v1/phone/otp     -> challengeID           (an SMS is dispatched)
    POST grabid/v1/phone/token   -> preAuthToken          ANON  -> PARTIAL
    POST grabid/v1/phone/login   -> 401 + X-GRAB-AUTHZ-REQ  PARTIAL stays PARTIAL
                                    (the step-up the account enrolled)
    <satisfy the named factor>                            PARTIAL -> FULL

MEASURED, 2026-09-16, and why the mapping below is shaped as it is:

  * The layer ordering is  field-validation (10015) -> credential (14000) -> service.
    A request consumes an OTP attempt IF AND ONLY IF it passes the credential check,
    so every structural question is free. `probe_structure()` exploits exactly that.
  * `phone/otp` alone requires an `Authorization: grabsecure <sig>` REQUEST SIGNATURE
    the app computes. It cannot be driven from off-device, which is why
    `first_factor()` raises rather than pretending: the SMS leg needs the rig.
  * The preAuthToken is FACTOR-SCOPED: every login/verify route refuses one minted
    for a different factor with 14000.
  * BUT `phone/reset/pin` — a credential-MUTATING recovery route — accepts it
    (409/10111 "no PIN set" vs 401/16004 for a bogus token). That asymmetry is the
    TPI-6 hypothesis this adapter exists to test.

⛔ SAFETY, structural rather than remembered:
  * No code, PIN or token is ever guessed. Codes come from an out-of-band relay the
    operator supplies via `code_provider`; absent one, the SMS leg simply does not run.
  * `BARRED` routes are refused before a request is built.
  * Nothing here creates an account: `register()` raises. Account creation is an
    operator action on this target, by policy.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..types import Channel, Identifier, Observation, Principal, ProofEvent, SessionLevel

HOST = "api.grab.com"

# ⛔ refused before a request is constructed: these mutate a credential or can lock an account.
BARRED = re.compile(r"(reset[-/]?pin|pinrecovery|recovery-setup|/approve|/reject|"
                    r"unenroll|register|pin/verify)", re.I)

# Error codes whose meaning is MEASURED on the live target (see ato/recon/error_codes.json).
FIELD_MISSING = "10015"   # per-field; the COUNT equals the number of absent required fields
CRED_WRONG_FLOW = "14000"  # "token present but not a valid preAuthToken FOR THIS FLOW"
CRED_INVALID = "16004"     # generic invalid/expired token
NO_PIN = "10111"           # user has no PIN set


@dataclass
class _Ctx:
    """One principal's independent context. A partial context holds an intermediate
    credential; a full one would hold a session token."""
    pre_auth: Optional[str] = None
    challenge: Optional[str] = None
    session: Optional[str] = None
    level: SessionLevel = SessionLevel.ANON


@dataclass
class GrabIDAdapter:
    """Two-principal adapter over the live GrabID pre-auth plane.

    `code_provider(msisdn) -> str | None` returns an OTP the operator obtained
    out of band (an SMS relay). It is never generated here.
    `first_factor_driver(msisdn) -> (preAuthToken, challengeID)` drives the signed
    SMS leg on a device. Both are injected, so this class never fabricates a secret.
    """
    bug_bounty_header: str
    device_id: str
    code_provider: Optional[Callable[[str], Optional[str]]] = None
    first_factor_driver: Optional[Callable[[str], tuple[str, str]]] = None
    ctx: dict = field(default_factory=dict)
    sent: list = field(default_factory=list)

    # ── transport ────────────────────────────────────────────────────────────
    def _post(self, path: str, body: dict, method: str = "POST") -> tuple[int, str]:
        if BARRED.search(path):
            raise PermissionError(f"refused: {path} matches a barred class")
        return self._raw(path, body, method)

    def _raw(self, path: str, body: Optional[dict], method: str = "POST") -> tuple[int, str]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            f"https://{HOST}/grabid/v1/{path}", data=data, method=method,
            headers={"Content-Type": "application/json; charset=UTF-8",
                     "X-Bug-Bounty": self.bug_bounty_header,
                     "X-Grab-Device-ID": self.device_id,
                     "Accept-Language": "en-US"})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                return r.status, r.read().decode("utf8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf8", "replace")

    @staticmethod
    def _code(body: str) -> str:
        try:
            j = json.loads(body)
            return str(j.get("statusCode") or (j.get("errors") or [{}])[0].get("code") or "")
        except Exception:
            return ""

    def _ctx(self, p: Principal) -> _Ctx:
        return self.ctx.setdefault(p.name, _Ctx())

    # ── Sigma ────────────────────────────────────────────────────────────────
    def register(self, p: Principal, email: str, password: str) -> Observation:
        raise PermissionError(
            "account creation is an operator action on this target and is not automated")

    def first_factor(self, p: Principal, msisdn: str) -> Observation:
        """ANON -> PARTIAL. Requires the signed SMS leg, so it delegates to a driver."""
        if self.first_factor_driver is None:
            raise RuntimeError(
                "phone/otp requires an `Authorization: grabsecure` request signature only the "
                "app computes (MEASURED: unsigned calls get a bodyless 400). Supply "
                "first_factor_driver to drive a device, or the SMS leg cannot run.")
        tok, chal = self.first_factor_driver(msisdn)
        c = self._ctx(p)
        c.pre_auth, c.challenge, c.level = tok, chal, SessionLevel.PARTIAL
        return Observation(ok=True, status=200, session=SessionLevel.PARTIAL,
                           extracted={"token": tok, "challengeID": chal},
                           proof=ProofEvent(principal=p, resource=Identifier("phone", msisdn),
                                            channel=Channel.SMS),
                           note="intermediate credential minted from the SMS factor")

    def session_upgrade(self, p: Principal) -> Observation:
        """The PRIMARY flow. Its refusal is the control TPI-6 requires."""
        c = self._ctx(p)
        if not c.pre_auth:
            return Observation(ok=False, status=401, session=SessionLevel.ANON,
                               note="no intermediate credential")
        body = urllib.parse.urlencode({"token": c.pre_auth}).encode()
        req = urllib.request.Request(
            f"https://{HOST}/grabid/v1/phone/login", data=body, method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "X-Bug-Bounty": self.bug_bounty_header,
                     "X-Grab-Device-ID": self.device_id})
        try:
            with urllib.request.urlopen(req, timeout=25) as r:
                st, hdrs = r.status, dict(r.headers)
                c.level = SessionLevel.FULL
                return Observation(ok=True, status=st, session=SessionLevel.FULL,
                                   note="session minted")
        except urllib.error.HTTPError as e:
            hdrs = {k.lower(): v for k, v in dict(e.headers).items()}
            req_factor = hdrs.get("x-grab-authz-req")
            c.challenge = hdrs.get("x-grab-challenge-id") or c.challenge
            return Observation(ok=False, status=e.code, session=SessionLevel.PARTIAL,
                               extracted={"authz_req": req_factor or "",
                                          "challengeID": c.challenge or ""},
                               note=f"step-up required: {req_factor}" if req_factor
                                    else "refused without a named factor")

    def privileged_recovery(self, p: Principal) -> Observation:
        """The sibling transition TPI-6 asks about: does it accept what login refused?

        ⛔ `phone/reset/pin` is in BARRED, so this goes through `_raw` deliberately and
        ONLY when the operator has opted in for a disposable account.
        """
        c = self._ctx(p)
        if not c.pre_auth:
            return Observation(ok=False, status=401, note="no intermediate credential")
        st, body = self._raw("phone/reset/pin", {"token": c.pre_auth})
        code = self._code(body)
        return Observation(ok=(st == 200), status=st, session=c.level,
                           extracted={"code": code},
                           note={NO_PIN: "accepted the credential; account has no PIN to reset",
                                 CRED_INVALID: "credential rejected as invalid"}.get(code, body[:120]))

    # ── free structural probing (costs no OTP attempt) ───────────────────────
    def probe_structure(self, path: str, candidate_fields: list[str]) -> dict:
        """Recover a route's Go struct via the type-mismatch oracle, then its required
        set via the 10015 count. Uses BOGUS values only, so it cannot pass the
        credential layer and therefore cannot consume an attempt or mutate state."""
        bogus = "00000000-0000-4000-a000-000000000000"
        struct, fields = None, {}
        for f in candidate_fields:
            _, body = self._raw(path, {f: []})
            m = re.search(r"Go struct field (\w+)\.(\w+) of type ([\w\.\[\]]+)", body)
            if m:
                struct, fields[m.group(2)] = m.group(1), m.group(3)
        required = []
        if fields:
            full = {f: (bogus if "str" in t else []) for f, t in fields.items()}
            for f in list(fields):
                _, b = self._raw(path, {k: v for k, v in full.items() if k != f})
                if self._code(b) == FIELD_MISSING:
                    required.append(f)
        return {"struct": struct, "fields": fields, "required": required}
