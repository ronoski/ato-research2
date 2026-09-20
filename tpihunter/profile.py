"""A target described as data, so an agent can author it instead of writing Python.

The wall between "the framework works" and "an AI session hunts a real system" is not
the hunt — it is the adapter. Today hunting a real target means a human subclasses
`TargetAdapter`; an agent in an MCP session cannot do that, and should not be able to.

So the target becomes a `TargetProfile`: a JSON-shaped description of its auth surface —
which endpoint registers, how a session is carried, where the identity comes back, which
private resource holds the canary — that `live.LiveAdapter` interprets. An agent can
propose one, run `validate.validate_target()`, read a red line, fix one field, and try
again, without anyone writing or loading code.

A profile is UNTRUSTED INPUT. It is authored by a model reading a target's own responses,
and it decides what requests get sent, so it is validated like any other untrusted input
and every URL it produces is checked against the engagement policy at request time (see
`live.ScopedTransport`). Two rules do most of the work:

  * an action's `path` is a path, never an absolute URL. One profile addresses one
    origin; a target that spans hosts needs each host in the policy's allowlist, and
    saying so out loud beats discovering it through a redirect.
  * placeholders are a closed set. An unknown `{...}` is a validation error, not a
    literal passed through to the target, because a silently-unsubstituted placeholder
    is how a probe ends up asserting something about a field that was never filled in.

Shape:

    {
      "name": "acme-staging",
      "base_url": "https://staging.acme.example",
      "accounts": {"victim": {"email": "...", "password": "..."}, "attacker": {...},
                   "bystander": {...}},
      "session": {"kind": "cookie"},                  # or a bearer token, see SessionSpec
      "actions":  {"register": {...}, "login": {...}, ...},
      "oracle":   {"whoami": {...}, "plant_marker": {...}, "read_marker": {...}, ...},
      "channel":  {...}                               # how a mailed token is retrieved
    }
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import quote, urlsplit

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD")

# Every placeholder a template may use. Closed on purpose: an unknown one is an error.
PLACEHOLDERS = frozenset({
    "email", "password", "new_password", "new_email", "alias", "role",
    "value", "ref", "token", "code", "identity", "base_url",
})

# The oracle surface a profile must describe for a two-principal hunt to mean anything.
REQUIRED_ORACLE = ("whoami", "read_marker")
OPTIONAL_ORACLE = ("plant_marker", "write_marker", "read_marker_by_ref",
                   "write_marker_by_ref")

_PLACEHOLDER = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_FORBIDDEN_HEADERS = frozenset({"host", "content-length", "transfer-encoding"})
_MAX_REGEX = 200


class ProfileError(ValueError):
    """The profile is not usable. The message names every problem, so one round trip
    is enough to fix them all."""


# --------------------------------------------------------------------------- #
#  Extraction: how a value is pulled out of a response.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Extract:
    kind: str      # json | header | cookie | regex | status | const
    spec: str

    def apply(self, response) -> Optional[str]:
        if self.kind == "status":
            return str(response.status)
        if self.kind == "const":
            return self.spec
        if self.kind == "header":
            return response.headers.get(self.spec.lower())
        if self.kind == "cookie":
            return response.cookies.get(self.spec)
        if self.kind == "regex":
            # Scans the whole response, which the transport has ALREADY bounded by the
            # profile's max_bytes. An earlier version cut the scan at 64 KiB as a crude
            # ReDoS guard, and on a real target the value it was looking for sat at offset
            # 69,800 of a 74 KiB page: the extractor returned nothing, the oracle correctly
            # refused to render a verdict, and the cause was this guard rather than the
            # target. Response size is the right place to bound this; truncating the scan
            # silently changes what the profile means.
            m = re.search(self.spec, response.text)
            return (m.group(1) if m.groups() else m.group(0)) if m else None
        if self.kind == "json":
            return _dig(response.json(), self.spec)
        return None

    @staticmethod
    def parse(raw: Any, where: str, problems: list) -> Optional["Extract"]:
        if not isinstance(raw, dict) or len(raw) != 1:
            problems.append(f"{where}: an extractor is one of "
                            f"{{json|header|cookie|regex|status|const}}: <spec>")
            return None
        (kind, spec), = raw.items()
        if kind not in ("json", "header", "cookie", "regex", "status", "const"):
            problems.append(f"{where}: unknown extractor {kind!r}")
            return None
        spec = "" if spec is None else str(spec)
        if kind == "regex":
            if len(spec) > _MAX_REGEX:
                problems.append(f"{where}: regex longer than {_MAX_REGEX} characters")
                return None
            try:
                re.compile(spec)
            except re.error as e:
                problems.append(f"{where}: regex does not compile ({e})")
                return None
        return Extract(kind, spec)


def _dig(doc: Any, path: str) -> Optional[str]:
    """Walk a dotted path into parsed JSON. `a.b.0.c` indexes lists too."""
    cur = doc
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit() and int(part) < len(cur):
            cur = cur[int(part)]
        else:
            return None
        if cur is None:
            return None
    return cur if isinstance(cur, str) else json.dumps(cur)


# --------------------------------------------------------------------------- #
#  One request.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Request:
    method: str
    path: str
    json_body: Optional[Any] = None
    form: Optional[dict] = None
    headers: dict = field(default_factory=dict)
    expect: tuple = (200, 201, 202, 204)
    extract: dict = field(default_factory=dict)        # name -> Extract
    session_from: Optional[Extract] = None             # capture a bearer token here

    @staticmethod
    def parse(raw: Any, where: str, problems: list) -> Optional["Request"]:
        if not isinstance(raw, dict):
            problems.append(f"{where}: must be an object describing one request")
            return None
        method = str(raw.get("method", "GET")).upper()
        if method not in METHODS:
            problems.append(f"{where}.method: must be one of {', '.join(METHODS)}")
        path = raw.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            problems.append(f"{where}.path: must be a path beginning with '/' — an "
                            f"absolute URL would leave the profile's own origin")
            path = "/"
        elif "://" in path or path.startswith("//"):
            problems.append(f"{where}.path: must not contain a scheme or authority")
        _check_placeholders(path, f"{where}.path", problems)

        body = raw.get("json")
        form = raw.get("form")
        if body is not None and form is not None:
            problems.append(f"{where}: give either 'json' or 'form', not both")
        if body is not None:
            _check_placeholders(body, f"{where}.json", problems)
        if form is not None:
            if not isinstance(form, dict):
                problems.append(f"{where}.form: must be an object")
                form = None
            else:
                _check_placeholders(form, f"{where}.form", problems)

        headers = {}
        for k, v in (raw.get("headers") or {}).items():
            if not _HEADER_NAME.match(str(k)) or str(k).lower() in _FORBIDDEN_HEADERS:
                problems.append(f"{where}.headers: {k!r} is not a settable header name")
                continue
            _check_placeholders(str(v), f"{where}.headers.{k}", problems)
            headers[str(k)] = str(v)

        expect = raw.get("expect", [200, 201, 202, 204])
        if not isinstance(expect, (list, tuple)) or not expect:
            problems.append(f"{where}.expect: must be a non-empty list of status codes")
            expect = [200]
        bad = [c for c in expect if not (isinstance(c, int) and 100 <= c <= 599)]
        if bad:
            problems.append(f"{where}.expect: not HTTP status codes: {bad}")
            expect = [c for c in expect if c not in bad] or [200]

        extract = {}
        for name, spec in (raw.get("extract") or {}).items():
            e = Extract.parse(spec, f"{where}.extract.{name}", problems)
            if e is not None:
                extract[str(name)] = e
        session_from = None
        if raw.get("session_from") is not None:
            session_from = Extract.parse(raw["session_from"], f"{where}.session_from", problems)

        return Request(method=method, path=path, json_body=body, form=form,
                       headers=headers, expect=tuple(expect), extract=extract,
                       session_from=session_from)


def _check_placeholders(value: Any, where: str, problems: list) -> None:
    """Every `{name}` must be one we know how to fill. A placeholder that survives
    rendering is silently wrong: the request goes out with a literal brace in it and the
    probe reports on a field that was never filled."""
    if isinstance(value, str):
        for name in _PLACEHOLDER.findall(value):
            if name not in PLACEHOLDERS:
                problems.append(f"{where}: unknown placeholder {{{name}}} "
                                f"(known: {', '.join(sorted(PLACEHOLDERS))})")
    elif isinstance(value, dict):
        for k, v in value.items():
            _check_placeholders(k, where, problems)
            _check_placeholders(v, where, problems)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _check_placeholders(v, where, problems)


def render_path(template: str, vars: dict) -> str:
    """Render a path, percent-encoding whatever is substituted in.

    A `{ref}` or `{email}` is routinely a value the TARGET returned, so an unencoded
    substitution lets the target pick path segments — `..`, a stray `?`, a second query
    string. The origin is still fixed by `base_url` (and re-checked by the transport), but
    a value should not be able to change the shape of the request it travels in."""
    def sub(m):
        got = vars.get(m.group(1))
        return "" if got is None else quote(str(got), safe="")
    return _PLACEHOLDER.sub(sub, template)


def render(value: Any, vars: dict) -> Any:
    """Substitute placeholders through a structure, leaving non-strings alone.

    Substitution happens on VALUES, never on serialised JSON text, so a value containing
    a quote or a brace cannot restructure the request it travels in."""
    if isinstance(value, str):
        def sub(m):
            got = vars.get(m.group(1))
            return "" if got is None else str(got)
        return _PLACEHOLDER.sub(sub, value)
    if isinstance(value, dict):
        return {render(k, vars): render(v, vars) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [render(v, vars) for v in value]
    return value


# --------------------------------------------------------------------------- #
#  How a session is carried.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class SessionSpec:
    kind: str = "cookie"          # "cookie" (a jar per principal) | "header" (bearer token)
    header: str = "Authorization"
    format: str = "Bearer {token}"
    # True when this tool must NOT authenticate here and sessions are handed to it instead.
    # Set it for any target whose login is gated by a CAPTCHA, a device check or a push
    # approval: defeating those is a hard stop on every programme worth testing, so the
    # honest description of such a target is "I cannot log in", declared up front.
    supplied: bool = False

    @staticmethod
    def parse(raw: Any, problems: list) -> "SessionSpec":
        if raw is None:
            return SessionSpec()
        if not isinstance(raw, dict):
            problems.append("session: must be an object")
            return SessionSpec()
        kind = str(raw.get("kind", "cookie"))
        if kind not in ("cookie", "header"):
            problems.append("session.kind: must be 'cookie' or 'header'")
            kind = "cookie"
        header = str(raw.get("header", "Authorization"))
        if not _HEADER_NAME.match(header) or header.lower() in _FORBIDDEN_HEADERS:
            problems.append(f"session.header: {header!r} is not a settable header name")
            header = "Authorization"
        fmt = str(raw.get("format", "Bearer {token}"))
        _check_placeholders(fmt, "session.format", problems)
        return SessionSpec(kind, header, fmt, bool(raw.get("supplied", False)))


@dataclass(frozen=True)
class Account:
    email: str
    password: str


# --------------------------------------------------------------------------- #
#  The profile.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class TargetProfile:
    name: str
    base_url: str
    accounts: dict                 # role -> Account
    session: SessionSpec
    actions: dict                  # action name -> Request
    oracle: dict                   # surface name -> Request
    channel: Optional[Request] = None
    canary: str = "planted"        # "planted" (needs a writable private field) | "natural"
    verify_tls: bool = True
    timeout: float = 10.0
    max_bytes: int = 262_144

    # -- construction ---------------------------------------------------------
    @staticmethod
    def from_dict(raw: Any) -> "TargetProfile":
        problems: list = []
        if not isinstance(raw, dict):
            raise ProfileError("profile must be an object")

        name = str(raw.get("name") or "").strip()
        if not name:
            problems.append("name: required, so findings and audit records can be attributed")

        base_url = str(raw.get("base_url") or "").strip()
        parts = urlsplit(base_url)
        if parts.scheme not in ("http", "https"):
            problems.append("base_url: must be an http(s) URL")
        if not parts.hostname:
            problems.append("base_url: has no host")
        if parts.username or parts.password:
            problems.append("base_url: must not carry credentials in the URL")
        if parts.query or parts.fragment:
            problems.append("base_url: must not carry a query or fragment")

        accounts = {}
        raw_accounts = raw.get("accounts") or {}
        if not isinstance(raw_accounts, dict):
            problems.append("accounts: must be an object of role -> {email, password}")
            raw_accounts = {}
        for role, spec in raw_accounts.items():
            if not isinstance(spec, dict) or not spec.get("email"):
                problems.append(f"accounts.{role}: needs at least an 'email'")
                continue
            accounts[str(role)] = Account(str(spec["email"]), str(spec.get("password") or ""))
        for role in ("victim", "attacker"):
            if role not in accounts:
                problems.append(f"accounts.{role}: required — a two-principal hunt needs "
                                f"an independent account per principal")

        session = SessionSpec.parse(raw.get("session"), problems)

        actions = {}
        for aname, spec in (raw.get("actions") or {}).items():
            if not re.match(r"^[a-z][a-z0-9_]{0,62}$", str(aname)):
                problems.append(f"actions.{aname}: name must be a lowercase identifier")
                continue
            r = Request.parse(spec, f"actions.{aname}", problems)
            if r is not None:
                actions[str(aname)] = r
        if session.supplied:
            offenders = sorted({"register", "login"} & set(actions))
            if offenders:
                problems.append(
                    f"actions.{'/'.join(offenders)}: must not be declared when "
                    f"session.supplied is true — that setting means this tool does not "
                    f"authenticate here, so it must not be able to try")
        elif "register" not in actions and "login" not in actions:
            problems.append("actions: needs at least 'register' or 'login' — a principal "
                            "has to be able to establish a session. If the target's login "
                            "is gated by a CAPTCHA or a device check, set "
                            '"session": {"supplied": true} and pass sessions captured '
                            "out of band instead")

        oracle = {}
        for oname, spec in (raw.get("oracle") or {}).items():
            if oname not in REQUIRED_ORACLE + OPTIONAL_ORACLE:
                problems.append(f"oracle.{oname}: unknown; expected one of "
                                f"{', '.join(REQUIRED_ORACLE + OPTIONAL_ORACLE)}")
                continue
            r = Request.parse(spec, f"oracle.{oname}", problems)
            if r is not None:
                oracle[oname] = r
        for oname in REQUIRED_ORACLE:
            if oname not in oracle:
                problems.append(f"oracle.{oname}: required — without it the oracle has no "
                                f"ground truth and every verdict is vacuous")
        if "whoami" in oracle and "identity" not in oracle["whoami"].extract:
            problems.append("oracle.whoami.extract.identity: required — it is how the "
                            "oracle tells two principals apart")
        if "read_marker" in oracle and "value" not in oracle["read_marker"].extract:
            problems.append("oracle.read_marker.extract.value: required — it is the canary")

        channel = None
        if raw.get("channel") is not None:
            channel = Request.parse(raw["channel"], "channel", problems)
            if channel is not None and "token" not in channel.extract:
                problems.append("channel.extract.token: required — it is how a mailed "
                                "reset/magic-link token is recovered")

        canary = str(raw.get("canary", "planted"))
        if canary not in ("planted", "natural"):
            problems.append("canary: must be 'planted' (write a secret into a private "
                            "field) or 'natural' (observe one the account already has — "
                            "for a rules-of-engagement that authorises reads, not writes)")
            canary = "planted"
        if canary == "planted" and not ({"plant_marker", "write_marker"} & set(oracle)):
            problems.append("oracle.plant_marker: required in 'planted' canary mode — "
                            "declare one, or set \"canary\": \"natural\" if the "
                            "engagement does not authorise writes")
        if canary == "natural" and ({"plant_marker", "write_marker", "write_marker_by_ref"}
                                    & set(oracle)):
            problems.append("oracle: 'natural' canary mode must declare no write route — "
                            "remove plant_marker/write_marker so a write cannot be issued")

        verify_tls = bool(raw.get("verify_tls", True))
        try:
            timeout = float(raw.get("timeout", 10.0))
            if not 0 < timeout <= 120:
                raise ValueError
        except (TypeError, ValueError):
            problems.append("timeout: must be a number of seconds in (0, 120]")
            timeout = 10.0
        try:
            max_bytes = int(raw.get("max_bytes", 262_144))
            if not 1024 <= max_bytes <= 8_388_608:
                raise ValueError
        except (TypeError, ValueError):
            problems.append("max_bytes: must be between 1024 and 8388608")
            max_bytes = 262_144

        if problems:
            raise ProfileError("profile has " + str(len(problems)) + " problem(s):\n  - "
                               + "\n  - ".join(problems))
        return TargetProfile(name=name, base_url=base_url.rstrip("/"), accounts=accounts,
                             session=session, actions=actions, oracle=oracle,
                             channel=channel, canary=canary, verify_tls=verify_tls,
                             timeout=timeout, max_bytes=max_bytes)

    # -- helpers --------------------------------------------------------------
    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    def identifiers(self) -> frozenset:
        """Every account identifier this profile touches — the set an engagement policy
        has to name before the profile may be used."""
        return frozenset(a.email for a in self.accounts.values())

    def describe(self) -> dict:
        """A compact, credential-free summary — safe to show an agent or put in a report."""
        return {
            "name": self.name, "base_url": self.base_url, "host": self.host,
            "accounts": {r: a.email for r, a in self.accounts.items()},
            "session": self.session.kind + (" (supplied)" if self.session.supplied else ""),
            "actions": sorted(self.actions),
            "oracle": sorted(self.oracle),
            "channel": self.channel is not None,
            "canary": self.canary,
            "verify_tls": self.verify_tls,
        }
