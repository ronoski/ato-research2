"""The vulnerable mock, behind a real socket.

`mock_target.VulnerableTarget` is the in-memory auth system every demo runs against.
This module puts an HTTP skin on *that same object*, so the live path — profile →
`LiveAdapter` → sockets → JSON → oracle — can be exercised end to end with no
authorization and no third-party dependency, and can be checked for the property that
actually matters: it finds the **same** TPI-1 and TPI-4 that the in-process path finds.

It is a deliberately vulnerable auth server. It binds to 127.0.0.1 and nothing else, and
`/testing/...` exposes an inbox the way a catch-all test mailbox would — neither belongs
anywhere but a loopback interface on a development machine.

    with serve(patched=False) as url:
        ...   # url is http://127.0.0.1:<port>
"""
from __future__ import annotations

import json
import re
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from .channels import InMemoryInbox
from .mock_target import VulnerableTarget

BIND_HOST = "127.0.0.1"          # never anything else: this server is vulnerable by design
_USER_NOTE = re.compile(r"^/api/users/([^/]+)/note$")


class _App:
    """The state one server instance serves: the target, an inbox, and the scoping flag."""

    def __init__(self, patched: bool, flat_idor: bool, **target_kw) -> None:
        self.t = VulnerableTarget(patched=patched, **target_kw)
        self.inbox = InMemoryInbox()
        # When true, /api/users/<id>/note answers for any id — a plain object-level
        # authorization bug, so the bystander control can be demonstrated over HTTP.
        self.flat_idor = flat_idor


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "tpihunter-mock/1.0"

    # -- plumbing -------------------------------------------------------------
    def log_message(self, *a) -> None:      # quiet: the demos print their own trace
        pass

    @property
    def app(self) -> _App:
        return self.server.app          # type: ignore[attr-defined]

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n) or b"{}")
        except (ValueError, UnicodeDecodeError):
            return {}

    def _send(self, status: int, payload: dict, cookie: str = "") -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", f"sid={cookie}; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(raw)

    def _sid(self):
        raw = self.headers.get("Cookie") or ""
        for part in raw.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sid":
                return v
        return None

    def _account(self):
        return self.app.t.account_of(self._sid())

    # -- routes ---------------------------------------------------------------
    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/health":
            return self._send(200, {"ok": True})
        if path == "/testing/redirect":
            # Real targets redirect, and a redirect is the target choosing the next URL.
            # This route exists so that choice can be tested against the scope check.
            to = (parse_qs(urlsplit(self.path).query).get("to") or [""])[0]
            self.send_response(302)
            self.send_header("Location", to)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if path == "/testing/inbox":
            addr = (parse_qs(urlsplit(self.path).query).get("address") or [""])[0]
            body = self.app.inbox.latest_link(addr, "http")
            return self._send(200 if body else 404, {"link": body or ""})
        if path == "/api/me":
            acc = self._account()
            return (self._send(200, {"id": acc.id, "email": acc.email}) if acc
                    else self._send(401, {"error": "no session"}))
        if path == "/api/me/note":
            acc = self._account()
            return (self._send(200, {"id": acc.id, "note": acc.marker}) if acc
                    else self._send(401, {"error": "no session"}))
        m = _USER_NOTE.match(path)
        if m:
            acc = self._account()
            if acc is None:
                return self._send(401, {"error": "no session"})
            target = self.app.t.accounts.get(m.group(1))
            if target is None:
                return self._send(404, {"error": "no such resource"})
            if target.id != acc.id and not self.app.flat_idor:
                return self._send(403, {"error": "not yours"})
            return self._send(200, {"id": target.id, "note": target.marker})
        return self._send(404, {"error": "no such route"})

    def do_PUT(self) -> None:
        path = urlsplit(self.path).path
        acc = self._account()
        if acc is None:
            return self._send(401, {"error": "no session"})
        if path == "/api/me/note":
            acc.marker = self._body().get("note")
            return self._send(200, {"id": acc.id, "note": acc.marker})
        m = _USER_NOTE.match(path)
        if m:
            target = self.app.t.accounts.get(m.group(1))
            if target is None:
                return self._send(404, {"error": "no such resource"})
            if target.id != acc.id and not self.app.flat_idor:
                return self._send(403, {"error": "not yours"})
            target.marker = self._body().get("note")
            return self._send(200, {"id": target.id, "note": target.marker})
        return self._send(404, {"error": "no such route"})

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        b = self._body()
        t = self.app.t
        if path == "/api/signup":
            tok, aid = t.register(str(b.get("email", "")), str(b.get("password", "")))
            return (self._send(201, {"id": aid}, cookie=tok) if tok
                    else self._send(409, {"error": "already registered"}))
        if path == "/api/login":
            tok, aid = t.login(str(b.get("email", "")), str(b.get("password", "")))
            return (self._send(200, {"id": aid}, cookie=tok) if tok
                    else self._send(401, {"error": "bad credentials"}))
        if path == "/api/sso":
            # the IdP asserts control of the address; the app trusts the assertion
            tok, aid = t.sso_login(str(b.get("email", "")))
            return self._send(200, {"id": aid}, cookie=tok)
        if path == "/api/reset":
            tok = t.reset_request(str(b.get("email", "")))
            if tok:
                self.app.inbox.deliver(str(b["email"]),
                                       f"Reset your password: http://target/reset?token={tok}")
            return self._send(202, {"sent": bool(tok)})
        if path == "/api/reset/confirm":
            tok, aid = t.reset_consume(str(b.get("token", "")), str(b.get("password", "")))
            return (self._send(200, {"id": aid}, cookie=tok) if tok
                    else self._send(400, {"error": "bad or spent token"}))
        if path == "/api/logout":
            t.logout(self._sid())
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "no such route"})


# The worked example: the profile that drives the server above. A real target's profile
# differs only in routes and field names, so this is the thing to copy and edit.
VICTIM_EMAIL = "victim@corp.example"
ATTACKER_EMAIL = "attacker@corp.example"
BYSTANDER_EMAIL = "bystander@corp.example"


def profile_for(base_url: str) -> dict:
    """A complete, valid `TargetProfile` dict for the server `serve()` runs."""
    return {
        "name": "http-mock",
        "base_url": base_url,
        "accounts": {
            "victim": {"email": VICTIM_EMAIL, "password": "Vv!validate12345"},
            "attacker": {"email": ATTACKER_EMAIL, "password": "Aa!validate12345"},
            "bystander": {"email": BYSTANDER_EMAIL, "password": "Bb!validate12345"},
        },
        "session": {"kind": "cookie"},
        "actions": {
            "register": {"method": "POST", "path": "/api/signup", "expect": [201],
                         "json": {"email": "{email}", "password": "{password}"}},
            "login": {"method": "POST", "path": "/api/login", "expect": [200],
                      "json": {"email": "{email}", "password": "{password}"}},
            "sso_login": {"method": "POST", "path": "/api/sso", "expect": [200],
                          "json": {"email": "{email}"}},
            "reset_request": {"method": "POST", "path": "/api/reset", "expect": [202],
                              "json": {"email": "{email}"}},
            "reset_consume": {"method": "POST", "path": "/api/reset/confirm", "expect": [200],
                              "json": {"token": "{token}", "password": "{new_password}"}},
            "logout": {"method": "POST", "path": "/api/logout", "expect": [200]},
        },
        "oracle": {
            "whoami": {"method": "GET", "path": "/api/me", "expect": [200],
                       "extract": {"identity": {"json": "id"}}},
            "plant_marker": {"method": "PUT", "path": "/api/me/note", "expect": [200],
                             "json": {"note": "{value}"}, "extract": {"ref": {"json": "id"}}},
            "read_marker": {"method": "GET", "path": "/api/me/note", "expect": [200],
                            "extract": {"value": {"json": "note"}}},
            "read_marker_by_ref": {"method": "GET", "path": "/api/users/{ref}/note",
                                   "expect": [200], "extract": {"value": {"json": "note"}}},
            "write_marker": {"method": "PUT", "path": "/api/me/note", "expect": [200],
                             "json": {"note": "{value}"}},
            "write_marker_by_ref": {"method": "PUT", "path": "/api/users/{ref}/note",
                                    "expect": [200], "json": {"note": "{value}"}},
        },
        "channel": {"method": "GET", "path": "/testing/inbox?address={email}", "expect": [200],
                    "extract": {"token": {"regex": "token=([A-Za-z0-9]+)"}}},
    }


def engagement_for(base_url: str) -> dict:
    """The matching engagement file an operator would write for the loopback server."""
    from urllib.parse import urlsplit
    return {"name": "loopback-mock",
            "authorized_by": "the in-process mock server owned by this test run",
            "identifiers": [VICTIM_EMAIL, ATTACKER_EMAIL, BYSTANDER_EMAIL],
            "hosts": [urlsplit(base_url).hostname or BIND_HOST],
            "allow_credential_change": True, "max_actions": 50_000}


@contextmanager
def serve(patched: bool = False, flat_idor: bool = False, **target_kw):
    """Run the vulnerable target on a loopback port for the life of the block."""
    server = ThreadingHTTPServer((BIND_HOST, 0), _Handler)
    server.app = _App(patched, flat_idor, **target_kw)      # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://{BIND_HOST}:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
