"""Surface triage — deciding WHERE to point the modes, before pointing them.

A framework with five hunting modes and no way to choose a target will be pointed at the
most obvious asset, which on any mature estate is the most hardened one. That is what
happened on this project's first real engagement: eleven of twelve cells went to the
flagship consumer identity provider, while eleven other in-scope auth surfaces — two with
`dev` in the hostname, several device-auth and internal management planes — were never
touched at all. No methodology gap explains that. It was a targeting gap.

So this ranks a scope list before the hunt starts, on evidence rather than on which name
is most familiar. Every signal is read from ONE bounded request per asset; nothing is
enumerated, nothing is guessed from the name alone except where the name is itself the
evidence (`-dev`, `-sb`, `staging`).

The ranking is a hypothesis about where to look, not a finding. It says which surface is
most likely to repay the modes, and why.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlsplit

# Names that state their own non-production status. Being non-production is not a
# vulnerability; it is a reason to look, because such estates are patched later and
# watched less.
_NONPROD = re.compile(r"(^|[.\-])(dev|test|stage|staging|sandbox|sb|qa|uat|int|preview)([.\-]|$)")
_AUTHY = re.compile(r"(^|[.\-])(account|accounts|auth|id|login|sso|oauth|idp|adfs|dauth|aauth|ndid)([.\-]|$)")


@dataclass
class Surface:
    url: str
    host: str = ""
    status: Optional[int] = None
    server: str = ""
    content_type: str = ""
    sets_cookie: tuple = ()
    www_authenticate: str = ""
    json_api: bool = False
    reachable: bool = False
    signals: list = field(default_factory=list)
    score: int = 0

    def render(self) -> str:
        bits = f"{str(self.status or '-'):>4}  {self.host:<44}"
        return f"{self.score:>3}  {bits} {', '.join(self.signals) or '-'}"


def characterise(url: str, send: Callable) -> Surface:
    """One request. `send(url) -> response` with .status/.headers/.text."""
    s = Surface(url=url, host=(urlsplit(url).hostname or url))
    r = send(url)
    if r is None:
        s.signals.append("refused-by-scope")
        return s
    s.status = getattr(r, "status", None)
    h = {k.lower(): v for k, v in (getattr(r, "headers", {}) or {}).items()}
    s.server = h.get("server", "")
    s.content_type = h.get("content-type", "")
    s.www_authenticate = h.get("www-authenticate", "")
    raw = h.get("set-cookie", "")
    s.sets_cookie = tuple(sorted({c.split("=")[0].strip() for c in raw.split(",") if "=" in c}))
    body = getattr(r, "text", "") or ""
    s.json_api = "json" in s.content_type or body.strip().startswith(("{", "["))
    s.reachable = bool(s.status)
    return score(s)


def score(s: Surface) -> Surface:
    """Rank by how likely the modes are to find something, with the reason recorded."""
    pts = 0
    host = s.host.lower()

    if not s.reachable:
        s.signals.append("unreachable")
        return s

    if _NONPROD.search(host):
        pts += 40
        s.signals.append("non-production name — patched later, watched less")
    if _AUTHY.search(host):
        pts += 25
        s.signals.append("identity surface")
    if s.json_api:
        pts += 20
        s.signals.append("API, not a rendered UI — drivable without a browser")
    if s.www_authenticate:
        pts += 20
        s.signals.append(f"declares an auth scheme ({s.www_authenticate.split()[0]})")
    if s.status in (401, 403):
        pts += 15
        s.signals.append(f"{s.status}: something is gated here")
    if s.sets_cookie:
        pts += 15
        s.signals.append(f"issues cookies ({', '.join(s.sets_cookie[:3])})")
    if s.status == 200 and not s.json_api and not s.sets_cookie:
        pts -= 10
        s.signals.append("static/marketing page")
    if s.status in (404, 501):
        pts -= 5
        s.signals.append("no root handler")

    s.score = pts
    return s


def triage(urls: list, send: Callable, budget=None) -> list:
    """Characterise each asset once and return them best-first."""
    out = []
    for u in urls:
        if budget is not None:
            try:
                budget.take("surface")
            except Exception:
                break
        out.append(characterise(u, send))
    return sorted(out, key=lambda s: -s.score)


# --------------------------------------------------------------------------- #
#  The catch-all control.
# --------------------------------------------------------------------------- #
import hashlib
import secrets as _secrets


@dataclass
class Baseline:
    """What the app returns for a path that certainly does not exist.

    Without this, "HTTP 200 on /admin" reads as reachable when the app serves one page for
    every path. Measured live: an in-scope developer portal returned a byte-identical
    11,998-byte page for `/`, `/welcome`, `/j_spring_security_logout` AND a nonsense path —
    three "reachable without auth" results, all artefacts of a catch-all.
    """
    status: Optional[int]
    digest: str
    length: int

    def distinct(self, status: Optional[int], text: str) -> bool:
        """True when a response says something the catch-all does not."""
        if status != self.status:
            return True
        return hashlib.sha256((text or "").encode()).hexdigest() != self.digest


def catchall_baseline(base_url: str, send: Callable) -> Optional[Baseline]:
    """Fetch a path nobody has ever served. Its response is the floor every other
    response must clear before it counts as anything."""
    nonce = _secrets.token_hex(8)
    r = send(base_url.rstrip("/") + f"/does-not-exist-{nonce}")
    if r is None:
        return None
    text = getattr(r, "text", "") or ""
    return Baseline(getattr(r, "status", None),
                    hashlib.sha256(text.encode()).hexdigest(), len(text))


def render_table(surfaces: list) -> str:
    lines = [f"{'pts':>3}  {'code':>4}  {'host':<44} why",
             f"{'---':>3}  {'----':>4}  {'-'*44} {'-'*40}"]
    lines += [s.render() for s in surfaces]
    return "\n".join(lines)
