"""Secret scrubbing for anything this tool emits.

Two of the outputs here leave the operator's machine: the evidence bundle in
`report.py` (pasted into a bug-bounty submission or a ticket) and the audit log in
`policy.py` (kept as the record of an engagement). Both are assembled from adapter
observations, and on a real target an observation's `note` is whatever the app said —
which routinely includes a live session token, a password-reset link, an authorization
header, or a one-time code.

Handing a triage team a working reset link for a test account is a real disclosure, and
it is the kind that happens by accident at the last step of otherwise careful work. So
everything secret-shaped is masked on the way out, keeping a short prefix so two
occurrences of the same value can still be correlated across a report:

    http://target/reset?token=b3f1...  ->  http://target/reset?token=b3f1…[redacted:32]

This is a safety net, not a licence to put secrets in notes. It is deliberately
conservative: it would rather mask a harmless identifier than leak a live credential.
"""
from __future__ import annotations

import re
from typing import Any

_PREFIX = 4          # characters of a secret kept, so occurrences stay correlatable
_MIN = 16            # shortest opaque blob treated as a secret


def _mask(value: str) -> str:
    return f"{value[:_PREFIX]}…[redacted:{len(value)}]"


# One combined pass, so a mask inserted by one rule can never be re-matched by the next.
# Ordered most-specific first; only the `secret` group of a match is replaced.
_SECRET = re.compile(r"""(?xi)
    # 1. a labelled value: token=..., "password": "...", Authorization: Bearer ...
      \b(?P<key>token|secret|password|passwd|pwd|api[_-]?key|apikey|authorization|
            session|sid|cookie|otp|nonce|assertion|credential|access[_-]?token|
            refresh[_-]?token|id[_-]?token)
      (?P<sep>["\']?\s*[=:]\s*(?:bearer\s+)?|\s+bearer\s+)
      (?P<quote>["\']?)(?P<secret>[A-Za-z0-9._~+/=-]{6,})(?P=quote)
    # 2. a JWT / signed token: three base64url segments
    | (?P<jwt>\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b)
    # 3. a long opaque handle: hex, or high-entropy base64url
    | (?P<hex>\b[0-9a-fA-F]{%d,}\b)
    | (?P<b64>\b[A-Za-z0-9_-]{24,}\b)
""" % _MIN)

# Words that are shaped like a blob but carry no secret; masking them only makes a
# report unreadable.
_ALLOW = frozenset({"true", "false", "null", "none", "undefined", "application", "bearer"})

# A field NAME that makes its value a secret whatever the value looks like. In a dict the
# sensitivity lives in the key, and a short or low-entropy password ("hunter2") is exactly
# the one no shape-based rule would catch on its own.
_SECRET_KEY = re.compile(
    r"(?i)(^|[_.\-])(token|secret|password|passwd|pwd|api[_-]?key|apikey|authorization|"
    r"auth|session|sid|cookie|otp|nonce|assertion|credential|canary|marker)([_.\-]|$)")


# Control characters and the line/paragraph separators that let a crafted value break out
# of the sentence it was interpolated into.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029]")


def untrusted(value: Any, limit: int = 120) -> str:
    """Render a TARGET-supplied value safe to interpolate into text a model will read.

    An account identifier, a resource reference or an error note comes from the system
    under test, and on a live target that system is not trustworthy — its responses reach
    the strategist's context through the oracle's evidence and the MCP tool results. This
    does not "solve" prompt injection; it removes the cheap version of it, where a crafted
    identity string carries its own newlines and impersonates a new instruction block, and
    it caps length so one field cannot flood the context.
    """
    text = value if isinstance(value, str) else repr(value)
    text = _CONTROL.sub(" ", text).replace("\n", " ").replace("\r", " ").strip()
    if len(text) > limit:
        text = text[:limit] + "…"
    return text


def redact(value: Any) -> Any:
    """Mask secret-shaped substrings in `value`, recursing through dicts/lists/tuples.

    In a dict, a key that names a secret masks its value outright: `{"password": "hunter2"}`
    is a credential even though "hunter2" is shaped like an ordinary word."""
    if isinstance(value, str):
        return _redact_text(value)
    if isinstance(value, dict):
        return {k: (_mask(v) if isinstance(v, str) and v and _SECRET_KEY.search(str(k))
                    else redact(v))
                for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact(v) for v in value)
    return value


def _sub(m: "re.Match") -> str:
    if m.group("secret") is not None:
        return f"{m.group('key')}{m.group('sep')}{m.group('quote')}{_mask(m.group('secret'))}{m.group('quote')}"
    hit = m.group("jwt") or m.group("hex") or m.group("b64")
    return hit if hit.lower() in _ALLOW else _mask(hit)


def _redact_text(text: str) -> str:
    return _SECRET.sub(_sub, text) if text else text
