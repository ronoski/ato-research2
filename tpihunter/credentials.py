"""Credential structure — the other thing the state machine treats as opaque.

TPI reasons about a binding: who holds it, what proof justifies it, what revokes it. The
binding's HANDLE — the session cookie, the reset token, the bearer — is an atom to it. So
a handle that is *derivable* rather than unguessable is invisible: an attacker who can
predict the next one holds a binding with no proof event behind it, and the trace the
oracle reads contains nothing at all.

That is a provenance gap (TPI-5) reached without any transition, which is why it needs its
own mode rather than another probe shape.

WHY THIS IS HARD TO DO HONESTLY

Positional analysis over a handful of samples ALWAYS looks alarming: with six tokens, no
character position can show more than six distinct values, and a naive reading calls that
2.6 bits per position. The number is an artefact of the sample size, not a property of the
target, and reporting it would be manufacturing a finding.

So every structural claim here is made DIFFERENTIALLY, against reference samples drawn
from `secrets` at the same length and the same sample count. A real token is only called
weak when it scores materially worse than randomness measured the same crippled way.

    rep = analyse([CredentialSample(v, label="NASID") for v in seen])
    print(rep.render())
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import secrets
import string
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

MIN_SESSION_BITS = 64          # below this a handle is guessable at internet scale
MIN_SAMPLES_FOR_STRUCTURE = 4  # fewer, and positional analysis says nothing at all


class Shape(str, Enum):
    JWT = "jwt"
    HEX = "hex"
    BASE64URL = "base64url"
    UUID = "uuid"
    NUMERIC = "numeric"
    OPAQUE = "opaque"


@dataclass(frozen=True)
class CredentialSample:
    value: str
    label: str = "credential"
    account: Optional[str] = None
    minted_at: Optional[float] = None
    # Has this value been SHOWN to authenticate? Entropy is only a finding for something
    # that grants access. Measured live: a 10-digit browser-state cookie sitting beside a
    # real session cookie was flagged "low-entropy handle" — true of the string, and
    # meaningless, because nothing had shown it authenticated anything. Unknown by
    # default, and unknown means a note rather than a finding.
    authenticates: Optional[bool] = None


@dataclass
class Finding:
    kind: str
    detail: str
    severity: str = "medium"

    def render(self) -> str:
        return f"[{self.severity}] {self.kind}: {self.detail}"


@dataclass
class Report:
    label: str
    n: int
    shape: Shape
    length: int
    alphabet: int
    naive_bits: float
    jwt: Optional[dict] = None
    findings: list = field(default_factory=list)
    controls: dict = field(default_factory=dict)
    notes: list = field(default_factory=list)

    @property
    def sound(self) -> bool:
        return bool(self.controls.get("estimator_passes_on_random", True))

    def render(self) -> str:
        head = (f"{self.label}: n={self.n} shape={self.shape.value} len={self.length} "
                f"alphabet={self.alphabet} ~{self.naive_bits:.0f} bits")
        if not self.sound:
            return head + "\n  INCONCLUSIVE — the estimator failed its own control."
        lines = [head]
        for f in self.findings:
            lines.append("  " + f.render())
        for n in self.notes:
            lines.append("  note: " + n)
        if not self.findings:
            lines.append("  no structural weakness found")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_B64 = re.compile(r"^[A-Za-z0-9_-]+={0,2}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_JWT = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$")


def shape_of(value: str) -> Shape:
    if _JWT.match(value):
        return Shape.JWT
    if _UUID.match(value):
        return Shape.UUID
    if value.isdigit():
        return Shape.NUMERIC
    if _HEX.match(value):
        return Shape.HEX
    if _B64.match(value):
        return Shape.BASE64URL
    return Shape.OPAQUE


def _alphabet_size(shape: Shape, values: list) -> int:
    seen = len(set("".join(values)))
    nominal = {Shape.HEX: 16, Shape.NUMERIC: 10, Shape.BASE64URL: 64,
               Shape.UUID: 16, Shape.JWT: 64}.get(shape, 0)
    return max(seen, 1) if not nominal else min(nominal, max(seen, 1)) or 1


def decode_jwt(value: str) -> Optional[dict]:
    parts = value.split(".")
    if len(parts) != 3:
        return None
    def seg(s):
        try:
            return json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
        except (ValueError, binascii.Error):
            return None
    return {"header": seg(parts[0]), "payload": seg(parts[1]),
            "signature_len": len(parts[2])}


def _positional_distinct(values: list) -> float:
    """Bits implied by per-position variety. Meaningless alone — see the differential."""
    if not values:
        return 0.0
    n = min(len(v) for v in values)
    total = 0.0
    for i in range(n):
        d = len({v[i] for v in values})
        total += math.log2(d) if d > 1 else 0.0
    return total


def _reference(shape: Shape, length: int, count: int) -> list:
    """Random samples of the same shape, length and COUNT — the differential's baseline."""
    alpha = {Shape.HEX: string.hexdigits[:16], Shape.NUMERIC: string.digits,
             Shape.UUID: string.hexdigits[:16]}.get(
                 shape, string.ascii_letters + string.digits + "_-")
    return ["".join(secrets.choice(alpha) for _ in range(length)) for _ in range(count)]


def analyse(samples: list, label: str = "", min_bits: int = MIN_SESSION_BITS) -> Report:
    values = [s.value for s in samples if s.value]
    label = label or (samples[0].label if samples else "credential")
    if not values:
        return Report(label, 0, Shape.OPAQUE, 0, 0, 0.0,
                      notes=["no samples"], controls={"estimator_passes_on_random": True})

    shape = shape_of(values[0])
    grants = any(s.authenticates for s in samples)
    length = min(len(v) for v in values)
    alpha = _alphabet_size(shape, values)
    naive = length * math.log2(alpha) if alpha > 1 else 0.0
    rep = Report(label, len(values), shape, length, alpha, naive)
    rep.controls["shown_to_authenticate"] = grants

    if len(set(shape_of(v) for v in values)) > 1:
        rep.notes.append("samples are not all the same shape; analysed as the first")

    # -- JWT: the structure is the finding -------------------------------------
    if shape is Shape.JWT:
        rep.jwt = decode_jwt(values[0])
        hdr = (rep.jwt or {}).get("header") or {}
        alg = str(hdr.get("alg", "")).lower()
        if alg in ("none", ""):
            rep.findings.append(Finding("jwt-alg-none",
                "the token declares no signature algorithm; it is a bearer of claims "
                "anyone can write", "high"))
        elif alg.startswith("hs"):
            rep.notes.append(f"symmetric alg {alg}: forgeable iff the key leaks or is guessable")
        payload = (rep.jwt or {}).get("payload") or {}
        if not payload.get("exp"):
            rep.findings.append(Finding("jwt-no-exp",
                "no expiry claim: the binding outlives any revocation that relies on it"))
        elif payload.get("iat"):
            days = (payload["exp"] - payload["iat"]) / 86400.0
            rep.controls["lifetime_days"] = round(days, 1)
            if days > 365:
                rep.notes.append(
                    f"lifetime {days:.0f} days. Whether that matters depends on something "
                    f"this mode cannot see: if revocation is enforced SERVER-SIDE the long "
                    f"expiry is bounded by it, and if the token is accepted on signature "
                    f"alone it is a two-year bearer. Settle it with the revocation matrix "
                    f"before reporting either way.")

    # -- length / alphabet ------------------------------------------------------
    if naive < min_bits:
        if grants:
            rep.findings.append(Finding(
                "low-entropy-handle",
                f"~{naive:.0f} bits of handle is under the {min_bits}-bit floor; a binding "
                f"whose handle is guessable needs no proof event behind it", "high"))
        else:
            rep.notes.append(
                f"~{naive:.0f} bits, under the {min_bits}-bit floor — but nothing has shown "
                f"this value authenticates anything, so it is not reported as a finding. "
                f"Re-run with authenticates=True once it has been demonstrated to grant "
                f"access.")

    # -- structure, but only differentially -------------------------------------
    if shape is Shape.JWT:
        # A JWT's header and claim layout are FIXED BY THE FORMAT, so positional variety is
        # low in every correct implementation. Measured live: a perfectly sound HS256
        # session cookie scored 173 bits against a 619-bit random baseline purely because
        # `{"alg":"HS256"}` and the claim names are identical in every issue. Running the
        # structural test here guarantees a false positive on every JWT, so it does not run;
        # what matters for a JWT is the signature and the claims, analysed above.
        rep.controls["structure_measured"] = False
        rep.notes.append("JWT: positional structure not analysed — the format fixes most "
                         "positions, so the test would fire on every correct token. "
                         "Strength here rests on the signature, not the layout.")
    elif len(values) < MIN_SAMPLES_FOR_STRUCTURE:
        rep.controls["structure_measured"] = False
        rep.notes.append(f"{len(values)} sample(s): too few for structural analysis. With "
                         f"this many, ANY set looks structured, so nothing is claimed.")
    else:
        rep.controls["structure_measured"] = True
        observed = _positional_distinct(values)
        ref_runs = [_positional_distinct(_reference(shape, length, len(values)))
                    for _ in range(9)]
        ref = sorted(ref_runs)[len(ref_runs) // 2]
        rep.controls["observed_positional_bits"] = round(observed, 1)
        rep.controls["random_baseline_bits"] = round(ref, 1)
        # the estimator must not flag randomness itself
        rep.controls["estimator_passes_on_random"] = ref > 0
        if ref > 0 and observed < ref * 0.70:
            detail = (f"positional variety {observed:.0f} bits against a random baseline "
                      f"of {ref:.0f} at the same length and sample count — parts of the "
                      f"handle do not vary between issues")
            if grants:
                rep.findings.append(Finding("structured-handle", detail, "high"))
            else:
                rep.notes.append(detail + " — not reported as a finding: nothing has shown "
                                          "this value authenticates anything")
        prefix = _common_affix(values)
        if prefix:
            rep.notes.append(f"all samples share the prefix {prefix!r} "
                             f"({len(prefix)} chars carry no entropy)")

    # -- sequence ----------------------------------------------------------------
    timed = [s for s in samples if s.minted_at is not None]
    if len(timed) >= 3 and shape in (Shape.NUMERIC, Shape.HEX):
        order = [int(s.value, 16 if shape is Shape.HEX else 10)
                 for s in sorted(timed, key=lambda s: s.minted_at)]
        if all(b > a for a, b in zip(order, order[1:])):
            rep.findings.append(Finding("monotonic-handle",
                "handles increase with mint time: the next one is predictable from the "
                "last", "high"))
    return rep


def _common_affix(values: list) -> str:
    if len(values) < 2:
        return ""
    first = values[0]
    i = 0
    while i < len(first) and all(len(v) > i and v[i] == first[i] for v in values):
        i += 1
    return first[:i]
