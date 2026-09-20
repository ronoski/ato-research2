"""Identifier equivalence — the account-takeover class the state machine cannot see.

Trust-Provenance Integrity models an identifier as an ATOM. Every question it can ask is
about transitions over time: who held which binding when, and what revoked it. That makes
a whole family of real takeovers invisible to it, because they involve no transition at
all — only two layers of one system disagreeing about whether two strings are the same
identity:

    the layer that decides an identifier is FREE TO CLAIM   says these are different
    the layer that decides which account an identifier AUTHENTICATES says they are the same

When those disagree, an attacker registers a variant the first layer calls available and
lands on the account the second layer resolves it to. No binding survived anything; no
proof was laundered. `justifies(prov(B), B)` holds at every step. The takeover comes from
canonicalization, and TPI is structurally blind to it.

This module makes that question askable. It is deliberately not an FSM: there are no
states, no principals, no proof events — just a bounded set of hypothesis-led variants and
a two-layer differential.

Bounded on purpose. Real rules of engagement permit "structured input probing, bounded,
hypothesis-led" and forbid scanners; `variants()` returns one representative per
equivalence class, never a product, and `MAX_VARIANTS` caps the run.

    rep = probe_identifier(base="v@x.example", account="acct_1",
                           claimable=claim_fn, resolves_to=resolve_fn)
    for f in rep.findings: print(f.render())
"""
from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

MAX_VARIANTS = 40          # a rules-of-engagement ceiling, not a suggestion


class Layer(str, Enum):
    CLAIM = "claim"        # "may this identifier be registered?"
    RESOLVE = "resolve"    # "which account does this identifier authenticate to?"


@dataclass(frozen=True)
class Variant:
    kind: str              # the equivalence class being tested
    value: str
    rationale: str         # why a system might canonicalise this to the base

    def render(self) -> str:
        return f"{self.kind:<18} {self.value!r}"


# --------------------------------------------------------------------------- #
#  Variant generation: one representative per class, each with a reason.
# --------------------------------------------------------------------------- #
def _split(identifier: str) -> tuple:
    local, sep, domain = identifier.partition("@")
    return (local, domain) if sep else (identifier, "")


def variants(identifier: str, limit: int = MAX_VARIANTS) -> list:
    """One representative per canonicalization class. Never a cross product."""
    local, domain = _split(identifier)
    at = f"@{domain}" if domain else ""
    out: list = []

    def add(kind, value, why):
        if value and value != identifier and all(v.value != value for v in out):
            out.append(Variant(kind, value, why))

    add("case-upper", identifier.upper(), "many systems lower-case on lookup but not on claim")
    add("case-local", local.upper() + at, "the local part is case-SENSITIVE per RFC 5321, "
                                          "but almost no system treats it that way")
    add("trailing-space", identifier + " ", "trimmed at one layer, stored at another")
    add("leading-space", " " + identifier, "same, and it survives more parsers")
    add("trailing-dot", f"{local}@{domain}." if domain else identifier + ".",
        "a trailing dot is a legal FQDN and resolves identically")
    add("dot-stripped", local.replace(".", "") + at,
        "Gmail-style dot folding; if the target folds on lookup only, the two collide")
    add("dot-inserted", (local[0] + "." + local[1:] + at) if len(local) > 1 else "",
        "the inverse of the same folding rule")
    add("plus-tag", f"{local}+x{at}", "sub-addressing is stripped by some canonicalisers")
    add("unicode-nfkc", unicodedata.normalize("NFKC", local + "․" + at)
        if False else f"{local}​{at}",
        "a zero-width character is dropped by NFKC and by many validators")
    add("unicode-fullwidth", "".join(chr(ord(c) + 0xFEE0) if "a" <= c <= "z" else c
                                     for c in local) + at,
        "fullwidth letters NFKC-fold to ASCII")
    add("dotless-i", local.replace("i", "ı") + at,
        "Turkish casing maps I/i to dotless forms; upper/lower round trips collide")
    add("null-suffix", identifier + "\x00", "a trailing NUL is truncated by some layers")
    add("newline-suffix", identifier + "\n", "trimmed by one layer, stored by another")
    if domain:
        add("domain-upper", f"{local}@{domain.upper()}", "domains are case-insensitive")
        add("domain-idn", f"{local}@{domain.replace('a', 'а', 1)}",
            "a Cyrillic homoglyph: a different identifier that reads identically")
    add("quoted-local", f'"{local}"{at}', "a quoted local part is legal and often unquoted "
                                          "by a canonicaliser")
    return out[:limit]


# --------------------------------------------------------------------------- #
#  The differential.
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    variant: Variant
    claimable: Optional[bool]
    resolved: Optional[str]
    account: str
    kind: str              # takeover_primitive | squat | inconsistent

    def render(self) -> str:
        if self.kind == "takeover_primitive":
            return (f"[{self.variant.kind}] {self.variant.value!r} is offered as FREE TO "
                    f"CLAIM, yet authenticates to {self.account!r}. Registering it is a "
                    f"takeover of that account. ({self.variant.rationale})")
        if self.kind == "squat":
            return (f"[{self.variant.kind}] {self.variant.value!r} is refused as already "
                    f"taken, yet authenticates to nothing — an identifier that can be "
                    f"denied to its owner. ({self.variant.rationale})")
        return (f"[{self.variant.kind}] {self.variant.value!r}: layers disagree "
                f"(claimable={self.claimable}, resolves_to={self.resolved!r})")


@dataclass
class Report:
    base: str
    account: str
    controls: dict = field(default_factory=dict)
    tested: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    skipped: list = field(default_factory=list)

    @property
    def sound(self) -> bool:
        """False when a control failed — then nothing here means anything."""
        return bool(self.controls.get("base_resolves")) and \
            bool(self.controls.get("unrelated_does_not_resolve"))

    def summary(self) -> str:
        if not self.sound:
            return (f"INCONCLUSIVE — controls did not hold ({self.controls}); the probe "
                    f"could not tell equivalence from noise and nothing is reported.")
        return (f"{len(self.tested)} variant(s) probed against {self.account!r}; "
                f"{len(self.findings)} finding(s), {len(self.skipped)} unanswerable")


def probe_identifier(base: str, account: str,
                     claimable: Callable[[str], Optional[bool]],
                     resolves_to: Callable[[str], Optional[str]],
                     unrelated: Optional[str] = None,
                     limit: int = MAX_VARIANTS) -> Report:
    """Ask, for each variant, whether the two layers agree about its identity.

    `claimable(x) -> True/False/None`  may x be registered? None = could not tell.
    `resolves_to(x) -> account-id/None` which account does x authenticate to?

    CONTROLS, and the report is INCONCLUSIVE without them:
      * the base identifier must resolve to `account` — otherwise `resolves_to` is not
        measuring what we think, and every "collides with the base" is meaningless;
      * an unrelated identifier must NOT resolve to it — otherwise the layer resolves
        everything and each variant would look like a collision.
    """
    rep = Report(base=base, account=account)
    rep.controls["base_resolves"] = (resolves_to(base) == account)
    other = unrelated or ("zz-" + base)
    rep.controls["unrelated_does_not_resolve"] = (resolves_to(other) != account)
    if not rep.sound:
        return rep

    for v in variants(base, limit=limit):
        c, r = claimable(v.value), resolves_to(v.value)
        rep.tested.append(v)
        if c is None or (c is False and r is None):
            if c is None:
                rep.skipped.append(v)
            continue
        if c is True and r == account:
            rep.findings.append(Finding(v, c, r, account, "takeover_primitive"))
        elif c is False and r is None:
            rep.findings.append(Finding(v, c, r, account, "squat"))
        elif c is True and r is not None and r != account:
            rep.findings.append(Finding(v, c, r, account, "inconsistent"))
    return rep
