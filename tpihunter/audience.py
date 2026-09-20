"""The audience matrix — TPI-2 where identity actually federates.

Every mode before this one stayed inside a single host. But an account takeover rarely
lives there: the account lives at an identity provider, and the damage happens at the
relying parties that trust its tokens. The question that surface asks is TPI-2 in its
purest form —

    a token minted to prove control of resource X,
    presented to resource server Y:  does Y take it?

`justifies(prov(B), B)` fails by FORGERY when a proof of the wrong resource is accepted.
An `aud` claim is that pinning written down; an RS that does not check it will hand an
attacker a session on Y for a token they were legitimately issued for X — and every OIDC
deployment has more clients than anyone is tracking.

Cells are token × audience. The controls are the whole value, because "HTTP 200" is not
acceptance and "HTTP 403" is not refusal:

  * **Subject witness.** An audience counts as ACCEPTING a token only if it echoes *which
    principal* it resolved it to. A 200 carrying an anonymous page is not an accepted
    token, and treating it as one is how this mode would invent a critical finding out of
    a marketing page. The witness is also what makes a cross-audience acceptance
    *exploitable* rather than merely interesting: it names whose account you got.
  * **Negative control, per audience.** A structurally valid but never-issued token must be
    REFUSED there. Until that fires, "it accepted my token" is unfalsifiable — the endpoint
    may accept anything, including nothing.
  * **Positive control.** The token must be accepted at its OWN audience. A token that
    works nowhere proves nothing about pinning; it is just expired.
  * **Tamper control.** A copy with one byte flipped in the signature must be refused. An
    audience that takes it is not checking signatures at all, which outranks any aud
    finding and is reported as its own verdict rather than folded into one.

Nothing here mints tokens or talks to a network: callers supply `present`, so the mode is
testable offline and the same code runs against a mock and a live estate.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Acceptance(str, Enum):
    ACCEPTED = "accepted"          # resolved to a principal — the witness fired
    REFUSED = "refused"            # rejected, as an unpinned proof should be
    INCONCLUSIVE = "inconclusive"  # no verdict; never evidence of an absence


@dataclass(frozen=True)
class Token:
    """A credential, and the two facts that make a cross-audience result meaningful."""
    id: str
    value: str
    aud: str        # the audience it was minted for
    subject: str    # the principal it represents, as the ISSUER understands it


@dataclass(frozen=True)
class Audience:
    """A resource server that consumes tokens."""
    id: str
    label: str = ""


@dataclass
class Presentation:
    """What an audience did with a token. `subject` is the witness."""
    acceptance: Acceptance
    subject: Optional[str] = None      # which principal the RS resolved it to
    evidence: str = ""


# A structurally well-formed token that was never issued. Refusing it is the baseline
# every "accepted" result is measured against.
NEVER_ISSUED = ("eyJhbGciOiJSUzI1NiIsImtpZCI6Il9fbmV2ZXJfaXNzdWVkX18ifQ"
                ".eyJzdWIiOiJfX25ldmVyX2lzc3VlZF9fIiwiYXVkIjoiX19uZXZlcl9pc3N1ZWRfXyJ9"
                ".__never_issued_signature__")


def tamper(token_value: str) -> str:
    """Flip one character of the signature, leaving header and claims byte-identical."""
    parts = token_value.split(".")
    if len(parts) != 3 or not parts[2]:
        return token_value + "x"
    sig = parts[2]
    flipped = ("B" if sig[-1] != "B" else "C")
    return ".".join([parts[0], parts[1], sig[:-1] + flipped])


@dataclass
class Cell:
    token: Token
    audience: Audience
    acceptance: Acceptance
    subject: Optional[str] = None
    evidence: str = ""

    @property
    def cross(self) -> bool:
        return self.token.aud != self.audience.id


@dataclass
class Finding:
    clause_id: str
    title: str
    detail: str

    def render(self) -> str:
        return f"{self.clause_id} ({self.title})\n    {self.detail}"


@dataclass
class AudienceResult:
    cells: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    withheld: list = field(default_factory=list)

    def render(self) -> str:
        w = max([len(c.token.id) for c in self.cells] + [8])
        out = [f"{'token'.ljust(w)}  {'presented to':<22} {'result':<14} subject"]
        for c in self.cells:
            mark = " *" if c.cross else "  "
            out.append(f"{c.token.id.ljust(w)}{mark}{c.audience.id:<22} "
                       f"{c.acceptance.value:<14} {c.subject or '-'}")
        for f in self.findings:
            out.append("\n" + f.render())
        for note in self.withheld:
            out.append(f"\n[withheld] {note}")
        if not self.findings and not self.withheld:
            out.append("\nno finding: every audience took only the tokens minted for it")
        return "\n".join(out)


def run_audience_matrix(tokens: list, audiences: list,
                        present: Callable[[Token, Audience], Presentation],
                        check_tamper: bool = True) -> AudienceResult:
    """Present every token to every audience and judge only what the controls support."""
    res = AudienceResult()

    def _present(tok, aud):
        try:
            return present(tok, aud)
        except Exception as exc:
            return Presentation(Acceptance.INCONCLUSIVE, None, f"{type(exc).__name__}: {exc}")

    # -- per-audience controls, run first: without them no cell means anything ----
    sound: dict = {}
    for aud in audiences:
        probe = Token(f"never-issued@{aud.id}", NEVER_ISSUED, "__never__", "__never__")
        neg = _present(probe, aud)
        if neg.acceptance is Acceptance.ACCEPTED:
            res.findings.append(Finding(
                "AUDIENCE-0", "endpoint accepts anything",
                f"'{aud.id}' resolved a token that was never issued to "
                f"subject={neg.subject!r}. No result from this audience can mean anything "
                f"until that is explained, so its cells are not interpreted."))
            sound[aud.id] = False
            continue
        sound[aud.id] = neg.acceptance is Acceptance.REFUSED
        if not sound[aud.id]:
            res.withheld.append(
                f"'{aud.id}': the never-issued control was {neg.acceptance.value}, so "
                f"'accepted' there is unfalsifiable — its cells are recorded, not judged")

    # -- the matrix ---------------------------------------------------------------
    for tok in tokens:
        for aud in audiences:
            p = _present(tok, aud)
            acc = p.acceptance
            if acc is Acceptance.ACCEPTED and not p.subject:
                # 200 is not acceptance. Without a subject the RS may have served an
                # anonymous page, which is the easiest false critical in this whole mode.
                acc = Acceptance.INCONCLUSIVE
                p = Presentation(acc, None, (p.evidence + " | no subject witness").strip(" |"))
            res.cells.append(Cell(tok, aud, acc, p.subject, p.evidence))

    # -- verdicts ------------------------------------------------------------------
    for tok in tokens:
        own = [c for c in res.cells if c.token.id == tok.id and not c.cross]
        if not any(c.acceptance is Acceptance.ACCEPTED for c in own):
            res.withheld.append(
                f"'{tok.id}' was not accepted at its own audience '{tok.aud}', so a refusal "
                f"elsewhere shows nothing about pinning — the token may simply be spent")
            continue
        for c in res.cells:
            if c.token.id != tok.id or not c.cross:
                continue
            if c.acceptance is Acceptance.ACCEPTED and sound.get(c.audience.id):
                same = (c.subject == tok.subject)
                res.findings.append(Finding(
                    "TPI-2", "proof-pinned-to-resource",
                    f"'{c.audience.id}' accepted a token minted for audience '{tok.aud}' "
                    f"and resolved it to subject={c.subject!r}"
                    + (" — the token's own subject, so the proof crossed an audience "
                       "boundary it was never pinned to" if same else
                       f" — which is NOT the token's subject ({tok.subject!r})")))

    if check_tamper:
        for aud in audiences:
            if not sound.get(aud.id):
                continue
            takes = [c for c in res.cells
                     if c.audience.id == aud.id and c.acceptance is Acceptance.ACCEPTED]
            if not takes:
                continue
            t = takes[0].token
            p = _present(Token(t.id + "+tampered", tamper(t.value), t.aud, t.subject), aud)
            if p.acceptance is Acceptance.ACCEPTED:
                res.findings.append(Finding(
                    "AUDIENCE-1", "signature not verified",
                    f"'{aud.id}' accepted '{t.id}' with one byte flipped in its signature "
                    f"(subject={p.subject!r}). Claims are being read without verifying who "
                    f"wrote them, which subsumes any audience-pinning question here."))
    return res
