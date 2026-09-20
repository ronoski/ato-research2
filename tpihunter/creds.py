"""Per-run credentials and identifiers — never literals in source.

A hunting loop has to supply passwords (to register a test account, to complete a
reset) and secondary identifiers (a recovery address). Writing those as constants in
the source is convenient on a mock and wrong on a real target: every account the tool
touches is left holding a credential that is published in this repository, and a reset
run against a live system hands the account a password anyone can read on GitHub.

So every credential is generated once per process from `secrets`, and is *stable within
the process* — the enumerator's minimization re-runs the same plan dozens of times, and
a `register` followed by a `login` has to present the same password both times.

`session_id()` tags anything the tool leaves behind on a target, so an operator (or the
target's owner) can tell at a glance which artefacts came from this run and clean them up.
"""
from __future__ import annotations

import secrets

_SESSION = secrets.token_hex(4)
_cache: dict[str, str] = {}


def session_id() -> str:
    """A short, unique tag for this process's run — stamped into anything left behind."""
    return _SESSION


def password(label: str) -> str:
    """A strong password for `label` (e.g. a role), stable for the life of the process.

    Mixed classes and length are deliberate: a target's password policy should never be
    the reason a probe fails to execute, because that reads as a SAFE verdict."""
    if label not in _cache:
        _cache[label] = f"Tpi!{secrets.token_urlsafe(18)}9aZ"
    return _cache[label]


def fallback_password(label: str) -> str:
    """The password used when a plan did not specify one. Separate from `password` only
    so the two are distinguishable in an audit log."""
    return password(f"fallback:{label}")


def recovery_alias(role: str, domain: str = "recovery.invalid") -> str:
    """A secondary identifier the given role controls — a *second* identifier, distinct
    from the shared account email.

    The default domain is `.invalid`, which RFC 2606 reserves and guarantees cannot
    resolve: a probe that tries to send mail to it fails closed instead of delivering to
    a domain someone else owns. A real engagement passes a mailbox it genuinely controls.
    """
    return f"{role}-{_SESSION}@{domain}"
