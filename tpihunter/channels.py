"""Channel providers.

Auth spans more than HTTP: a proof event often travels through an inbox, an SMS
endpoint, a TOTP authenticator, or an IdP. The hunter must be able to *read* what
lands there (a reset link, a code) as whichever principal controls that channel.
These providers abstract that so the same probe runs against a mock inbox here and
a real catch-all mailbox (IMAP / Mailosaur / temp-mail API) in production.
"""
from __future__ import annotations

from typing import Optional, Protocol


class EmailChannel(Protocol):
    def latest_link(self, address: str, pattern: str = "http") -> Optional[str]:
        """Return the most recent link/token delivered to `address`, or None."""
        ...


class TotpChannel(Protocol):
    def code(self, secret: str) -> str:
        """Return the current TOTP code for an enrolled secret."""
        ...


class InMemoryInbox:
    """A test EmailChannel. The target 'delivers' here; a principal who controls
    an address reads links from it. Real deployments swap this for a mailbox the
    hunter genuinely controls."""

    def __init__(self) -> None:
        self._msgs: dict[str, list[str]] = {}

    def deliver(self, address: str, body: str) -> None:
        self._msgs.setdefault(address, []).append(body)

    def latest_link(self, address: str, pattern: str = "http") -> Optional[str]:
        for body in reversed(self._msgs.get(address, [])):
            i = body.find(pattern)
            if i >= 0:
                return body[i:].split()[0]
        return None
