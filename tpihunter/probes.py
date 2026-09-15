"""A small library of TPI probe plans.

Each plan is an interleaving of the alphabet across two principals that *targets*
a specific provenance failure. These are hand-written seeds; the next component
(the enumerator) will generate them from the TPI clauses and the learned alphabet.
"""
from __future__ import annotations

from .harness import Plan, Step
from .types import Principal


def pre_hijacking_plan(attacker: Principal, victim: Principal, email: str) -> Plan:
    """Classic federated-merge pre-hijacking (targets TPI-1, laundering).

    Attacker claims the victim's future email with a credential + session; the
    victim later verifies it via SSO; the attacker's binding is never revoked.
    """
    return Plan(
        name="pre-account-hijacking (classic federated merge)",
        targets_clause="TPI-1",
        steps=[
            Step(attacker, "register", {"email": email, "password": "AttackerPw!1"}),
            Step(victim, "sso_login", {"email": email}),
            Step(None, "arm"),      # victim now authenticated; snapshot attacker's pre-canary view
            Step(None, "plant"),    # victim writes private state it believes is its own
            Step(None, "assess"),
        ],
    )


def reset_survives_change_plan(attacker: Principal, victim: Principal, email: str) -> Plan:
    """A reset token consumed after the row moved underneath it (targets TPI-2/4).

    Illustrative second shape showing the same oracle generalizes; wire it to a
    target whose reset token is not re-pinned to the current email binding.
    """
    return Plan(
        name="reset-token survives rebind",
        targets_clause="TPI-2",
        steps=[
            Step(attacker, "register", {"email": email, "password": "AttackerPw!1"}),
            Step(attacker, "reset_request", {"email": email}),
            Step(victim, "sso_login", {"email": email}),
            Step(None, "arm"),
            Step(None, "plant"),
            Step(attacker, "reset_consume", {"email": email, "new_password": "Pwn!pw12345"}),
            Step(None, "assess"),
        ],
    )
