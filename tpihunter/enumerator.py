"""Probe enumerator — generate Plans instead of hand-writing them.

This is the piece that turns the loop from "runs the attacks you thought of" into
"finds the interleavings you didn't". It enumerates two-principal interleavings of
the alphabet and keeps only those the theory says *could* be a laundering/
composition bug, via the composition-relevance filter:

    keep an interleaving iff both principals act over the shared resource AND at
    least one action raises identifier trust or changes a credential on it.

That filter is the Composition-Blindness theorem used as a search prune: it throws
away the vast single-principal / no-trust-event majority and leaves exactly the
region where laundering lives. Each surviving plan gets oracle checkpoints inserted
automatically and a probed clause guessed from its effect shape; the oracle gives
the authoritative verdict at run time (it proposes, the oracle disposes).

Channel-aware generation: actions that require control of the target identifier
(sso_login, reset_consume) are only assigned to a principal who controls it, so no
requests are wasted on attacks that cannot even execute.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from itertools import permutations
from typing import Optional

from .harness import Plan, Step
from .types import Principal


class Effect(str, Enum):
    SEED = "seed"        # establishes a binding/credential/session (register, login)
    RAISE = "raise"      # raises identifier trust (sso_login, email_change_confirm)
    CRED = "cred"        # changes a credential (reset_consume)
    REQUEST = "request"  # sets up an outstanding token (reset_request)


@dataclass(frozen=True)
class ActionSpec:
    name: str
    effect: Effect
    requires: tuple = ()          # action names that must appear earlier in the merged sequence
    needs_control: bool = False   # true if the actor must control the target identifier
    params: tuple = ()            # extra (name, template) params beyond the implicit {email}:
                                  # templates may use {email}, {alias}, {role} (see _render_param).
                                  # Lets a synthesized action carry a code, an invite token, or a
                                  # SECOND identifier (a recovery/secondary email) — not just email.


ACTIONS: dict[str, ActionSpec] = {
    "register":      ActionSpec("register", Effect.SEED),
    "login":         ActionSpec("login", Effect.SEED, requires=("register",)),
    "sso_login":     ActionSpec("sso_login", Effect.RAISE, needs_control=True),
    "reset_request": ActionSpec("reset_request", Effect.REQUEST, requires=("register",)),
    "reset_consume": ActionSpec("reset_consume", Effect.CRED, requires=("reset_request",), needs_control=True),
}

DEFAULT_ACTIONS = list(ACTIONS.keys())


@dataclass
class Candidate:
    plan: Plan
    probed_mode: str
    probed_clause: str
    rationale: str
    length: int
    attacker_ops: int
    merged: tuple = ()   # the (role, action) interleaving this plan was built from


# ---- generation ------------------------------------------------------------
def _perms(pool: list[str], maxlen: int) -> list[tuple[str, ...]]:
    out: list[tuple[str, ...]] = []
    for r in range(1, maxlen + 1):
        out.extend(permutations(pool, r))
    return out


def _merge(a: list[tuple[str, str]], b: list[tuple[str, str]]) -> list[tuple[tuple[str, str], ...]]:
    """All order-preserving interleavings of two role-tagged sequences."""
    out: list[tuple[tuple[str, str], ...]] = []

    def rec(i: int, j: int, acc: list[tuple[str, str]]) -> None:
        if i == len(a) and j == len(b):
            out.append(tuple(acc))
            return
        if i < len(a):
            rec(i + 1, j, acc + [a[i]])
        if j < len(b):
            rec(i, j + 1, acc + [b[j]])

    rec(0, 0, [])
    return out


def _wellformed(merged: tuple[tuple[str, str], ...], specs: dict[str, ActionSpec]) -> bool:
    """Preconditions checked against the merged prefix (a shared store/inbox: a
    reset_request by anyone enables a later reset_consume)."""
    seen: set[str] = set()
    for _role, action in merged:
        for req in specs[action].requires:
            if req not in seen:
                return False
        seen.add(action)
    return True


def _relevant(merged: tuple[tuple[str, str], ...], specs: dict[str, ActionSpec]) -> bool:
    """The composition-relevance filter: both principals present, and a trust-raise
    or credential-change occurs on the shared resource."""
    roles = {r for r, _ in merged}
    if len(roles) < 2:
        return False
    effects = {specs[a].effect for _, a in merged}
    return Effect.RAISE in effects or Effect.CRED in effects


def _classify(merged: tuple[tuple[str, str], ...], specs: dict[str, ActionSpec]) -> tuple[str, str, str]:
    effects = [specs[a].effect for _, a in merged]
    if Effect.RAISE in effects:
        return ("laundering", "TPI-1",
                "attacker seeds the row; victim later raises its trust -> the attacker "
                "binding must be revoked on rebind")
    if Effect.CRED in effects:
        attacker_cred = any(r == "attacker" and specs[a].effect is Effect.CRED for r, a in merged)
        if attacker_cred:
            return ("forgery", "TPI-2",
                    "attacker consumes a proof pinned to a now-stale binding")
        return ("laundering", "TPI-4",
                "victim changes a credential; the attacker's prior session must be revoked")
    return ("gap", "TPI-5", "privileged action without a matching proof")


def _name(merged: tuple[tuple[str, str], ...]) -> str:
    a = ">".join(x for r, x in merged if r == "attacker")
    v = ">".join(x for r, x in merged if r == "victim")
    return f"atk:{a}  |  vic:{v}"


def _insert_checkpoints(steps: list[Step], victim: Principal) -> list[Step]:
    last_v = max((i for i, s in enumerate(steps) if s.principal == victim), default=None)
    at = (last_v + 1) if last_v is not None else len(steps)
    out = list(steps)
    out[at:at] = [Step(None, "arm"), Step(None, "plant")]
    out.append(Step(None, "assess"))
    return out


def recovery_alias(role: str) -> str:
    """A recovery/secondary email the given role controls — a *second identifier*, distinct
    from the shared account email. This is what `{alias}` renders to, so a synthesized action
    (e.g. adding a recovery email, then logging in via it) can be driven with an identifier
    that is not the account's primary email."""
    return f"{role}.recovery@evil.example"


def _render_param(tmpl: str, *, email: str, role: str) -> str:
    """Fill a param template. Placeholders: {email} (the shared account), {alias} (a recovery
    email this role controls), {role}. A template with no placeholder is used literally — so a
    strategist can pass a fixed code / invite token."""
    return (tmpl.replace("{email}", email)
                .replace("{alias}", recovery_alias(role))
                .replace("{role}", role))


def _to_plan(merged: tuple[tuple[str, str], ...], attacker: Principal,
             victim: Principal, email: str, specs: dict[str, ActionSpec]) -> Candidate:
    steps: list[Step] = []
    for role, action in merged:
        p = attacker if role == "attacker" else victim
        params: dict = {"email": email}
        if action in ("register", "login"):
            params["password"] = "AttackerPw!1" if role == "attacker" else "VictimPw!1"
        if action == "reset_consume":
            params["new_password"] = "AtkReset!9" if role == "attacker" else "VicReset!9"
        for name, tmpl in specs[action].params:   # synthesized-action params (codes/tokens/aliases)
            params[name] = _render_param(tmpl, email=email, role=role)
        steps.append(Step(p, action, params))
    mode, clause, why = _classify(merged, specs)
    plan = Plan(name=_name(merged), targets_clause=clause,
                steps=_insert_checkpoints(steps, victim), note=why)
    return Candidate(plan, mode, clause, why, len(merged),
                     attacker_ops=sum(1 for r, _ in merged if r == "attacker"),
                     merged=merged)


_MODE_ORDER = {"laundering": 0, "forgery": 1, "gap": 2}


def enumerate_plans(attacker: Principal, victim: Principal, email: str,
                    actions: Optional[list[str]] = None,
                    specs: Optional[dict[str, ActionSpec]] = None,
                    attacker_controls_target: bool = False,
                    victim_controls_target: bool = True,
                    max_attacker: int = 2, max_victim: int = 2) -> list[Candidate]:
    """Generate composition-relevant two-principal probes.

    `specs` is the action model driving generation. It defaults to the hand-coded
    `ACTIONS`, but pass a spec dict synthesized from a *learned* machine
    (`synthesis.specs_from_machine`) to run generation on observed behaviour. When
    `actions` is omitted it defaults to the spec's own action set.
    """
    specs = specs if specs is not None else ACTIONS
    actions = actions if actions is not None else list(specs.keys())

    a_pool = [a for a in actions if not (specs[a].needs_control and not attacker_controls_target)]
    v_pool = [a for a in actions if not (specs[a].needs_control and not victim_controls_target)]

    seen: set[tuple] = set()
    cands: list[Candidate] = []
    for a_seq in _perms(a_pool, max_attacker):
        a_tagged = [("attacker", x) for x in a_seq]
        for v_seq in _perms(v_pool, max_victim):
            v_tagged = [("victim", x) for x in v_seq]
            for merged in _merge(a_tagged, v_tagged):
                if merged in seen or not _wellformed(merged, specs) or not _relevant(merged, specs):
                    continue
                seen.add(merged)
                cands.append(_to_plan(merged, attacker, victim, email, specs))
    cands.sort(key=lambda c: (_MODE_ORDER.get(c.probed_mode, 9), c.length, c.attacker_ops, c.plan.name))
    return cands


# ---- public helpers for post-processing (e.g. dedup / minimization) --------
def build_plan(merged: tuple[tuple[str, str], ...], attacker: Principal,
               victim: Principal, email: str,
               specs: Optional[dict[str, ActionSpec]] = None) -> Plan:
    """Rebuild an executable Plan from a (role, action) interleaving — used to
    re-test reduced interleavings during minimization."""
    return _to_plan(merged, attacker, victim, email, specs if specs is not None else ACTIONS).plan


def is_wellformed(merged: tuple[tuple[str, str], ...],
                  specs: Optional[dict[str, ActionSpec]] = None) -> bool:
    """True if every action's ordering preconditions are met in `merged`."""
    return _wellformed(merged, specs if specs is not None else ACTIONS)


def make_candidate(merged: tuple[tuple[str, str], ...], attacker: Principal,
                   victim: Principal, email: str,
                   specs: Optional[dict[str, ActionSpec]] = None) -> Candidate:
    """Build a full Candidate (plan + classification) from a (role, action)
    interleaving — used by a strategist that proposes probes directly."""
    return _to_plan(merged, attacker, victim, email, specs if specs is not None else ACTIONS)
