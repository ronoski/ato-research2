"""Plan execution — a probe is *data*, so the hypothesis layer (an LLM now, an
Alloy/enumeration pass later) can generate and mutate attacks without touching
this runner.

A Plan is a list of Steps over the alphabet Sigma, interleaved across principals,
plus three oracle checkpoints:

    arm    -> capture the victim's identity + attacker's pre-canary baseline
    plant  -> the victim writes its canary
    assess -> judge, and diagnose the violated TPI clause

Convention: place `arm` right after the victim's identity-establishing action and
`plant` immediately after, then `assess` at the end.
"""
from __future__ import annotations

import inspect
from dataclasses import dataclass, field
from typing import Optional

from .adapter import Trace
from .oracle import AtoOracle, Verdict
from .types import Observation, Principal

# alphabet action -> how to invoke it on the adapter with a step's params
_DISPATCH = {
    "register":       lambda a, p, prm: a.register(p, prm["email"], prm.get("password", "Seed!pw01")),
    "login":          lambda a, p, prm: a.login(p, prm["email"], prm["password"]),
    "sso_login":      lambda a, p, prm: a.sso_login(p, prm["email"]),
    "reset_request":  lambda a, p, prm: a.reset_request(p, prm["email"]),
    "reset_consume":  lambda a, p, prm: a.reset_consume(p, prm["email"], prm.get("new_password", "Pwn!pw12345")),
    "logout":         lambda a, p, prm: a.logout(p),
    "enroll_factor":  lambda a, p, prm: a.enroll_factor(p),
    "email_change":   lambda a, p, prm: a.email_change(p, prm.get("new_email", "changed@corp.example")),
}


def execute_action(adapter, principal, action: str, params: dict) -> Observation:
    """Run one alphabet action on the adapter and return its Observation. Uses the
    built-in dispatcher for the known verbs and a generic fallback
    (`adapter.<action>(principal, **params)`) for synthesized ones — the same rule
    `run_plan` uses, factored out so other drivers (e.g. the revocation matrix) share it."""
    fn = _DISPATCH.get(action)
    if fn is not None:
        return fn(adapter, principal, params)
    method = getattr(adapter, action, None)
    if method is None:
        return Observation(False, note=f"action '{action}' has no binding on this target")
    # A synthesized action gets only the params its method actually accepts — the implicit
    # {email} every step carries is dropped for a verb that doesn't take it (e.g. add_alias
    # takes `alias`, not `email`), so declared non-email params (codes/tokens/aliases) work.
    sig = inspect.signature(method)
    if any(p.kind is p.VAR_KEYWORD for p in sig.parameters.values()):
        kw = params
    else:
        kw = {k: v for k, v in params.items() if k in sig.parameters}
    return method(principal, **kw)


@dataclass
class Step:
    principal: Optional[Principal]
    action: str
    params: dict = field(default_factory=dict)


@dataclass
class Plan:
    name: str
    targets_clause: str
    steps: list[Step]
    note: str = ""


def run_plan(adapter, plan: Plan, oracle: AtoOracle) -> tuple[Verdict, Trace]:
    trace = Trace()
    verdict: Optional[Verdict] = None
    for s in plan.steps:
        if s.action == "arm":
            oracle.arm()
        elif s.action == "plant":
            oracle.plant()
        elif s.action == "assess":
            verdict = oracle.assess(trace)
        else:
            obs = execute_action(adapter, s.principal, s.action, s.params)
            trace.record(s.principal, s.action, s.params, obs)
    assert verdict is not None, "plan must contain an 'assess' checkpoint"
    return verdict, trace
