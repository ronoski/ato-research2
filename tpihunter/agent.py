"""Agent-as-hunter: the control loop and the strategy seam.

The project's goal is an autonomous agent that hunts TPI account-takeover bugs. The
deterministic pieces (adapter, oracle, harness, dedup) are the agent's *tools* and
its *ground truth*; this module is where an agent actually drives them.

The key idea: probe generation is a **strategy**, not a fixed step. `AgentHunter`
runs a loop — ask the strategist for probes, execute each, feed the oracle verdict
back — until the budget runs out or the strategist stops. The mechanical enumerator
becomes just one strategist (`EnumeratorStrategist`, non-adaptive: fire everything
once). A real agent is `LLMStrategist`: it reads the TPI briefing, the known action
alphabet, and the history of what it has tried and what happened, then proposes the
next few probes — adapting instead of brute-forcing.

`LLMStrategist` takes an injected `complete_fn: str -> str` (prompt in, model text
out), so there is no hard LLM dependency and the seam is fully testable with a fake
completion. Wire `complete_fn` to a real model to get a live agent.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from .clauses import CLAUSES
from .dedup import Cluster, deduplicate
from .enumerator import ACTIONS, ActionSpec, Effect, is_wellformed, make_candidate
from .harness import run_plan
from .oracle import AtoOracle
from .types import Principal

Merged = tuple           # tuple[tuple[str, str], ...] of (role, action)
CompleteFn = Callable[[str], str]
AdapterFactory = Callable[[], object]   # () -> a fresh TargetAdapter for one trial


@dataclass
class Attempt:
    merged: Merged
    severity: str
    clause_id: Optional[str]
    note: str


@dataclass
class HuntState:
    """Everything a strategist sees to decide what to try next."""
    specs: dict[str, ActionSpec]
    attacker: Principal
    victim: Principal
    email: str
    history: list[Attempt] = field(default_factory=list)
    budget: int = 0
    round: int = 0


class Strategist(Protocol):
    def propose(self, state: HuntState) -> list[Merged]:
        """Return the next batch of (role, action) interleavings to try; [] to stop."""
        ...


# --------------------------------------------------------------------------- #
#  Baseline strategist: the mechanical enumerator, fired once.
# --------------------------------------------------------------------------- #
class EnumeratorStrategist:
    def __init__(self, attacker_controls_target: bool = False,
                 victim_controls_target: bool = True,
                 max_attacker: int = 2, max_victim: int = 2) -> None:
        self.kw = dict(attacker_controls_target=attacker_controls_target,
                       victim_controls_target=victim_controls_target,
                       max_attacker=max_attacker, max_victim=max_victim)
        self._done = False

    def propose(self, state: HuntState) -> list[Merged]:
        if self._done:
            return []
        self._done = True
        from .enumerator import enumerate_plans
        cands = enumerate_plans(state.attacker, state.victim, state.email,
                                specs=state.specs, **self.kw)
        return [c.merged for c in cands]


# --------------------------------------------------------------------------- #
#  Agent strategist: an LLM proposes probes, adapting to feedback.
# --------------------------------------------------------------------------- #
class LLMStrategist:
    def __init__(self, complete_fn: CompleteFn, max_rounds: int = 3) -> None:
        self.complete_fn = complete_fn
        self.max_rounds = max_rounds

    def propose(self, state: HuntState) -> list[Merged]:
        if state.round >= self.max_rounds:
            return []
        text = self.complete_fn(self.render_prompt(state))
        return self.parse_proposals(text, state)

    # --- the prompt the agent sees (also the human-legible tool contract) ----
    def render_prompt(self, state: HuntState) -> str:
        clauses = "\n".join(f"  {c.id} ({c.title}, {c.mode.value}): {c.statement}"
                            for c in CLAUSES.values())
        actions = "\n".join(
            f"  {name}: effect={s.effect.value}, requires={list(s.requires) or 'none'}"
            f"{', needs channel control' if s.needs_control else ''}"
            f"{f', params={[n for n, _ in s.params]}' if s.params else ''}"
            for name, s in state.specs.items())
        if state.history:
            hist = "\n".join(
                f"  tried [{' , '.join(f'{r}:{a}' for r, a in h.merged)}] "
                f"-> {h.severity}" + (f" ({h.clause_id})" if h.clause_id else "")
                for h in state.history[-20:])
        else:
            hist = "  (nothing tried yet)"
        return f"""You are hunting account-takeover bugs via Trust-Provenance Integrity.
A bug is a reachable state holding a privileged binding whose provenance does not
justify it. The dangerous class is LAUNDERING: it needs TWO principals (attacker,
victim) interleaved over one shared account (the same email), where the victim's
genuine proof is laundered into access for the attacker's pre-existing binding.

TPI clauses to violate:
{clauses}

Known actions (alphabet) for this target:
{actions}

Roles: "attacker" (does NOT control the email's inbox/IdP) and "victim" (DOES).
An action marked "needs channel control" only works for the victim.

What you have tried and what happened:
{hist}

Budget remaining: {state.budget} probes.

The alphabet is a STARTING point. Real auth systems have flows it lacks — magic-link /
passwordless login, device pairing, org invites, adding a secondary email, email
aliasing. If you suspect one exists, declare it as a new action (a fix applied to one
flow is often missing on a parallel one). effect is one of seed/raise/cred/request;
set needs_control=true if only the inbox/IdP owner can do it. If the flow needs an input
beyond the email — a code, an invite token, or a SECOND identifier (a recovery/secondary
email you control) — declare it in "params" as {{name: template}}, where a template may use
{{email}} (the shared account), {{alias}} (a recovery email THIS role controls), or {{role}};
a plain string is a literal.

Reply with ONLY a JSON object:
  {{"new_actions": [{{"id":"add_alias","effect":"seed","requires":["register"],
                     "needs_control":true,"params":{{"alias":"{{alias}}"}}}}],
   "probes": [{{"steps": [["attacker","register"], ["attacker","add_alias"],
                          ["victim","sso_login"], ["attacker","alias_login"]]}}]}}
new_actions may be omitted. Prefer short probes that seed an attacker binding, then have
the victim raise trust or change a credential on the same account."""

    # --- parse the model's reply into interleavings --------------------------
    def parse_proposals(self, text: str, state: HuntState) -> list[Merged]:
        raw = self._extract_json(text)
        if isinstance(raw, dict):
            self._register_new_actions(raw.get("new_actions", []), state)
            probes = raw.get("probes", [])
        else:
            probes = raw   # a bare array of probes (back-compat)
        out: list[Merged] = []
        for item in probes if isinstance(probes, list) else []:
            steps = item.get("steps") if isinstance(item, dict) else item
            if not isinstance(steps, list):
                continue
            merged = tuple((str(r), str(a)) for r, a in steps
                           if a in state.specs and r in ("attacker", "victim"))
            if merged and is_wellformed(merged, state.specs):
                out.append(merged)
        return out

    @staticmethod
    def _register_new_actions(new_actions, state: HuntState) -> None:
        """Extend the alphabet in place with any well-formed action the model declared."""
        valid = {e.value for e in Effect}
        for a in new_actions if isinstance(new_actions, list) else []:
            if not isinstance(a, dict):
                continue
            aid, effect = a.get("id"), a.get("effect")
            if not aid or effect not in valid:
                continue
            requires = tuple(r for r in (a.get("requires") or []) if r in state.specs)
            state.specs[str(aid)] = ActionSpec(str(aid), Effect(effect), requires=requires,
                                               needs_control=bool(a.get("needs_control")),
                                               params=_parse_new_action_params(a.get("params")))

    @staticmethod
    def _extract_json(text: str):
        try:
            return json.loads(text)
        except Exception:
            for lo, hi in (("{", "}"), ("[", "]")):
                i, j = text.find(lo), text.rfind(hi)
                if 0 <= i < j:
                    try:
                        return json.loads(text[i:j + 1])
                    except Exception:
                        pass
            return []


def _parse_new_action_params(params) -> tuple:
    """Normalize a declared action's params into ((name, template), ...). Accepts a
    {name: template} object or a list of [name, template] pairs; anything else -> no params.
    Templates may use {email}/{alias}/{role} (see enumerator._render_param) or be literals."""
    if isinstance(params, dict):
        items = params.items()
    elif isinstance(params, list):
        items = ((p[0], p[1]) for p in params if isinstance(p, (list, tuple)) and len(p) == 2)
    else:
        return ()
    return tuple((str(n), str(t)) for n, t in items)


# --------------------------------------------------------------------------- #
#  The control loop.
# --------------------------------------------------------------------------- #
@dataclass
class HuntResult:
    bugs: list[Cluster]
    probes_used: int
    attempts: list[Attempt]


class AgentHunter:
    """Drives a strategist against a target and returns the distinct bugs found.

    `adapter_factory` yields a fresh (vulnerable) adapter per trial, so the loop is
    target-agnostic: pass a MockAdapter factory now, a real TargetAdapter factory
    later. Reuses the oracle for judgment and dedup for reporting."""

    def __init__(self, adapter_factory: AdapterFactory, attacker: Principal,
                 victim: Principal, email: str, specs: Optional[dict[str, ActionSpec]] = None,
                 budget: int = 200, confirm: int = 0) -> None:
        self.adapter_factory = adapter_factory
        self.attacker = attacker
        self.victim = victim
        self.email = email
        # a private copy — a strategist may extend the alphabet (new-action synthesis)
        self.specs = dict(specs) if specs is not None else dict(ACTIONS)
        self.budget = budget
        # oracle confirmation passes — leave 0 against the deterministic mock, raise it
        # against a flaky/rate-limited real target so a verdict must reproduce before it fires.
        self.confirm = confirm

    def _verdict(self, plan):
        a = self.adapter_factory()
        effects = {n: s.effect.value for n, s in self.specs.items()}
        return run_plan(a, plan, AtoOracle(a, self.attacker, self.victim,
                                           effects=effects, confirm=self.confirm))[0]

    def hunt(self, strategist: Strategist) -> HuntResult:
        state = HuntState(self.specs, self.attacker, self.victim, self.email,
                          budget=self.budget)
        fired = []
        seen: set = set()
        while state.budget > 0:
            proposals = strategist.propose(state)
            if not proposals:
                break
            state.round += 1
            for merged in proposals:
                if state.budget <= 0:
                    break
                if merged in seen or not is_wellformed(merged, self.specs):
                    continue
                seen.add(merged)
                cand = make_candidate(merged, self.attacker, self.victim, self.email, self.specs)
                v = self._verdict(cand.plan)
                state.budget -= 1
                state.history.append(Attempt(merged, v.severity.value, v.clause_id,
                                             v.narrative[:80]))
                if v.severity.value == "takeover":
                    fired.append(cand)
        bugs = deduplicate(fired, self.attacker, self.victim, self.email,
                           self._verdict, self.specs)
        return HuntResult(bugs=bugs, probes_used=self.budget - state.budget,
                          attempts=state.history)
