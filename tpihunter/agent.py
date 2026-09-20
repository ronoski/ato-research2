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
import re
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
    is_new: bool = False    # a takeover whose (clause, effect-shape, trigger) had not fired before
    reason: str = ""        # outcome code the strategist can act on (see _outcome_reason)


# --------------------------------------------------------------------------- #
#  Situational awareness: turn each probe's raw verdict into signal the agent can
#  reason over — WHY a probe landed or didn't, WHAT has been covered, and WHEN to stop.
# --------------------------------------------------------------------------- #
# A synthesized action name becomes an attribute lookup on the target adapter
# (`harness.execute_action`), and the name is chosen by a model reading target output. So
# it is validated the way any untrusted identifier is: a plain lowercase verb, never a
# dunder or private name that would reach into the adapter's own machinery
# (`__init__`, `_client`, `close`) instead of naming a flow on the target.
_ACTION_ID = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_RESERVED_ACTIONS = frozenset({
    "arm", "plant", "assess",                      # oracle checkpoints, handled by run_plan
    "planes", "capture_binding", "present_binding",  # the matrix's binding-lifecycle surface
    "whoami", "plant_marker", "read_marker", "write_marker",  # the oracle's ground truth
})


def valid_action_id(action_id) -> Optional[str]:
    """None if `action_id` may name a synthesized action, else why it may not."""
    if not isinstance(action_id, str) or not _ACTION_ID.match(action_id):
        return ("action id must be a lowercase identifier of 1-63 chars matching "
                "[a-z][a-z0-9_]* (no dunder, private or dotted names)")
    if action_id in _RESERVED_ACTIONS:
        return f"'{action_id}' is reserved by the harness and cannot be redefined"
    return None


def _outcome_reason(verdict, trace, is_new: bool) -> str:
    """A single actionable code per probe. `new_bug`/`duplicate` for a takeover; otherwise
    distinguish `unbound_action` (a synthesized verb the target does not implement — stop
    proposing it), `incomplete` (a step did not execute as posed — reformulate),
    `inconclusive` (the probe ran but a control failed or the access was unattributable, so
    it measured nothing — see `Verdict.withheld`), and `enforced` (the probe ran fully and
    the target correctly denied cross-access — a real secure result).

    A step that did not execute is reported ahead of the verdict, because it explains *why*
    the experiment was void, which is what the strategist needs in order to reformulate."""
    sev = verdict.severity.value
    if sev == "takeover":
        return "new_bug" if is_new else "duplicate"
    if sev == "suspect":
        return "suspect"
    for s in trace.steps:
        if s.action in ("arm", "plant", "assess") or s.obs is None or s.obs.ok:
            continue
        return "unbound_action" if "no binding" in (s.obs.note or "").lower() else "incomplete"
    if sev == "inconclusive":
        return "inconclusive"
    return "enforced"


def _fired_signature(merged: Merged, verdict, specs: dict) -> tuple:
    """A cheap distinctness key aligned with dedup's signature — clause + effect-classes +
    trigger verbs — so the loop can tell a genuinely new bug from another path to a known one
    without paying for full causal minimization every round."""
    from .clauses import BROAD_AUTHORIZATION
    if verdict.clause_id == BROAD_AUTHORIZATION.id:
        return (verdict.clause_id, frozenset(), frozenset())   # see dedup._signature
    effects = frozenset(specs[a].effect.value for _r, a in merged if a in specs)
    triggers = frozenset(a for _r, a in merged
                         if a in specs and specs[a].effect.value in ("raise", "cred"))
    return (verdict.clause_id, effects, triggers)


def _frontier(specs: dict, attacker: Principal, victim: Principal, email: str, tried: set) -> int:
    """How many composition-relevant, well-formed interleavings in the KNOWN alphabet remain
    untried — a floor on the systematic space left (the agent may also invent new actions)."""
    from .enumerator import enumerate_plans
    return sum(1 for c in enumerate_plans(attacker, victim, email, specs=specs)
               if c.merged not in tried)


@dataclass
class Coverage:
    """What the hunt has covered so far — the agent's map of where it has and hasn't looked."""
    distinct_bugs: int
    clauses_found: list
    effect_combos_tried: list        # list[frozenset[str]] of effect-classes per probe shape
    frontier_remaining: int
    probes_used: int

    def summary(self) -> str:
        combos = ", ".join("{" + "+".join(sorted(c)) + "}" for c in self.effect_combos_tried) or "none"
        found = ", ".join(self.clauses_found) or "none"
        return (f"{self.distinct_bugs} distinct bug(s) [{found}]; effect-combinations tried: "
                f"{combos}; ~{self.frontier_remaining} known-alphabet probes still untried")

    @classmethod
    def compute(cls, history: list, specs: dict, attacker: Principal, victim: Principal,
                email: str, distinct_bugs: Optional[int] = None) -> "Coverage":
        tried = {h.merged for h in history}
        found: list = []
        combos: list = []
        sigs: set = set()
        for h in history:
            eff = frozenset(specs[a].effect.value for _r, a in h.merged if a in specs)
            if eff and eff not in combos:
                combos.append(eff)
            if h.severity == "takeover" and h.clause_id:
                if h.clause_id not in found:
                    found.append(h.clause_id)
                triggers = frozenset(a for _r, a in h.merged
                                     if a in specs and specs[a].effect.value in ("raise", "cred"))
                sigs.add((h.clause_id, eff, triggers))
        return cls(distinct_bugs=distinct_bugs if distinct_bugs is not None else len(sigs),
                   clauses_found=sorted(found), effect_combos_tried=combos,
                   frontier_remaining=_frontier(specs, attacker, victim, email, tried),
                   probes_used=len(history))


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
                + (f" [{h.reason}]" if h.reason else "")
                for h in state.history[-20:])
        else:
            hist = "  (nothing tried yet)"
        cov = Coverage.compute(state.history, state.specs, state.attacker, state.victim, state.email)
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

What you have tried and what happened (the reason in [brackets] tells you what to do next:
`enforced` = the target is secure there, move on; `unbound_action` = that verb does not exist
on this target, stop proposing it; `incomplete` = the probe could not run as posed, reformulate;
`inconclusive` = the probe measured NOTHING (a control failed, or the access could not be
attributed to your steps) — this is not a secure result, reformulate and try again;
`duplicate` = you already found that bug another way; `new_bug` = keep pulling that thread):
{hist}

Coverage so far: {cov.summary()}

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
            if effect not in valid or valid_action_id(aid) is not None:
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
    coverage: Optional[Coverage] = None
    stop_reason: str = ""       # budget | patience | strategist_stopped


class AgentHunter:
    """Drives a strategist against a target and returns the distinct bugs found.

    `adapter_factory` yields a fresh (vulnerable) adapter per trial, so the loop is
    target-agnostic: pass a MockAdapter factory now, a real TargetAdapter factory
    later. Reuses the oracle for judgment and dedup for reporting."""

    def __init__(self, adapter_factory: AdapterFactory, attacker: Principal,
                 victim: Principal, email: str, specs: Optional[dict[str, ActionSpec]] = None,
                 budget: int = 200, confirm: int = 0, mutate: bool = False,
                 canary: str = "planted") -> None:
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
        # let the oracle attempt the destructive cross-principal write probe; off by default
        self.mutate = bool(mutate)
        # "planted" or "natural" ground truth — see oracle._observe_natural_canary
        self.canary = canary

    def _run(self, plan):
        a = self.adapter_factory()
        effects = {n: s.effect.value for n, s in self.specs.items()}
        return run_plan(a, plan, AtoOracle(a, self.attacker, self.victim,
                                           effects=effects, confirm=self.confirm,
                                           resource=self.email, mutate=self.mutate,
                                           canary=self.canary))

    def _verdict(self, plan):
        return self._run(plan)[0]

    def hunt(self, strategist: Strategist, patience: Optional[int] = None) -> HuntResult:
        """Drive the strategist until it stops, the budget runs out, or — when `patience` is
        set — `patience` consecutive rounds pass with no new distinct bug (so an adaptive agent
        does not burn probes once the surface is exhausted). `HuntResult.stop_reason` says which."""
        state = HuntState(self.specs, self.attacker, self.victim, self.email,
                          budget=self.budget)
        fired = []
        seen: set = set()
        fired_sigs: set = set()
        stale_rounds = 0
        stop_reason = ""
        while state.budget > 0:
            proposals = strategist.propose(state)
            if not proposals:
                stop_reason = "strategist_stopped"
                break
            state.round += 1
            progressed = False
            for merged in proposals:
                if state.budget <= 0:
                    break
                if merged in seen or not is_wellformed(merged, self.specs):
                    continue
                seen.add(merged)
                cand = make_candidate(merged, self.attacker, self.victim, self.email, self.specs)
                verdict, trace = self._run(cand.plan)
                state.budget -= 1
                is_new = False
                if verdict.severity.value == "takeover":
                    sig = _fired_signature(merged, verdict, self.specs)
                    is_new = sig not in fired_sigs
                    fired_sigs.add(sig)
                    fired.append(cand)
                    progressed = progressed or is_new
                state.history.append(Attempt(merged, verdict.severity.value, verdict.clause_id,
                                             verdict.narrative[:80], is_new=is_new,
                                             reason=_outcome_reason(verdict, trace, is_new)))
            if patience is not None:
                stale_rounds = 0 if progressed else stale_rounds + 1
                if stale_rounds >= patience:
                    stop_reason = "patience"
                    break
        if not stop_reason:
            stop_reason = "budget"
        bugs = deduplicate(fired, self.attacker, self.victim, self.email,
                           self._verdict, self.specs)
        coverage = Coverage.compute(state.history, self.specs, self.attacker, self.victim,
                                    self.email, distinct_bugs=len(bugs))
        return HuntResult(bugs=bugs, probes_used=self.budget - state.budget,
                          attempts=state.history, coverage=coverage, stop_reason=stop_reason)
