"""Hunt-session logic behind the MCP server — stdlib only, fully testable.

This is what lets the **Claude Code CLI agent be the strategist**, hunting on a Claude
Max subscription instead of pay-per-token API billing. `mcp_server.py` is a thin wrapper
that exposes these `HuntSession` methods as MCP tools; all the logic lives here with no
`mcp` dependency, so it is tested directly.

The agent's workflow over the tools:
    briefing()            -> the TPI method, the roles, the clauses, how to hunt
    list_actions()        -> the known action alphabet (effects, ordering, channel)
    run_probe(steps)      -> execute a two-principal probe; get the oracle's verdict
    ... repeat run_probe, adapting to verdicts ...
    findings()            -> the distinct bugs found so far (deduplicated)

Each method returns plain JSON-able dicts.
"""
from __future__ import annotations

from typing import Optional

from .clauses import CLAUSES
from .dedup import deduplicate
from .enumerator import ACTIONS, ActionSpec, Effect, is_wellformed, make_candidate
from .harness import run_plan
from .mock_target import MockAdapter
from .oracle import AtoOracle
from .types import Principal

_TARGETS = {"mock-vulnerable": False, "mock-patched": True}


class HuntSession:
    """One hunting session against a target. Holds the accumulated findings so the
    agent can call run_probe repeatedly and then ask for the distinct bugs."""

    def __init__(self, target: str = "mock-vulnerable",
                 email: str = "victim@corp.example") -> None:
        self.attacker = Principal("attacker")
        self.victim = Principal("victim")
        self.email = email
        self.control = {self.victim.name: {self.email}}   # victim controls the inbox/IdP
        self.reset(target)

    # -- lifecycle ------------------------------------------------------------
    def reset(self, target: str = "mock-vulnerable") -> dict:
        if target not in _TARGETS:
            return {"ok": False, "error": f"unknown target '{target}'",
                    "targets": list(_TARGETS)}
        self.target = target
        self.patched = _TARGETS[target]
        self.specs = dict(ACTIONS)     # a private copy — register_action never mutates the global
        self._fired: list = []
        self._fired_keys: set = set()
        self.probes_run = 0
        return {"ok": True, "target": target,
                "note": "session reset; attacker does NOT control the email, victim does"}

    def register_action(self, action_id: str, effect: str,
                        requires: Optional[list] = None, needs_control: bool = False) -> dict:
        """Extend the alphabet with a flow the target has but the default set lacks —
        e.g. a magic-link login, device pairing, an org invite, an email alias.

        effect: one of seed/raise/cred/request. requires: action ids that must run first.
        needs_control: true if only the channel-controlling principal (victim) can do it.
        The action then works in run_probe; on this mock it *executes* only if the target
        implements it (e.g. "magic_link"), otherwise it composes but no-ops."""
        valid = {e.value for e in Effect}
        if effect not in valid:
            return {"ok": False, "error": f"effect must be one of {sorted(valid)}"}
        requires = tuple(requires or [])
        for r in requires:
            if r not in self.specs:
                return {"ok": False, "error": f"requires unknown action '{r}'"}
        self.specs[action_id] = ActionSpec(action_id, Effect(effect),
                                           requires=requires, needs_control=bool(needs_control))
        return {"ok": True, "action": action_id, "effect": effect,
                "note": "registered; use it in run_probe like any other action"}

    # -- read tools -----------------------------------------------------------
    def briefing(self) -> dict:
        return {
            "method": (
                "Hunt account-takeover bugs via Trust-Provenance Integrity. A bug is a "
                "reachable state holding a privileged binding whose provenance does not "
                "justify it. The dangerous class is LAUNDERING: it needs TWO principals "
                "(attacker, victim) interleaved over ONE shared account (the same email), "
                "where the victim's genuine proof is laundered into access for the "
                "attacker's pre-existing binding."
            ),
            "roles": {
                "attacker": "does NOT control the email's inbox/IdP",
                "victim": "DOES control the email's inbox/IdP",
            },
            "clauses": [{"id": c.id, "title": c.title, "failure": c.mode.value,
                         "statement": c.statement} for c in CLAUSES.values()],
            "how_to_hunt": [
                "Call list_actions() to see the alphabet.",
                "Propose a probe: an interleaving of [role, action] steps over the shared "
                "account, e.g. [['attacker','register'],['victim','sso_login']].",
                "Call run_probe(steps); read the verdict (severity + which TPI clause).",
                "Prefer short probes: seed an attacker binding, then have the victim raise "
                "trust or change a credential on the same account. Adapt from verdicts.",
                "The alphabet is a STARTING point, not the whole target. Real auth systems "
                "have flows it lacks — magic-link / passwordless login, device pairing, org "
                "invites, adding a secondary email, email aliasing/plus-addressing. If you "
                "suspect one exists, register_action(id, effect, requires, needs_control) "
                "and probe with it — a fix applied to one flow is often missing on a "
                "parallel one.",
                "Call findings() to get the distinct bugs (deduplicated, with minimal repro).",
            ],
            "extending_the_alphabet": (
                "register_action(action_id, effect, requires=[], needs_control=bool). "
                "effect: seed (establishes a binding), raise (verifies/raises trust), cred "
                "(changes a credential), request (creates an outstanding token). Set "
                "needs_control=true if only the inbox/IdP owner can do it."
            ),
            "target": self.target,
        }

    def list_actions(self) -> dict:
        return {"actions": {
            name: {"effect": s.effect.value, "requires": list(s.requires),
                   "needs_channel_control": s.needs_control}
            for name, s in self.specs.items()}}

    # -- the core tool --------------------------------------------------------
    def run_probe(self, steps) -> dict:
        merged, err = self._parse(steps)
        if err:
            return {"ok": False, "error": err}
        cand = make_candidate(merged, self.attacker, self.victim, self.email, self.specs)
        adapter = MockAdapter(patched=self.patched, control=self.control)
        verdict, trace = run_plan(adapter, cand.plan,
                                  AtoOracle(adapter, self.attacker, self.victim, effects=self._effects()))
        self.probes_run += 1
        unbound = [s.action for s in trace.steps
                   if s.obs and not s.obs.ok and "no binding" in (s.obs.note or "")]

        is_new = False
        if verdict.severity.value == "takeover" and merged not in self._fired_keys:
            self._fired_keys.add(merged)
            self._fired.append(cand)
            is_new = True
        out = {
            "ok": True,
            "probe": "  ->  ".join(f"{r}:{a}" for r, a in merged),
            "severity": verdict.severity.value,
            "clause_id": verdict.clause_id,
            "failure_mode": verdict.failure_mode,
            "laundered_proof": verdict.laundered_proof,
            "narrative": verdict.narrative,
            "evidence": [{"kind": e.kind, "detail": e.detail, "strength": e.strength}
                         for e in verdict.evidence],
            "is_new_takeover": is_new,
            "probes_run": self.probes_run,
        }
        if unbound:
            out["unbound_actions"] = unbound   # registered but the target has no such flow
        return out

    def _effects(self) -> dict:
        return {name: s.effect.value for name, s in self.specs.items()}

    def _clusters(self) -> list:
        return deduplicate(self._fired, self.attacker, self.victim, self.email,
                           self._verdict, self.specs)

    def findings(self) -> dict:
        clusters = self._clusters()
        return {
            "distinct_bugs": len(clusters),
            "probes_run": self.probes_run,
            "bugs": [{
                "clause_id": cl.clause_id,
                "minimal_repro": "  ->  ".join(f"{r}:{a}" for r, a in cl.representative),
                "laundered_proof": cl.laundered_proof,
                "variants_collapsed": cl.size,
            } for cl in clusters],
        }

    def report(self, fmt: str = "markdown") -> dict:
        """A shareable, submittable evidence bundle for the distinct bugs found so far.
        fmt: "markdown" (a document) or "json" (structured). Each bug carries steps to
        reproduce, the canary evidence proving the takeover, the laundered proof, and
        the remediation derived from the violated TPI clause."""
        from .report import build_bundle, bundle_to_json, bundle_to_markdown
        reports = build_bundle(self._clusters(), attacker=self.attacker,
                               victim=self.victim, email=self.email,
                               run_fn=self._run_pair, specs=self.specs)
        if fmt == "json":
            return {"ok": True, "format": "json", "distinct_bugs": len(reports),
                    "content": bundle_to_json(reports)}
        return {"ok": True, "format": "markdown", "distinct_bugs": len(reports),
                "content": bundle_to_markdown(reports)}

    # -- internals ------------------------------------------------------------
    def _run_pair(self, plan):
        a = MockAdapter(patched=self.patched, control=self.control)
        return run_plan(a, plan, AtoOracle(a, self.attacker, self.victim, effects=self._effects()))

    def _verdict(self, plan):
        return self._run_pair(plan)[0]

    def _parse(self, steps) -> tuple[Optional[tuple], Optional[str]]:
        if not isinstance(steps, list) or not steps:
            return None, "steps must be a non-empty list of [role, action] pairs"
        merged = []
        for step in steps:
            if not (isinstance(step, (list, tuple)) and len(step) == 2):
                return None, f"each step must be [role, action]; got {step!r}"
            role, action = str(step[0]), str(step[1])
            if role not in ("attacker", "victim"):
                return None, f"role must be 'attacker' or 'victim'; got {role!r}"
            if action not in self.specs:
                return None, f"unknown action {action!r}; call list_actions()"
            merged.append((role, action))
        merged = tuple(merged)
        if not is_wellformed(merged, self.specs):
            return None, ("ordering precondition unmet (an action ran before its "
                          "requirement); see requires in list_actions()")
        return merged, None
