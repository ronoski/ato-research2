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
    revocation_matrix()   -> the own-account lifecycle mode: does each mutation revoke
                             each predating binding? (single-principal, reversible)
    findings()            -> the distinct bugs found so far (deduplicated)

Each method returns plain JSON-able dicts.
"""
from __future__ import annotations

import os
from typing import Optional

from .agent import Attempt, Coverage, _fired_signature, _outcome_reason, valid_action_id
from .clauses import CLAUSES
from .dedup import deduplicate
from .enumerator import ACTIONS, ActionSpec, Effect, is_wellformed, make_candidate, recovery_alias
from .harness import run_plan
from .matrix import RevocationMatrix, default_mints, default_mutations
from .mock_target import MockAdapter
from .oracle import AtoOracle
from .policy import EngagementPolicy, PolicyViolation
from .redact import redact, untrusted
from .types import Principal

# Target name -> MockAdapter kwargs. "mock-plane-split" models a multi-plane estate where
# logout revokes only the plane it is issued on — the cross-plane laundering (Grab T-ATO-05).
_TARGETS = {
    "mock-vulnerable": {"patched": False},
    "mock-patched": {"patched": True},
    "mock-plane-split": {"patched": True, "planes": ("auth", "mts"),
                         "revokes": {"logout"}, "plane_local": {"logout"}},
}

# The name a live, profile-driven target goes by. It only becomes available once the
# OPERATOR has authorized one (see `_load_engagement`) and the agent has described it
# with set_target() and proved the description works with validate_target().
LIVE = "live"

# Where the operator's authorization lives. Read from disk at session start, never from
# anything the model can write: a policy authored by the agent it constrains is not a
# control. The agent may describe a target; it may not widen the scope it runs in.
ENGAGEMENT_ENV = "TPIHUNTER_ENGAGEMENT"


def _load_engagement() -> tuple[Optional[EngagementPolicy], str]:
    """(policy, why-not). No env var => no live hunting, and that is the default."""
    path = os.environ.get(ENGAGEMENT_ENV)
    if not path:
        return None, (f"no live engagement is authorized. To hunt a real target, the "
                      f"OPERATOR (not the agent) writes an engagement file and points "
                      f"{ENGAGEMENT_ENV} at it: "
                      f'{{"name": "...", "authorized_by": "who authorized this and where '
                      f'it is recorded", "identifiers": ["the test accounts"], "hosts": '
                      f'["the in-scope hosts"], "max_actions": 500}}')
    try:
        policy = EngagementPolicy.from_file(path)
    except (OSError, PolicyViolation) as e:
        return None, f"{ENGAGEMENT_ENV}={path} could not be loaded: {e}"
    problems = policy.preflight()
    if problems:
        return None, (f"the engagement file at {path} is not usable:\n  - "
                      + "\n  - ".join(problems))
    return policy, ""


def _parse_params(params) -> tuple[tuple, Optional[str]]:
    """Normalize a synthesized action's params into an ordered ((name, template), ...) tuple.
    Accepts {name: template} or a list of [name, template] pairs; templates are strings."""
    if not params:
        return (), None
    items = params.items() if isinstance(params, dict) else params
    out = []
    try:
        for name, tmpl in items:
            out.append((str(name), str(tmpl)))
    except (TypeError, ValueError):
        return (), "params must be {name: template} or a list of [name, template] pairs"
    return tuple(out), None


class HuntSession:
    """One hunting session against a target. Holds the accumulated findings so the
    agent can call run_probe repeatedly and then ask for the distinct bugs."""

    def __init__(self, target: str = "mock-vulnerable",
                 email: str = "victim@corp.example", confirm: int = 0,
                 mutate: bool = False) -> None:
        self.attacker = Principal("attacker")
        self.victim = Principal("victim")
        self.email = email
        # victim controls the shared inbox/IdP; the attacker controls only their OWN recovery
        # email (a second identifier), never the shared account — so an alias-based finding is
        # genuine, not an artifact of an all-permissive channel model.
        self.control = {self.victim.name: {self.email},
                        self.attacker.name: {recovery_alias("attacker")}}
        # oracle confirmation passes: 0 for the deterministic mock; raise against a flaky
        # real target so a takeover must reproduce across passes before it is reported.
        self.confirm = confirm
        # the oracle's destructive cross-principal WRITE probe. Off by default: reading the
        # victim's canary already proves takeover, and writing another principal's private
        # resource is the one irreversible thing the loop can do to a live target.
        self.mutate = bool(mutate)
        # live-target state: the operator's authorization, the agent's description of the
        # target, and whether that description has been shown to work.
        self.policy, self._no_engagement = _load_engagement()
        self.profile = None
        self.validation = None
        self.reset(target)

    # -- lifecycle ------------------------------------------------------------
    def reset(self, target: str = "mock-vulnerable") -> dict:
        if target == LIVE:
            if self.profile is None:
                return {"ok": False, "error": "no live target described yet; call "
                                              "set_target(profile) first"}
        elif target not in _TARGETS:
            return {"ok": False, "error": f"unknown target '{target}'",
                    "targets": self._target_names()}
        self.target = target
        self._cfg = dict(_TARGETS.get(target, {}))  # MockAdapter kwargs for this target
        self.patched = self._cfg.get("patched", False)
        self.specs = dict(ACTIONS)     # a private copy — register_action never mutates the global
        self._fired: list = []
        self._fired_keys: set = set()
        self._fired_sigs: set = set()  # (clause, effects, triggers) — distinctness, for is_new
        self._history: list = []       # Attempt per probe — feeds coverage()
        self.probes_run = 0
        return {"ok": True, "target": target, "targets": self._target_names(),
                "note": "session reset; attacker does NOT control the email, victim does. "
                        "Targets: mock-vulnerable, mock-patched, mock-plane-split (the last "
                        "shows a cross-plane SPLIT in revocation_matrix())."}

    def _target_names(self) -> list:
        names = list(_TARGETS)
        if self.profile is not None:
            names.append(LIVE)
        return names

    def _adapter(self, control):
        if self.target == LIVE:
            from .live import live_adapter
            return live_adapter(self.profile, self.policy, control=control)
        return MockAdapter(control=control, **self._cfg)

    # -- describing and proving a real target ---------------------------------
    def set_target(self, profile: dict) -> dict:
        """Describe a real target as data, so it can be hunted without anyone writing code.

        The engagement policy is NOT part of this: the operator authorizes the scope out of
        band and this session only checks the description against it. A profile naming an
        identifier or host the operator did not authorize is refused here, before a single
        request is sent."""
        from .profile import ProfileError, TargetProfile
        if self.policy is None:
            return {"ok": False, "error": self._no_engagement}
        try:
            prof = TargetProfile.from_dict(profile)
        except ProfileError as e:
            return {"ok": False, "error": str(e),
                    "next": "Fix the listed fields and call set_target again."}
        outside = prof.identifiers() - set(self.policy.identifiers)
        if outside:
            return {"ok": False, "error": f"the profile uses identifiers the engagement does "
                                          f"not authorize: {sorted(outside)}",
                    "authorized": sorted(self.policy.identifiers),
                    "next": "Use the authorized test accounts, or ask the operator to widen "
                            "the engagement file. This session cannot widen it."}
        host_problem = self.policy.check_host(prof.host)
        if host_problem:
            return {"ok": False, "error": host_problem, "authorized": sorted(self.policy.hosts)}
        self.profile = prof
        self.validation = None
        victim = prof.accounts.get("victim")
        if victim is not None:
            self.email = victim.email
            self.control = {self.victim.name: {self.email},
                            self.attacker.name: {recovery_alias("attacker")}}
        return {"ok": True, "profile": prof.describe(),
                "next": "Call validate_target() before probing. An unvalidated profile "
                        "produces confident SAFE verdicts on a target it never reached."}

    def validate_target(self) -> dict:
        """Prove the profile works before any verdict from it is treated as evidence.

        Performs real writes on the engagement's own accounts (registers, plants a marker,
        reads it back) and reports every check with a one-line fix for the ones that failed."""
        if self.policy is None:
            return {"ok": False, "error": self._no_engagement}
        if self.profile is None:
            return {"ok": False, "error": "no target described; call set_target(profile) first"}
        from .validate import validate_target as _validate
        self.validation = _validate(self.profile, self.policy)
        out = {"ok": True, **self.validation.as_dict(self.profile)}
        if self.validation.ready:
            self.reset(LIVE)
            out["next"] = ("Profile validated. The session is now on the live target — "
                           "call briefing() and start probing.")
        return out

    def register_action(self, action_id: str, effect: str,
                        requires: Optional[list] = None, needs_control: bool = False,
                        params: Optional[dict] = None) -> dict:
        """Extend the alphabet with a flow the target has but the default set lacks —
        e.g. a magic-link login, device pairing, an org invite, an email alias.

        effect: one of seed/raise/cred/request. requires: action ids that must run first.
        needs_control: true if only the channel-controlling principal (victim) can do it.
        params: extra inputs the flow needs beyond the implicit email, as {name: template}.
        A template may use {email} (the shared account), {alias} (a recovery/secondary email
        THIS role controls — a second identifier), or {role}; a plain string is a literal
        (e.g. a fixed code / invite token). This is what lets a synthesized action be driven
        with a code, an invite token, or an identifier that is not the account's email.
        The action then works in run_probe; on this mock it *executes* only if the target
        implements it (e.g. "magic_link", "add_alias", "alias_login"), else it no-ops."""
        valid = {e.value for e in Effect}
        if effect not in valid:
            return {"ok": False, "error": f"effect must be one of {sorted(valid)}"}
        # An action id becomes getattr(adapter, id) at run time, so it is validated before
        # it is stored — not after it has already been dispatched.
        id_error = valid_action_id(action_id)
        if id_error:
            return {"ok": False, "error": id_error}
        requires = tuple(requires or [])
        for r in requires:
            if r not in self.specs:
                return {"ok": False, "error": f"requires unknown action '{r}'"}
        pspec, perr = _parse_params(params)
        if perr:
            return {"ok": False, "error": perr}
        self.specs[action_id] = ActionSpec(action_id, Effect(effect), requires=requires,
                                           needs_control=bool(needs_control), params=pspec)
        return {"ok": True, "action": action_id, "effect": effect,
                "params": [n for n, _ in pspec],
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
                "There is a second, single-principal mode: revocation_matrix(). It asks, for "
                "each way of minting a session and each credential-mutating transition, "
                "whether the mutation revokes a session minted BEFORE it. A SURVIVED cell is "
                "a stolen session that outlives the owner's logout/reset (TPI-4); a SPLIT cell "
                "means the mutation revoked the credential on the plane it was issued on but "
                "NOT on another verify-point plane — the subtle cross-plane bug a same-plane "
                "test would call fixed. It is own-account and reversible — the safe mode to "
                "reach for first on a real, authorized target where reading another "
                "principal's data is not permitted. (reset('mock-plane-split') to see a SPLIT.)",
                "Read `reason` and `withheld` on every verdict. `inconclusive` means the "
                "probe measured NOTHING — a control failed (the victim could not plant a "
                "canary, so there was no ground truth) or the access could not be attributed "
                "to your steps. It is never evidence that the target is secure; reformulate "
                "so the victim actually establishes a session before the oracle arms.",
                "A verdict may cite AUTHZ-1 instead of a TPI clause. That means the "
                "bystander control fired: an account that took no part in your probe could "
                "read the victim's resource too, so the access was never provenance-"
                "specific. It is a real bug (object-level authorization) but not a "
                "laundering one — do not keep probing identity flows to explain it.",
                "Call findings() to get the distinct bugs (deduplicated, with minimal repro).",
            ],
            "extending_the_alphabet": (
                "register_action(action_id, effect, requires=[], needs_control=bool, "
                "params={}). effect: seed (establishes a binding), raise (verifies/raises "
                "trust), cred (changes a credential), request (creates an outstanding token). "
                "Set needs_control=true if only the inbox/IdP owner can do it. Some flows need "
                "more than the email — a code, an invite token, or a SECOND identifier (a "
                "recovery/secondary email you control): declare them in params={name: "
                "template}, where a template may use {email} (the shared account), {alias} (a "
                "recovery email THIS role controls), or {role}, and a plain string is a "
                "literal. E.g. add_alias with params={'alias':'{alias}'} adds a recovery email "
                "you control, then alias_login (params={'alias':'{alias}'}) logs in via it — "
                "a takeover if that alias outlived the victim's rebind."
            ),
            "target": self.target,
            "live_target": (self.profile.describe() if self.profile is not None
                            else self._no_engagement or
                            "no live target described — call set_target(profile) to hunt a "
                            "real system, then validate_target() to prove the description "
                            "works. Until then these tools drive the built-in mock."),
        }

    def list_actions(self) -> dict:
        return {"actions": {
            name: {"effect": s.effect.value, "requires": list(s.requires),
                   "needs_channel_control": s.needs_control}
            for name, s in self.specs.items()}}

    # -- the core tool --------------------------------------------------------
    def run_probe(self, steps) -> dict:
        gate = self._live_gate()
        if gate is not None:
            return gate
        merged, err = self._parse(steps)
        if err:
            return {"ok": False, "error": err}
        cand = make_candidate(merged, self.attacker, self.victim, self.email, self.specs)
        adapter = self._adapter(self.control)
        verdict, trace = run_plan(adapter, cand.plan,
                                  AtoOracle(adapter, self.attacker, self.victim,
                                            effects=self._effects(), confirm=self.confirm,
                                            resource=self.email, mutate=self.mutate))
        self.probes_run += 1
        unbound = [s.action for s in trace.steps
                   if s.obs and not s.obs.ok and "no binding" in (s.obs.note or "")]

        is_new = False
        if verdict.severity.value == "takeover":
            sig = _fired_signature(merged, verdict, self.specs)
            is_new = sig not in self._fired_sigs
            self._fired_sigs.add(sig)
            if merged not in self._fired_keys:      # keep every takeover path for dedup
                self._fired_keys.add(merged)
                self._fired.append(cand)
        reason = _outcome_reason(verdict, trace, is_new)
        self._history.append(Attempt(merged, verdict.severity.value, verdict.clause_id,
                                     verdict.narrative[:80], is_new=is_new, reason=reason))
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
            # set when access evidence existed but a finding was NOT raised, with the reason
            # (principals_not_independent / attacker_proved_control / no_attacker_action /
            # canary_not_planted). Read it: it usually means the probe, not the target, is wrong.
            "withheld": verdict.withheld,
            # per-probe control outcomes (canary_planted, ref_reads_scoped, ...). A verdict
            # whose controls did not hold measured nothing.
            "controls": verdict.controls,
            # what this outcome means for your NEXT probe: new_bug/duplicate/enforced/
            # unbound_action/incomplete/inconclusive/suspect — see coverage() for the whole map.
            "reason": reason,
            "probes_run": self.probes_run,
        }
        if unbound:
            out["unbound_actions"] = unbound   # registered but the target has no such flow
        # Everything below leaves for a model's context and, on a live target, is partly
        # the target's own text. Scrub secrets and neutralise instruction-shaped content.
        for key in ("narrative", "laundered_proof"):
            if out.get(key):
                out[key] = untrusted(redact(out[key]), 400)
        for e in out["evidence"]:
            e["detail"] = untrusted(redact(e["detail"]), 240)
        return out

    def _live_gate(self) -> Optional[dict]:
        """Refuse to hunt a live target whose description has not been shown to work.

        This is the same rule the oracle applies to its own controls, one level up: a probe
        against a target the profile never correctly reached is not a SAFE result, it is no
        result, and letting it read as SAFE is how an agent concludes a system is secure
        without ever having tested it."""
        if self.target != LIVE:
            return None
        if self.validation is None:
            return {"ok": False, "error": "this live target has not been validated",
                    "next": "Call validate_target() first."}
        if not self.validation.ready:
            return {"ok": False, "error": "the live target's profile has blocking failures",
                    "blocking_failures": [c.name for c in self.validation.checks
                                          if c.status == "fail" and c.blocking],
                    "next": "Call validate_target() to see each fix, repair the profile with "
                            "set_target(), and validate again."}
        return None

    def revocation_matrix(self) -> dict:
        """The own-account lifecycle hunt: for each way of minting a session and each
        credential-mutating transition, does the mutation revoke a session minted before
        it? A SURVIVED cell is TPI-4 laundering (a stolen session that outlives the
        owner's logout/reset). Single-principal, reversible, reads no one else's data —
        the ROE-safe mode for a real engagement. Each cell carries its own positive and
        negative control, so a SURVIVED verdict is not a broken-check artifact."""
        gate = self._live_gate()
        if gate is not None:
            return gate
        owner = Principal("owner")
        email = "owner@corp.example"
        control = {owner.name: {email}}

        def factory():
            return self._adapter(control)

        matrix = RevocationMatrix(owner, default_mints(email), default_mutations(email))
        results = matrix.run(factory)
        findings = matrix.findings(results)
        return {
            "grid": {f"{mid}|{xid}": v.survival.value for (mid, xid), v in results.items()},
            "rendered": matrix.render(results),
            "laundering_cells": len(findings),
            "findings": [{"clause_id": v.clause_id, "mint": v.mint_id,
                          "mutation": v.mutation_id, "note": v.note, "evidence": v.evidence}
                         for v in findings],
        }

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

    def coverage(self) -> dict:
        """The agent's map of where it has and hasn't looked, so it can decide whether to keep
        pulling the same thread, try a new probe shape, or stop: how many DISTINCT bugs found,
        which TPI clauses have evidence, which effect-combinations have been tried, and how many
        composition-relevant probes in the known alphabet remain UNTRIED (a floor — you may also
        invent new actions). Pair it with each run_probe's `reason` (enforced / unbound_action /
        incomplete / duplicate / new_bug) to avoid re-probing settled surface."""
        cov = Coverage.compute(self._history, self.specs, self.attacker, self.victim,
                               self.email, distinct_bugs=len(self._clusters()))
        return {
            "distinct_bugs": cov.distinct_bugs,
            "clauses_found": cov.clauses_found,
            "effect_combinations_tried": ["+".join(sorted(c)) for c in cov.effect_combos_tried],
            "frontier_remaining": cov.frontier_remaining,
            "probes_run": cov.probes_used,
            "summary": cov.summary(),
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
        a = self._adapter(self.control)
        return run_plan(a, plan, AtoOracle(a, self.attacker, self.victim,
                                           effects=self._effects(), confirm=self.confirm,
                                           resource=self.email, mutate=self.mutate))

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
