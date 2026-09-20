"""The success oracle: does principal A hold access that only principal V should?

This is the piece that makes autonomy possible — the agent's *verdict*. Without
it you generate candidate attacks and never learn which one landed.

Design: canary-based, differential, controlled, provenance-labeling.

  1. arm()   -- capture the victim's identity and record what the attacker can
                already see about the victim *before* a canary exists (baseline).
  2. plant() -- as the victim, write a unique 128-bit secret into a private
                resource. This is the ground truth of "V's private state".
  3. assess()-- re-probe as the attacker. Report TAKEOVER only on hard evidence:
                an exact canary match, an identity confluence, or a confirmed
                cross-principal write. Then diagnose *which* TPI clause the trace
                shows was violated, so the result is a diagnosis, not just a hit.

CONTROLS (why a verdict can be trusted)
---------------------------------------
A measurement without controls is an anecdote, and both directions of error are
expensive: a false TAKEOVER is a bogus Critical in someone's bug tracker, a false
SAFE teaches the agent that a surface is secure and it stops looking there. So each
assessment carries the same positive/negative control discipline the revocation
matrix applies per cell (`matrix.run_cell`):

  * POSITIVE control (did the experiment run at all?) — after planting, the victim
    must be able to read its own canary back. If it cannot, no canary exists, every
    subsequent comparison is vacuous, and the honest answer is INCONCLUSIVE, never
    a confident SAFE.
  * NEGATIVE control (is the read channel scoped?) — a reference that cannot name
    any real resource must be refused. If the target answers it with data, the
    endpoint is unscoped and a by-reference read proves nothing, so that evidence
    is dropped rather than counted.

ATTRIBUTION (why the *probe* caused it)
---------------------------------------
Evidence of access is necessary but not sufficient: a finding must be attributable
to the probe, and unjustified by the attacker's own provenance. Three guards, all
black-box computable from the trace, gate a non-SAFE severity:

  * INDEPENDENCE — if the attacker context already resolved to the victim's identity
    *before the attacker had acted at all*, the two principals were never independent
    (a shared ops mailbox, a family plan, a tenant seat, an SSO org account). Nothing
    was taken over; the experiment is void.
  * JUSTIFICATION — if the attacker itself demonstrated control of the shared
    identifier over a possession channel (IdP, inbox, SMS, TOTP, WebAuthn), its access
    has justifying provenance. That is a co-owner, not a laundering bug. This is the
    TPI thesis applied to the oracle's own output: access with provenance is not a
    violation, however much confluence it produces.
  * ATTRIBUTION — if the trace holds no successful attacker action, there is nothing
    to attribute the access to.

A guard never silently rewrites a verdict: `Verdict.withheld` carries the reason code,
so an agent (and a human reading a report) sees exactly why a finding was not raised.

Confirmation (retry): a real target is not the deterministic mock — it rate-limits and
returns transient errors, so a single observation can miss (or, more rarely, spuriously
show) access. `AtoOracle(confirm=k)` re-runs the assessment 1+k times and reports a
non-SAFE severity only if it holds a strict majority of the passes; with no majority the
honest answer is SUSPECT. This protects the load-bearing invariant — a takeover that
cannot be reproduced never fires — while recovering the recall a flaky target would
otherwise cost. Note what confirmation does *not* buy: it defends against transient
noise, not against a systematic condition (a shared account, a stale identity cache)
that every pass reproduces. That is what the controls and attribution guards above are
for, and why they are not optional.

Mutation (`mutate=True`): proving the attacker can *write* the victim's private resource
is the strongest evidence there is, and also the only destructive thing this oracle does.
It is therefore OFF by default — a read-only assessment is the safe default for an
authorized engagement — and when enabled the restore is verified, with any failure
surfaced in `Verdict.controls` rather than silently leaving the victim's data corrupted.
"""
from __future__ import annotations

import secrets
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .adapter import Trace
from .clauses import BROAD_AUTHORIZATION, CATALOG, FailureMode
from .redact import untrusted
from .types import Channel, Principal

# A reference that must not name any real resource. If the target answers it with data,
# the read endpoint is unscoped and a by-reference read is not evidence of anything.
NEVER_VALID_REF = "__tpihunter_never_valid_ref__"

# Channels over which a principal demonstrates *control* of a resource. A proof over one
# of these justifies the access it grants; KNOWLEDGE (a password) is an assertion about a
# credential, not a demonstration of control over the identifier, so it is excluded.
CONTROL_CHANNELS = frozenset({Channel.EMAIL, Channel.SMS, Channel.TOTP,
                              Channel.WEBAUTHN, Channel.IDP})

# The uninvolved third account used as the diagnosis control. Pass `bystander=None` to
# disable it; a control that must be opted into is a control nobody runs.
DEFAULT_BYSTANDER = Principal("bystander")


class Severity(str, Enum):
    SAFE = "safe"
    SUSPECT = "suspect"
    TAKEOVER = "takeover"
    INCONCLUSIVE = "inconclusive"   # a control failed or the access is unattributable:
                                    # the probe measured nothing, so neither SAFE nor a finding


class Withheld(str, Enum):
    """Why a finding was not raised although access evidence existed."""
    NOT_INDEPENDENT = "principals_not_independent"
    ATTACKER_PROVED_CONTROL = "attacker_proved_control"
    NO_ATTACKER_ACTION = "no_attacker_action"
    CANARY_NOT_PLANTED = "canary_not_planted"


@dataclass
class Evidence:
    kind: str        # identity_confluence | canary_read | canary_write
    detail: str
    strength: int    # 0..3


@dataclass
class Verdict:
    severity: Severity
    confidence: float
    evidence: list[Evidence]
    clause_id: Optional[str]
    failure_mode: Optional[str]
    laundered_proof: Optional[str]
    narrative: str
    withheld: Optional[str] = None        # a Withheld reason code, when a finding was gated
    controls: dict = field(default_factory=dict)   # control name -> outcome


class AtoOracle:
    def __init__(self, adapter, attacker: Principal, victim: Principal,
                 effects: Optional[dict] = None, confirm: int = 0,
                 resource: Optional[str] = None, mutate: bool = False,
                 bystander: Optional[Principal] = DEFAULT_BYSTANDER) -> None:
        self.a = adapter
        self.attacker = attacker
        self.victim = victim
        # action -> effect-class name ("seed"/"raise"/"cred"/"request"). When given,
        # diagnosis is effect-based, so newly-synthesized actions classify correctly;
        # when None, it falls back to the built-in action-name heuristic.
        self.effects = effects
        # The shared identifier the two principals are contending over (the account's
        # email). Used by the JUSTIFICATION guard to decide whether an attacker proof
        # was over *this* resource. Falls back to the victim's resolved identity.
        self.resource = resource
        # Number of ADDITIONAL confirming passes at assess time. 0 => a single pass
        # (identical to the pre-confirmation oracle). >0 => re-probe and require a strict
        # majority before a non-SAFE verdict fires — de-risks a flaky/rate-limited target.
        self.confirm = max(0, int(confirm))
        # Attempt the destructive cross-principal WRITE probe. Off by default: it mutates
        # another principal's private resource, which many rules of engagement forbid.
        self.mutate = bool(mutate)
        self._canary = secrets.token_hex(16)   # 128-bit ground-truth secret
        # A distinct value for the write probe: never re-use the canary as the thing we
        # write, so the ground-truth secret is never planted anywhere we did not plant it.
        self._stamp = "tpihunter-write-probe-" + secrets.token_hex(16)
        # The diagnosis control: an account that takes no part in the probe. If it can
        # reach the victim's resource too, the access is not provenance-specific.
        self.bystander = bystander
        self._bystander_ready = False
        self._victim_id: Optional[str] = None
        self._victim_ref: Optional[str] = None
        self._planted = False
        self._attacker_acted_before_arm = False
        self.baseline: list[Evidence] = []
        self.controls: dict = {}

    # -- phase 1 --------------------------------------------------------------
    def arm(self, trace: Optional[Trace] = None) -> "AtoOracle":
        """Call after the victim has authenticated, before planting the canary.

        `trace` (when the runner supplies it) records whether the attacker had already
        acted by this point. That is what makes the baseline a *control*: a confluence
        observed before the attacker did anything cannot have been caused by the probe.
        """
        self._victim_id = self.a.whoami(self.victim).identity
        if trace is not None:
            self._attacker_acted_before_arm = any(
                s.obs is not None and s.obs.ok for s in trace.by_principal(self.attacker))
        else:
            # No trace supplied: assume the attacker may already have acted, so the
            # baseline is not treated as a pre-attack control (fail toward reporting).
            self._attacker_acted_before_arm = True
        self._enrol_bystander()
        self.baseline = self._probe_attacker()
        return self

    def _enrol_bystander(self) -> None:
        """Stand up the uninvolved third account, and verify it really is uninvolved.

        A 'bystander' that resolves to the victim's identity is not a control, it is a
        second victim context; using it would turn every probe into a broad-authorization
        finding. When the adapter cannot provide one the oracle still works — it just
        cannot separate laundering from a plain authorization bug, and `controls` says so.
        """
        if self.bystander is None:
            self.controls["bystander"] = "disabled"
            return
        enrol = getattr(self.a, "enrol_bystander", None)
        if not callable(enrol):
            self.controls["bystander"] = "unavailable (adapter has no enrol_bystander)"
            return
        obs = enrol(self.bystander)
        if not getattr(obs, "ok", False):
            self.controls["bystander"] = "enrolment failed"
            return
        who = self.a.whoami(self.bystander)
        if not who.identity or who.identity == self._victim_id:
            self.controls["bystander"] = "not independent of the victim — not used"
            return
        self._bystander_ready = True
        self.controls["bystander"] = "enrolled and independent"

    # -- phase 2 --------------------------------------------------------------
    def plant(self) -> "AtoOracle":
        """Write the canary as the victim, then POSITIVE-control it by reading it back.

        If the read-back does not return the canary the canary is not there, every later
        comparison against it is vacuous, and a SAFE verdict would be a false negative.
        """
        m = self.a.plant_marker(self.victim, self._canary)
        self._victim_ref = m.extracted.get("ref")
        back = self.a.read_marker(self.victim, ref=self._victim_ref)
        self._planted = back.extracted.get("value") == self._canary
        self.controls["canary_planted"] = self._planted
        return self

    # -- phase 3 --------------------------------------------------------------
    def assess(self, trace: Trace) -> Verdict:
        trials = [self._gather() for _ in range(1 + self.confirm)]
        severity, confidence, ev = self._reconcile(trials)
        severity, confidence, withheld = self._gate(severity, confidence, trace)

        bystander = next((e for t in trials for e in t if e.kind == "bystander_read"), None)
        if bystander is not None:
            # The DIAGNOSIS control fired. An account that did nothing can read the
            # victim's canary, so whatever the attacker achieved was not provenance-
            # specific: this is an object-level authorization failure, and citing a
            # laundering clause here would ship the wrong remediation. A single
            # successful bystander read is enough — flakiness can drop a read, never
            # invent one — so no majority is required.
            if not any(e.kind == "bystander_read" for e in ev):
                ev = ev + [bystander]
            severity, confidence, withheld = Severity.TAKEOVER, 0.99, None
            clause_id, mode, laundered = BROAD_AUTHORIZATION.id, "authorization", None
        else:
            clause_id = mode = laundered = None
            if severity is Severity.TAKEOVER or severity is Severity.SUSPECT:
                clause_id, mode, laundered = self._diagnose(trace)
        return Verdict(severity, confidence, ev, clause_id, mode, laundered,
                       self._narrate(severity, ev, clause_id, laundered, withheld),
                       withheld=withheld, controls=dict(self.controls))

    # -- attribution guards ---------------------------------------------------
    def _gate(self, severity: Severity, confidence: float,
              trace: Trace) -> tuple[Severity, float, Optional[str]]:
        """Decide whether evidence of access may be reported as a finding.

        Returns the (possibly downgraded) severity and the reason code, if any. A guard
        that fires never fabricates a clean bill of health it cannot support: only the
        JUSTIFICATION guard yields SAFE (the access is affirmatively accounted for); the
        others yield INCONCLUSIVE, which says "this probe measured nothing", not "secure".
        """
        if not self._planted:
            # The positive control failed: no canary existed, so a SAFE reading is
            # meaningless too. Report it as such rather than as a secure result.
            return Severity.INCONCLUSIVE, 0.0, Withheld.CANARY_NOT_PLANTED.value
        if severity is Severity.SAFE:
            return severity, confidence, None

        if self._confluence_predates_the_attack():
            return Severity.INCONCLUSIVE, 0.0, Withheld.NOT_INDEPENDENT.value

        justification = self._attacker_proof_of_control(trace)
        if justification is not None:
            self.controls["attacker_justification"] = justification
            return Severity.SAFE, 0.9, Withheld.ATTACKER_PROVED_CONTROL.value

        if not any(s.obs is not None and s.obs.ok for s in trace.by_principal(self.attacker)):
            return Severity.INCONCLUSIVE, 0.0, Withheld.NO_ATTACKER_ACTION.value

        return severity, confidence, None

    def _confluence_predates_the_attack(self) -> bool:
        """True if the contexts were already one identity before the attacker acted —
        a legitimately shared account, or two principals wired to the same context."""
        return (not self._attacker_acted_before_arm
                and any(e.kind == "identity_confluence" for e in self.baseline))

    def _attacker_proof_of_control(self, trace: Trace) -> Optional[str]:
        """The attacker's own justification, if it has one: a *successful* action that
        demonstrated control of the contended identifier over a possession channel.

        `obs.ok` matters — an adapter may build a ProofEvent for an action that was then
        refused, and a refused action proves nothing."""
        target = self.resource or self._victim_id
        if target is None:
            return None
        for s in trace.by_principal(self.attacker):
            obs = s.obs
            if obs is None or not obs.ok or obs.proof is None:
                continue
            p = obs.proof
            if p.channel in CONTROL_CHANNELS and getattr(p.resource, "value", None) == target:
                return (f"attacker demonstrated control of {untrusted(str(p.resource))} over "
                        f"{p.channel.value} via '{untrusted(s.action, 64)}'")
        return None

    # -- internals ------------------------------------------------------------
    def _gather(self) -> list[Evidence]:
        """One re-runnable evidence-gathering pass: probe the attacker, and — only when
        `mutate` is enabled and a read/confluence already indicates access — attempt a
        mutation, then restore the canary so the victim's state is never left corrupted."""
        ev = self._probe_attacker()
        detail = self._probe_bystander()
        if detail is not None:
            ev.append(Evidence("bystander_read", detail, 3))
        if self.mutate and any(e.strength >= 2 for e in ev):
            ev.extend(self._write_probe())
        return ev

    def _probe_bystander(self) -> Optional[str]:
        """DIAGNOSIS control: can an account that took no part in the probe reach the
        victim's canary? If it can, the attacker's access was never the interesting part."""
        if not (self._bystander_ready and self._planted):
            return None
        if self._victim_ref is not None:
            r = self.a.read_marker(self.bystander, ref=self._victim_ref)
            if r.extracted.get("value") == self._canary:
                return (f"an uninvolved account read the victim's private resource "
                        f"{untrusted(self._victim_ref)} — the resource is not scoped to "
                        f"its owner, so this access is not provenance-specific")
        r = self.a.read_marker(self.bystander)
        if r.extracted.get("value") == self._canary:
            return ("an uninvolved account's own-account read returns the victim's canary "
                    "— the resource is shared across accounts")
        return None

    def _write_probe(self) -> list[Evidence]:
        """The destructive half, run only on request. Writes a value that is NOT the
        canary, confirms the round-trip as the victim, then restores — and verifies the
        restore, recording a failure instead of leaving the target quietly corrupted."""
        ev: list[Evidence] = []
        w = self.a.write_marker(self.attacker, self._stamp, ref=self._victim_ref)
        back = self.a.read_marker(self.victim, ref=self._victim_ref)
        mutated = bool(w.ok) and back.extracted.get("value") == self._stamp
        if mutated:
            ev.append(Evidence("canary_write",
                               "attacker mutated the victim's private resource (round-trip confirmed)", 3))
        if mutated or back.extracted.get("value") != self._canary:
            self.a.write_marker(self.victim, self._canary, ref=self._victim_ref)
            restored = self.a.read_marker(self.victim, ref=self._victim_ref)
            ok = restored.extracted.get("value") == self._canary
            self.controls["write_probe_restored"] = ok
            if not ok:
                self.controls["restore_failure"] = (
                    f"could not restore the victim's resource {untrusted(self._victim_ref)} "
                    "after the write probe — the target is left holding a tpihunter value")
        return ev

    def _reconcile(self, trials: list[list[Evidence]]) -> tuple[Severity, float, list[Evidence]]:
        """Fold repeated evidence passes into one stable verdict. A non-SAFE severity is
        reported only if it holds a STRICT MAJORITY of the passes, so a transient blip in a
        single pass (a dropped read, a spurious hit) cannot flip the verdict. With no
        majority the honest answer is SUSPECT — we neither fire a takeover we cannot
        reproduce (the load-bearing invariant) nor claim SAFE over access we did see.
        Confidence is the winning grade's confidence scaled by the agreement fraction. With
        `confirm=0` there is exactly one pass and this reduces to `_grade`."""
        grades = [self._grade(ev) for ev in trials]
        sevs = [s for s, _ in grades]
        n = len(sevs)
        counts = Counter(sevs)
        for sev in (Severity.TAKEOVER, Severity.SUSPECT, Severity.SAFE):
            if counts[sev] * 2 > n:                       # strict majority
                agree = counts[sev] / n
                base = max(c for s, c in grades if s is sev)
                rep = max((ev for ev, (s, _) in zip(trials, grades) if s is sev),
                          key=lambda ev: max((e.strength for e in ev), default=0))
                return sev, round(base * agree, 3), rep
        rep = max(trials, key=lambda ev: max((e.strength for e in ev), default=0))
        return Severity.SUSPECT, 0.5, rep

    def _ref_reads_are_scoped(self) -> bool:
        """NEGATIVE control: a reference that names nothing must be refused. If the target
        answers it with a value, by-reference reads carry no information and must not be
        counted as evidence."""
        if "ref_reads_scoped" not in self.controls:
            probe = self.a.read_marker(self.attacker, ref=NEVER_VALID_REF)
            self.controls["ref_reads_scoped"] = probe.extracted.get("value") is None
        return self.controls["ref_reads_scoped"]

    def _probe_attacker(self) -> list[Evidence]:
        ev: list[Evidence] = []
        who = self.a.whoami(self.attacker)
        if who.identity and who.identity == self._victim_id:
            # the identity is the target's own string; neutralise it before it is
            # interpolated into evidence a model will read (see redact.untrusted)
            ev.append(Evidence("identity_confluence",
                               f"attacker session resolves to victim identity "
                               f"'{untrusted(who.identity)}'", 3))
        if self._planted:
            r = self.a.read_marker(self.attacker)              # confluence read (my-account)
            if r.extracted.get("value") == self._canary:
                ev.append(Evidence("canary_read",
                                   "attacker's own session returns the victim's planted canary", 3))
            if self._victim_ref is not None and self._ref_reads_are_scoped():
                r2 = self.a.read_marker(self.attacker, ref=self._victim_ref)   # direct-object read
                if r2.extracted.get("value") == self._canary:
                    ev.append(Evidence("canary_read",
                                       f"attacker read the victim's private resource "
                                       f"{untrusted(self._victim_ref)}", 2))
        return ev

    @staticmethod
    def _grade(ev: list[Evidence]) -> tuple[Severity, float]:
        # bystander evidence says who ELSE can do it; it classifies a finding rather than
        # establishing that the attacker gained access, so it is excluded from the grade.
        ev = [e for e in ev if e.kind != "bystander_read"]
        if any(e.kind in ("canary_read", "canary_write") for e in ev):
            return Severity.TAKEOVER, 0.99
        if any(e.kind == "identity_confluence" for e in ev):
            return Severity.TAKEOVER, 0.90
        if ev:
            return Severity.SUSPECT, 0.50
        return Severity.SAFE, 0.95

    def _diagnose(self, trace: Trace) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """Infer the violated clause from the black-box trace shape. This is what a
        real hunter has (no store visibility); a white-box hook can corroborate."""
        a_steps = trace.by_principal(self.attacker)
        a_actions = [s.action for s in a_steps]
        v_steps = trace.by_principal(self.victim)
        v_actions = [s.action for s in v_steps]

        if self.effects is not None:
            # effect-based: generalizes to any action, including synthesized ones
            def has(actions, eff):
                return any(self.effects.get(a) == eff for a in actions)
            seeded = has(a_actions, "seed")
            victim_raise = has(v_actions, "raise")
            victim_cred = has(v_actions, "cred")
            attacker_cred = has(a_actions, "cred")
        else:
            # fallback: the built-in alphabet by name
            seeded = any(x in a_actions for x in ("register", "login"))
            victim_raise = any(x in v_actions for x in ("sso_login", "email_change_confirm"))
            victim_cred = "reset_consume" in v_actions
            attacker_cred = "reset_consume" in a_actions

        def victim_proof() -> Optional[str]:
            return next((str(s.obs.proof) for s in v_steps if s.obs and s.obs.proof), None)

        # Attacker seeded a row; the victim later RAISED its trust -> the attacker's
        # binding should have been revoked on rebind.
        if seeded and victim_raise:
            return "TPI-1", FailureMode.LAUNDERING.value, victim_proof()

        # Attacker seeded a row; the victim CHANGED a credential (reset) but the
        # attacker's pre-existing session/credential survived it.
        if seeded and victim_cred:
            return "TPI-4", FailureMode.LAUNDERING.value, victim_proof()

        # Attacker consumed a proof pinned to a now-stale binding.
        if attacker_cred:
            return "TPI-2", FailureMode.FORGERY.value, None

        # Attacker reached access without ever emitting a proof -> gap.
        if not any(s.obs and s.obs.proof for s in a_steps):
            return "TPI-5", FailureMode.GAP.value, None

        return None, None, None

    _WITHHELD_NARRATIVE = {
        Withheld.NOT_INDEPENDENT.value:
            "Not a finding: the attacker context already resolved to the victim's identity "
            "before the attacker acted, so the two principals were never independent (a "
            "shared, tenant or family account, or a misconfigured harness). Nothing was "
            "taken over — re-run with two genuinely separate contexts.",
        Withheld.ATTACKER_PROVED_CONTROL.value:
            "Not a finding: the attacker itself demonstrated control of the contended "
            "identifier over a possession channel, so its access has justifying provenance "
            "— this is a co-owner of the account, not laundering.",
        Withheld.NO_ATTACKER_ACTION.value:
            "Inconclusive: access evidence was observed but the trace contains no successful "
            "attacker action, so nothing in this probe can be credited with causing it.",
        Withheld.CANARY_NOT_PLANTED.value:
            "Inconclusive: the victim could not read its own canary back, so no ground truth "
            "existed and every comparison in this probe was vacuous. This is NOT a secure "
            "result — the probe did not run.",
    }

    def _narrate(self, sev, ev, clause_id, laundered, withheld=None) -> str:
        if withheld:
            body = self._WITHHELD_NARRATIVE.get(withheld, f"Finding withheld: {withheld}.")
            extra = self.controls.get("attacker_justification")
            return f"{body} ({extra})" if extra else body
        if sev is Severity.SAFE:
            return ("No cross-principal access: the attacker context cannot resolve to, "
                    "read, or mutate the victim's account.")
        if clause_id == BROAD_AUTHORIZATION.id:
            return ("CROSS-ACCOUNT ACCESS confirmed, but it is NOT a provenance failure. "
                    "The bystander control fired: an account that took no part in this probe "
                    "reads the victim's private resource just as well as the attacker does. "
                    f"Diagnosis: {BROAD_AUTHORIZATION.id} ({BROAD_AUTHORIZATION.title}) — "
                    "fix the resource's ownership check, not the identity lifecycle. No TPI "
                    "clause is cited: this bug is reachable with a single principal and a "
                    "reachability model already finds it.")
        lead = "ACCOUNT TAKEOVER confirmed." if sev is Severity.TAKEOVER else "Suspected cross-principal access."
        clause = CATALOG.get(clause_id) if clause_id else None
        mode = f" — {clause.mode.value}" if clause and clause.mode else ""
        body = f" Diagnosis: {clause.id} ({clause.title}){mode}." if clause else ""
        prov = f" Laundered proof: {laundered}." if laundered else ""
        return lead + body + prov
