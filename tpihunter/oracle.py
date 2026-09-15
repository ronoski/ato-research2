"""The success oracle: does principal A hold access that only principal V should?

This is the piece that makes autonomy possible — the agent's *verdict*. Without
it you generate candidate attacks and never learn which one landed.

Design: canary-based, differential, provenance-labeling.

  1. arm()   -- capture the victim's identity and record what the attacker can
                already see about the victim *before* a canary exists (baseline).
  2. plant() -- as the victim, write a unique 128-bit secret into a private
                resource. This is the ground truth of "V's private state".
  3. assess()-- re-probe as the attacker. Report TAKEOVER only on hard evidence:
                an exact canary match, an identity confluence, or a confirmed
                cross-principal write. Then diagnose *which* TPI clause the trace
                shows was violated, so the result is a diagnosis, not just a hit.

False-positive discipline: the canary is a random secret compared by exact match,
so reflected input or public fields cannot fake a read; identity confluence
compares the resolved account identity, which a correctly-scoped app never shares
between two principals.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .adapter import Trace
from .clauses import CLAUSES, FailureMode
from .types import Principal


class Severity(str, Enum):
    SAFE = "safe"
    SUSPECT = "suspect"
    TAKEOVER = "takeover"


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


class AtoOracle:
    def __init__(self, adapter, attacker: Principal, victim: Principal) -> None:
        self.a = adapter
        self.attacker = attacker
        self.victim = victim
        self._canary = secrets.token_hex(16)   # 128-bit ground-truth secret
        self._victim_id: Optional[str] = None
        self._victim_ref: Optional[str] = None
        self._planted = False
        self.baseline: list[Evidence] = []

    # -- phase 1 --------------------------------------------------------------
    def arm(self) -> "AtoOracle":
        """Call after the victim has authenticated, before planting the canary."""
        self._victim_id = self.a.whoami(self.victim).identity
        self.baseline = self._probe_attacker()
        return self

    # -- phase 2 --------------------------------------------------------------
    def plant(self) -> "AtoOracle":
        m = self.a.plant_marker(self.victim, self._canary)
        self._victim_ref = m.extracted.get("ref")
        self._planted = True
        return self

    # -- phase 3 --------------------------------------------------------------
    def assess(self, trace: Trace) -> Verdict:
        ev = self._probe_attacker()
        # Only attempt a mutation once a read/confluence already indicates access,
        # then restore the canary so we don't leave the victim's state corrupted.
        if any(e.strength >= 2 for e in ev):
            stamp = self._canary + "::A"
            w = self.a.write_marker(self.attacker, stamp, ref=self._victim_ref)
            back = self.a.read_marker(self.victim, ref=self._victim_ref)
            if w.ok and back.extracted.get("value") == stamp:
                ev.append(Evidence("canary_write",
                                   "attacker mutated the victim's private resource (round-trip confirmed)", 3))
            self.a.write_marker(self.victim, self._canary, ref=self._victim_ref)  # restore

        severity, confidence = self._grade(ev)
        clause_id = mode = laundered = None
        if severity is not Severity.SAFE:
            clause_id, mode, laundered = self._diagnose(trace)
        return Verdict(severity, confidence, ev, clause_id, mode, laundered,
                       self._narrate(severity, ev, clause_id, laundered))

    # -- internals ------------------------------------------------------------
    def _probe_attacker(self) -> list[Evidence]:
        ev: list[Evidence] = []
        who = self.a.whoami(self.attacker)
        if who.identity and who.identity == self._victim_id:
            ev.append(Evidence("identity_confluence",
                               f"attacker session resolves to victim identity '{who.identity}'", 3))
        if self._planted:
            r = self.a.read_marker(self.attacker)              # confluence read (my-account)
            if r.extracted.get("value") == self._canary:
                ev.append(Evidence("canary_read",
                                   "attacker's own session returns the victim's planted canary", 3))
            if self._victim_ref is not None:                   # direct-object read
                r2 = self.a.read_marker(self.attacker, ref=self._victim_ref)
                if r2.extracted.get("value") == self._canary:
                    ev.append(Evidence("canary_read",
                                       f"attacker read the victim's private resource {self._victim_ref}", 2))
        return ev

    @staticmethod
    def _grade(ev: list[Evidence]) -> tuple[Severity, float]:
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

    def _narrate(self, sev, ev, clause_id, laundered) -> str:
        if sev is Severity.SAFE:
            return ("No cross-principal access: the attacker context cannot resolve to, "
                    "read, or mutate the victim's account.")
        lead = "ACCOUNT TAKEOVER confirmed." if sev is Severity.TAKEOVER else "Suspected cross-principal access."
        clause = CLAUSES.get(clause_id) if clause_id else None
        body = f" Diagnosis: {clause.id} ({clause.title}) — {clause.mode.value}." if clause else ""
        prov = f" Laundered proof: {laundered}." if laundered else ""
        pre = (" Identity confluence was present from the seeding step — a pre-hijacking signature."
               if any(e.kind == "identity_confluence" for e in self.baseline) else "")
        return lead + body + prov + pre
