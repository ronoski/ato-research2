"""Evidence bundles — turn a distinct bug into a shareable, submittable report.

This is the agent's *report* step. Dedup gives the distinct bugs (each a `Cluster`
with a minimal repro); this module re-runs that minimal repro to capture the full
execution `Trace` + `Verdict`, then assembles a report a human can read and submit:
what the bug is, exact steps to reproduce over two principals, the canary evidence
that *proves* it is a real takeover, the laundered proof (root cause), and the
remediation derived from the violated TPI clause.

Target-agnostic by the same pattern as the rest of the package: execution is
injected as `run_fn(plan) -> (Verdict, Trace)`. `make_run_fn(...)` builds one from
an adapter factory; a real target reuses it unchanged.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Optional

from .clauses import CLAUSES
from .enumerator import ACTIONS, ActionSpec, build_plan
from .harness import run_plan
from .oracle import AtoOracle
from .types import Principal

RunFn = Callable[[object], tuple]   # plan -> (Verdict, Trace)

_SEVERITY_LABEL = {"takeover": "Critical — account takeover",
                   "suspect": "Suspected cross-principal access",
                   "safe": "No cross-principal access"}


@dataclass
class ReproStep:
    n: int
    principal: str
    action: str
    ok: bool
    note: str
    proof: Optional[str]
    identity: Optional[str]


@dataclass
class Report:
    clause_id: Optional[str]
    clause_title: Optional[str]
    failure_mode: Optional[str]
    severity: str
    confidence: float
    email: str
    minimal_repro: list          # [(role, action), ...]
    steps: list                  # [ReproStep, ...]
    evidence: list               # [{kind, detail, strength}, ...]
    laundered_proof: Optional[str]
    narrative: str
    clause_statement: Optional[str]
    variants_collapsed: int

    # -- rendering ------------------------------------------------------------
    def title(self) -> str:
        what = self.clause_title or "provenance violation"
        cid = f" ({self.clause_id})" if self.clause_id else ""
        return f"Account takeover via {what}{cid}"

    def to_dict(self) -> dict:
        return {
            "title": self.title(),
            "severity": self.severity,
            "severity_label": _SEVERITY_LABEL.get(self.severity, self.severity),
            "confidence": self.confidence,
            "tpi_clause": self.clause_id,
            "clause_title": self.clause_title,
            "failure_mode": self.failure_mode,
            "shared_account": self.email,
            "minimal_repro": [f"{r}:{a}" for r, a in self.minimal_repro],
            "steps_to_reproduce": [
                {"n": s.n, "principal": s.principal, "action": s.action,
                 "ok": s.ok, "note": s.note, "proof": s.proof, "resolved_identity": s.identity}
                for s in self.steps],
            "evidence": self.evidence,
            "root_cause": {"laundered_proof": self.laundered_proof,
                           "violated_clause": self.clause_id,
                           "clause_statement": self.clause_statement},
            "remediation": self._remediation(),
            "impact": self.narrative,
            "variants_collapsed": self.variants_collapsed,
        }

    def _remediation(self) -> Optional[str]:
        if not (self.clause_title and self.clause_statement):
            return None
        return f"Enforce {self.clause_title}: {self.clause_statement}"

    def to_markdown(self) -> str:
        L: list[str] = []
        L.append(f"# {self.title()}")
        L.append("")
        L.append(f"**Severity:** {_SEVERITY_LABEL.get(self.severity, self.severity)}  ")
        if self.clause_id:
            L.append(f"**Class:** Trust-Provenance Integrity — {self.failure_mode} "
                     f"({self.clause_id} {self.clause_title})  ")
        L.append(f"**Confidence:** {self.confidence:.2f}  ")
        L.append(f"**Shared account:** `{self.email}`")
        L.append("")
        L.append("## Summary")
        L.append(self.narrative)
        L.append("")
        L.append("## Steps to reproduce")
        L.append("Two principals — **attacker** (does not control the account's "
                 "inbox/IdP) and **victim** (does) — acting over the one shared account:")
        L.append("")
        for s in self.steps:
            proof = f" _(proof: {s.proof})_" if s.proof else ""
            fail = "" if s.ok else " ❌ (denied)"
            desc = s.note or (f"resolves to `{s.identity}`" if s.identity else "")
            tail = f" — {desc}" if desc else ""
            L.append(f"{s.n}. **{s.principal}** — `{s.action}`{fail}{tail}{proof}")
        L.append("")
        L.append("## Evidence — why this is a confirmed takeover")
        if self.evidence:
            L.append("A unique canary secret was planted in the victim's private "
                     "resource; the attacker context then:")
            for e in self.evidence:
                L.append(f"- **[{e['strength']}] {e['kind']}** — {e['detail']}")
        else:
            L.append("_No hard evidence captured._")
        L.append("")
        L.append("## Root cause")
        if self.laundered_proof:
            L.append(f"The system laundered a legitimate proof — `{self.laundered_proof}` "
                     "— into access for a binding it no longer justifies.")
        if self.clause_id and self.clause_statement:
            L.append("")
            L.append(f"This violates **{self.clause_id} ({self.clause_title})**: "
                     f"{self.clause_statement}")
        L.append("")
        L.append("## Remediation")
        L.append(self._remediation() or "_See the violated clause above._")
        L.append("")
        L.append("---")
        collapsed = (f"{self.variants_collapsed} equivalent interleavings collapse to "
                     "this minimal repro. " if self.variants_collapsed > 1 else "")
        L.append(f"_{collapsed}Generated by TPI-Hunter._")
        return "\n".join(L)


# --------------------------------------------------------------------------- #
def make_run_fn(adapter_factory, attacker: Principal, victim: Principal,
                effects: Optional[dict] = None) -> RunFn:
    """Build a `run_fn(plan) -> (Verdict, Trace)` from an adapter factory."""
    def run_fn(plan):
        a = adapter_factory()
        return run_plan(a, plan, AtoOracle(a, attacker, victim, effects=effects))
    return run_fn


def build_report(cluster, *, attacker: Principal, victim: Principal, email: str,
                 run_fn: RunFn, specs: Optional[dict[str, ActionSpec]] = None) -> Report:
    """Re-run a cluster's minimal repro and assemble a Report from the trace+verdict."""
    specs = specs if specs is not None else ACTIONS
    merged = tuple(tuple(x) for x in cluster.representative)
    plan = build_plan(merged, attacker, victim, email, specs)
    verdict, trace = run_fn(plan)

    steps = []
    for i, ts in enumerate(trace.steps, 1):
        obs = ts.obs
        steps.append(ReproStep(
            n=i, principal=(ts.principal.name if ts.principal else "-"),
            action=ts.action, ok=bool(obs and obs.ok),
            note=(obs.note if obs and obs.note else ""),
            proof=(str(obs.proof) if obs and obs.proof else None),
            identity=(obs.identity if obs else None)))

    clause = CLAUSES.get(cluster.clause_id) if cluster.clause_id else None
    return Report(
        clause_id=cluster.clause_id,
        clause_title=(clause.title if clause else None),
        failure_mode=verdict.failure_mode,
        severity=verdict.severity.value,
        confidence=verdict.confidence,
        email=email,
        minimal_repro=list(merged),
        steps=steps,
        evidence=[{"kind": e.kind, "detail": e.detail, "strength": e.strength}
                  for e in verdict.evidence],
        laundered_proof=verdict.laundered_proof or cluster.laundered_proof,
        narrative=verdict.narrative,
        clause_statement=(clause.statement if clause else None),
        variants_collapsed=cluster.size,
    )


def build_bundle(clusters, *, attacker: Principal, victim: Principal, email: str,
                 run_fn: RunFn, specs: Optional[dict[str, ActionSpec]] = None) -> list:
    """A Report per distinct bug."""
    return [build_report(c, attacker=attacker, victim=victim, email=email,
                         run_fn=run_fn, specs=specs) for c in clusters]


def bundle_to_markdown(reports: list) -> str:
    """A single markdown document for a whole bundle."""
    if not reports:
        return "# TPI-Hunter findings\n\nNo distinct bugs found."
    head = [f"# TPI-Hunter findings — {len(reports)} distinct bug(s)", ""]
    head.append("| # | Severity | TPI clause | Minimal repro |")
    head.append("|---|---|---|---|")
    for i, r in enumerate(reports, 1):
        repro = " → ".join(f"{p}:{a}" for p, a in r.minimal_repro)
        head.append(f"| {i} | {r.severity} | {r.clause_id or '—'} | `{repro}` |")
    head.append("")
    body = ("\n\n" + "\n\n---\n\n").join(r.to_markdown() for r in reports)
    return "\n".join(head) + "\n" + body


def bundle_to_json(reports: list) -> str:
    return json.dumps({"distinct_bugs": len(reports),
                       "bugs": [r.to_dict() for r in reports]}, indent=2)
