"""TPI-Hunter — a black-box account-takeover hunting loop built on the
Trust-Provenance Integrity (TPI) theory (see the working paper
*Provenance, Not Reachability*).

The pieces:
  types        core domain (principals, channels, proof events, observations)
  clauses      the TPI invariant clauses a verdict can cite
  channels     out-of-band providers (email inbox, TOTP, ...) behind interfaces
  adapter      TargetAdapter: the two-principal surface + the Trace it records
  oracle       AtoOracle: canary-based, differential, provenance-labeling verdict
  harness      Plan/Step + run_plan: probes as data, executed with oracle checkpoints
  mock_target  a deliberately vulnerable in-memory target + its adapter
  probes       hand-written TPI probe plans
  profile      TargetProfile: a real target described as data, not code
  live         LiveAdapter: drives that profile over HTTP, scope enforced per request
  validate     validate_target(): prove the profile works before trusting a verdict
  http_mock    the vulnerable mock behind a real socket, plus a worked example profile
  h1_scope     build an engagement file from a HackerOne scope export
  policy       EngagementPolicy + guard(): rules of engagement enforced per action
  redact       secret scrubbing for anything the tool emits
  creds        per-run credentials and identifiers (never literals in source)
  demo         end-to-end self-test
"""
from .adapter import ALPHABET, TargetAdapter, Trace
from .agent import (AgentHunter, Attempt, Coverage, EnumeratorStrategist, HuntResult,
                    HuntState, LLMStrategist, Strategist)
from .clauses import BROAD_AUTHORIZATION, CATALOG, CLAUSES, FailureMode
from .dedup import Cluster, deduplicate
from .flaky import FlakyAdapter
from .harness import Plan, Step, execute_action, run_plan
from .matrix import (CellVerdict, MintSpec, MutationSpec, RevocationMatrix, Survival,
                     default_mints, default_mutations, run_cell)
from .h1_scope import from_hackerone_csv, parse_instruction
from .live import LiveAdapter, ScopedTransport, live_adapter
from .policy import (AuditLog, BudgetExhausted, EngagementPolicy, GuardedAdapter,
                     PolicyViolation, ScopeViolation, for_mock, guard, policy_report)
from .profile import ProfileError, TargetProfile
from .validate import Check, Validation, validate_target
from .redact import redact
from .mcp_tools import HuntSession
from .report import Report, build_bundle, build_report, bundle_to_json, bundle_to_markdown, make_run_fn, revocation_report
from .oracle import AtoOracle, Evidence, Severity, Verdict, Withheld
from .types import Channel, Identifier, Observation, Principal, ProofEvent, TrustLevel

# Note: `tpihunter.llm.make_complete_fn` (the real-model backend) is intentionally NOT
# imported here — it lazy-imports `anthropic` only when called, so the core stays
# stdlib-only. Import it directly: `from tpihunter.llm import make_complete_fn`.

__all__ = [
    "ALPHABET", "TargetAdapter", "Trace",
    "AgentHunter", "Strategist", "EnumeratorStrategist", "LLMStrategist",
    "HuntState", "HuntResult", "Attempt", "Coverage",
    "Cluster", "deduplicate",
    "FlakyAdapter",
    "HuntSession",
    "RevocationMatrix", "MintSpec", "MutationSpec", "CellVerdict", "Survival",
    "default_mints", "default_mutations", "run_cell", "execute_action",
    "Report", "build_report", "build_bundle", "bundle_to_markdown", "bundle_to_json",
    "make_run_fn", "revocation_report",
    "EngagementPolicy", "GuardedAdapter", "AuditLog", "guard", "for_mock", "policy_report",
    "PolicyViolation", "ScopeViolation", "BudgetExhausted", "redact",
    "TargetProfile", "ProfileError", "LiveAdapter", "ScopedTransport", "live_adapter",
    "from_hackerone_csv", "parse_instruction",
    "validate_target", "Validation", "Check",
    "CLAUSES", "CATALOG", "BROAD_AUTHORIZATION", "FailureMode",
    "Plan", "Step", "run_plan",
    "AtoOracle", "Evidence", "Severity", "Verdict", "Withheld",
    "Channel", "Identifier", "Observation", "Principal", "ProofEvent", "TrustLevel",
]
