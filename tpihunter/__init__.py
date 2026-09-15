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
  demo         end-to-end self-test
"""
from .adapter import ALPHABET, TargetAdapter, Trace
from .agent import (AgentHunter, EnumeratorStrategist, HuntResult, HuntState,
                    LLMStrategist, Strategist)
from .clauses import CLAUSES, FailureMode
from .dedup import Cluster, deduplicate
from .harness import Plan, Step, run_plan
from .mcp_tools import HuntSession
from .oracle import AtoOracle, Evidence, Severity, Verdict
from .types import Channel, Identifier, Observation, Principal, ProofEvent, TrustLevel

# Note: `tpihunter.llm.make_complete_fn` (the real-model backend) is intentionally NOT
# imported here — it lazy-imports `anthropic` only when called, so the core stays
# stdlib-only. Import it directly: `from tpihunter.llm import make_complete_fn`.

__all__ = [
    "ALPHABET", "TargetAdapter", "Trace",
    "AgentHunter", "Strategist", "EnumeratorStrategist", "LLMStrategist",
    "HuntState", "HuntResult",
    "Cluster", "deduplicate",
    "HuntSession",
    "CLAUSES", "FailureMode",
    "Plan", "Step", "run_plan",
    "AtoOracle", "Evidence", "Severity", "Verdict",
    "Channel", "Identifier", "Observation", "Principal", "ProofEvent", "TrustLevel",
]
