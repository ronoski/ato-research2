# HANDOFF — start here

You are the next session taking over this project — the **third contributor** (the relay
so far: person 1 built the theory + core oracle/adapter/learner; person 2 built dedup, the
agent control loop, both live strategists, and new-action synthesis; you are person 3).
The previous session has paused. **We work as a relay: one session at a time, never
concurrently.** Your shift, in order: (1) get oriented, (2) review the existing work with a
critical eye, (3) improve what needs it and continue the roadmap, (4) leave the tree green
and hand back cleanly. You have a real mandate to **review and refactor**, not just append
— but read the *Decisions log* in `STATUS.md` before reopening a settled trade-off.

---

## 1. The goal (north star)

Build an **autonomous AI agent that hunts account-takeover bugs** — grounded in one
theory: **Trust-Provenance Integrity (TPI)**. The thesis: the worst ATO / auth-bypass
bugs are not reachability faults in a login flow, they are **provenance failures** that
only appear when two principals interleave over a shared identity store.

> Trust levels compose; provenance does not.

**★ The goal is AGENT AS HUNTER (owner-confirmed).** The deterministic pieces (adapter,
oracle, harness, dedup) are the agent's **tools + ground truth**; probe generation is a
**strategy**. The mechanical enumerator is only the baseline strategist — the real
target is an **LLM strategist** that adapts. Weigh every task by whether it moves us
toward a live agent driving the loop.

**Success looks like:** an agent, pointed at an *authorized* target, (1) drives two
principals (attacker + victim) through the auth flows, (2) detects when the attacker
gains access only the victim should have, and (3) reports each finding with a verdict,
a minimal repro, and the exact TPI clause violated.

Today the full loop is built and **self-validating against a mock**: oracle, dedup, the
agent control seam, a live strategist both via the API (M9) and via the Claude Code agent
on the owner's Max subscription (M10, the MCP server), the agent extending its own alphabet
(M11), and submittable evidence reports (M7). The remaining frontier is **real targets**
(M4) and the robustness that de-risks them.

**Read the theory first:** open `paper/provenance.html` in a browser. It defines the
invariant, the three failure modes (gap / forgery / laundering), the
Composition-Blindness argument that justifies the whole black-box approach, and the
taxonomy that maps real ATO classes onto the theory. Everything in the code traces
back to it. (Published copy: https://claude.ai/artifact/LxyHRRCnZB7NNQWP6SF1sC)

---

## 2. Get oriented in five minutes

Run the test suite and the seven self-tests — the fastest way to see what exists:

```bash
python3 -m unittest discover     # 31 tests: the invariants that must not regress
python3 -m tpihunter.demo         # the oracle: TAKEOVER on a vulnerable target, SAFE on the patched one
python3 -m tpihunter.enum_demo    # the enumerator: generates probes → dedups to 2 distinct bugs
python3 -m tpihunter.learn_demo   # automata learning: L* recovers the mock's auth state machine
python3 -m tpihunter.synth_demo   # the closed loop: learn → synthesize action model → enumerate
python3 -m tpihunter.agent_demo   # agent as hunter: a strategist drives the loop (enumerator vs LLM seam)
python3 -m tpihunter.live_agent_demo  # the real LLM strategist (gated by TPIHUNTER_LIVE=1; else prints setup)
python3 -m tpihunter.newaction_demo   # the agent registers a new action to find a bug beyond the alphabet
python3 -m tpihunter.report_demo      # hunt the mock, then print the submittable evidence bundle
```

Then read, in this order:
1. **this file**
2. **`STATUS.md`** — the task board + changelog. *The top changelog entry is where the
   last shift ended.*
3. **`tpihunter/README.md`** — the tool in depth
4. **the code**, in dependency order:
   `types.py` → `clauses.py` → `channels.py` → `adapter.py` → `oracle.py` →
   `mock_target.py` → `harness.py` → `probes.py` → `enumerator.py` →
   `dedup.py` → `sul.py` → `learner.py` → `synthesis.py` → `agent.py` →
   `mcp_tools.py` → `mcp_server.py` → `llm.py` → `report.py`

   `agent.py` (and `mcp_tools.py`, its MCP twin) is where it all comes together for the
   goal — read them last but treat them as the top of the design: everything else is a
   tool the agent (strategist) drives.

---

## 3. Architecture (what does what)

The loop the project implements:

```
   map ──► abstract ──► generate ──► EXECUTE ──► JUDGE ──► refine
 (recon)  (TPI terms)  (probes)     (adapter)   (oracle)
```

| file | role |
|------|------|
| `types.py` | domain: principals, identifiers, channels, proof events, observations |
| `clauses.py` | the TPI invariant clauses a verdict can cite (TPI-1…TPI-5) |
| `channels.py` | out-of-band providers (email inbox, TOTP) behind interfaces |
| `adapter.py` | `TargetAdapter` — the **two-principal** surface (alphabet Σ) + the `Trace` it records |
| `oracle.py` | `AtoOracle` — the **verdict engine** (the star) |
| `mock_target.py` | a deliberately vulnerable in-memory target + adapter, with a `patched` toggle |
| `harness.py` | `Plan`/`Step` + `run_plan`: probes as data, run with oracle checkpoints |
| `probes.py` | hand-written TPI probe plans |
| `enumerator.py` | **generates** probes — composition-relevant interleavings; takes a `specs` model |
| `dedup.py` | collapses fired findings to distinct bugs (causal minimization + signature) |
| `agent.py` | **the goal**: `AgentHunter` loop + `Strategist` seam (enumerator baseline, LLM seam) |
| `llm.py` | real-model backend for `LLMStrategist` (isolates `anthropic`; API/pay-per-token path) |
| `mcp_tools.py` | `HuntSession` — the hunt loop as agent-drivable tools (stdlib, tested) |
| `mcp_server.py` | MCP server so the Claude Code agent hunts on a Max plan (isolates `mcp`) |
| `report.py` | evidence bundles — each distinct bug → submittable markdown/JSON report |
| `sul.py` | System-Under-Learning interface + single-account view of the mock |
| `learner.py` | Angluin's L* Mealy learner (black-box automata learning) |
| `synthesis.py` | learned machine → the enumerator's `ActionSpec` model (closes the loop) |

**Key design decisions (don't undo without cause — rationale in `STATUS.md`):**
- **Black-box loop, not Alloy, for hunting.** A hunter's scarce resource is a
  *verdict*; the loop touches the target and has an oracle, Alloy only enumerates
  hypotheses over an abstraction it can't validate.
- **Two independent principal contexts.** Laundering is invisible single-session.
- **Canary-based differential oracle.** Ground truth = a random secret the victim
  plants; a takeover is the attacker reading/writing it, or resolving to the victim's
  identity. Exact-match keeps false positives out.
- **Composition-relevance prune in the enumerator.** Keep only interleavings where
  two principals contend over one shared resource with a trust-raise or
  credential-change — the Composition-Blindness theorem used as a search filter.
- **Channel-control model in the mock.** You can only SSO / consume-reset an
  identifier you actually control, so enumerated findings are genuine.

---

## 4. Review this critically — where I'd look first

The previous contributors flag the spots most worth your scrutiny. Treat these as
invitations to improve:

- **Everything is validated only against the mock.** The single biggest risk: the mock's
  vocabulary and behaviour are simple and clean; a real target (M4) is noisy, has a larger
  output alphabet, and rate-limits. Most items below are really "this is tuned to the mock;
  re-check it on a real target."
- **The oracle is the load-bearing component — audit it first.** `_diagnose` is now
  effect-based (`AtoOracle(effects=…)`, so new verbs classify), with the old name heuristic
  as a fallback; the *grading* (`_grade`) treats an identity-confluence as a decisive
  takeover. Convince yourself confluence can't false-positive on a legitimately shared /
  tenant / SSO-org account on a real target. The oracle has **no retry** — a flaky real
  target could flip a verdict; a suspect→retry loop is on the roadmap.
- **Dedup signature is `(clause, effect-set, trigger-verbs)`** (`dedup.py`). It merges
  padding/order variants but keeps different trigger endpoints (e.g. `sso_login` vs a
  synthesized `magic_link`) separate. Still coarse on role/count — if a real target shows a
  false merge, refine the signature; don't just raise the cluster count.
- **New-action synthesis has an email-only param model.** `register_action` /
  `LLMStrategist` new_actions let the agent add verbs, but `_to_plan` gives a new action
  only `{"email": …}` params. Actions needing other inputs (a code, a second identifier for
  aliasing) need a richer param model — real-target work will hit this.
- **`synthesis.py` effect classifier is signature-based** (`OK_VERIFIED`→RAISE,
  `SENT`→REQUEST, session-after-token→CRED). Matches the mock; a real target's outputs
  differ — adapt `SUCCESS_OUTPUTS` / `classify_effect`. `needs_control` is declared, not
  learned (single-account traces always control the identifier).
- **L\* uses a random-walk equivalence oracle** — fine for a black box, but the learned
  machine can be incomplete for larger alphabets. A W-method / Wp-method conformance oracle
  would make it sound within a bound. *(Still open.)*
- **Tests are the safety net — extend them with every change.** `tests/test_tpihunter.py`,
  stdlib `unittest`, **31 tests** covering the load-bearing invariant, the learn→synthesize
  pipeline, dedup, the agent loop + LLM wiring (fake client), the MCP `HuntSession`,
  new-action synthesis, and the report bundle. Add assertions for whatever you build.

---

## 5. Invariants to preserve

- **The load-bearing invariant:** a verdict must **never** fire on the patched
  target. `enum_demo` self-checks this and prints a `WARNING` if broken — treat that
  WARNING as a build failure.
- **Keep it runnable and self-validating.** Every capability ships with a demo that
  proves it on the mock, and a test that asserts it.
- **Core stays stdlib-only; isolate every optional dep.** Two exist so far — `anthropic`
  (in `llm.py`) and `mcp` (in `mcp_server.py`) — each lazy-imported so `import tpihunter`
  never needs it. A real HTTP adapter will add `httpx` the same way. Verify with:
  `python3 -c "import tpihunter, sys; assert 'anthropic' not in sys.modules and 'mcp' not in sys.modules"`.
- **`unittest discover` and all eight demos stay green.** Don't hand back on red.

---

## 6. Your next task

The mock loop is complete end-to-end: live via the API strategist (M9) and the Claude Code
agent on a Max subscription (M10, the owner's path), the agent extends its own alphabet
(M11), and findings render as submittable reports (M7). The frontier is **real targets**.
From `STATUS.md` → *Pick this up next*:

1. **M4 — real `TargetAdapter` (the big one).** Implement `TargetAdapter` (and a
   real-target `HuntSession`) against an authorized live app: one `httpx` client per
   principal, real register/login/sso/reset flows, a real mailbox channel
   (`channels.EmailChannel`), and the oracle surface (`whoami` + a private per-account
   resource for the canary). Then the whole stack — agent, new-action synthesis, dedup,
   report — runs against something real. **Blocked on an authorized target from the
   owner** — see Scope in `README.md`; do not point at anything without written
   authorization. *Ask the owner for a target before starting.*
2. **Robustness for real targets** (do-able now against the mock, de-risks M4): adapter
   rate-limit/backoff, oracle retry on a suspect verdict (real targets are noisy), and a
   richer param model for synthesized actions — currently `_to_plan` gives a new action
   only `{"email": …}`, so codes / invite tokens / second identifiers can't be passed yet.
3. **W-method conformance oracle** for the learner (soundness within a bound).

Start wherever you have the most conviction. Update `STATUS.md` to claim it (mark the
milestone `🚧 IN PROGRESS — <your handle>, <date>`).

---

## 7. Hand back cleanly (end of your shift)

1. Confirm `python3 -m unittest discover` and all eight demos pass, and modules compile
   (`python3 -m py_compile tpihunter/*.py`).
2. Update `STATUS.md`: milestone statuses + a new **Changelog** entry (newest first)
   saying what you did, what you found, and what's next. That entry *is* your handoff
   to the following session.
3. Commit (end the message with
   `Co-Authored-By: <your model> <noreply@anthropic.com>`) and `git push`.
4. If anything is half-done or risky, say so explicitly in the changelog.

---

## 8. Environment

- Repo: `/home/ron/ato-research2` → https://github.com/ronoski/ato-research2 (private, `main`).
- `gh` is authenticated as **ronoski** (`repo` scope); git identity is set. `git push` works over HTTPS.
- Python 3; the core is stdlib-only, no virtualenv needed. Run modules from the repo root as `python3 -m tpihunter.<name>`; tests as `python3 -m unittest discover`. Optional extras only for the two integrations: `pip install anthropic` (API strategist) and `pip install "mcp[cli]"` (MCP server / the owner's Max-subscription path).
- `gh` authenticated as **ronoski** (`repo` scope); git identity set; `git push` works over HTTPS. The owner hunts on a **Claude Max 20x subscription** — prefer the MCP path (M10), not the pay-per-token API path, for anything the owner runs.
- Commit history (see `git log`): initial (M0–M2) → M3 core → M3 complete → M5 dedup → M8 agent loop → M9 API strategist → M10 MCP server → M11 new-action synthesis → M7 evidence bundle. Each shift is one or more commits ending with a `Co-Authored-By` line.
