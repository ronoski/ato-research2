# HANDOFF — start here

You are the next shift taking over this project. **We work as a relay: one session at a
time, never concurrently**, and the rotation cycles back around — so "new to the project"
and "returning after two shifts away" both land here; either way, treat the repo as the
source of truth and re-orient from it, because a lot has changed.

> ⚠️ **Read [`READINESS.md`](READINESS.md) before you pick a task.** The mock loop is
> complete (M0–M15) and self-validating, but the project is a finished *framework*, not a
> proven *AI hunter* — and the highest-risk mistake now is spending a shift hardening the
> mock, which has ~zero marginal value. `READINESS.md` is the honest state-of-the-project:
> the gaps that matter, and the one decision (authorize a live target, or call the framework
> the deliverable) that everything else is gated on.

The relay so far (what each shift built — see `git log` and the Changelog):
- **s1** — the theory + the core: oracle, two-principal adapter, learner, synthesis.
- **s2** — dedup, the agent control loop, both live strategists (API + Claude-Code/MCP),
  new-action synthesis, the evidence bundle.
- **s3** — the Grab engagement lens (offline), and the **revocation matrix** (a whole
  second hunting mode: cross-plane + factor/lifecycle kinds).
- **s4** — **oracle confirmation** (M13): a verdict must reproduce (strict majority of
  re-probes) before it fires, so a flaky/rate-limited real target can't flip it. Then
  **richer synthesized-action params** (M14): actions can take codes / invite tokens / a
  second identifier (a recovery email), not just the account email — completing new-action
  synthesis and closing both roadmap robustness items. (Also exposed `register_action` on the
  MCP server, which was missing.) Then the **W-method conformance oracle** (M15): the learner
  is now sound within a state bound, not just sampled — the last open L* limitation.

Your shift, in order: (1) get oriented, (2) review the existing work with a critical eye,
(3) improve what needs it and continue the roadmap, (4) leave the tree green and hand back
cleanly. You have a real mandate to **review and refactor**, not just append — but read the
*Decisions log* in `STATUS.md` before reopening a settled trade-off.

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

Today the full loop is built and **self-validating against a mock**: two judgment modes
(two-principal confluence oracle + single-principal revocation matrix, M12), dedup, the
agent control seam, a live strategist both via the API (M9) and via the Claude Code agent
on the owner's Max subscription (M10, the MCP server), the agent extending its own alphabet
(M11), and submittable evidence reports (M7). The remaining frontier is **real targets**
(M4) and deepening the matrix.

**Read the theory first:** open `paper/provenance.html` in a browser. It defines the
invariant, the three failure modes (gap / forgery / laundering), the
Composition-Blindness argument that justifies the whole black-box approach, and the
taxonomy that maps real ATO classes onto the theory. Everything in the code traces
back to it. (Published copy: https://claude.ai/artifact/LxyHRRCnZB7NNQWP6SF1sC)

---

## 2. Get oriented in five minutes

Run the test suite and the ten self-tests — the fastest way to see what exists:

```bash
python3 -m unittest discover     # 57 tests: the invariants that must not regress
python3 -m tpihunter.demo         # the oracle: TAKEOVER on a vulnerable target, SAFE on the patched one
python3 -m tpihunter.enum_demo    # the enumerator: generates probes → dedups to 2 distinct bugs
python3 -m tpihunter.learn_demo   # automata learning: L* recovers the mock's auth state machine
python3 -m tpihunter.synth_demo   # the closed loop: learn → synthesize action model → enumerate
python3 -m tpihunter.agent_demo   # agent as hunter: a strategist drives the loop (enumerator vs LLM seam)
python3 -m tpihunter.live_agent_demo  # the real LLM strategist (gated by TPIHUNTER_LIVE=1; else prints setup)
python3 -m tpihunter.newaction_demo   # the agent registers a new action to find a bug beyond the alphabet
python3 -m tpihunter.matrix_demo      # the revocation matrix: a 'patched' target still leaks via logout
python3 -m tpihunter.report_demo      # hunt the mock, then print the submittable evidence bundle
python3 -m tpihunter.retry_demo       # oracle confirmation: a flaky target can't flip the verdict (M13)
python3 -m tpihunter.alias_demo       # richer params: drive a flow that needs a second identifier (M14)
```

Then read, in this order:
1. **this file**
2. **`STATUS.md`** — the task board + changelog. *The top changelog entry is where the
   last shift ended.*
3. **`tpihunter/README.md`** — the tool in depth
4. **the code**, in dependency order:
   `types.py` → `clauses.py` → `channels.py` → `adapter.py` → `oracle.py` →
   `flaky.py` → `mock_target.py` → `harness.py` → `probes.py` → `enumerator.py` →
   `dedup.py` → `matrix.py` → `sul.py` → `learner.py` → `wmethod.py` → `synthesis.py` →
   `agent.py` → `mcp_tools.py` → `mcp_server.py` → `llm.py` → `report.py`

   Two judgment modes sit side by side: `oracle.py` (two-principal confluence) and
   `matrix.py` (single-principal revocation over time). The matrix is the ROE-safe mode
   for real engagements — own-account, reversible, reads no one else's data.

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
| `oracle.py` | `AtoOracle` — the **verdict engine** (the star); `confirm=k` re-probes and requires a strict majority so a flaky target can't flip a verdict (M13) |
| `flaky.py` | `FlakyAdapter` — wraps an adapter and drops the attacker's reads (deterministic under a seed); exercises oracle confirmation without a real target |
| `mock_target.py` | a deliberately vulnerable in-memory target + adapter, with a `patched` toggle |
| `harness.py` | `Plan`/`Step` + `run_plan`: probes as data, run with oracle checkpoints; generic dispatch filters kwargs to what a synthesized verb accepts (M14) |
| `probes.py` | hand-written TPI probe plans |
| `enumerator.py` | **generates** probes — composition-relevant interleavings; takes a `specs` model |
| `dedup.py` | collapses fired findings to distinct bugs (causal minimization + signature) |
| `agent.py` | **the goal**: `AgentHunter` loop + `Strategist` seam (enumerator baseline, LLM seam) |
| `llm.py` | real-model backend for `LLMStrategist` (isolates `anthropic`; API/pay-per-token path) |
| `mcp_tools.py` | `HuntSession` — the hunt loop as agent-drivable tools (stdlib, tested) |
| `mcp_server.py` | MCP server so the Claude Code agent hunts on a Max plan (isolates `mcp`) |
| `matrix.py` | **revocation matrix** — single-principal own-account lifecycle mode, per-plane (2nd judgment mode) |
| `report.py` | evidence bundles — each distinct bug → submittable markdown/JSON report |
| `sul.py` | System-Under-Learning interface + single-account view of the mock |
| `learner.py` | Angluin's L* Mealy learner; default equivalence oracle is the W-method (M15), random-walk selectable via `eq_method="random"` |
| `wmethod.py` | W-method conformance oracle — a finite test suite (P·M·W) that certifies a learned machine sound up to `n + extra_states` states |
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
  tenant / SSO-org account on a real target. Retry landed (M13): `AtoOracle(confirm=k)`
  re-probes and reports a non-SAFE verdict only on a strict majority (no majority ⇒ SUSPECT),
  so a flaky target can't flip a verdict; `confirm=0` (default) is unchanged. Still to weigh:
  the majority rule assumes *independent* transient failures — a systematically misleading
  target (e.g. a cache that consistently returns stale identity) would fool every pass; that
  needs a different signal, not more passes.
- **Dedup signature is `(clause, effect-set, trigger-verbs)`** (`dedup.py`). It merges
  padding/order variants but keeps different trigger endpoints (e.g. `sso_login` vs a
  synthesized `magic_link`) separate. Still coarse on role/count — if a real target shows a
  false merge, refine the signature; don't just raise the cluster count.
- **New-action synthesis now has a real param model (M14).** `ActionSpec.params` carries
  declared `(name, template)` pairs (`{email}`/`{alias}`/`{role}` or a literal), `_to_plan`
  fills them, and the harness dispatch drops params a verb doesn't accept. So a synthesized
  action can take a code, an invite token, or a second identifier (a recovery email). Watch on
  a real target: `{alias}` is a fixed `role.recovery@evil.example` and the template grammar is
  deliberately tiny — a flow needing a value derived from an *earlier step's output* (e.g. a
  code emitted by a request step, not carried by the adapter's inbox side-channel) still isn't
  expressible; that would need step-scoped params, a bigger change to the `(role, action)` tuple.
- **`synthesis.py` effect classifier is signature-based** (`OK_VERIFIED`→RAISE,
  `SENT`→REQUEST, session-after-token→CRED). Matches the mock; a real target's outputs
  differ — adapt `SUCCESS_OUTPUTS` / `classify_effect`. `needs_control` is declared, not
  learned (single-account traces always control the identifier).
- **L\* now uses the W-method conformance oracle by default (M15, `wmethod.py`)** — sound up to
  `n + extra_states` states, so the learned machine is certified, not just sampled (random-walk
  is still there under `eq_method="random"`). *Resolved.* What's left is empirical: the suite is
  exponential in `extra_states` (the mock converges even at 0, so tuning only bites on a real
  target), and a Wp-method / adaptive-distinguishing variant is the natural fix if a big real
  alphabet makes the suite too large. Also, the oracle certifies the *single-account* SUL; a
  real learn against a live target arrives with M4.
- **Tests are the safety net — extend them with every change.** `tests/test_tpihunter.py`,
  stdlib `unittest`, **57 tests** covering the load-bearing invariant, the learn→synthesize
  pipeline, the W-method oracle (M15: certifies a correct hypothesis, catches wrong ones),
  dedup, the agent loop + LLM wiring (fake client), the MCP `HuntSession`, new-action synthesis
  + the richer param model (M14), the revocation matrix (cross-plane SPLIT + factor/lifecycle
  kinds + the expectation model), oracle confirmation under a flaky target (M13), and the report
  bundle. Add assertions for whatever you build.

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
- **`unittest discover` (57 tests) and all eleven demos stay green.** Don't hand back on red.

---

## 6. Your next task

The mock loop is complete end-to-end and now has **two judgment modes**: two-principal
confluence (`oracle.py`) and single-principal revocation (`matrix.py`, M12 — the mode that
fits a real authorized engagement). The frontier is **real targets** and deepening the
matrix. From `STATUS.md` → *Pick this up next*:

1. **The revocation matrix (M12) is now rich** — cross-plane (SPLIT) *and* lifecycle kinds
   (session + factor mints; logout/reset/email-change mutations; an expectation model so a
   passkey surviving logout is `n/a`, not a false finding). It maps cleanly onto the Grab
   lens (TPI-L1 logout/plane, TPI-L2 reset survival, T-ATO-22 factor-survives-reset). The
   highest-value next step is no longer more mock kinds — it is **running this matrix against
   a real target** (below). A minor pure-mock extension (popkey-rebind mint, PIN-change
   mutation) exists but is low-value vs. going live.
2. **M4 — real `TargetAdapter`** (blocked on an authorized target from the owner). When
   unblocked, **bring the revocation matrix live first** — it is the most ROE-compatible
   mode (own-account, reversible, reads no one else's data), which is precisely why the real
   Grab engagement's cheap wins (TPI-L1/L2) are matrix-shaped. Do not point at anything
   without written authorization; see Scope in `README.md`.
3. **Robustness** (do-able now against the mock, de-risks M4): ✅ **both items landed** —
   oracle confirmation/retry (M13: `AtoOracle(confirm=k)`, `flaky.py`, `retry_demo`) and the
   richer synthesized-action param model (M14: `ActionSpec.params`, `alias_demo`). Nothing left
   here that's high-value on the mock alone; the two open follow-ups are the theory-nuance items
   noted in §4 (systematic-failure oracle signal; step-scoped params) — design them when a real
   target actually shows the need.
4. ✅ **W-method conformance oracle** for the learner — done (M15, `wmethod.py`); the learner
   is sound within a state bound. With the robustness items (M13/M14) also done, **there is no
   remaining purely-mock item of note.** The frontier is now genuinely: iterate the Grab lens
   (offline, other repo) and go live (M4, owner-gated). If you want a mock task anyway, the
   honest candidates are small: a Wp-method variant (only matters for a large real alphabet),
   or the two theory-nuance items in §4 (systematic-failure oracle signal; step-scoped params).
   Weigh them against just waiting for an authorized target — the north star is a *live* agent.

Start wherever you have the most conviction. Update `STATUS.md` to claim it (mark the
milestone `🚧 IN PROGRESS — <your handle>, <date>`).

---

## 7. Hand back cleanly (end of your shift)

1. Confirm `python3 -m unittest discover` and all eleven demos pass, and modules compile
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
- Commit history (see `git log`): initial (M0–M2) → M3 core → M3 complete → M5 dedup → M8 agent loop → M9 API strategist → M10 MCP server → M11 new-action synthesis → M7 evidence bundle → M4-redirect (Grab lens) → M12 revocation matrix → M12 cross-plane axis → M12 lifecycle kinds → M13 oracle confirmation → M14 richer synthesized-action params → M15 W-method conformance oracle. Each shift is one or more commits ending with a `Co-Authored-By` line.
