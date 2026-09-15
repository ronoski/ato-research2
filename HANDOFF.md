# HANDOFF — start here

You are the next session taking over this project. The previous session has paused.
**We work as a relay: one session at a time, never concurrently.** Your shift, in
order: (1) get oriented, (2) review the existing work with a critical eye, (3)
improve what needs it and continue the roadmap, (4) leave the tree green and hand
back cleanly. You have a real mandate to **review and refactor**, not just append —
but read the *Decisions log* in `STATUS.md` before reopening a settled trade-off.

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

Today the loop, the dedup, and the **agent control seam** are built and
**self-validating against a mock**. The remaining work is to wire a real model into the
strategist (M9), connect it to real targets (M4), and report findings (M7).

**Read the theory first:** open `paper/provenance.html` in a browser. It defines the
invariant, the three failure modes (gap / forgery / laundering), the
Composition-Blindness argument that justifies the whole black-box approach, and the
taxonomy that maps real ATO classes onto the theory. Everything in the code traces
back to it. (Published copy: https://claude.ai/artifact/LxyHRRCnZB7NNQWP6SF1sC)

---

## 2. Get oriented in five minutes

Run the test suite and the four self-tests — the fastest way to see what exists:

```bash
python3 -m unittest discover     # 9 tests: the invariants that must not regress
python3 -m tpihunter.demo        # the oracle: TAKEOVER on a vulnerable target, SAFE on the patched one
python3 -m tpihunter.enum_demo   # the enumerator: generates probes, rediscovers TPI-1 and finds TPI-4
python3 -m tpihunter.learn_demo  # automata learning: L* recovers the mock's auth state machine
python3 -m tpihunter.synth_demo  # the closed loop: learn → synthesize action model → enumerate
```

Then read, in this order:
1. **this file**
2. **`STATUS.md`** — the task board + changelog. *The top changelog entry is where the
   last shift ended.*
3. **`tpihunter/README.md`** — the tool in depth
4. **the code**, in dependency order:
   `types.py` → `clauses.py` → `channels.py` → `adapter.py` → `oracle.py` →
   `mock_target.py` → `harness.py` → `probes.py` → `enumerator.py` →
   `dedup.py` → `sul.py` → `learner.py` → `synthesis.py` → `agent.py`

   `agent.py` is where it all comes together for the goal — read it last but treat it
   as the top of the design: everything else is a tool the agent (strategist) drives.

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

I (the previous session) am flagging the spots most worth your scrutiny. Treat these
as invitations to improve:

- **Oracle `_diagnose` is heuristic** (rules over trace shape). It can mislabel the
  clause on unusual interleavings. A white-box corroboration hook, or a more
  principled mapping, would strengthen it.
- **The oracle's confluence handling is subtle.** In pre-hijacking the attacker
  resolves to the victim's identity *from the seeding step*, so confluence pre-exists
  the "attack". The grading treats confluence as decisive at assess-time regardless —
  convince yourself this is sound, and that it can't false-positive on a legitimately
  shared/tenant account.
- **Enumerator over-generation is now handled by `dedup.py`** (M5): 106 findings →
  2 distinct bugs via causal minimization + a `(clause, effect-set)` signature. The
  one thing to watch: the signature is deliberately coarse (drops role/count), so two
  genuinely different bugs sharing a clause *and* effect-set would merge. Fine on the
  mock; if a real target shows a false merge, make the signature finer — don't just
  raise the cluster count.
- **The mock is a simplification.** Its bugs and patches are illustrative. The
  reset-token / inbox model in `mock_target.py` is slightly quirky (stale links after
  consume) — verify it doesn't create phantom states in the learner. **If you add a
  new bug to the mock, add its patch too**, or you break the load-bearing invariant
  (below).
- **L\* uses a random-walk equivalence oracle** — realistic for a black box, but the
  learned machine can be incomplete for larger alphabets. A W-method / Wp-method
  conformance oracle would make it sound within a bound. *(Still open.)*
- **`tests/` now exists** (`tests/test_tpihunter.py`, stdlib `unittest`, 9 tests) and
  codifies the load-bearing invariant + the learn→synthesize pipeline. *Extend it
  when you add behaviour* — e.g. M5 should assert "~2 distinct findings on the mock".
- **`synthesis.py` effect classifier is signature-based** (`OK_VERIFIED`→RAISE,
  `SENT`→REQUEST, session-after-token→CRED). It matches the mock exactly, but a real
  target's output vocabulary will differ — the mapping in `SUCCESS_OUTPUTS` /
  `classify_effect` is where you adapt it, and `needs_control` is declared, not
  learned (single-account traces always control the identifier).

---

## 5. Invariants to preserve

- **The load-bearing invariant:** a verdict must **never** fire on the patched
  target. `enum_demo` self-checks this and prints a `WARNING` if broken — treat that
  WARNING as a build failure.
- **Keep it runnable and self-validating.** Every capability ships with a demo that
  proves it on the mock, and a test that asserts it.
- **Stdlib-only** unless there is a strong reason (a real HTTP adapter will want
  `httpx` — that's fine; isolate it so the core stays dependency-free).
- **`unittest discover` and all five demos stay green.** Don't hand back on red.

---

## 6. Your next task

The loop is live via the API strategist (M9). **The owner hunts on a Claude Max 20x
subscription**, so the priority is making the Claude Code CLI agent the strategist (that
runs on the subscription; the API path bills separately). From `STATUS.md` → *Pick this
up next*:

1. **M10 — Claude-Code / Max-subscription strategist (owner's goal).** Build a tpihunter
   **MCP server** exposing the loop's primitives (`learn_target`, `enumerate_candidates`,
   `run_probe(steps)->verdict`, `dedup_findings`, `report`). Then `claude mcp add
   tpihunter …` and the Opus agent in Claude Code drives the hunt on the Max plan — no
   API key. Everything it needs already exists as functions (`AgentHunter` internals,
   `run_plan`, `deduplicate`); keep the `mcp` dep isolated like `llm.py` isolates
   `anthropic`. Accept: from a Claude Code session, "hunt the mock" → 2 distinct bugs.
2. **New-action synthesis** — let the strategist propose *new* `ActionSpec`s (flows the
   fixed alphabet lacks: magic links, device pairing, org invites, email aliasing),
   feeding straight into generation. Applies to both strategists.
3. **M7 (evidence bundle)** — turn each dedup `Cluster` into a shareable report; the
   agent's final "report" step. `dedup.deduplicate(...)` gives the distinct bugs + minimal
   repros; `run_plan(build_plan(cluster.representative, …))` gives the full `Trace`.
4. **M4 (real adapter)** — blocked on an authorized target from the owner.

Start wherever you have the most conviction. Update `STATUS.md` to claim it (mark the
milestone `🚧 IN PROGRESS — <your handle>, <date>`).

---

## 7. Hand back cleanly (end of your shift)

1. Confirm `python3 -m unittest discover` and all five demos pass, and modules compile
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
- Python 3, stdlib only, no virtualenv needed. Run modules from the repo root as `python3 -m tpihunter.<name>`; tests as `python3 -m unittest discover`.
- Commit history (see `git log`): initial (M0–M2) → M3 core → M3 complete (synthesis + tests). Each shift is one or more commits ending with a `Co-Authored-By` line.
