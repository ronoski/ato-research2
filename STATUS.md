# Project Status Board

> **Live coordination doc.** Multiple agents/sessions work on this repo. Read this
> file first; update it last. It is the source of truth for *what stage we are at*
> and *what to do next*.

**Project:** TPI-Hunter — a black-box account-takeover hunting loop built on the
Trust-Provenance Integrity theory (see [`README.md`](README.md) and
[`paper/provenance.html`](paper/provenance.html)).

**Baseline (last verified green): 2026-09-15.** Test suite + four self-tests pass:
`python3 -m unittest discover` (12 tests), and
`python3 -m tpihunter.{demo,enum_demo,learn_demo,synth_demo}`.

---

## The loop, and where each stage stands

```
   map ──► abstract ──► generate ──► EXECUTE ──► JUDGE ──► refine
 (recon)  (TPI terms)  (probes)     (adapter)   (oracle)
   M4        M1/M3        M2           M1/M4       M1
```

| stage | component | status |
|-------|-----------|--------|
| abstract | domain types, TPI clauses | ✅ done (M1) |
| judge | `AtoOracle` — the verdict engine | ✅ done (M1) |
| execute | `TargetAdapter` (two-principal) + mock | ✅ done (M1); real target = M4 |
| generate | `enumerator` — composition-relevant interleavings | ✅ done (M2) |
| abstract (auto) | learn FSM (L*) → synthesize action model → generate | ✅ done (M3) |
| refine | `dedup` — causal minimization → distinct bugs | ✅ done (M5) |

---

## How to collaborate (relay model)

Sessions work **one at a time, never concurrently** — a relay. New here? Read
[`HANDOFF.md`](HANDOFF.md) first: it onboards you, explains the goal, and points to
where the last shift ended (the top Changelog entry below).

1. **Start of shift.** `git pull`, then run the three self-tests. Don't build on red.
2. **Claim your task** by marking its milestone `🚧 IN PROGRESS — <handle>, <date>`.
3. **Definition of done for any change:**
   - `python3 -m unittest discover` is green (add a test for what you build);
   - all four self-tests still pass (`demo`, `enum_demo`, `learn_demo`, `synth_demo`);
   - the oracle stays **discriminating** — if you add a vulnerability to the mock,
     add its patch too, so `enum_demo` shows TAKEOVER on vuln *and* SAFE on patched;
   - you updated this board (status + Changelog) in the same commit.
4. **End of shift.** Commit, push, leave the tree green. The Changelog top entry is
   your handoff to the next session.

The load-bearing invariant: **a verdict must never fire on the patched target.**
`enum_demo` self-checks this and prints a WARNING if it breaks — treat that WARNING
as a build failure.

---

## Milestones

### ✅ M0 — Theory / thesis  *(done)*
The TPI reframe, the Composition-Blindness argument, the taxonomy, the method.
- Files: `paper/provenance.html` · artifact: https://claude.ai/artifact/LxyHRRCnZB7NNQWP6SF1sC

### ✅ M1 — Oracle + two-principal adapter  *(done)*
Canary-based, differential, provenance-labeling verdict; independent context per
principal; runnable, self-validating mock.
- Files: `types.py`, `clauses.py`, `channels.py`, `adapter.py`, `oracle.py`,
  `mock_target.py`, `harness.py`, `probes.py`, `demo.py`
- Accept: `demo` → TAKEOVER (TPI-1) on vuln, SAFE on patched.

### ✅ M2 — Enumerator  *(done)*
Generates two-principal interleavings, pruned by the composition-relevance filter
(Composition-Blindness as a search prune); channel-aware.
- Files: `enumerator.py`, `enum_demo.py`
- Accept: `enum_demo` finds TPI-1 **and** TPI-4 with no hand-written probe; all
  findings close under patch.

### ✅ M3 — Automata learning → synthesis → generation  *(done 2026-09-15)*
Learn the Mealy machine a **black-box** target really implements, then generate from
*that* instead of the hand-coded `ACTIONS` table.
- [x] `SUL` interface (`reset()`, `step`) over the adapter's action names — `sul.py`
- [x] L* Mealy learner + random-walk equivalence oracle — `learner.py`
- [x] `learn_demo` recovers the mock's **9-state** auth FSM (captures session,
      *verified* via `sso_login`→`OK_VERIFIED`, reset-token, and logged-out dims)
- [x] `synthesis.py` — derives the enumerator's `ActionSpec` model from a learned
      machine: `requires` from FSM structure, effect (SEED/RAISE/CRED/REQUEST) from
      output signature; `needs_control` declared per channel (unobservable from
      single-account traces)
- [x] `enumerate_plans(..., specs=…)` now takes a synthesized model
- [x] `synth_demo` — learn → synthesize → enumerate; synthesized effects match the
      hand-coded `ACTIONS`, and generation reproduces {TPI-1, TPI-4}, all closing
      under patch. **M3 acceptance: PASS.**
- Follow-ups worth doing: W-method/Wp conformance oracle for soundness within a
  bound (currently random-walk); learn against a real target once M4 lands.

### ⬜ M4 — Real `TargetAdapter`  *(unclaimed)*
Implement `TargetAdapter` against a live app: one `httpx` client per principal, real
flows, and a `channels.EmailChannel` backed by a mailbox you control.
- **Needs:** an authorized target (ask the human). Do not point at anything without
  written authorization; see Scope in `README.md`.
- Accept: `demo`/`enum_demo` verdicts reproduce against the real target.

### ✅ M5 — Semantic dedup of enumerator output  *(done 2026-09-15)*
The enumerator over-generates (124 candidates, 106 findings) because it explores every
interleaving and padding. Dedup collapses them to the distinct bugs.
- Files: `dedup.py` (+ `Candidate.merged`, `build_plan`/`is_wellformed` in
  `enumerator.py`)
- How: **causal minimization** (delta-debug each fired probe against the oracle,
  keeping the takeover *and its clause*) yields a minimal repro; findings are then
  grouped by **causal signature** `(clause_id, set of effect-classes in the core)`.
  Role/count/interleaving are abstracted away — the clause already encodes who/what.
- Accept: `enum_demo` now reports **106 findings → 2 distinct bugs** (TPI-1 in 2
  steps, TPI-4 in 3), each with a minimal repro and laundered proof; all close under
  patch. Tests assert exactly 2 clusters and that every fired candidate is clustered.

### ⬜ M6 — Alloy offline attack-shape compiler  *(optional / later)*
A relational Alloy model used **offline** to pre-compute violating interleavings
that seed the enumerator. A design-time force-multiplier, never in the live loop.
(Decision log below explains why Alloy is not in the loop.)

### ⬜ M7 — Findings report / evidence bundle  *(unclaimed)*
Turn a `Verdict` + `Trace` into a shareable repro (minimal steps, the laundered
proof, the canary evidence) — a bug-bounty-ready artifact.

---

## Pick this up next

The loop is closed end-to-end and deduplicated (learn → synthesize → generate →
judge → dedup). Best next tasks:
1. **M7 (findings/evidence bundle)** — turn each dedup `Cluster` (`Verdict` + minimal
   repro `Trace` + laundered proof + canary evidence) into a shareable, bug-bounty-
   ready report (markdown/JSON). Dedup already hands you the distinct bugs and their
   minimal repros — this is the natural next step and needs no new target.
2. **M4 (real `TargetAdapter`)** — needs an authorized target from the human; blocked
   until then. When unblocked, also point the learner (`sul.py`) at the real target.

Also open (small): give the learner a **W-method conformance oracle** so the learned
machine is sound within a bound, not just random-walk-tested.

---

## Decisions log

- **Black-box loop over Alloy for autonomous hunting.** A hunter's scarce resource
  is a *verdict* (did the takeover land?). The black-box loop touches the target and
  has an oracle; Alloy only enumerates hypotheses over an abstraction it cannot
  validate. Alloy is therefore relegated to an optional offline compiler (M6).
- **Channel-control model in the mock.** Actions needing control of an identifier
  (`sso_login`, `reset_consume`) only succeed for a principal who controls it — this
  keeps enumerated findings genuine rather than artifacts of an all-permissive mock.

## Known limitations

- Dedup groups by `(clause, effect-set)`, so two genuinely different bugs that share a
  clause *and* the same effect-classes would merge into one cluster. Acceptable for
  now (the clause already carries the who/what distinction); revisit if a real target
  produces false merges — the fix is a finer signature, not more clusters by default.
- Oracle diagnosis is heuristic over the black-box trace; a white-box hook could
  corroborate.
- Learner uses a random-walk equivalence oracle (sound only up to sampling); a
  W-method oracle would make the learned machine sound within a bound.
- Temporal/TOCTOU races and freshness windows are modelled as ordering only, not yet
  as timed automata.

---

## Changelog  *(append-only, newest first)*

- **2026-09-15** — *Session 3.* **M5 complete: semantic dedup.** Added `dedup.py`:
  causal minimization (delta-debug each fired probe against the oracle, preserving the
  takeover + clause) → minimal repro, then group by causal signature
  `(clause, effect-set)`. First cut grouped by `(role, effect)` and split TPI-4 into 3
  exploitation-path variants; coarsened to effect-set (the clause already encodes
  who/what) → **106 findings collapse to 2 distinct bugs**. Exposed `Candidate.merged`
  + `build_plan`/`is_wellformed` in `enumerator.py`; rewrote `enum_demo` around dedup;
  added 3 dedup tests (suite now 12). All demos + tests green. **Next:** M7 (turn a
  dedup `Cluster` into a shareable evidence bundle) — see *Pick this up next*.
- **2026-09-15** — *End of shift (session 2).* **M3 complete.** Refactored `sul.py`
  to learn over the adapter's own action names and to expose the trust-raise
  (`sso_login`→`OK_VERIFIED`); added `synthesis.py` (learned machine → enumerator
  `ActionSpec` model) and threaded a `specs` param through `enumerator.py`; added
  `synth_demo.py`. The learner now recovers a 9-state machine and the synthesized
  effects match the hand-coded `ACTIONS` exactly, reproducing {TPI-1, TPI-4} with no
  patched-target firing. Also added a **stdlib `tests/` suite** (9 tests,
  `python3 -m unittest discover`) codifying the load-bearing invariant and the
  learn→synthesize pipeline — addresses the "no tests" gap the last shift flagged.
  **Next session:** M5 (semantic dedup) is the best pick; see *Pick this up next*.
  Everything green; nothing half-done.
- **2026-09-15** — *End of shift (session 1).* Added [`HANDOFF.md`](HANDOFF.md) as the
  onboarding + relay entry point and switched the collaboration model to a relay
  (one session at a time). **Next session:** read HANDOFF.md, then pick up the M3
  wiring (learned machine → enumerator) or M5 (semantic dedup). Tree is green; all
  three self-tests pass. Nothing half-done.
- **2026-09-15** — M3 core: black-box automata learning landed (`sul.py`,
  `learner.py`, `learn_demo.py`). L* recovers the mock's 5-state auth FSM in 542
  membership queries. Remaining M3 sub-task: feed the learned machine into the
  enumerator. All three self-tests green.
- **2026-09-15** — Repo initialized. M0 (thesis), M1 (oracle + adapter), M2
  (enumerator) landed and green. Mock hardened with a channel-control model and a
  completed patch (register cannot attach to an existing account).
