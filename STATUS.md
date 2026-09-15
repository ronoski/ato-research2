# Project Status Board

> **Live coordination doc.** Multiple agents/sessions work on this repo. Read this
> file first; update it last. It is the source of truth for *what stage we are at*
> and *what to do next*.

**Project:** TPI-Hunter — a black-box account-takeover hunting loop built on the
Trust-Provenance Integrity theory (see [`README.md`](README.md) and
[`paper/provenance.html`](paper/provenance.html)).

**Baseline (last verified green): 2026-09-15.** Test suite + four self-tests pass:
`python3 -m unittest discover` (9 tests), and
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

### ⬜ M5 — Semantic dedup of enumerator output  *(unclaimed)*
The enumerator over-generates: 124 candidates collapse to 2 distinct bugs (order /
padding variants). Collapse plans by causal signature so a hunter sees N *distinct*
attacks, not N interleavings.
- Files: `enumerator.py`
- Accept: `enum_demo` reports ~2 distinct findings on the mock, not 106.

### ⬜ M6 — Alloy offline attack-shape compiler  *(optional / later)*
A relational Alloy model used **offline** to pre-compute violating interleavings
that seed the enumerator. A design-time force-multiplier, never in the live loop.
(Decision log below explains why Alloy is not in the loop.)

### ⬜ M7 — Findings report / evidence bundle  *(unclaimed)*
Turn a `Verdict` + `Trace` into a shareable repro (minimal steps, the laundered
proof, the canary evidence) — a bug-bounty-ready artifact.

---

## Pick this up next

The black-box loop is now closed end-to-end (learn → synthesize → generate → judge).
Best next tasks:
1. **M5 (semantic dedup)** — highest-value, self-contained. The enumerator emits 106
   near-duplicate findings that collapse to 2 distinct bugs (order/padding variants).
   Collapse candidates by causal signature so a hunter sees *distinct* attacks. Add a
   test asserting ~2 distinct findings on the mock. Low risk, high readability.
2. **M7 (findings/evidence bundle)** — turn a `Verdict` + `Trace` into a shareable
   minimal repro. Pairs well with M5 (dedup first, then report the distinct ones).
3. **M4 (real `TargetAdapter`)** — needs an authorized target from the human; blocked
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

- Enumerator over-generation (→ M5).
- Oracle diagnosis is heuristic over the black-box trace; a white-box hook could
  corroborate.
- Temporal/TOCTOU races and freshness windows are modelled as ordering only, not yet
  as timed automata.

---

## Changelog  *(append-only, newest first)*

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
