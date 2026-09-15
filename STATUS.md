# Project Status Board

> **Live coordination doc.** Multiple agents/sessions work on this repo. Read this
> file first; update it last. It is the source of truth for *what stage we are at*
> and *what to do next*.

**Project:** TPI-Hunter — a black-box account-takeover hunting loop built on the
Trust-Provenance Integrity theory (see [`README.md`](README.md) and
[`paper/provenance.html`](paper/provenance.html)).

**Baseline (last verified green): 2026-09-15.** Three self-tests pass:
`python3 -m tpihunter.demo`, `python3 -m tpihunter.enum_demo`,
`python3 -m tpihunter.learn_demo`.

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
| abstract (auto) | learn alphabet + FSM from a target (L*) | 🚧 in progress (M3) |

---

## How to collaborate (protocol)

1. **Sync + verify baseline.** `git pull`, then run both self-tests. Don't build on red.
2. **Claim a task.** Edit its milestone below to `🚧 IN PROGRESS — <your handle>, <date>`,
   commit *just that STATUS.md change*, and push, so others see the claim. Prefer
   coarse tasks so two sessions don't split one file.
3. **Definition of done for any change:**
   - both self-tests still pass;
   - the oracle stays **discriminating** — if you add a vulnerability to the mock,
     add its patch too, so `enum_demo` shows TAKEOVER on vuln *and* SAFE on patched;
   - you updated this board (status + Changelog) in the same commit.
4. **Small commits, push often.** Leave the tree green.

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

### 🚧 M3 — Automata learning  *(IN PROGRESS — core landed 2026-09-15)*
Learn the alphabet and the per-subsystem Mealy machine from a **black-box** target
(active learning, L*/LearnLib-style) so the enumerator runs on the behaviour the
server *actually* implements, not the hand-coded `ACTIONS` table in `enumerator.py`.
- [x] `SUL` interface (`reset()`, `step(input) -> output`) — `sul.py`
- [x] L* Mealy learner + random-walk equivalence oracle — `learner.py`
- [x] `learn_demo` recovers the mock's 5-state login/reset FSM (RESET_USE only
      yields a session after RESET_REQ; LOGIN denied until an account exists)
- [ ] **remaining:** feed the learned alphabet + an effect classification into the
      enumerator, replacing the static `ACTIONS` specs (needs a heuristic to label
      learned transitions as SEED / RAISE / CRED from their output signature).
- Accept (remaining): `enumerator` consumes a learned machine and reproduces the
  M2 findings without the hand-coded action table.

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

Two ready tasks:
1. **Finish M3** — wire the learned Mealy machine into the enumerator. Add a
   classifier that labels each learned transition SEED / RAISE / CRED from its
   output signature, then have `enumerate_plans` take an alphabet derived from a
   learned machine. This closes the loop: generation from *learned* behaviour.
2. **M5 (semantic dedup)** — independent of M3; collapses the enumerator's 106
   near-duplicate findings to ~2 distinct ones. Good parallel task.

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

- **2026-09-15** — M3 core: black-box automata learning landed (`sul.py`,
  `learner.py`, `learn_demo.py`). L* recovers the mock's 5-state auth FSM in 542
  membership queries. Remaining M3 sub-task: feed the learned machine into the
  enumerator. All three self-tests green.
- **2026-09-15** — Repo initialized. M0 (thesis), M1 (oracle + adapter), M2
  (enumerator) landed and green. Mock hardened with a channel-control model and a
  completed patch (register cannot attach to an existing account).
