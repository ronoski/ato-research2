# READINESS — is TPI-Hunter ready to be an AI hunter?

**A candid strategic handoff. Written 2026-09-16 by the shift that landed M13–M15.**
Read this *before* picking a task. `HANDOFF.md` onboards you to the code; `STATUS.md` is the
task board; **this file tells you the truth about where the project actually stands**, so you
don't spend a rotation polishing the wrong thing. If you only read one paragraph, read the
bottom line.

---

## Bottom line

★ **The framework is complete and self-validating. The hunter is not proven.**

TPI-Hunter is a coherent, well-engineered **reference implementation** of an account-takeover
hunting loop — theory → learn → synthesize → generate → execute → judge → dedup → report, with
two judgment modes, a certified learner, and the agent seam wired. As *architecture*, treat it
as **done**.

But "ready for an **AI hunter**" — an autonomous agent finding real ATO bugs on real targets —
is **No, not yet.** Everything so far is validated **only against a deliberately-vulnerable mock
the project authored itself**, and the AI-agent part specifically is the *least*-proven piece.
The entire remaining distance is one thing — **live validation on an authorized target** — and it
is gated on the owner and **cannot be shortcut on the mock**.

---

## The readiness ladder — we are on rung 1

| # | rung | status |
|---|------|--------|
| 1 | Theory + a self-validating reference implementation | ✅ **here** (M0–M3, M5, M7–M15) |
| 2 | Runs live vs. **one authorized target**, reproduces a *known* finding | ❌ M4 — unbuilt, owner-gated |
| 3 | A **real** LLM strategist drives a live run, adapts, and knows when to stop | ❌ never run |
| 4 | Finds a bug that **wasn't planted**, on a system it didn't build | ❌ the real bar |

Rungs 2–4 *are* the "AI hunter" claim. None is reachable on the mock.

---

## What IS done — do not redo it

- The full loop, self-validating on the mock: **57 tests, 11 demos green**, stdlib-only core.
- Two judgment modes: the two-principal confluence **oracle** and the single-principal
  **revocation matrix**.
- Automated abstraction: **L\*** learns the auth FSM, the **W-method** oracle (M15) certifies it
  sound within a state bound, **synthesis** turns it into the enumerator's action model.
- Robustness: **oracle confirmation** (M13, verdicts must reproduce) and a **richer param model**
  (M14, synthesized actions take codes/tokens/second identifiers).
- The agent seam wired both ways: **API** (`llm.py`) and **Claude-Code/MCP on the Max plan**
  (`mcp_server.py`), plus new-action synthesis.

⇒ **More mock features have ~zero marginal value toward the north star.** The last three shifts
(M13/M14/M15) already took the worthwhile robustness fruit. Resist the pull to append another
mock capability just because it is the only unblocked thing.

---

## The gaps that matter (ranked)

1. ★ **Never run live; only ever finds bugs it planted.** Every "success" is detecting a
   vulnerability the author inserted into the mock, then patched to prove discrimination. That is
   a *validated detector*, not a *productive hunter*. **The one real target it was aimed at (the
   Grab engagement) didn't fit** — its ROE forbids scripted account creation and its own model
   out-classes the mock plumbing, so TPI-Hunter became an offline lens that that model already
   subsumes. That is a signal, not a footnote.
2. **The oracle can false-positive on a real target.** `identity_confluence` grades TAKEOVER
   whenever the attacker resolves to the victim's identity — true by construction on the mock
   (the control model *defines* the principals as independent), but on a real target a
   legitimately **shared / tenant / SSO-org / family** account resolves two principals to one
   identity (and yields a canary read too). The load-bearing invariant — *never a false takeover*
   — currently rests on an independence assumption a real target won't honor. M13 confirmation
   guards *flaky independent* failures, not *systematic* deception (a stale-identity cache fools
   every pass).
3. **The thesis is argued, not measured.** The Composition-Blindness argument and the taxonomy
   *assert* that the worst ATOs are provenance failures; there is **no CVE-corpus study** showing
   real disclosed ATOs are TPI-classifiable *and* invisible to a reachability view.
4. **Automated abstraction is only half-learned.** State-machine learning is **single-principal**
   (`MockSUL` = one account); the provenance-relevant structure — `needs_control`, cross-principal
   effects — is **hand-specified, not learned**. The half that catches laundering isn't the half
   that's learned.
5. **The AI agent — the north star — is the least-proven part.** Adaptivity has only been shown
   with a **hard-coded fake completion** finding the 2 planted mock bugs; the live-model path is
   gated out of every green check. No real-model eval, no coverage/stopping model. "Adapt, don't
   brute-force" currently rests on a script.
6. **Robustness gaps that only bite live:** L\* assumes determinism (real auth is not —
   timeouts, rate-limits, async email, per-plane divergence); the W-method suite is exponential in
   `extra_states` and untested on anything that needs >0; params are action-level only (no
   value carried from an earlier step's output); no real channels (only `InMemoryInbox`); TOCTOU
   modeled as ordering, not timing.

---

## What the next shift should — and should NOT — do

⛔ **Do NOT keep hardening the mock.** It is the tempting move because it is the only *unblocked*
move, and it is nearly worthless now. If you catch yourself adding a mock verb or a new judgment
sub-mode, stop and re-read the Bottom line.

✅ **If the owner authorizes a target** (the only thing that moves the needle):
1. Build **M4** minimally — a real `TargetAdapter` (one HTTP client per principal) + real channels
   (mailbox/IdP) + **ROE enforcement baked in** (auth header, own-accounts-only, in-scope
   allowlist, preflight gate). Isolate the new dep (`httpx`) like `anthropic`/`mcp`.
2. **Reproduce a known finding** on that target and *watch the oracle for a false positive on a
   shared/tenant account* — that is the invariant's first real test.
3. **Only then** let a real LLM strategist drive the live run, and add a stopping/coverage model.

✅ **If the owner does NOT authorize a target** — the honest ungated options, in value order:
1. ★ **A CVE-corpus validation of the TPI taxonomy** (addresses gap 3; needs no target; it is the
   single highest-value thing buildable while gated, because it tests the thesis the whole project
   rests on). Take N real disclosed ATOs, show each is TPI-classifiable and reachability-invisible
   — or find the ones that aren't and refine the theory.
2. **Harden the oracle against benign confluence** (gap 2) *as a design*, not by reworking the
   settled canary approach — e.g. require the setup to prove principal-independence, and make a
   pre-existing (baseline) confluence downgrade rather than fire. Do this carefully; it touches the
   load-bearing component. Read the Decisions log first.
3. **Accept that the framework is the deliverable and stop.** A clean, honest "done" beats
   busywork. This is a legitimate outcome.

---

## The decision this hands to the owner

The project has reached **the limit of what can be built without a live target.** The real
question is no longer *"what do we build next?"* — it is **"do we authorize a live run, or is the
framework the deliverable?"** Everything of value from here is either gated on that authorization,
or is the CVE-corpus study that tests the thesis. Please decide which, because the alternative —
another shift of mock polish — is motion without progress, and this handoff exists to stop it.
