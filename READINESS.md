# READINESS — is TPI-Hunter ready to be an AI hunter?

**A candid strategic handoff. Written 2026-09-16 by the shift that landed M13–M15;
amended 2026-09-20 by the safety-hardening shift (see *Amendment* at the bottom).**
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

- The full loop, self-validating on the mock: **102 tests, 12 demos green**, stdlib-only core.
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
2. **The oracle can false-positive on a real target** — *reduced, not closed (2026-09-20).*
   The diagnosis above was right and was, if anything, understated: a legitimately shared
   account graded **TAKEOVER at 0.99 on an empty trace**, with `confirm=4` agreeing on every
   pass, and it performed a cross-principal *write* while doing so. The oracle now carries
   positive/negative controls and three attribution guards (independence, justification,
   attribution) that make that class a non-finding by construction, with regression tests and
   `safety_demo` as the witness. What is *not* closed: the guards are validated only on the
   mock, and they cover the shapes we could name. A systematic deception that produces
   confluence **after** the attacker has acted and **without** an attacker proof — a stale
   identity cache is the example the original text gave — still fires. Only a live target
   tells you which shapes actually occur.
3. **The thesis is argued, not measured.** The Composition-Blindness argument and the taxonomy
   *assert* that the worst ATOs are provenance failures; there is **no CVE-corpus study** showing
   real disclosed ATOs are TPI-classifiable *and* invisible to a reachability view.
4. **Automated abstraction is only half-learned.** State-machine learning is **single-principal**
   (`MockSUL` = one account); the provenance-relevant structure — `needs_control`, cross-principal
   effects — is **hand-specified, not learned**. The half that catches laundering isn't the half
   that's learned.
5. **The AI agent — the north star — is the least-proven part.** *Scaffolding improved in M16*
   (the agent now gets per-probe reason codes, a coverage map, and a principled `patience` stop —
   so it can reason about where it has looked). **But the proof gap is unchanged:** adaptivity has
   still only been shown with a **hard-coded fake completion** finding the 2 planted mock bugs; the
   live-model path is gated out of every green check. "Adapt, don't brute-force" rests on a script
   until a real model drives a real (or at least noisy) target.
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
   (mailbox/IdP). Isolate the new dep (`httpx`) like `anthropic`/`mcp`. **The ROE half is already
   built** (`policy.py`: identifier/host allowlists, destructive-action gates, budget, dry run,
   preflight, audit trail) and is ungated, so M4 is now adapter + channels, wrapped in
   `policy.guard()`.
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

---

## Amendment — 2026-09-20 (safety hardening)

A security review of the codebase, not of the theory. It changed no milestone and moved no
rung; it fixed things that would have produced wrong answers or unsafe behaviour the first
time this was pointed at something real.

**Three demonstrated defects in the verdict engine**, each reproduced before it was fixed:

| | was | now |
|---|---|---|
| a legitimately shared / tenant / co-owned account | `TAKEOVER 0.99` on an **empty trace**; `confirm=4` agreed every pass; it also *wrote* to the account | `SAFE`, `withheld=attacker_proved_control` — the attacker's own proof justifies its access |
| two principals wired to one context (a mis-built live adapter) | `TAKEOVER 0.99` | `INCONCLUSIVE`, `withheld=principals_not_independent` |
| a probe whose canary never got planted | `SAFE 0.95` — a **false negative reported as a secure result**, which is what teaches the agent to stop looking there | `INCONCLUSIVE`, `withheld=canary_not_planted` |

The third was not on the ranked list and is arguably the worse one: `enforced` reason codes
feed the agent's coverage map and its patience-stop, so a probe that never ran was being
counted as a surface that had been tested.

**A fourth defect, in the diagnosis rather than the verdict.** A target with correct
identity handling but a flat IDOR (any session reads any resource by reference) produced a
true `TAKEOVER` under a *false clause*: `TPI-1, revoke-on-rebind`, whose remediation cannot
close an authorization bug. Both existing controls passed — the endpoint is scoped-shaped,
it just does not check ownership. The oracle now enrols a **bystander**, a third account
that takes no part in the probe; if it reaches the victim's canary too, the access was
never provenance-specific and the finding is reclassified `AUTHZ-1` (object-level
authorization), which is kept **out of `CLAUSES`** — the three failure modes are the whole
surface of a provenance failure, and absorbing a reachability-visible bug into them would
make the taxonomy unfalsifiable. This is also the first executable version of the paper's
own boundary claim: the control *measures* whether a finding is TPI-shaped or merely
reachable.

**What it added**
- `oracle.py`: a positive control (the victim must read its own canary back), a negative
  control (a never-valid reference must be refused) and a bystander control (an uninvolved
  account must NOT reach the victim's resource) — the discipline `matrix.run_cell` already
  had per cell, which the oracle lacked entirely; three attribution guards; a new
  `Severity.INCONCLUSIVE` and `Verdict.withheld` / `Verdict.controls` so nothing is silently
  downgraded; and the destructive cross-principal write is now **opt-in** with a verified
  restore (it was on by default, once per confirmation pass, restore unchecked).
- `policy.py`: rules of engagement as data, enforced per action, with an audit trail —
  the M4 prerequisite, buildable without a target.
- `redact.py` + `creds.py`: evidence bundles and audit trails scrubbed of secret-shaped
  material, and no credential the tool presents to a target is a literal in this repo
  (a live run used to leave accounts holding a password published on GitHub).
- Input validation on the one place a model-chosen string reached `getattr(adapter, …)`:
  `register_action("__init__", …)` was accepted and silently re-initialised the adapter
  mid-probe; `register_action("capture_binding", …)` crashed the MCP server.

**What it deliberately did not do:** add a mock feature, or claim any of this constitutes
live validation. The bottom line below is unchanged.

---

## The decision this hands to the owner

The project has reached **the limit of what can be built without a live target.** The real
question is no longer *"what do we build next?"* — it is **"do we authorize a live run, or is the
framework the deliverable?"** Everything of value from here is either gated on that authorization,
or is the CVE-corpus study that tests the thesis. Please decide which, because the alternative —
another shift of mock polish — is motion without progress, and this handoff exists to stop it.
