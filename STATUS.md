# Project Status Board

> **Live coordination doc.** Multiple agents/sessions work on this repo. Read this
> file first; update it last. It is the source of truth for *what stage we are at*
> and *what to do next*.

**Project:** TPI-Hunter — a black-box account-takeover hunting loop built on the
Trust-Provenance Integrity theory (see [`README.md`](README.md) and
[`paper/provenance.html`](paper/provenance.html)).

**★ North star (owner-confirmed): AGENT AS HUNTER.** The end goal is an autonomous
AI agent that hunts TPI account-takeover bugs. The deterministic pieces (adapter,
oracle, harness, dedup) are the agent's **tools + ground truth**; probe generation is
a **strategy**. The mechanical enumerator is just the *baseline* strategist — the real
target is an LLM strategist that adapts. Judge every task by: *does it move us toward a
live agent driving the loop?*

**Baseline (last verified green): 2026-09-15.** Test suite + eight self-tests pass:
`python3 -m unittest discover` (31 tests), and `python3 -m tpihunter.{demo,enum_demo,
learn_demo,synth_demo,agent_demo,live_agent_demo,newaction_demo,report_demo}` (the live
one is gated behind `TPIHUNTER_LIVE=1`). MCP server for the Claude Code agent:
`python3 -m tpihunter.mcp_server` (needs `mcp`).

---

## The loop, and where each stage stands

```
        ┌──────────────── AGENT (strategist) ────────────────┐
   map ─►│ abstract ──► generate ──► EXECUTE ──► JUDGE ──► refine │─► report
 (recon) └  (TPI)      (probes)     (adapter)   (oracle)   (dedup) ┘
```

| stage | component | status |
|-------|-----------|--------|
| abstract | domain types, TPI clauses | ✅ done (M1) |
| judge | `AtoOracle` — the verdict engine | ✅ done (M1) |
| execute | `TargetAdapter` (two-principal) + mock | ✅ done (M1); real target = M4 |
| generate | `enumerator` — composition-relevant interleavings | ✅ done (M2) |
| abstract (auto) | learn FSM (L*) → synthesize action model → generate | ✅ done (M3) |
| refine | `dedup` — causal minimization → distinct bugs | ✅ done (M5) |
| **control** | `AgentHunter` + `Strategist` seam (enumerator / LLM) | ✅ done (M8); API strategist = M9 ✓; Claude-Code/Max strategist = M10 ✓ |
| report | `report` — evidence bundle per distinct bug (markdown/JSON) | ✅ done (M7) |

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

### ✅ M7 — Findings report / evidence bundle  *(done 2026-09-15, session 3)*
Turn each distinct bug (a dedup `Cluster`) into a shareable, submittable report.
- Files: `report.py` (`build_report`/`build_bundle`, `Report.to_markdown`/`.to_dict`,
  `make_run_fn`, `bundle_to_markdown`/`bundle_to_json`), `report_demo.py`;
  `HuntSession.report(fmt)` + a `report` MCP tool; helpful notes added to the mock's
  reset flow so repro steps read cleanly.
- Each report re-runs the minimal repro to capture the full `Trace`+`Verdict`, then
  assembles: title, severity, numbered steps-to-reproduce (with per-step proof), the
  canary evidence that *proves* the takeover, the laundered proof (root cause), the
  violated TPI clause, and remediation derived from the clause statement.
- Target-agnostic by the same injected-execution pattern (`run_fn(plan)->(Verdict,Trace)`);
  a real target (M4) reuses it unchanged. +5 tests (suite 31), 8 demos.

### ✅ M8 — Agent control loop + strategy seam  *(done 2026-09-15)*
Recast probe generation as a pluggable **strategy** so an agent can drive the loop.
- Files: `agent.py` (`AgentHunter`, `HuntState`, `Strategist`, `EnumeratorStrategist`,
  `LLMStrategist`), `agent_demo.py`; `make_candidate` in `enumerator.py`.
- `AgentHunter.hunt(strategist)` loops: propose → execute (harness) → judge (oracle) →
  feed back → dedup. Target-agnostic via an `adapter_factory`.
- `EnumeratorStrategist` = the mechanical enumerator as a (non-adaptive) baseline.
- `LLMStrategist(complete_fn)` = the agent seam: `render_prompt(state)` (TPI briefing +
  known alphabet + history) → `complete_fn` (prompt→text, INJECTED, no hard LLM dep) →
  `parse_proposals`. Fully runnable/testable with a fake completion.
- Accept: `agent_demo` finds the same 2 bugs via both strategies; the fake-LLM agent
  does it in **2 probes vs the enumerator's 124** — the adapt-don't-brute-force point.

### ✅ M9 — Real LLM strategist (API / headless path)  *(done 2026-09-15)*
`complete_fn` backed by a real model, so the loop is a live agent.
- Files: `llm.py` (`make_complete_fn`, `anthropic_complete`, `RefusalError`),
  `live_agent_demo.py`; `agent.py`/`dedup.py` exported from `__init__`.
- Uses the official `anthropic` SDK, **lazy-imported** so the core stays stdlib-only.
  Default model **`claude-opus-5`** (Opus-tier), adaptive thinking. `client` is
  injectable → tested with a fake (no network); `live_agent_demo` is gated behind
  `TPIHUNTER_LIVE=1` so the green-check never makes a paid call.
- **Billing note:** this path calls the **Messages API** — pay-per-token API billing,
  *separate from a Claude Max/Pro subscription*. It's the right path for CI / headless
  / non-Claude-Code runs. To hunt on a **Max subscription**, use M10.
- Accept: live wiring test (fake client → `complete_fn` → `LLMStrategist` →
  `AgentHunter`) finds both bugs in 2 probes; defaults assert Opus + adaptive thinking.

### ✅ M11 — New-action synthesis (agent extends its own alphabet)  *(done 2026-09-15)*
The agent proposes *new* actions for flows the fixed alphabet lacks — the biggest lever
for finding bugs an enumerator never could.
- Files: `mcp_tools.py` (`register_action`), `agent.py` (`LLMStrategist` parses
  `new_actions`), `newaction_demo.py`; supporting generalizations in `oracle.py`
  (effect-based diagnosis so new verbs classify), `harness.py` (generic dispatch:
  `adapter.<action>(principal, **params)`), `dedup.py` (trigger-aware signature so a bug
  via a new verb is a distinct finding), `mock_target.py` (a real `magic_link` flow).
- Demo story: on `mock-patched` both known laundering flows are fixed, so the fixed
  alphabet finds nothing — but the fix was applied to SSO and NOT the parallel
  passwordless `magic_link` flow. The agent registers `magic_link` and finds it (TPI-1).
- Registration never mutates the global `ACTIONS`; new verbs execute only if the target
  implements them (else they compose but no-op, flagged as `unbound_actions`).
- +4 tests (suite 27), 7 demos green.

### ✅ M10 — Claude-Code / Max-subscription strategist  *(done 2026-09-15)*
**The Opus agent in the Claude Code CLI** is now a supported strategist, so hunting runs
on the owner's **Claude Max 20x subscription** instead of pay-per-token API billing.
- Files: `mcp_tools.py` (`HuntSession`, stdlib, tested), `mcp_server.py` (thin FastMCP
  wrapper, lazy `mcp` import so the core never needs it).
- Tools exposed: `briefing()`, `list_actions()`, `run_probe(steps) -> verdict`,
  `findings()` (deduplicated distinct bugs), `reset(target)`.
- Setup: `pip install "mcp[cli]"` then
  `claude mcp add tpihunter -- python3 -m tpihunter.mcp_server`; in a session, "use the
  tpihunter tools to hunt the mock." Claude Code (on Max) IS the strategist — no API key.
- Accept: through the tool surface, the TPI-1 and TPI-4 probes return takeover verdicts
  and `findings()` returns 2 distinct bugs; the patched target returns safe (invariant).
  +5 tests (suite 23).

---

## Pick this up next

North star is **agent as hunter** — reachable on the owner's **Max subscription** via the
MCP server (M10), the agent extends its own alphabet (M11), and findings render as
submittable reports (M7). The whole mock loop is complete end-to-end.

⭐ **Course correction (2026-09-15):** the real engagement (`~/singularity/grab`, an
authorized Grab HackerOne ATO campaign) is being pursued via an **offline TPI lens**
(`~/singularity/grab/ato/TPI_LENS.md`), not a live `TargetAdapter` — its ROE forbids
scripted account creation and its toolchain out-classes the mock plumbing. So **M4 is
deferred**, not the next task. In priority order now:

1. **Iterate the TPI lens on the real engagement** (offline, in the *grab* repo, not this
   one). If the owner promotes a TPI-L composition cell (e.g. TPI-L1 logout-propagation),
   help turn it into a house-format `hunts/G<n>/HYPOTHESIS.md` — through *their*
   `tools/hunt.py preflight` gate; **no firing without the owner's OK; filing is theirs.**
2. **Robustness (do-able now against the mock, de-risks any future live adapter):**
   oracle retry on a suspect verdict, and a param model richer than email-only for
   synthesized actions (magic-link codes, invites, aliasing).
3. **M4 — real `TargetAdapter`** — only if a promoted TPI-L hypothesis genuinely needs a
   bespoke two-principal runner the *grab* toolchain can't express; ROE hard-wired
   (X-Bug-Bounty header, own-accounts-only, in-scope allowlist, preflight-gated).
4. **W-method conformance oracle** for the learner (soundness within a bound).

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

- **2026-09-15** — *Session 3 (cont).* **M4 redirected — TPI as an offline lens over a real
  engagement, not a live adapter.** Owner named the real target: an active, authorized Grab
  HackerOne engagement at `~/singularity/grab` (separate repo, mature ATO model — 90 threat
  statements, its own preflight/rig toolchain). Chose (via AskUserQuestion) the offline
  *lens* integration over building a live `TargetAdapter`, because (a) that engagement's ROE
  forbids scripted account creation — which TPI-Hunter's `register` does — and (b) its
  toolchain already out-classes the mock plumbing. Deliverable: `~/singularity/grab/ato/
  TPI_LENS.md` — maps the TPI clause catalog onto their T-ATO rows (compression), builds the
  mutation×predating-binding **composition matrix**, and ranks the open composition cells
  (TPI-L1 logout-propagation is the cheap reversible keystone). **No live requests sent;
  nothing filed.** Honest finding: their model already embodies composition thinking; TPI's
  add is the unifying invariant + the coverage matrix, not new mechanism. *Implication for
  this repo:* M4 (live adapter) is **deferred, not the next task** — the lens is the chosen
  vehicle; only build a bespoke ROE-enforced runner if a promoted TPI-L hypothesis needs one.
- **2026-09-15** — *Session 3 (third contributor).* **M7 done: evidence bundle.** Added
  `report.py` — turns each distinct bug (dedup `Cluster`) into a submittable report by
  re-running its minimal repro to capture the full `Trace`+`Verdict`, then rendering steps
  to reproduce, the canary evidence proving the takeover, the laundered proof (root cause),
  and remediation from the violated TPI clause. `Report.to_markdown()`/`.to_dict()`,
  bundle helpers, `HuntSession.report(fmt)` + a `report` MCP tool, `report_demo.py`. Kept
  it target-agnostic via an injected `run_fn`. Also added clean repro notes to the mock's
  reset flow. +5 tests (suite 31), 8 demos, import isolation intact. **Next: M4 — real
  `TargetAdapter`** (still blocked on an authorized target), or the robustness items that
  de-risk it.
- **2026-09-15** — *End of shift — handing to the third contributor.* The mock loop is
  complete end-to-end (M0–M11): theory → oracle → two-principal adapter → learner →
  synthesis → enumerator → dedup → agent control loop → live via the API strategist *and*
  the Claude Code agent on the owner's Max subscription (MCP) → agent extends its own
  alphabet. 27 tests + 7 demos green; nothing half-done. **Next session: read
  [`HANDOFF.md`](HANDOFF.md) first, then start M4 — a real `TargetAdapter`** (the one
  milestone blocked on an authorized target from the owner; ask for one). Everything else
  is polish (M7 evidence bundle) or robustness (adapter backoff, oracle retry, richer
  synthesized-action params). HANDOFF.md was refreshed to current state for a fresh reader.
- **2026-09-15** — *Session 3 (cont).* **M11 done: new-action synthesis.** The agent can
  now register actions the fixed alphabet lacks — `HuntSession.register_action` (MCP path)
  and `LLMStrategist` parsing `new_actions` (API path). Generalized the stack to support
  it: effect-based oracle diagnosis (new verbs classify), generic harness dispatch,
  trigger-aware dedup signature (a bug via a new verb is a *distinct* finding), and a real
  `magic_link` flow in the mock that the *patched* target forgot to fix. `newaction_demo`
  shows the payoff: patched target, fixed alphabet finds 0 bugs; the agent hypothesizes
  `magic_link` and finds a TPI-1 laundering an enumerator never could. +4 tests (27), 7
  demos. **Next: M4 — real `TargetAdapter`** (blocked on an authorized target).
- **2026-09-15** — *Session 3 (cont).* **M10 done: Claude-Code / Max-subscription
  strategist.** Added `mcp_tools.py` (`HuntSession` — the hunt loop as agent-drivable
  tools: `briefing`/`list_actions`/`run_probe`/`findings`/`reset`; stdlib, tested) and
  `mcp_server.py` (thin FastMCP wrapper, lazy `mcp` import so the core never needs it).
  `pip install "mcp[cli]"` + `claude mcp add tpihunter -- python3 -m tpihunter.mcp_server`
  and the Opus agent in Claude Code hunts on the Max subscription — no API key. Verified
  through the tool surface: TPI-1/TPI-4 probes → takeover, `findings()` → 2 distinct bugs,
  patched target → safe. +5 tests (suite 23). **Next: new-action synthesis** (agent
  proposes new ActionSpecs for target-specific flows) — see *Pick this up next*.
- **2026-09-15** — *Session 3 (cont).* **M9 done (API path).** Added `llm.py` — a real
  `complete_fn` on the `anthropic` SDK (lazy-imported; core stays stdlib), default
  `claude-opus-5` + adaptive thinking, injectable client, tested with a fake. Added
  `live_agent_demo.py` (gated by `TPIHUNTER_LIVE=1`). +3 tests (suite 19). **Owner
  clarified they hunt on a Claude Max 20x subscription** — the API path bills
  separately, so **M10 (Claude-Code/MCP strategist) is now the priority**: make the CLI
  Opus agent the strategist so hunting runs on the subscription. See M10 / *Pick this up
  next*.
- **2026-09-15** — *Session 3 (cont).* **Goal confirmed by owner: AGENT AS HUNTER**,
  and **M8 built** to serve it. Recast probe generation as a pluggable `Strategist`
  and added `AgentHunter` (`agent.py`): the enumerator is now just the baseline
  strategist, and `LLMStrategist(complete_fn)` is the agent seam — injectable model
  function, no hard LLM dependency, fully testable. `agent_demo` shows a fake-LLM agent
  finding the same 2 bugs in **2 probes vs the enumerator's 124**. +4 tests (suite 16);
  5 demos green. **Next: M9 — wire a real LLM strategist** (owner decision needed on
  model/runtime + MCP vs in-process; see *Pick this up next*).
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
