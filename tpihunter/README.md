# TPI-Hunter

A black-box **account-takeover hunting loop** built on the Trust-Provenance
Integrity (TPI) theory from the working paper *Provenance, Not Reachability*.

It is the practical half of that theory: where the paper argues ATO is a
**provenance** failure that lives in the *composition* of two principals over a
shared store, this package gives an autonomous agent the one thing that makes
hunting possible — a **verdict**: *did principal A gain access that only principal
V should have, and which TPI clause was broken to allow it?*

```
python3 -m tpihunter.demo
```

runs the pre-hijacking probe against a built-in mock, on both a vulnerable and a
patched target, and prints the oracle's verdicts. The same probe yields TAKEOVER
on one and SAFE on the other — the scaffold is self-validating.

## The loop

```
   map ──► abstract ──► generate probe ──► EXECUTE ──► JUDGE ──► refine
 (recon)  (TPI terms)   (interleavings)   (adapter)   (oracle)
                                          └────────── this package ──────────┘
```

`execute` and `judge` are the hard, decisive half — the half a formal model (e.g.
Alloy) cannot touch, because it never sees the real system. That is what this
package is. `generate` is deliberately *data* (see `probes.py` / `harness.Plan`)
so the hypothesis layer — an LLM now, an enumerator later — can produce and mutate
attacks without touching the runner.

## Why two principals

Laundering, the dominant ATO class, is **invisible to a single session**: it needs
the victim's genuine proof to be read by the attacker's binding across one shared
store row. So the adapter keeps an *independent* authenticated context per
principal, and every action is executed *as* a named principal.

## The oracle (the star)

`AtoOracle` is **canary-based, differential, and provenance-labeling**:

1. `arm()` — capture the victim's identity and what the attacker can *already* see
   about the victim before any canary exists (baseline).
2. `plant()` — as the victim, write a random 128-bit secret into a private
   resource. This is the ground truth of "V's private state".
3. `assess()` — re-probe as the attacker and report **TAKEOVER only on hard
   evidence**: an exact canary match, an identity confluence, or a confirmed
   cross-principal write. Then diagnose *which* TPI clause the trace shows was
   violated.

**False-positive discipline.** The canary is compared by exact match, so reflected
input or a public field cannot fake a read; identity confluence compares the
resolved account identity, which a correctly-scoped app never shares between two
principals. The `patched=True` toggle on the mock is the oracle's own regression
test — a detector that fired on both the bug and its fix would be worthless.

## The revocation matrix (the second mode)

The oracle hunts *confluence* — two principals, does the attacker read the victim's
data. But the sharpest expression of Composition-Blindness is a different,
**single-principal, over-time** question, and it is the mode that fits a real
authorized engagement (own-account, reversible, reads no one else's data):

> for each binding **B** minted before a credential-mutating transition **M**,
> does **M** revoke **B**?

`matrix.py` makes that a computable grid — mutations as columns, ways-of-minting-a-session
as rows, each cell a measured `revoked | survived`. A **SURVIVED** cell is TPI-4
laundering: a stolen session that outlives the owner's own logout or password reset.

```
python3 -m tpihunter.matrix_demo
```

Against the **patched** mock — the target whose pre-hijacking bugs are all fixed — the
matrix still finds red cells: the password-reset flow revokes predating sessions, but the
parallel **logout** flow does not. One red cell in a green column is Composition-Blindness
made visible, and it is exactly the shape a real engagement surfaces (a fix that didn't
propagate to a parallel flow). Every cell carries its own **positive control** (B
authenticated before M) and **negative control** (a never-valid handle is rejected), so a
SURVIVED verdict can't be a broken-check artifact. Drive it from the agent with the
`revocation_matrix()` tool; a SURVIVED cell renders as a submittable report via
`report.revocation_report`.

**Cross-plane (the subtle one).** A credential is checked on several *verify-point planes*
(route surfaces owned by different teams), and revocation can be per-plane state. So each
cell is measured **on every plane**. A mutation that revokes on the plane it was issued on
but leaves the credential alive on another surfaces as a **SPLIT** — the bug a same-plane
test calls fixed. The `mock-plane-split` target models it: `logout` revokes only its `mts`
plane while the binding lives on `auth`. This is the exact shape of the open cross-plane
cell on a real engagement (a plane-local logout, the token still valid on another plane).

**The whole lifecycle, honestly.** Rows are ways to *mint* a binding — a password session,
an SSO session, and an enrolled **passkey/biometric factor** (a durable binding that outlives
the session that made it). Columns are mutations — logout, password reset, email change. Not
every mutation must revoke every kind: a passkey is *not* lost on logout, so that cell is
`n/a`, never a false finding (each `MutationSpec` declares the kinds it is obliged to revoke).
But a passkey surviving a **password reset** *is* the bug — `passkey_factor × password_reset`
SURVIVES even on the `mock-patched` target, because the fix reached the session layer and not
the factor layer: an attacker-enrolled factor outlives the victim's own remediation, a durable
account takeover (the shape of Grab T-ATO-22, Critical).

## Files

| file | role |
|------|------|
| `types.py` | principals, identifiers, channels, proof events, observations |
| `clauses.py` | the TPI invariant clauses a verdict can cite |
| `channels.py` | out-of-band providers (email inbox, TOTP) behind interfaces |
| `adapter.py` | `TargetAdapter` protocol (alphabet Σ) + the `Trace` it records |
| `oracle.py` | `AtoOracle` — the verdict engine |
| `harness.py` | `Plan`/`Step` + `run_plan`: probes as data, run with oracle checkpoints |
| `mock_target.py` | a deliberately vulnerable in-memory target + its adapter |
| `probes.py` | hand-written TPI probe plans |
| `enumerator.py` | **generates** probe plans — composition-relevant interleavings |
| `dedup.py` | collapses near-duplicate findings to distinct bugs (minimization + signature) |
| `sul.py` | System-Under-Learning interface + a single-account view of the mock |
| `learner.py` | L* Mealy-machine learner (black-box automata learning) |
| `synthesis.py` | turns a learned machine into the enumerator's action model |
| `agent.py` | **agent-as-hunter**: `AgentHunter` loop + `Strategist` seam (enumerator / LLM) |
| `llm.py` | real-model backend for `LLMStrategist` (lazy `anthropic`; default `claude-opus-5`) |
| `mcp_tools.py` | `HuntSession` — the hunt loop as agent-drivable tools (stdlib) |
| `mcp_server.py` | MCP server exposing those tools (lazy `mcp`; for the Claude Code agent) |
| `matrix.py` | **revocation matrix** — single-principal lifecycle mode (does a mutation revoke a predating binding?) |
| `report.py` | evidence bundles — each distinct bug as a submittable markdown/JSON report |
| `demo.py` | end-to-end self-test (one hand-written probe) |
| `enum_demo.py` | self-test of the enumerator (zero hand-written probes) |
| `learn_demo.py` | self-test of the learner (recovers the mock's auth FSM) |
| `synth_demo.py` | self-test of the closed loop (learn → synthesize → enumerate) |
| `agent_demo.py` | self-test of the agent loop (enumerator vs a fake-LLM strategist) |
| `live_agent_demo.py` | the real LLM strategist on the mock (gated by `TPIHUNTER_LIVE=1`) |
| `newaction_demo.py` | the agent registering a new action to find a bug beyond the alphabet |
| `matrix_demo.py` | the revocation matrix on a 'patched' target — one flow still leaks |
| `report_demo.py` | hunt the mock, then print the submittable evidence bundle |

Tests live in `../tests/` (stdlib `unittest`): `python3 -m unittest discover`.

## Hunting a real target

Implement one `TargetAdapter` (see `adapter.py`). The only real work:

- **Per-principal transport.** One `httpx.Client` (its own cookie jar / token) per
  principal, so two contexts run truly independently.
- **Identity lifecycle → real endpoints.** Back `register / login / sso_login /
  reset_request / reset_consume` with the app's flows; extract tokens and links
  from responses and from a `channels.EmailChannel` you actually control (a
  catch-all mailbox, IMAP, Mailosaur…).
- **Oracle surface.** Back `whoami` with the app's "my account" endpoint, and
  `plant_marker / read_marker / write_marker` with a private per-account resource
  (a profile note, a saved field). That resource holding the canary is the entire
  ground truth the oracle needs.

Then reuse `AtoOracle`, `run_plan`, and the plans in `probes.py` unchanged.

## Generating probes

`enumerator.py` produces plans instead of hand-writing them:

```
python3 -m tpihunter.enum_demo
```

It enumerates two-principal interleavings of the alphabet and keeps only those
the theory says could be a laundering/composition bug — the
**composition-relevance filter**: both principals act over the shared resource
*and* a trust-raise or credential-change occurs on it. That filter is the
Composition-Blindness theorem used as a search prune. Generation is
channel-aware: an action that needs control of the target identifier
(`sso_login`, `reset_consume`) is only assigned to a principal who controls it.

Against the built-in mock it rediscovers the pre-hijacking bug (**TPI-1**) and,
with no hand-written probe, finds a distinct one (**TPI-4**, session survives a
victim's password reset). Every finding closes under the patch — the enumerator
proposes, the oracle disposes.

## Deduplicating findings

The enumerator over-generates on purpose (every interleaving, every padding), so one
bug appears as dozens of near-identical findings. `dedup.py` collapses them to the
distinct bugs, driven by the authoritative oracle verdict:

1. **Causal minimization** — delta-debug each fired probe against the oracle, dropping
   steps as long as the verdict stays a takeover *of the same clause*. What survives
   is the minimal repro.
2. **Causal signature** — group by `(clause, set of effect-classes in the core)`.
   Role, count, and interleaving are abstracted away (the clause already encodes the
   who/what), so "attacker seeds, victim raises" is one TPI-1 bug however it
   interleaves.

On the mock, **106 findings collapse to 2 distinct bugs** (TPI-1 in 2 steps, TPI-4 in
3), each with a minimal repro — see the tail of `python3 -m tpihunter.enum_demo`.

## Agent as hunter (the goal)

The end goal is an autonomous agent driving this loop. Everything above is the agent's
**tools + ground truth**; probe generation is a **strategy**. `agent.py` makes that
explicit:

```
python3 -m tpihunter.agent_demo
```

- `AgentHunter.hunt(strategist)` loops: propose → execute → judge → feed back → dedup.
  It is target-agnostic (an `adapter_factory`), so the same loop runs on the mock now
  and a real `TargetAdapter` later.
- `EnumeratorStrategist` is the mechanical enumerator recast as a (non-adaptive)
  baseline strategist.
- `LLMStrategist(complete_fn)` is the agent seam. `render_prompt(state)` hands the model
  the TPI briefing, the known action alphabet, and the history of what it has tried;
  `complete_fn(prompt) -> text` is **injected**, so there is no hard LLM dependency and
  the seam is testable with a fake completion. Wire `complete_fn` to a real model to get
  a live agent.

In the demo the fake-LLM agent finds the same 2 bugs in **2 probes vs the enumerator's
124** — the point of agent-as-hunter: adapt, don't brute-force.

### Two ways to make the strategist real

- **API / headless** (`llm.py`): `LLMStrategist(make_complete_fn())` calls the `anthropic`
  SDK (default `claude-opus-5`, adaptive thinking). Best for CI / headless / non-Claude-
  Code runs. **Bills pay-per-token on the Messages API — separate from a Claude Max/Pro
  subscription.** Run it with `TPIHUNTER_LIVE=1 python3 -m tpihunter.live_agent_demo`.
- **Claude Code / Max subscription** (`mcp_server.py`): expose the loop's primitives as an
  **MCP server** so the Opus agent in the Claude Code CLI drives the hunt — Claude Code
  *is* the strategist, running on your subscription, no API key. This is the path for
  hunting on a Max plan:

  ```bash
  pip install "mcp[cli]"
  claude mcp add tpihunter -- python3 -m tpihunter.mcp_server
  ```

  Tools: `briefing()`, `list_actions()`, `run_probe(steps)`, `register_action(...)`,
  `findings()`, `reset(target)`. The agent reads the briefing, proposes probes, adapts to
  verdicts, and reports the distinct bugs. `HuntSession` in `mcp_tools.py` holds all the
  logic (stdlib, tested); the server is a thin wrapper.

## New-action synthesis — the agent escapes the fixed alphabet

The built-in alphabet is a *starting point*, not the whole target. Real auth systems have
flows it lacks (magic-link login, device pairing, org invites, email aliasing), and a fix
applied to one flow is often missing on a parallel one. The agent can register a new
action and probe with it — `register_action(id, effect, requires, needs_control)` on the
MCP path, or a `new_actions` block in the `LLMStrategist` reply on the API path.

```
python3 -m tpihunter.newaction_demo
```

On the *patched* mock, both known laundering flows are fixed — so the fixed alphabet finds
nothing. But the fix was applied to SSO and not to the parallel `magic_link` flow; the
agent registers `magic_link` and finds a **TPI-1 laundering an enumerator never could**.
Supporting this required an effect-based oracle diagnosis (new verbs classify), generic
harness dispatch, and a trigger-aware dedup signature (a bug via a new verb is a distinct
finding). Registration never mutates the global alphabet.

## Reporting findings — the evidence bundle

Once bugs are found, `report.py` turns each distinct one into a shareable, submittable
report (`HuntSession.report(fmt)` / the `report` MCP tool, or `build_bundle(...)` directly):

```
python3 -m tpihunter.report_demo
```

It re-runs each bug's minimal repro to capture the full `Trace`+`Verdict`, then renders —
in markdown or JSON — the title, severity, numbered **steps to reproduce** (with the proof
each step emits), the **canary evidence** that proves the takeover, the **laundered proof**
(root cause), the violated TPI clause, and **remediation** derived from the clause
statement. Like the rest of the package it is target-agnostic: execution is an injected
`run_fn(plan) -> (Verdict, Trace)`, so a real target (M4) reuses it unchanged.

## Automata learning

`learner.py` learns the Mealy machine a target actually implements from black-box
queries (Angluin's L* + a random-walk equivalence oracle):

```
python3 -m tpihunter.learn_demo
```

Against the mock it recovers a 9-state auth FSM — session, *verified* (the
`sso_login`→`OK_VERIFIED` trust-raise), reset-token, and logged-out dimensions —
from ~1.5k membership queries. Wrap a real target in the `SUL` interface
(`reset()`, `step`) to learn *its* machine.

## Closing the loop: learn → synthesize → generate

`synthesis.py` turns a learned machine into the enumerator's action model, so
probe generation runs on *observed* behaviour rather than the hand-coded `ACTIONS`
table:

```
python3 -m tpihunter.synth_demo
```

It derives each action's ordering (`requires`, from the FSM structure) and effect
(SEED / RAISE / CRED / REQUEST, from the output signature — e.g. a verified session
is a RAISE, a session gated behind a token is a CRED). Only `needs_control` is
declared per channel, since single-account traces always control the identifier.
Against the mock the synthesized effects **match the hand-coded model exactly**, and
generation reproduces the same {TPI-1, TPI-4} findings — the static table is no
longer trusted. Pass the result via `enumerate_plans(..., specs=synthesized)`.

## Roadmap

The mock loop is complete end-to-end (learn → synthesize → generate → judge → dedup →
agent-driven, live via API and the Claude Code MCP agent → new-action synthesis → report).
What's left:

- **Real `TargetAdapter`** (the frontier): drive an authorized live app — one `httpx`
  client per principal, real flows, a real mailbox channel. The whole stack then runs
  against something real. Blocked on an authorized target.
- **Robustness for real targets**: adapter rate-limit/backoff, oracle retry on a suspect
  verdict, a richer param model for synthesized actions (codes, invites, aliasing).
- **W-method conformance oracle**: replace the learner's random-walk equivalence
  check so the learned machine is sound within a bound.
- **Alloy** (optional, offline): a relational model as an *attack-shape compiler*
  that pre-computes violating interleavings to seed the enumerator — a design-time
  force-multiplier, never in the live loop.

## Scope

Run only against systems you are authorized to test. This is a research and
authorized-testing tool; the mock target exists so the loop can be exercised and
validated without touching anyone's infrastructure.
