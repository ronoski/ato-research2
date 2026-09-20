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
input or a public field cannot fake a read. The `patched=True` toggle on the mock is
the oracle's own regression test — a detector that fired on both the bug and its fix
would be worthless.

**Controls, because a measurement without controls is an anecdote.** Both directions
of error are expensive — a false TAKEOVER is a bogus Critical in someone's tracker, a
false SAFE teaches the agent a surface is secure — so every assessment carries the same
control discipline the revocation matrix applies per cell:

* *positive*: after planting, the victim must read its own canary back. If it cannot,
  no ground truth exists, every comparison is vacuous, and the verdict is
  `INCONCLUSIVE` — never a confident SAFE.
* *negative*: a reference that names nothing must be refused. A target that answers it
  with data has an unscoped read endpoint, so a by-reference read proves nothing and
  that evidence is dropped.

**Attribution, because access is not a finding unless the probe caused it.** Three
guards gate a non-SAFE severity, all computable from the black-box trace:

* *independence* — if the attacker already resolved to the victim's identity **before
  the attacker acted**, the principals were never independent (a shared ops mailbox, a
  family plan, a tenant seat, an SSO org seat, or a harness that gave two principals one
  context). Void, not a finding.
* *justification* — if the attacker itself demonstrated control of the contended
  identifier over a possession channel (IdP, inbox, SMS, TOTP, WebAuthn), its access has
  justifying provenance. That is a co-owner, not laundering. This is the TPI thesis
  turned on the oracle's own output.
* *attribution* — no successful attacker action in the trace means nothing to credit.

A guard never silently rewrites a verdict: `Verdict.withheld` carries the reason code
and `Verdict.controls` the control outcomes, so an agent and a human both see why.
`python3 -m tpihunter.safety_demo` runs the three probes that used to grade TAKEOVER at
0.90–0.99 on no attack at all, beside the real bug still firing at 0.99.

**The diagnosis control — is the access provenance-specific at all?** A takeover is not
automatically a *provenance* takeover. If the app has a flat IDOR (any session can read
any resource by reference), the attacker reads the victim's canary and the oracle used to
report it as **TPI-1, revoke-on-rebind** — a real bug under a clause whose remediation
cannot close it. So the oracle enrols a **bystander**: a third account that takes no part
in the probe (`TargetAdapter.enrol_bystander`, optional, verified independent at `arm()`).
If the bystander can read the victim's canary too, the access was never provenance-
specific, and the finding is reclassified as `AUTHZ-1` — *object-level authorization*,
which is deliberately **not** a TPI clause:

```
TAKEOVER  TPI-1    a genuinely laundering target      bystander=enrolled and independent
TAKEOVER  AUTHZ-1  a target with flat IDOR instead    bystander=enrolled and independent
TAKEOVER  TPI-1    ...the same target, control off    bystander=disabled      <- the old answer
```

`clauses.BROAD_AUTHORIZATION` stays out of `CLAUSES` on purpose. The three failure modes
(gap / forgery / laundering) are the whole surface over which `justifies(prov(B), B)` can
be negated; widening them to absorb a plain authorization bug would make the taxonomy
unfalsifiable by swallowing its own complement. A flat IDOR is single-principal and
reachability-visible — the class the paper argues TPI is *not* about. Use `CLAUSES` where
the theory is meant, `CATALOG` to resolve whatever id a verdict carries. Without an
adapter that implements `enrol_bystander` the oracle still detects the takeover; it just
records `controls["bystander"] = "unavailable"` and cannot discriminate.

**Mutation is opt-in.** Proving the attacker can *write* the victim's resource is the
strongest evidence there is and the only destructive thing the oracle does, so it is off
by default (`AtoOracle(..., mutate=True)` enables it). When on, it writes a value that is
never the canary, and the restore is verified — a failure is recorded in
`Verdict.controls`, not left silently corrupting the target.

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
| `clauses.py` | the TPI invariant clauses a verdict can cite, plus `BROAD_AUTHORIZATION` (`AUTHZ-1`) — deliberately outside the taxonomy |
| `channels.py` | out-of-band providers (email inbox, TOTP) behind interfaces |
| `adapter.py` | `TargetAdapter` protocol (alphabet Σ) + the `Trace` it records |
| `oracle.py` | `AtoOracle` — the verdict engine |
| `harness.py` | `Plan`/`Step` + `run_plan`: probes as data, run with oracle checkpoints |
| `mock_target.py` | a deliberately vulnerable in-memory target + its adapter |
| `probes.py` | hand-written TPI probe plans |
| `enumerator.py` | **generates** probe plans — composition-relevant interleavings |
| `dedup.py` | collapses near-duplicate findings to distinct bugs (minimization + signature) |
| `sul.py` | System-Under-Learning interface + a single-account view of the mock |
| `learner.py` | L* Mealy-machine learner (black-box automata learning); default equivalence oracle is the W-method |
| `wmethod.py` | W-method conformance oracle — certifies a learned machine sound up to `n + extra_states` states |
| `synthesis.py` | turns a learned machine into the enumerator's action model |
| `agent.py` | **agent-as-hunter**: `AgentHunter` loop + `Strategist` seam (enumerator / LLM); per-probe reason codes, a `Coverage` map, and a `patience` stop (M16) |
| `llm.py` | real-model backend for `LLMStrategist` (lazy `anthropic`; default `claude-opus-5`) |
| `mcp_tools.py` | `HuntSession` — the hunt loop as agent-drivable tools (stdlib) |
| `mcp_server.py` | MCP server exposing those tools (lazy `mcp`; for the Claude Code agent) |
| `matrix.py` | **revocation matrix** — single-principal lifecycle mode (does a mutation revoke a predating binding?) |
| `report.py` | evidence bundles — each distinct bug as a submittable markdown/JSON report |
| `profile.py` | **a target described as data** — `TargetProfile`: endpoints, extraction, accounts. What an agent authors instead of writing an adapter |
| `live.py` | `LiveAdapter` + `ScopedTransport` — drives a profile over HTTP, one transport per principal, every URL and redirect checked against the policy |
| `validate.py` | `validate_target()` — prove the profile works before any verdict from it counts |
| `http_mock.py` | the vulnerable mock behind a real socket (loopback only), plus the worked example profile |
| `policy.py` | **rules of engagement as data** — `EngagementPolicy` + `guard()`: scope allowlists, destructive-action gates, budget, dry run, audit log |
| `redact.py` | secret scrubbing for everything the tool emits (reports, audit trail) |
| `creds.py` | per-run credentials and identifiers — never literals in source |
| `flaky.py` | `FlakyAdapter` — drops the attacker's reads (seeded); exercises oracle confirmation |
| `demo.py` | end-to-end self-test (one hand-written probe) |
| `enum_demo.py` | self-test of the enumerator (zero hand-written probes) |
| `learn_demo.py` | self-test of the learner (recovers the mock's auth FSM) |
| `synth_demo.py` | self-test of the closed loop (learn → synthesize → enumerate) |
| `agent_demo.py` | self-test of the agent loop (enumerator vs a fake-LLM strategist) |
| `live_agent_demo.py` | the real LLM strategist on the mock (gated by `TPIHUNTER_LIVE=1`) |
| `newaction_demo.py` | the agent registering a new action to find a bug beyond the alphabet |
| `matrix_demo.py` | the revocation matrix on a 'patched' target — one flow still leaks |
| `report_demo.py` | hunt the mock, then print the submittable evidence bundle |
| `retry_demo.py` | oracle confirmation — a flaky target can't flip the verdict (M13) |
| `alias_demo.py` | richer params — drive a flow that needs a second identifier (M14) |
| `coverage_demo.py` | agent situational awareness — reason codes, coverage map, patience-stop (M16) |
| `safety_demo.py` | the oracle's controls and the engagement policy — what stops this doing the wrong thing to a real system |
| `live_demo.py` | the live path end to end — describe an HTTP target, prove it, hunt it, same bugs |

Tests live in `../tests/` (stdlib `unittest`): `python3 -m unittest discover`.

## Hunting a real target

Nobody writes an adapter. A target is **described as data** and the description is
**proved before it is trusted**:

```
python3 -m tpihunter.live_demo
```

starts the vulnerable mock on a loopback HTTP port, describes it with a `TargetProfile`,
validates the description, and then runs the ordinary hunt against it — finding the same
TPI-1 and TPI-4, with the same minimal repros, through sockets and cookies and JSON.

### Who authorizes what

The trust boundary matters more than the plumbing. **The operator authorizes the scope;
the agent only describes the target.** A policy written by the agent it constrains is not
a control, so the engagement lives on disk, out of band:

```bash
export TPIHUNTER_ENGAGEMENT=/path/to/engagement.json
```
```json
{"name": "acme-bugbounty",
 "authorized_by": "security@acme.example, ticket SEC-1421, 2026-09-20",
 "identifiers": ["pentest-a@acme.example", "pentest-v@acme.example", "pentest-c@acme.example"],
 "hosts": ["staging.acme.example"],
 "allow_credential_change": false, "max_actions": 500, "min_interval": 0.5}
```

The agent then calls `set_target(profile)` and `validate_target()`. A profile naming an
identifier or host the operator did not authorize is refused **before a request is sent**,
and this session cannot widen the engagement — only the operator can.

### The profile

One request per alphabet action, plus the oracle surface. Placeholders are a closed set
(`{email} {password} {new_password} {new_email} {alias} {token} {code} {value} {ref}
{role}`) and an unknown one is a parse error, never a literal sent to the target:

```json
{"name": "acme-staging", "base_url": "https://staging.acme.example",
 "accounts": {"victim": {"email": "...", "password": "..."},
              "attacker": {"email": "...", "password": "..."},
              "bystander": {"email": "...", "password": "..."}},
 "session": {"kind": "cookie"},
 "actions": {
   "login": {"method": "POST", "path": "/api/login", "expect": [200],
             "json": {"email": "{email}", "password": "{password}"}},
   "sso_login": {"method": "POST", "path": "/api/sso", "expect": [200],
                 "json": {"email": "{email}"}}},
 "oracle": {
   "whoami": {"method": "GET", "path": "/api/me", "expect": [200],
              "extract": {"identity": {"json": "user.id"}}},
   "plant_marker": {"method": "PUT", "path": "/api/me/note", "expect": [200],
                    "json": {"note": "{value}"}, "extract": {"ref": {"json": "id"}}},
   "read_marker": {"method": "GET", "path": "/api/me/note", "expect": [200],
                   "extract": {"value": {"json": "note"}}},
   "read_marker_by_ref": {"method": "GET", "path": "/api/users/{ref}/note",
                          "expect": [200], "extract": {"value": {"json": "note"}}}},
 "channel": {"method": "GET", "path": "/testing/inbox?address={email}", "expect": [200],
             "extract": {"token": {"regex": "token=([A-Za-z0-9]+)"}}}}
```

`http_mock.profile_for()` is a complete working one — copy it and change the routes.
An action name the profile declares but the default alphabet lacks (a magic link, a
device pairing, an org invite) is reachable from `register_action`, so the agent can
extend the alphabet and have a real request behind it.

### Proving it works

An unvalidated profile is the worst failure mode this tool has: one wrong field — a login
route that returns 200 on failure, an `identity` extracted from a null, a marker route
that silently does nothing — and every probe returns a confident SAFE for a target it
never correctly reached. An agent reads that as "secure" and stops looking. So probing a
live target is **blocked** until `validate_target()` passes:

```
PASS  engagement        — policy 'acme-bugbounty' authorizes 3 identifier(s) and host staging.acme.example
PASS  reachable         — base_url answered HTTP 200
PASS  session:victim    — login -> session, identity 41ab…
PASS  session:attacker  — login -> session, identity 7c02…
PASS  independence      — the two principals resolve to two different accounts
PASS  canary            — planted and read back by the owner
PASS  by_ref            — the owner can read its own resource
PASS  baseline_scoping  — a second account is refused the victim's resource
PASS  negative_control  — an invalid reference is refused
PASS  bystander         — third account enrolled, independent
FAIL  channel           — reset_request sent, but no token came back from the channel
                          fix: `channel` (path/extract.token) must fetch the message
                          delivered to {email} and pull the token out.
```

Every failure names the field to fix, so the loop is: fix one line, re-validate. It also
reports what it left on the target (accounts created, markers planted, tokens outstanding).
A `baseline_scoping` failure is not a profile error — it is a finding, reported before the
hunt even starts.

### What the transport enforces

`live_adapter()` builds both layers over one audit log. The transport enforces what an
action-level guard cannot see — **every URL, including every redirect hop**, is re-checked
against the policy, so a target answering a probe with a 302 does not get to choose what
this tool connects to — plus TLS verification, a per-request timeout, a response size cap,
a rate limit and a hard request budget. On top of it `policy.guard()` applies the
action-level gates and records the audit trail.

Two things the profile cannot do for you: **one transport per principal** is handled (a
cookie jar each), but the accounts must genuinely be separate — `validate_target()`'s
independence check is what tells you — and **own accounts only** remains yours to honour.

---

### Writing an adapter by hand

Still supported, and the right answer for a target a profile cannot describe (a native
app, a gRPC surface, a flow needing a browser).

**First, the engagement.** Rules of engagement live in data and are enforced per action,
so the common accidents are impossible rather than unlikely:

```python
from tpihunter.policy import EngagementPolicy, guard, policy_report

policy = EngagementPolicy(
    name="acme-bugbounty",
    authorized_by="security@acme.example, ticket SEC-1421, 2026-09-20",  # empty => refuse everything
    identifiers={"pentest-a@acme.example", "pentest-v@acme.example"},    # the ONLY accounts in scope
    hosts={"staging.acme.example"},                                      # the ONLY hosts in scope
    allow_credential_change=False,      # resets / email changes / factor enrolment
    allow_cross_principal_write=False,  # the oracle's destructive write probe
    max_actions=500,                    # hard cap, fails closed
    min_interval=0.5,                   # be a good citizen
    dry_run=True,                       # review the run before it is a run
)
adapter = guard(AcmeAdapter(...), policy)     # every action now checked + audited
...
print(policy_report(adapter))                 # what the run actually did
```

An out-of-scope identifier raises `ScopeViolation` — it is never handled by continuing.
A spent budget raises `BudgetExhausted`, so a truncated run is never mistaken for a
clean one. `policy.check_url()` is the check a redirect or an emailed link needs before
you follow it. Every action lands in an audit trail with credentials redacted.

**Then the adapter.** Implement one `TargetAdapter` (see `adapter.py`). The only real work:

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

Two things the adapter author owns, because nothing outside the adapter can enforce
them: **one transport per principal** (separate cookie jars — two principals sharing a
context voids every verdict, and the oracle's independence control will say so), and
**own accounts only** (the oracle plants a canary in the victim's private resource).

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

**Situational awareness (M16).** So the strategist can adapt *well* — not just cheaply — each
probe comes back with a **reason** it can act on (`new_bug` / `duplicate` / `enforced` /
`unbound_action` / `incomplete`), the loop tracks a **coverage** map (distinct bugs, clauses with
evidence, effect-combinations tried, untried frontier), and `hunt(strategist, patience=k)` **stops
on its own** after `k` rounds with no new distinct bug (`HuntResult.stop_reason`). The MCP surface
mirrors this: `run_probe(...)` returns a `reason`, and `coverage()` reports progress. This is what
keeps a live agent from spending real requests re-testing settled surface —
`python3 -m tpihunter.coverage_demo` shows an agent stopping itself after 5 probes.

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
action and probe with it — `register_action(id, effect, requires, needs_control, params)`
on the MCP path, or a `new_actions` block in the `LLMStrategist` reply on the API path.

```
python3 -m tpihunter.newaction_demo
```

A synthesized action can take inputs beyond the account email — a code, an invite token, or
a **second identifier** (a recovery/secondary email) — via declared `params={name: template}`
(a template may use `{email}`, `{alias}`, `{role}`, or be a literal). `alias_demo` shows the
payoff: on the *patched* target the revoke-on-rebind fix forgot the recovery-email data, so an
attacker-added recovery email survives the victim's SSO merge and still resolves to the account
— a TPI-1 takeover only reachable by a probe that can pass that non-email identifier.

```
python3 -m tpihunter.alias_demo
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
queries (Angluin's L*), and by default certifies it with the **W-method** conformance
oracle (`wmethod.py`) instead of random sampling:

```
python3 -m tpihunter.learn_demo
```

Against the mock it recovers the full 9-state auth FSM — session, *verified* (the
`sso_login`→`OK_VERIFIED` trust-raise), reset-token, and logged-out dimensions — from a
few hundred membership queries, and the W-method suite (transition cover × Σ^≤k middles ×
a characterization set) certifies it sound up to `n + extra_states` states: no
counterexample exists within the bound, and it is exhaustively conformant on the mock. Wrap
a real target in the `SUL` interface (`reset()`, `step`) to learn *its* machine; select the
cheaper `eq_method="random"` oracle if the W-method suite gets too large.

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
- **Robustness for real targets**: ✅ oracle confirmation/retry (M13) and a richer param
  model for synthesized actions — codes, invites, second identifiers (M14). Still to do:
  adapter rate-limit/backoff for the live path.
- **W-method conformance oracle**: ✅ done (M15) — the learner's default equivalence oracle
  is now a finite conformance suite, sound up to `n + extra_states` states. A Wp-method /
  adaptive variant would help only if a large real alphabet makes the suite too big.
- **Alloy** (optional, offline): a relational model as an *attack-shape compiler*
  that pre-computes violating interleavings to seed the enumerator — a design-time
  force-multiplier, never in the live loop.

## Scope

Run only against systems you are authorized to test. This is a research and
authorized-testing tool; the mock target exists so the loop can be exercised and
validated without touching anyone's infrastructure.
