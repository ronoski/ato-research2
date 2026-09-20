# ato-research2 — Trust-Provenance Integrity

Novel research on **account takeover (ATO) and authentication bypass**, modelling
identity/auth as a state machine but reframing the target property from *state
reachability* to **trust-provenance integrity (TPI)**.

> **The one line:** trust levels compose; provenance does not. The worst ATOs
> (pre-hijacking, OAuth link confusion, reset-token survival) are *laundering*
> failures visible only in the composition of ≥2 principals over a shared store —
> invisible to single-session models.

This repo has two halves:

| | what | where |
|---|---|---|
| **Theory** | the working paper *Provenance, Not Reachability* | [`paper/provenance.html`](paper/provenance.html) · [published artifact](https://claude.ai/artifact/LxyHRRCnZB7NNQWP6SF1sC) |
| **Tool** | `tpihunter` — a black-box ATO hunting loop that operationalizes the theory | [`tpihunter/`](tpihunter/) · [tool README](tpihunter/README.md) |

## Quickstart

```bash
python3 -m unittest discover     # regression suite (258 tests, stdlib only)
python3 -m tpihunter.demo        # the oracle: TAKEOVER on a vulnerable target, SAFE on the patched one
python3 -m tpihunter.enum_demo   # the enumerator: generates probes → dedups to 2 distinct bugs
python3 -m tpihunter.learn_demo  # automata learning: L* + W-method oracle recovers & certifies the auth FSM
python3 -m tpihunter.synth_demo  # the closed loop: learn → synthesize action model → enumerate
python3 -m tpihunter.agent_demo  # agent as hunter: a strategist drives the loop (enumerator vs LLM seam)
python3 -m tpihunter.coverage_demo # agent situational awareness: reason codes, coverage, patience-stop
python3 -m tpihunter.newaction_demo  # the agent registers a new action to find a bug beyond the alphabet
python3 -m tpihunter.matrix_demo # the revocation matrix: a 'patched' target still leaks via a parallel flow
python3 -m tpihunter.report_demo # turn the findings into a submittable evidence bundle
python3 -m tpihunter.retry_demo  # oracle confirmation: a flaky target can't flip the verdict
python3 -m tpihunter.alias_demo  # richer params: the agent drives a flow needing a second identifier
python3 -m tpihunter.safety_demo # the oracle's controls + the engagement policy: what stops this misfiring
python3 -m tpihunter.live_demo   # a real HTTP target, described as data, proved, then hunted
```

The core is stdlib-only; no `pip install`. Two optional integrations bring their own
dep, each isolated so the core never imports it: the API strategist (`pip install
anthropic`) and the MCP server (`pip install "mcp[cli]"`).

## Hunt with the Claude Code agent (Max/Pro subscription)

The goal is **agent as hunter**. The cleanest way — and the one that runs on your Claude
**Max/Pro subscription** rather than pay-per-token API billing — is to let the Opus agent
in Claude Code be the strategist, via the bundled MCP server:

```bash
pip install "mcp[cli]"
claude mcp add tpihunter -- python3 -m tpihunter.mcp_server
```

Then in any Claude Code session:

> Use the tpihunter tools to hunt the mock target. Read the briefing first.

Claude Code reads `briefing()` / `list_actions()`, proposes probes via `run_probe(steps)`,
adapts to the verdicts, and reports the distinct bugs via `findings()` — no API key. It can
also `register_action(...)` to hypothesize a flow the alphabet lacks (magic-link, device
pairing, org invite, email alias) and probe with it — how it finds bugs a fixed enumerator
never could. (For CI / headless runs there's also an API strategist; see the
[tool README](tpihunter/README.md).)

### Pointing it at a real target

Nobody writes an adapter. The operator authorizes the scope out of band, and the agent
describes the target as data:

```bash
export TPIHUNTER_ENGAGEMENT=/path/to/engagement.json   # who authorized it, which accounts, which hosts
```

> Describe the staging login API with `set_target`, then `validate_target`, then hunt it.

The agent calls `set_target(profile)` (base URL, test accounts, one request per action,
the oracle surface) and `validate_target()`, which proves each piece works — each
principal gets its own session, two principals resolve to two accounts, the victim can
plant a canary and read it back, a foreign reference is refused — and names the profile
field to fix for anything that failed. **Probing is blocked until it passes**, because an
unvalidated profile returns confident SAFE verdicts for a target it never reached.

The agent cannot widen the scope: a profile naming an identifier or host the engagement
file does not authorize is refused before a request is sent, and every URL — including
every redirect — is re-checked against the policy. See
[`tpihunter/README.md`](tpihunter/README.md#hunting-a-real-target), or run
`python3 -m tpihunter.live_demo` to watch the whole thing against a loopback server.

### Sessions are inventory

Logging in is the scarcest thing a live hunt does — each one spends a mailbox code and
raises a risk score that does not reset — and its failure is silent, since a throttled
login and a wrong password return the same page. `SessionStore` reuses a validated
session before minting one, caps the spend per principal and per engagement, and refuses
after two consecutive failures instead of deepening the throttle. See
[`tpihunter/README.md`](tpihunter/README.md#sessions-are-inventory-not-a-function-call).

## Working on this project?

New session taking over? Read **[`HANDOFF.md`](HANDOFF.md) first** — it onboards you
to the goal, the theory, and how to review and continue the work. Then
**[`STATUS.md`](STATUS.md)** is the live board: current stage, what's done, what's
next. Sessions work as a **relay — one at a time, never concurrently.**

## Scope and safety

Run only against systems you are authorized to test. This is a research and
authorized-testing project; the built-in mock target exists so the loop can be
exercised and validated without touching anyone's infrastructure.

That instruction is also enforced in code, because "be careful" is not a control.
Before a live adapter is used it is wrapped in an **engagement policy**
([`tpihunter/policy.py`](tpihunter/policy.py)) that checks every action against the
rules of engagement: an identifier allowlist (out-of-scope account ⇒ `ScopeViolation`,
never handled by continuing), a host allowlist for redirects and emailed links, gates on
credential changes and cross-principal writes, a hard request budget that fails closed, a
rate limit, a `dry_run` that records what *would* run, and an audit trail with
credentials redacted. Two things the policy cannot enforce for you: one transport per
principal, and **own accounts only**.

The verdict engine carries its own controls for the same reason — see *The oracle* in
the [tool README](tpihunter/README.md#the-oracle-the-star), and
`python3 -m tpihunter.safety_demo` for the three probes that used to produce confident,
wrong answers.
