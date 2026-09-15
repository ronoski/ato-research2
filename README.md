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
python3 -m unittest discover     # regression suite (31 tests, stdlib only)
python3 -m tpihunter.demo        # the oracle: TAKEOVER on a vulnerable target, SAFE on the patched one
python3 -m tpihunter.enum_demo   # the enumerator: generates probes → dedups to 2 distinct bugs
python3 -m tpihunter.learn_demo  # automata learning: recovers the target's auth state machine (L*)
python3 -m tpihunter.synth_demo  # the closed loop: learn → synthesize action model → enumerate
python3 -m tpihunter.agent_demo  # agent as hunter: a strategist drives the loop (enumerator vs LLM seam)
python3 -m tpihunter.newaction_demo  # the agent registers a new action to find a bug beyond the alphabet
python3 -m tpihunter.report_demo # turn the findings into a submittable evidence bundle
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

## Working on this project?

New session taking over? Read **[`HANDOFF.md`](HANDOFF.md) first** — it onboards you
to the goal, the theory, and how to review and continue the work. Then
**[`STATUS.md`](STATUS.md)** is the live board: current stage, what's done, what's
next. Sessions work as a **relay — one at a time, never concurrently.**

## Scope

Run only against systems you are authorized to test. This is a research and
authorized-testing project; the built-in mock target exists so the loop can be
exercised and validated without touching anyone's infrastructure.
