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
python3 -m tpihunter.demo        # the oracle: TAKEOVER on a vulnerable target, SAFE on the patched one
python3 -m tpihunter.enum_demo   # the enumerator: generates probes, rediscovers TPI-1 and finds TPI-4
```

Stdlib-only; no `pip install`.

## Working on this project?

Read **[`STATUS.md`](STATUS.md) first** — it is the live coordination board that
tracks which stage the project is at, what is DONE, and what to pick up next.
Multiple agents/sessions collaborate here.

## Scope

Run only against systems you are authorized to test. This is a research and
authorized-testing project; the built-in mock target exists so the loop can be
exercised and validated without touching anyone's infrastructure.
