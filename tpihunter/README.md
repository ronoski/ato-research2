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
| `demo.py` | end-to-end self-test (one hand-written probe) |
| `enum_demo.py` | self-test of the enumerator (zero hand-written probes) |

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

## Roadmap

- **Automata learning** (next): learn the alphabet and the per-subsystem state
  machine from a *live* target (LearnLib / L*), so the enumerator runs on the
  behaviour the server really implements rather than an assumed action set.
- **Semantic dedup**: the enumerator currently over-generates order/padding
  variants (124 candidates, 2 distinct bugs); collapse plans by causal signature.
- **Alloy** (optional, offline): a relational model as an *attack-shape compiler*
  that pre-computes violating interleavings to seed the enumerator — a design-time
  force-multiplier, never in the live loop.

## Scope

Run only against systems you are authorized to test. This is a research and
authorized-testing tool; the mock target exists so the loop can be exercised and
validated without touching anyone's infrastructure.
