"""Self-test: oracle confirmation makes the verdict stable on a *flaky* target.

    python3 -m tpihunter.retry_demo

The deterministic mock always answers the same way, so on it a verdict never flips. A real
target does not: it rate-limits and drops responses, so a single probe can miss access that
is genuinely there. `FlakyAdapter` models that (it drops the attacker's read observations),
and `AtoOracle(confirm=k)` answers it — re-probe 1+k times and report a takeover only if it
holds a strict majority.

This demo runs the classic pre-hijacking probe against a flaky target across many seeds and
compares a single-probe oracle (confirm=0) with a confirming one (confirm=8):

  * on the VULNERABLE target, confirmation recovers the recall the single probe loses to
    dropped reads — every seed lands on the true TAKEOVER;
  * on the PATCHED target, confirmation never manufactures a takeover — the load-bearing
    invariant survives flakiness, because dropping observations can only lower severity.
"""
from __future__ import annotations

from .flaky import FlakyAdapter
from .harness import run_plan
from .mock_target import MockAdapter
from .oracle import AtoOracle
from .probes import pre_hijacking_plan
from .types import Principal

EMAIL = "victim@corp.example"
SEEDS = range(24)
DROP = 0.6
CONFIRM = 8


def _hr(c: str = "-", n: int = 74) -> str:
    return c * n


def _verdict(patched: bool, seed: int, confirm: int) -> str:
    attacker, victim = Principal("attacker"), Principal("victim")
    control = {victim.name: {EMAIL}}
    adapter = FlakyAdapter(MockAdapter(patched=patched, control=control),
                           attacker.name, drop=DROP, seed=seed)
    oracle = AtoOracle(adapter, attacker, victim, confirm=confirm)
    plan = pre_hijacking_plan(attacker, victim, EMAIL)
    return run_plan(adapter, plan, oracle)[0].severity.value


def _tally(patched: bool, confirm: int) -> dict:
    out: dict[str, int] = {}
    for s in SEEDS:
        v = _verdict(patched, s, confirm)
        out[v] = out.get(v, 0) + 1
    return out


def _fmt(tally: dict) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(tally.items())) or "(none)"


def _row(label: str, tally: dict, want: str) -> None:
    hit = tally.get(want, 0)
    n = sum(tally.values())
    print(f"  {label:26} {_fmt(tally):32} -> {want} in {hit}/{n}")


def main() -> None:
    print("\nTPI-HUNTER  -  oracle confirmation on a flaky target")
    print(f"pre-hijacking probe, drop={DROP} of the attacker's reads, {len(SEEDS)} seeds\n")

    print(_hr("="))
    print(" VULNERABLE target  (ground truth: TAKEOVER)")
    print(_hr())
    v0 = _tally(patched=False, confirm=0)
    vk = _tally(patched=False, confirm=CONFIRM)
    _row("single probe (confirm=0)", v0, "takeover")
    _row(f"confirmed  (confirm={CONFIRM})", vk, "takeover")
    print(f"  => a flaky single probe misses {v0.get('safe', 0)}/{sum(v0.values())} real "
          f"takeovers; confirmation recovers them.\n")

    print(_hr("="))
    print(" PATCHED target  (ground truth: SAFE — the load-bearing invariant)")
    print(_hr())
    p0 = _tally(patched=True, confirm=0)
    pk = _tally(patched=True, confirm=CONFIRM)
    _row("single probe (confirm=0)", p0, "safe")
    _row(f"confirmed  (confirm={CONFIRM})", pk, "safe")
    fired = pk.get("takeover", 0)
    print(f"  => confirmation fired {fired} false takeovers on the patched target "
          f"(must be 0).\n")

    print(_hr("="))
    ok = (vk.get("takeover", 0) == len(SEEDS)) and (pk.get("takeover", 0) == 0)
    if ok:
        print(" PASS: confirmation recovers every real takeover AND never fires on the")
        print("       patched target — recall bought back with no cost to the invariant.")
    else:
        print(" WARNING: confirmation did not stabilize as expected — investigate before")
        print("          relying on this against a real target.")
    print()


if __name__ == "__main__":
    main()
