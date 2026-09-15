"""New-action synthesis self-test: the agent escapes the fixed alphabet.

    python3 -m tpihunter.newaction_demo

The story: on the *patched* target both known laundering flows are fixed, so the fixed
alphabet finds nothing. But the fix was applied to SSO and NOT to the parallel
passwordless (magic-link) flow — a real, common gap. Only an agent that knows such flows
exist and can register one finds it. This is the leverage of agent-as-hunter: hypotheses
beyond the enumerator's built-in verbs.
"""
from __future__ import annotations

from .mcp_tools import HuntSession


def _run(session, label, steps):
    r = session.run_probe(steps)
    tag = f"[{r['severity'].upper()}]" + (f" {r['clause_id']}" if r["clause_id"] else "")
    print(f"   {label:34} {tag}")
    return r


def main() -> None:
    print("\nTPI-HUNTER  -  new-action synthesis (agent escapes the fixed alphabet)\n")
    s = HuntSession(target="mock-patched")
    print(" target: mock-patched (the two known laundering bugs are fixed here)\n")

    print(" 1) the fixed alphabet — every known laundering flow:")
    _run(s, "SSO merge (TPI-1 shape)", [["attacker", "register"], ["victim", "sso_login"]])
    _run(s, "reset survival (TPI-4 shape)",
         [["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]])
    print("   -> default alphabet on the patched target finds NOTHING.\n")

    print(" 2) the agent hypothesizes a flow the alphabet lacks and registers it:")
    reg = s.register_action("magic_link", "raise", needs_control=True)
    print(f"   register_action('magic_link', effect=raise, needs_control) -> ok={reg['ok']}")
    _run(s, "magic_link (passwordless login)",
         [["attacker", "register"], ["victim", "magic_link"]])
    print("   -> the fix was applied to SSO but not the parallel magic-link flow.\n")

    f = s.findings()
    print(" " + "=" * 74)
    print(f" distinct bugs found: {f['distinct_bugs']}  (in {f['probes_run']} probes)")
    for i, b in enumerate(f["bugs"], 1):
        print(f"   [{i}] {b['clause_id']} via  {b['minimal_repro']}")
    print(" " + "=" * 74)
    print(" A fixed enumerator (5 built-in verbs) could not reach this — the alphabet")
    print(" had no magic-link action. The agent's prior knowledge of auth flows did.\n")


if __name__ == "__main__":
    main()
