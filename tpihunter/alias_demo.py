"""Richer-param synthesis self-test: the agent drives a flow that needs a SECOND identifier.

    python3 -m tpihunter.alias_demo

New-action synthesis (M11) let the agent add verbs, but every step's params were email-only —
so a flow needing anything else (a code, an invite token, a recovery/secondary email) could be
*named* but not *driven*. This closes that gap: an ActionSpec can declare params, and a probe
fills them ({alias} => a recovery email the acting role controls; a literal => a fixed code).

The story, one turn past newaction_demo: on the *patched* target the revoke-on-rebind fix
severed the attacker's session and password on SSO — but forgot the parallel recovery-email
data. So an attacker who added their own recovery email *before* the victim's SSO merge still
holds a second identifier that resolves to the account. Only a probe that can pass that
non-email identifier reaches it:

    attacker: register  ->  attacker: add_alias(alias=attacker's recovery email)
    victim:   sso_login (patched: revokes session+password, NOT the alias)
    attacker: alias_login(alias=...)  -> resolves to the victim's account -> TAKEOVER
"""
from __future__ import annotations

from .mcp_tools import HuntSession


def _run(session, label, steps):
    r = session.run_probe(steps)
    tag = f"[{r['severity'].upper()}]" + (f" {r['clause_id']}" if r["clause_id"] else "")
    print(f"   {label:44} {tag}")
    return r


def main() -> None:
    print("\nTPI-HUNTER  -  richer-param synthesis (a flow that needs a second identifier)\n")
    s = HuntSession(target="mock-patched")
    print(" target: mock-patched (SSO/reset laundering fixed; recovery-email data was not)\n")

    print(" 1) known flows + a plain email-only new action all find NOTHING here:")
    _run(s, "SSO merge (TPI-1 shape)", [["attacker", "register"], ["victim", "sso_login"]])
    print("   -> the fixed alphabet is empty-handed on the patched target.\n")

    print(" 2) the agent hypothesizes a recovery-email flow and declares its non-email param:")
    r1 = s.register_action("add_alias", "seed", requires=["register"],
                           needs_control=True, params={"alias": "{alias}"})
    r2 = s.register_action("alias_login", "raise", requires=["add_alias"],
                           needs_control=True, params={"alias": "{alias}"})
    print(f"   register_action('add_alias',   params={{'alias':'{{alias}}'}}) -> ok={r1['ok']} params={r1['params']}")
    print(f"   register_action('alias_login', params={{'alias':'{{alias}}'}}) -> ok={r2['ok']} params={r2['params']}")
    _run(s, "attacker seeds a recovery email, then logs in via it",
         [["attacker", "register"], ["attacker", "add_alias"],
          ["victim", "sso_login"], ["attacker", "alias_login"]])
    print("   -> the rebind fix forgot the attacker-added recovery email — it survived.\n")

    f = s.findings()
    print(" " + "=" * 74)
    print(f" distinct bugs found: {f['distinct_bugs']}  (in {f['probes_run']} probes)")
    for i, b in enumerate(f["bugs"], 1):
        print(f"   [{i}] {b['clause_id']} via  {b['minimal_repro']}")
    print(" " + "=" * 74)
    print(" Email-only params could NAME this flow but never drive it — alias_login needs an")
    print(" identifier that is not the account's email. The declared {alias} param supplies it.\n")


if __name__ == "__main__":
    main()
