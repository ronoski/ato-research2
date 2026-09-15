"""Evidence-bundle self-test: hunt the mock, then generate a submittable report.

    python3 -m tpihunter.report_demo

Runs the two known laundering probes against the vulnerable mock, deduplicates to the
distinct bugs, and prints the markdown evidence bundle a hunter would submit — steps to
reproduce, the canary evidence that proves the takeover, the laundered proof, and the
remediation derived from the violated TPI clause.
"""
from __future__ import annotations

from .mcp_tools import HuntSession


def main() -> None:
    s = HuntSession(target="mock-vulnerable")
    # the two distinct laundering bugs (as an agent would find them)
    s.run_probe([["attacker", "register"], ["victim", "sso_login"]])
    s.run_probe([["attacker", "register"], ["victim", "reset_request"], ["victim", "reset_consume"]])

    f = s.findings()
    print("\nTPI-HUNTER  -  evidence bundle")
    print(f"found {f['distinct_bugs']} distinct bug(s) in {f['probes_run']} probes; "
          "rendering the submittable report:\n")
    print("=" * 78)
    print(s.report("markdown")["content"])
    print("=" * 78)
    print("\n(JSON form is also available: session.report('json') / the `report` MCP tool.)\n")


if __name__ == "__main__":
    main()
