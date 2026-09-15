"""tpihunter MCP server — lets the Claude Code CLI agent drive the hunt.

This exposes the hunt loop as MCP tools so the Opus agent in Claude Code (running on
your Claude Max subscription) is the strategist — no API key, no pay-per-token cost.
All logic lives in `mcp_tools.HuntSession`; this file is only the protocol wrapper, and
`mcp` is imported lazily so importing `tpihunter` never requires it.

Install and register (once):

    pip install "mcp[cli]"
    claude mcp add tpihunter -- python3 -m tpihunter.mcp_server

Then, in any Claude Code session:

    "Use the tpihunter tools to hunt the mock target. Read the briefing first."

The agent will call briefing() / list_actions(), propose probes via run_probe(steps),
adapt to the verdicts, and report the distinct bugs via findings().
"""
from __future__ import annotations

from .mcp_tools import HuntSession


def build_server():
    """Construct the FastMCP server. Imports `mcp` lazily (see module docstring)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:  # pragma: no cover - exercised only without the dep
        raise SystemExit(
            "The `mcp` package is required to run the tpihunter MCP server.\n"
            "Install it with:  pip install \"mcp[cli]\""
        ) from e

    session = HuntSession()
    server = FastMCP("tpihunter")

    @server.tool()
    def briefing() -> dict:
        """The TPI hunting method, the two roles, the clauses, and how to use these tools.
        Call this first."""
        return session.briefing()

    @server.tool()
    def list_actions() -> dict:
        """The known action alphabet for the target: each action's effect
        (seed/raise/cred/request), ordering requirements, and whether it needs the
        victim's channel control."""
        return session.list_actions()

    @server.tool()
    def run_probe(steps: list) -> dict:
        """Execute one two-principal probe and return the oracle's verdict.

        `steps` is a list of [role, action] pairs interleaved over the SAME shared
        account, e.g. [["attacker","register"],["victim","sso_login"]]. Roles are
        "attacker" (no channel control) and "victim" (controls the inbox/IdP). The
        verdict gives severity (safe/suspect/takeover), the violated TPI clause, the
        laundered proof, and canary evidence.
        """
        return session.run_probe(steps)

    @server.tool()
    def findings() -> dict:
        """The distinct bugs found so far — takeover probes deduplicated by causal
        signature, each with a minimal repro and the laundered proof."""
        return session.findings()

    @server.tool()
    def revocation_matrix() -> dict:
        """The own-account lifecycle hunt (single-principal, reversible, reads no one
        else's data). For each way of minting a session and each credential-mutating
        transition, measures whether the mutation revokes a session minted BEFORE it. A
        SURVIVED cell is TPI-4 laundering — a stolen session that outlives the owner's
        logout or reset. Reach for this first on a real authorized target. Returns the
        grid, a rendered table, and the laundering cells with per-cell controls."""
        return session.revocation_matrix()

    @server.tool()
    def report(fmt: str = "markdown") -> dict:
        """A shareable, submittable evidence bundle for the distinct bugs found so far.
        fmt: "markdown" (a document to paste into a report) or "json" (structured). Each
        bug carries steps to reproduce, the canary evidence proving the takeover, the
        laundered proof (root cause), and remediation from the violated TPI clause."""
        return session.report(fmt)

    @server.tool()
    def reset(target: str = "mock-vulnerable") -> dict:
        """Start a fresh hunt session. target: "mock-vulnerable" or "mock-patched"
        (use the patched one to confirm a bug closes under the fix)."""
        return session.reset(target)

    return server


def main() -> None:
    build_server().run()   # stdio transport by default


if __name__ == "__main__":
    main()
