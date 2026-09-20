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
    def register_action(action_id: str, effect: str, requires: list | None = None,
                        needs_control: bool = False, params: dict | None = None) -> dict:
        """Extend the alphabet with a flow the target has but the default set lacks — a
        magic-link login, device pairing, an org invite, a recovery/secondary email. A fix
        applied to one flow is often missing on a parallel one, so this is how you reach bugs
        the built-in verbs can't. effect: seed/raise/cred/request. requires: action ids that
        must run first. needs_control: true if only the inbox/IdP owner can do it. params:
        inputs beyond the email as {name: template} — a template may use {email} (the shared
        account), {alias} (a recovery email THIS role controls, a second identifier), or
        {role}; a plain string is a literal (e.g. a fixed code / invite token). Then use the
        action in run_probe. Example: register_action("add_alias","seed",requires=["register"],
        needs_control=True, params={"alias":"{alias}"}) then alias_login likewise."""
        return session.register_action(action_id, effect, requires=requires,
                                       needs_control=needs_control, params=params)

    @server.tool()
    def findings() -> dict:
        """The distinct bugs found so far — takeover probes deduplicated by causal
        signature, each with a minimal repro and the laundered proof."""
        return session.findings()

    @server.tool()
    def coverage() -> dict:
        """Your map of where you have and haven't looked, so you don't waste probes: how many
        DISTINCT bugs found, which TPI clauses have evidence, which effect-combinations you have
        tried, and how many composition-relevant probes in the known alphabet remain UNTRIED.
        Pair it with each run_probe `reason` (enforced=secure, move on / unbound_action=that verb
        does not exist here / incomplete=reformulate / duplicate / new_bug) to steer efficiently
        and to know when the surface is exhausted."""
        return session.coverage()

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
    def set_target(profile: dict) -> dict:
        """Describe a REAL target as data, so you can hunt it without anyone writing code.

        `profile` names the base URL, the test accounts, how a session is carried, and one
        request per alphabet action plus the oracle surface (whoami, plant_marker,
        read_marker, read_marker_by_ref, write_marker) and a `channel` that fetches a mailed
        token. Placeholders: {email} {password} {new_password} {new_email} {alias} {token}
        {code} {value} {ref} {role}. Example action:
        {"method":"POST","path":"/api/login","json":{"email":"{email}","password":"{password}"},
         "expect":[200],"extract":{"identity":{"json":"user.id"}}}

        You cannot widen the scope: the operator authorizes the accounts and hosts out of
        band, and a profile naming anything else is refused before a request is sent. After
        this, call validate_target()."""
        return session.set_target(profile)

    @server.tool()
    def validate_target() -> dict:
        """Prove the profile actually works before treating any verdict from it as evidence.

        Checks that each principal can get its own session, that two principals resolve to
        two different accounts, that the victim can plant a canary and read it back, that a
        foreign or invalid reference is refused, that the bystander account exists, and that
        the channel delivers a token. Every failure comes with the profile field to fix.
        Probing is blocked until this passes — an unvalidated profile produces confident
        SAFE verdicts on a target it never correctly reached."""
        return session.validate_target()

    @server.tool()
    def reset(target: str = "mock-vulnerable") -> dict:
        """Start a fresh hunt session. target: "mock-vulnerable", "mock-patched" (confirm a
        bug closes under the fix), "mock-plane-split" (a multi-plane estate where logout
        revokes only its own plane — revocation_matrix() shows a cross-plane SPLIT), or
        "live" once set_target()/validate_target() have succeeded."""
        return session.reset(target)

    return server


def main() -> None:
    build_server().run()   # stdio transport by default


if __name__ == "__main__":
    main()
