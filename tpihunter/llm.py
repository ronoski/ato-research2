"""Real LLM strategist backend — the one file that talks to a model.

This turns the agent from a scaffold into a live hunter: `make_complete_fn()` returns
a `complete_fn(prompt:str) -> str` that `agent.LLMStrategist` calls to propose the next
probes. Everything else in the package stays stdlib-only; `anthropic` is imported lazily
inside the call, so importing `tpihunter` never requires the SDK.

Defaults: Claude Opus 5 (`claude-opus-5`) with adaptive thinking — the deepest reasoning
for the creative work of proposing novel TPI-shaped attacks. The `client` is injectable
so the wiring is testable with a fake (no network); pass a real `anthropic.Anthropic()`
(or leave it None to construct one from the environment) to run live.

Usage:
    from tpihunter.agent import AgentHunter, LLMStrategist
    from tpihunter.llm import make_complete_fn
    hunter.hunt(LLMStrategist(make_complete_fn()))

Requires `pip install anthropic` and credentials (ANTHROPIC_API_KEY or an
`ant auth login` profile) only when run live.

Note: for production you may want server-side refusal fallbacks on Opus-5-class models
(betas=["server-side-fallback-2026-07-01"], fallbacks="default"). Omitted here to keep
the call simple per the chosen "simplest in-process" design; add it if you want it.
"""
from __future__ import annotations

from typing import Callable, Optional

CompleteFn = Callable[[str], str]

DEFAULT_MODEL = "claude-opus-5"     # Opus-tier: deepest reasoning for hypothesis work

SYSTEM = (
    "You are an authorized security researcher hunting account-takeover bugs via the "
    "Trust-Provenance Integrity method. You propose probe sequences for a controlled "
    "test harness (a mock or an explicitly authorized target); you never attack anything "
    "else. Reason about which two-principal interleavings could launder a victim's proof "
    "into attacker access, then output ONLY a JSON array of probes as instructed."
)


class RefusalError(RuntimeError):
    """The model declined the request (stop_reason == 'refusal')."""


def anthropic_complete(prompt: str, *, model: str = DEFAULT_MODEL,
                       max_tokens: int = 16000, system: str = SYSTEM,
                       client: Optional[object] = None) -> str:
    """Send one prompt to Claude and return the concatenated text of the reply.

    `client` is injectable for testing; when None, an `anthropic.Anthropic()` is built
    from the environment. Raises RefusalError on a safety refusal so the caller can stop
    cleanly rather than parse an empty reply.
    """
    if client is None:
        import anthropic  # lazy: only needed for a live run
        client = anthropic.Anthropic()

    response = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        thinking={"type": "adaptive"},   # Opus 5: deepest reasoning, on by default
        system=system,
        messages=[{"role": "user", "content": prompt}],
    )
    if getattr(response, "stop_reason", None) == "refusal":
        detail = getattr(response, "stop_details", None)
        raise RefusalError(f"model refused: {getattr(detail, 'category', 'unknown')}")
    return "".join(b.text for b in response.content if getattr(b, "type", None) == "text")


def make_complete_fn(*, model: str = DEFAULT_MODEL, max_tokens: int = 16000,
                     system: str = SYSTEM, client: Optional[object] = None) -> CompleteFn:
    """Return a `complete_fn(prompt) -> str` for `agent.LLMStrategist`."""
    def complete_fn(prompt: str) -> str:
        return anthropic_complete(prompt, model=model, max_tokens=max_tokens,
                                  system=system, client=client)
    return complete_fn
