"""LLM-engine guest — the bounded completion the Referee is allowed to release.

In production this VM runs llama.cpp and the Referee resets it between
evaluations (`--reset kv`, `LogicalKvResetManager`) so that no prompt can
influence the next evaluation through residual model state — that is the
"Resettable" pillar.

This file is the *deterministic stand-in* used when the demo runs without a
GPU: it answers from the prompt alone, with no randomness, no clock and no
hidden state, so the same evaluation always produces the same evidence. It is
deliberately unable to leak anything about the guards: it never sees which
stage let the prompt through, only the prompt itself.
"""

from __future__ import annotations

#: Upper bound the Referee may ask for; enforced here too, because a guest must
#: not be talked into doing unbounded work by a malformed request.
MAX_TOKENS_CEILING = 512


def _clip(text: str, max_tokens: int) -> str:
    """Approximate token clipping: one word per token, on a word boundary."""
    words = text.split()
    if len(words) <= max_tokens:
        return text
    return " ".join(words[:max_tokens])


def respond(prompt: str, max_tokens: int) -> dict:
    """Return `{"output": ...}`, shaped like the Referee's `LlmResponse`."""
    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string")
    if not isinstance(max_tokens, int) or max_tokens <= 0:
        raise ValueError("max_tokens must be a positive integer")
    if max_tokens > MAX_TOKENS_CEILING:
        raise ValueError(
            f"max_tokens {max_tokens} exceeds the {MAX_TOKENS_CEILING} ceiling"
        )

    # A real model does the interesting work; the stand-in answers
    # deterministically from the prompt text so the evidence is replayable.
    summary = " ".join(prompt.split())
    if len(summary) > 120:
        summary = summary[:117].rstrip() + "..."
    output = f"[llm-engine] acknowledged {len(prompt.encode('utf-8'))} byte prompt: {summary}"
    return {"output": _clip(output, max_tokens)}
