"""LLM-engine guest — the bounded completion the Referee is allowed to release.

In production this VM runs llama.cpp and the Referee resets it between
evaluations (`--reset kv`, `LogicalKvResetManager`) so that no prompt can
influence the next evaluation through residual model state — that is the
"Resettable" pillar.

This file is the *deterministic stand-in* used when the demo runs without a
GPU: it loads the model weights file and hashes it, producing real CPU work
proportional to the model size, then answers deterministically from the
prompt. The same evaluation always produces the same evidence. It never sees
which stage let the prompt through, only the prompt itself.
"""

from __future__ import annotations

import hashlib
import mmap
import os

#: Upper bound the Referee may ask for; enforced here too, because a guest must
#: not be talked into doing unbounded work by a malformed request.
MAX_TOKENS_CEILING = 512

#: Where the model weights live inside the guest image. Can be overridden via
#: the BAYORA_MODEL_PATH environment variable for development hosts that do not
#: run inside a Firecracker MicroVM.
MODEL_PATH = os.environ.get("BAYORA_MODEL_PATH", "/opt/bayora/model.gguf")

#: Deterministic fallback digest used when the model file is absent (e.g. running
#: the agent outside a MicroVM during development). Keeps the agent functional
#: without real weights while making it obvious this is not production inference.
_FALLBACK_MODEL_DIGEST = "00" * 32

#: Chunk size for hashing — large enough to do real CPU work per turn.
CHUNK_SIZE = 1 << 20  # 1 MiB

#: Cache the model hash so we only compute it once per VM lifetime (the VM is
#: reset between evaluations anyway, so this is effectively per-evaluation).
_model_digest = None


def _hash_model() -> str:
    """Hash the model weights file. This does real CPU work — reading and
    hashing a ~491 MiB file takes measurable CPU time and produces observable
    CPU spikes in the guest. Falls back to a deterministic dummy digest when the
    weights file is absent (development hosts only)."""
    global _model_digest
    if _model_digest is None:
        if not os.path.exists(MODEL_PATH):
            _model_digest = _FALLBACK_MODEL_DIGEST
            return _model_digest
        h = hashlib.sha256()
        with open(MODEL_PATH, "rb") as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                offset = 0
                size = len(mm)
                while offset < size:
                    chunk = mm[offset:offset + CHUNK_SIZE]
                    if not chunk:
                        break
                    h.update(chunk)
                    offset += CHUNK_SIZE
        _model_digest = h.hexdigest()
    return _model_digest


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

    # Do real CPU work: hash the model weights. This simulates the compute
    # that a real LLM would do when processing a prompt, producing observable
    # CPU usage in the guest.
    model_hash = _hash_model()

    # Combine the prompt hash with the model hash so different prompts give
    # different outputs, while keeping determinism.
    h = hashlib.sha256()
    h.update(prompt.encode("utf-8"))
    h.update(model_hash.encode("utf-8"))
    summary = h.hexdigest()[:64]

    output = f"[llm-engine] model_hash={model_hash[:16]}... prompt_hash={summary}"
    return {"output": _clip(output, max_tokens)}