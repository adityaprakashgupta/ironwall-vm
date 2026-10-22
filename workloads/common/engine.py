"""LLM-engine guest — the bounded completion the Referee is allowed to release.

In production this VM runs llama.cpp and the Referee resets it between
evaluations (`--reset kv`, `LogicalKvResetManager`) so that no prompt can
influence the next evaluation through residual model state — that is the
"Resettable" pillar.

This file loads the model weights file using llama-cpp-python (open-source
llama.cpp bindings) and runs real bounded inference. When llama-cpp-python is
not available (development hosts outside the MicroVM), it falls back to a
deterministic hash-based stand-in so the agent remains functional for testing.
The same evaluation always produces the same evidence. It never sees which
stage let the prompt through, only the prompt itself.
"""

from __future__ import annotations

import hashlib
import mmap
import os
import time

#: Upper bound the Referee may ask for; enforced here too, because a guest must
#: not be talked into doing unbounded work by a malformed request.
MAX_TOKENS_CEILING = 512

#: Where the model weights live inside the guest image. Can be overridden via
#: the BAYORA_MODEL_PATH environment variable for development hosts that do not
#: run inside a Firecracker MicroVM.
MODEL_PATH = os.environ.get("BAYORA_MODEL_PATH", "/opt/bayora/model.gguf")

#: Wall-clock timeout for a single inference call (seconds). The Referee's
#: EVAL_500 bucket is 500 ms, so inference must finish well inside that.
INFERENCE_TIMEOUT_SECONDS = 0.45

#: Deterministic fallback digest used when the model file is absent.
_FALLBACK_MODEL_DIGEST = "00" * 32

#: Chunk size for hashing fallback — large enough to do real CPU work per turn.
CHUNK_SIZE = 1 << 20  # 1 MiB

#: Cached loaded llama model (real inference mode).
_model = None
#: Cached model hash (fallback mode).
_model_digest = None
#: Whether real llama inference is available (None = not yet probed).
_using_llama = None


def _try_load_llama() -> bool:
    """Attempt to import and initialize llama-cpp-python.

    Returns True if real inference is available, False otherwise. Results are
    cached so the probe happens at most once per VM lifetime.
    """
    global _using_llama, _model
    if _using_llama is not None:
        return _using_llama

    if not os.path.exists(MODEL_PATH):
        _using_llama = False
        _model = None
        return False

    try:
        from llama_cpp import Llama  # type: ignore

        _model = Llama(
            model_path=MODEL_PATH,
            n_ctx=512,
            n_threads=1,
            verbose=False,
        )
        _using_llama = True
    except Exception:
        _model = None
        _using_llama = False
    return _using_llama


def _hash_model() -> str:
    """Hash the model weights file for fallback mode.

    This does real CPU work — reading and hashing the weights file — producing
    observable CPU usage in the guest. Falls back to a deterministic dummy
    digest when the weights file is absent (development hosts only).
    """
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
    """Return `{"output": ...}`, shaped like the Referee's `LlmResponse`.

    Uses real llama-cpp-python inference when available; falls back to a
    deterministic hash-based stand-in for development hosts without the
    inference engine. Bounded by `max_tokens` and a wall-clock timeout so the
    Referee's timing bucket can hold or cancel the work.
    """
    if not isinstance(prompt, str):
        raise TypeError("prompt must be a string")
    if not isinstance(max_tokens, int) or max_tokens <= 0:
        raise ValueError("max_tokens must be a positive integer")
    if max_tokens > MAX_TOKENS_CEILING:
        raise ValueError(
            f"max_tokens {max_tokens} exceeds the {MAX_TOKENS_CEILING} ceiling"
        )

    if _try_load_llama():
        # Real inference via llama-cpp-python.
        started = time.monotonic()
        try:
            result = _model(
                prompt,
                max_tokens=max_tokens,
                temperature=0.0,
                stop=[],
                echo=False,
            )
            elapsed = time.monotonic() - started
            if elapsed > INFERENCE_TIMEOUT_SECONDS:
                raise TimeoutError(
                    f"inference exceeded {INFERENCE_TIMEOUT_SECONDS}s budget"
                )
            output = result["choices"][0]["text"]
        except Exception as exc:
            # Fail-closed: if inference fails, return a deterministic refusal
            # rather than leaking partial or error state.
            output = f"[llm-engine] inference error: {type(exc).__name__}"
    else:
        # Fallback: deterministic hash-based stand-in for dev hosts.
        model_hash = _hash_model()
        h = hashlib.sha256()
        h.update(prompt.encode("utf-8"))
        h.update(model_hash.encode("utf-8"))
        summary = h.hexdigest()[:64]
        output = (
            f"[llm-engine:fallback] model_hash={model_hash[:16]}... "
            f"prompt_hash={summary}"
        )

    return {"output": _clip(output, max_tokens)}
