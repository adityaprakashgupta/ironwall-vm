#!/usr/bin/env python3
"""LLM-engine guest agent — the only component that produces generated text.

    in : {"eval_id": "...", "prompt": "...", "max_tokens": 64}   (LlmRequest)
    out: {"output": "..."}                                       (LlmResponse)

Reached *only* through the Referee, and only after Blue returned `allow`. The
Referee resets this VM between evaluations (`--reset kv` / `--reset snapshot`)
so no prompt can reach the next evaluation through leftover state.

In production this process is a thin shim in front of llama.cpp; the stand-in
keeps the same request/response contract and the same determinism guarantees
the evidence plane depends on.
"""

from __future__ import annotations

import os
import signal
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from common import engine, wire  # noqa: E402

VMADDR_CID_ANY = socket.VMADDR_CID_ANY if hasattr(socket, "VMADDR_CID_ANY") else 0xFFFFFFFF


def handle(sock) -> None:
    """Serve exactly one completion request on `sock`."""
    try:
        request = wire.read_message(sock)
    except wire.FrameError as exc:
        sys.stderr.write(f"llm: malformed request: {exc}\n")
        return

    try:
        response = engine.respond(request.get("prompt"), request.get("max_tokens"))
    except (TypeError, ValueError) as exc:
        sys.stderr.write(f"llm: refusing request: {exc}\n")
        return
    except Exception as exc:
        # Catch-all for unexpected inference errors (e.g. model load failure,
        # tokenizer errors, etc.). Fail-closed: don't send a partial response.
        sys.stderr.write(f"llm: inference error: {type(exc).__name__}: {exc}\n")
        return

    try:
        wire.send_message(sock, response)
    except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError) as exc:
        # The client (Referee) closed the connection before we could send the
        # response — typically because the timing guard cancelled the future.
        # This is not a crash; just close the connection and serve the next one.
        sys.stderr.write(f"llm: client disconnected before response: {type(exc).__name__}\n")
        return


def _cleanup_and_exit(signum=None, frame=None) -> None:
    """Release the model from memory before exiting.

    Called on SIGTERM/SIGINT so the model weights are released from guest RAM
    instead of lingering after the process exits.
    """
    sys.stderr.write("llm: shutting down, releasing model from memory\n")
    try:
        engine.cleanup()
    except Exception:
        pass
    sys.exit(0)


def serve(port: int = wire.LLM_PORT) -> None:
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((VMADDR_CID_ANY, port))
    listener.listen(8)
    sys.stderr.write(f"llm: listening on vsock any:{port}\n")

    # Register signal handlers for clean shutdown.
    signal.signal(signal.SIGTERM, _cleanup_and_exit)
    signal.signal(signal.SIGINT, _cleanup_and_exit)

    while True:
        connection, _addr = listener.accept()
        with connection:
            handle(connection)


if __name__ == "__main__":
    if not hasattr(socket, "AF_VSOCK"):
        sys.exit("llm: AF_VSOCK is unavailable; run inside the Linux MicroVM")
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else wire.LLM_PORT)
