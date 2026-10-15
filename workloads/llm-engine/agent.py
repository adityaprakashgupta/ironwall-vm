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

    wire.send_message(sock, response)


def serve(port: int = wire.LLM_PORT) -> None:
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((VMADDR_CID_ANY, port))
    listener.listen(8)
    sys.stderr.write(f"llm: listening on vsock any:{port}\n")
    while True:
        connection, _addr = listener.accept()
        with connection:
            handle(connection)


if __name__ == "__main__":
    if not hasattr(socket, "AF_VSOCK"):
        sys.exit("llm: AF_VSOCK is unavailable; run inside the Linux MicroVM")
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else wire.LLM_PORT)
