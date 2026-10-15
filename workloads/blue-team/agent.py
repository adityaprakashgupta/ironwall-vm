#!/usr/bin/env python3
"""Blue-team guest agent — the defence stages, inside an untrusted MicroVM.

Listens on VSOCK and answers one request with one verdict:

    in : {"eval_id": "...", "prompt": "..."}                  (BlueRequest)
    out: {"decision": "allow"|"block", "stage": "regex"|"semantic"|"pass",
          "reason": "...", "response": ""}                     (BlueVerdict)

Both messages are `u32 LE length || JSON` (see `common/wire.py`). The guest
never originates a connection, never learns the evaluation's identity beyond
the id it echoes, and cannot see the Red VM or the Referee's evidence.

`stage` travels to the Referee for the audit trail; the Referee is what keeps
it away from Red.
"""

from __future__ import annotations

import os
import socket
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from common import policy, wire  # noqa: E402

VMADDR_CID_ANY = socket.VMADDR_CID_ANY if hasattr(socket, "VMADDR_CID_ANY") else 0xFFFFFFFF


def handle(sock) -> None:
    """Serve exactly one request on `sock` (one connection, one verdict)."""
    try:
        request = wire.read_message(sock)
    except wire.FrameError as exc:
        # A malformed request is refused, never guessed at.
        sys.stderr.write(f"blue: malformed request: {exc}\n")
        return

    prompt = request.get("prompt")
    try:
        verdict = policy.classify(prompt)
    except (TypeError, ValueError) as exc:
        sys.stderr.write(f"blue: unclassifiable request: {exc}\n")
        return

    wire.send_message(sock, {
        "decision": verdict["decision"],
        "stage": verdict["stage"],
        "reason": verdict["reason"],
        "response": verdict["response"],
    })


def serve(port: int = wire.BLUE_PORT) -> None:
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((VMADDR_CID_ANY, port))
    listener.listen(16)
    sys.stderr.write(f"blue: listening on vsock any:{port}\n")
    while True:
        connection, _addr = listener.accept()
        with connection:
            handle(connection)


if __name__ == "__main__":
    if not hasattr(socket, "AF_VSOCK"):
        sys.exit("blue: AF_VSOCK is unavailable; run inside the Linux MicroVM")
    serve(int(sys.argv[1]) if len(sys.argv) > 1 else wire.BLUE_PORT)
