"""Bayora VSOCK wire codec.

The Referee is the only component that decides *what* crosses a trust
boundary; every guest speaks exactly one framing on its one socket:

    request   (guest -> referee, or referee -> guest)
        u32 LE length || JSON body          length <= MAX_BODY_BYTES

    response  (referee -> Red guest only)
        exactly RESPONSE_FRAME_BYTES of JSON, ASCII-space padded

The length prefix is checked *before* the body is read so an oversized
declaration costs nothing, and the body is decoded as strict UTF-8 and parsed
as JSON with no trailing garbage. Nothing here is allowed to be lenient: a
guest that tolerates sloppy frames is a guest that can be driven off its
protocol.

This module is deliberately transport-agnostic (it works on any object with
`recv`/`sendall`, e.g. an `AF_VSOCK` or `AF_UNIX` socket), so the same code is
unit-tested over `socket.socketpair()` on a developer machine and used over
`AF_VSOCK` inside the enclave.
"""

from __future__ import annotations

import json
import struct

#: Mirrors `policy.max_prompt_bytes` (config/policy.yaml). The Referee enforces
#: its own ceiling; guests enforce the same one so they cannot be made to
#: allocate an attacker-sized buffer.
MAX_BODY_BYTES = 8192

#: Mirrors `policy.response_frame_bytes`. Constant-size egress is a defence
#: property, not a formatting choice.
RESPONSE_FRAME_BYTES = 4096

#: VSOCK endpoint defaults; keep in step with `bayora-referee --help`.
BLUE_CID = 4
BLUE_PORT = 9001
LLM_CID = 5
LLM_PORT = 9002
#: `VMADDR_CID_HOST` — the host, where the Referee's vsock listener lives.
HOST_CID = 2


class FrameError(Exception):
    """A frame violated the protocol (never caught to continue anyway)."""


def recv_exact(sock, count: int) -> bytes:
    """Read exactly `count` bytes or raise.

    A short read is a protocol error: the peer closed mid-frame.
    """
    if count < 0:
        raise FrameError(f"negative read of {count} bytes")
    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise FrameError(
                f"peer closed after {count - remaining} of {count} bytes"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def encode(obj) -> bytes:
    """Serialize `obj` to `u32 LE length || JSON body`."""
    body = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if not body:
        raise FrameError("refusing to send an empty body")
    if len(body) > MAX_BODY_BYTES:
        raise FrameError(
            f"body of {len(body)} bytes exceeds the {MAX_BODY_BYTES}-byte ceiling"
        )
    return struct.pack("<I", len(body)) + body


def send_message(sock, obj) -> None:
    sock.sendall(encode(obj))


def read_message(sock, max_body: int = MAX_BODY_BYTES) -> dict:
    """Read one length-prefixed JSON message."""
    (length,) = struct.unpack("<I", recv_exact(sock, 4))
    if length == 0 or length > max_body:
        raise FrameError(
            f"length prefix {length} outside 1..{max_body}"
        )
    body = recv_exact(sock, length)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FrameError(f"body is not valid UTF-8: {exc}") from exc
    try:
        # `json.loads` rejects trailing non-whitespace, so a frame cannot
        # smuggle a second document past the first.
        message = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FrameError(f"body is not valid JSON: {exc}") from exc
    if not isinstance(message, dict):
        raise FrameError(f"expected a JSON object, got {type(message).__name__}")
    return message


def read_padded_response(sock, frame_bytes: int = RESPONSE_FRAME_BYTES) -> dict:
    """Read the Referee's constant-size reply.

    The padding is ASCII spaces, which is legal JSON whitespace, so the whole
    buffer parses in one go. The size is checked first: a variable-size egress
    frame would itself be the side channel.
    """
    raw = recv_exact(sock, frame_bytes)
    return read_body(raw)


def read_body(raw: bytes) -> dict:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FrameError(f"response is not valid UTF-8: {exc}") from exc
    try:
        message = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FrameError(f"response is not valid JSON: {exc}") from exc
    if not isinstance(message, dict):
        raise FrameError(f"expected a JSON object, got {type(message).__name__}")
    return message


def pad_response(message: dict, frame_bytes: int = RESPONSE_FRAME_BYTES) -> bytes:
    """Build a constant-size reply frame (guest-side mirror of the Referee).

    A payload that does not fit is refused rather than truncated, because
    truncation would silently change the answer the Referee recorded.
    """
    body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > frame_bytes:
        raise FrameError(
            f"response of {len(body)} bytes exceeds the {frame_bytes}-byte frame"
        )
    return body + b" " * (frame_bytes - len(body))
