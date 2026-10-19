#!/usr/bin/env python3
"""Red-team guest agent — the untrusted party, inside its own MicroVM.

Red is the adversary. It gets exactly one thing from the Control Plane: a
provisioned task file. It has no network, no filesystem outside its own
read-only rootfs, and no path to the evidence log or the signer.

    task file (written by the host before the run):
        {
          "host_cid": 1,                  optional; 1 == VMADDR_CID_LOCAL
          "vsock_port": 5000,             optional; the Referee's listener
          "evaluations": [
            {"eval_id": "eval_...", "capability": {...}, "prompts": ["..."]},
            ...
          ]
        }

Each evaluation comes with exactly one single-use capability, so Red gets one
accepted turn per evaluation; it may try several prompts against a capability
but every attempt after the first success is refused. That is the point.

    to the Referee:  u32 LE length || JSON PromptFrame
        {"frame_type": "prompt", "eval_id": "...", "capability": {...},
         "turn": 1, "prompt": "..."}
    from the Referee: exactly RESPONSE_FRAME_BYTES of JSON, space padded
        {"status": "ok" | "rejected" | "timeout", "data": "..."}

Red writes an NDJSON transcript to stdout and to `--transcript`, recording the
whole reply frame size and its own clock reading, because "the wire and the
latency never vary" are properties Red is the natural witness to.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from common import wire  # noqa: E402

DEFAULT_TASK = "/run/bayora/task.json"
DEFAULT_TRANSCRIPT = "/var/log/bayora/red-transcript.ndjson"


def load_task(path: str) -> dict:
    """Read and validate the provisioned task. Refuses anything ambiguous."""
    with open(path, "r", encoding="utf-8") as handle:
        task = json.load(handle)
    if not isinstance(task, dict):
        raise ValueError(f"task file {path} must be a JSON object")
    evaluations = task.get("evaluations")
    if not isinstance(evaluations, list) or not evaluations:
        raise ValueError("task file must list at least one evaluation")
    for index, entry in enumerate(evaluations):
        if not isinstance(entry, dict):
            raise ValueError(f"evaluation {index} must be a JSON object")
        for key in ("eval_id", "capability", "prompts"):
            if key not in entry:
                raise ValueError(f"evaluation {index} is missing {key!r}")
        if not isinstance(entry["prompts"], list) or not entry["prompts"]:
            raise ValueError(f"evaluation {index} must list at least one prompt")
    return task


def run_turn(
    host_cid: int, vsock_port: int, eval_id: str, capability, prompt: str, turn: int
) -> dict:
    """Send one prompt frame and read the constant-size reply.

    Connects are retried boundedly: the Referee's AF_UNIX listener may not be
    up the instant Red boots (boot race), and Red's one-shot connect must not
    fail the whole evaluation on a transient. Every attempt after a successful
    connect is a fresh socket; send/read errors are not retried past the
    deadline because they indicate a real fault, not a boot race.
    """
    frame = {
        "frame_type": "prompt",
        "eval_id": eval_id,
        "capability": capability,
        "turn": turn,
        "prompt": prompt,
    }
    retries = 30          # ~6 s of connect retries before giving up
    delay = 0.2
    last_exc: Exception | None = None
    for _ in range(retries):
        try:
            with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as sock:
                sock.settimeout(30.0)
                sock.connect((host_cid, vsock_port))
                started = time.monotonic()
                wire.send_message(sock, frame)
                reply = wire.read_padded_response(sock)
                held_us = int((time.monotonic() - started) * 1_000_000)
            reply["observed_held_us"] = held_us
            # Red is the witness to the constant-size egress property: it reads
            # the same number of bytes whatever the verdict was.
            reply["observed_frame_bytes"] = wire.RESPONSE_FRAME_BYTES
            return reply
        except (OSError, wire.FrameError) as exc:
            last_exc = exc
            time.sleep(delay)
    return {"status": "transport_error", "data": str(last_exc)}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Bayora Red-team guest agent")
    parser.add_argument("--task", default=DEFAULT_TASK)
    parser.add_argument("--transcript", default=DEFAULT_TRANSCRIPT)
    parser.add_argument("--host-cid", type=int, default=wire.HOST_CID)
    parser.add_argument("--vsock-port", type=int, default=5000)
    parser.add_argument("--start-turn", type=int, default=1)
    args = parser.parse_args(argv)

    if not hasattr(socket, "AF_VSOCK"):
        sys.exit("red: AF_VSOCK is unavailable; run inside the Linux MicroVM")

    task = load_task(args.task)
    host_cid = int(task.get("host_cid", args.host_cid))
    vsock_port = int(task.get("vsock_port", args.vsock_port))

    transcript_dir = os.path.dirname(args.transcript)
    if transcript_dir:
        os.makedirs(transcript_dir, exist_ok=True)

    with open(args.transcript, "w", encoding="utf-8") as transcript:
        for entry in task["evaluations"]:
            for prompt in entry["prompts"]:
                try:
                    reply = run_turn(
                        host_cid,
                        vsock_port,
                        entry["eval_id"],
                        entry["capability"],
                        prompt,
                        args.start_turn,
                    )
                except (OSError, wire.FrameError) as exc:
                    reply = {"status": "transport_error", "data": str(exc)}

                record = {
                    "eval_id": entry["eval_id"],
                    "turn": args.start_turn,
                    "prompt": prompt,
                    "status": reply.get("status", ""),
                    "frame_bytes": reply.get("observed_frame_bytes"),
                    "data": reply.get("data", ""),
                    "observed_held_us": reply.get("observed_held_us"),
                }
                line = json.dumps(record, separators=(",", ":"), ensure_ascii=False)
                print(line, flush=True)
                transcript.write(line + "\n")

                if reply.get("status") != "rejected":
                    # This capability is spent; the next prompt needs its own.
                    break
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
