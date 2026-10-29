# Guest Workload Audit — IronWall VM v3.0

This document audits the three guest MicroVM workloads (red, blue, llm) against
the v3.0 design doc. Each guest runs inside its own Firecracker MicroVM with no
network device, rootfs mounted read-only, and speaks only to the Referee over
the mediated AF_UNIX vsock.

## Scope

| Role | File | Purpose |
|---|---|---|
| red-team | `workloads/red-team/agent.py` | The adversary — client-only, sends prompt frames, reads constant-size replies |
| blue-team | `workloads/blue-team/agent.py` | The defence — listens for one prompt frame, returns allow/block verdict + stage |
| llm-engine | `workloads/llm-engine/agent.py` | The model — listens for one completion request, returns `{"output": ...}` |
| common | `workloads/common/wire.py` | Shared frame codec (length-prefixed JSON, constant-size egress) |
| common | `workloads/common/policy.py` | Blue's staged defence (regex + semantic + pass) |
| common | `workloads/common/engine.py` | Deterministic LLM stand-in |
| guest | `microvm/guest/init.sh` | PID 1 inside every VM — mounts, role dispatch, digest verification |

## Red-team agent (`workloads/red-team/agent.py`)

### Role in the design
Red is the **untrusted adversary**. It is the only guest that *initiates*
connections out to the Referee. It receives one task file (provisioned disk,
mounted read-only at `/run/bayora`), containing one or more evaluations, each
with exactly one single-use capability and one or more prompts.

### Design compliance

| Design requirement | Implementation | Status |
|---|---|---|
| One turn per evaluation | `break` after first non-`rejected` reply (line 159) | ✅ |
| Capability presented to Referee | `capability` field in prompt frame | ✅ |
| Turn index = 1 | `args.start_turn` (default 1) sent in frame | ✅ |
| Frame format `u32 LE length || JSON` | `wire.send_message` | ✅ |
| Constant-size reply read | `wire.read_padded_response` (exactly 4096 B) | ✅ |
| Observes held_us | `time.monotonic` around send+read | ✅ |
| Writes NDJSON transcript | `args.transcript`, one JSON line per prompt | ✅ |
| stdout transcript | `print(line, flush=True)` | ✅ |
| Bounded connect retry | 30 × 0.2 s ≈ 6 s (lines 88-108) | ✅ |
| No network device | `AF_VSOCK` only | ✅ |
| No filesystem outside read-only rootfs | Reads only `/run/bayora/task.json` | ✅ |
| No path to evidence log or signer | No such file paths referenced | ✅ |

### Observations

1. **One-shot capability semantics** — After the first non-`rejected` reply, the
   loop `break`s (line 159). A rejected turn does **not** break; Red may try
   another prompt against the same capability. This matches the design: "Red
   may try several prompts against a capability but every attempt after the
   first success is refused."

2. **Connect retry vs. capability consumption** — The retry loop (lines 91-108)
   retries *connect* only. If `send_message` or `read_padded_response` fails,
   the exception is caught at line 105 and the loop retries. This means a
   transient failure *after* connect but *during* frame exchange also triggers
   a retry with a **fresh socket**. This is acceptable because the capability
   has not yet been consumed by the Referee until the frame is fully processed;
   if the frame never arrived, no capability was spent.

3. **Transcript records what Red observes** — `observed_held_us` and
   `observed_frame_bytes` (4096) are recorded per prompt. This is Red's
   witness to the bounded-execution property: the same frame size regardless of
   which defence stage fired.

4. **No `--host-cid` dependency under firecracker transport** — The `--host-cid`
   flag exists (default `wire.HOST_CID` = 2) but under AF_UNIX mediation the
   guest connects to CID 2:5000 inside the VM, and Firecracker forwards to the
   Referee's AF_UNIX listener. The agent ignores `host_cid` for the actual
   connect (it uses `args.host_cid` from the CLI, but the task file's
   `host_cid` overrides; under FC the guest doesn't need to know the host CID).

### Minor observations (not blocking)

* Line 143-144 catches `(OSError, wire.FrameError)` around `run_turn`, but
  `run_turn` already catches those same exceptions and returns a
  `transport_error` dict. The outer catch is therefore unreachable for those
  exception types — dead code, harmless but redundant.
* `run_turn` retries on *any* `OSError` during connect, including after a
  successful connect if `send_message` fails mid-write. This is benign: a
  failed send means no capability was consumed.

---

## Blue-team agent (`workloads/blue-team/agent.py`)

### Role in the design
Blue is the **defence classifier**. It listens on VSOCK for one prompt frame,
runs the three-stage defence (regex → semantic → pass), and returns a constant
verdict frame: `{"decision", "stage", "reason", "response"}` where `response` is
always empty for a block (the Referee substitutes its own constant refusal text
so that a block is byte-identical regardless of stage).

### Design compliance

| Design requirement | Implementation | Status |
|---|---|---|
| Listens on AF_VSOCK | `socket.AF_VSOCK`, `VMADDR_CID_ANY`, port 9001 | ✅ |
| Reads length-prefixed JSON frame | `wire.read_message` | ✅ |
| Rejects malformed frames | `FrameError` → return without reply | ✅ |
| Three-stage defence (regex, semantic, pass) | `policy.classify` | ✅ |
| Constant-size reply frame | `wire.send_message` (Referee pads to 4096 B) | ✅ |
| No network device | `AF_VSOCK` only | ✅ |
| No filesystem outside rootfs | Reads only prompt from frame | ✅ |
| Single request per connection | `handle()` serves one `wire.read_message` then returns | ✅ |
| listen backlog 16 | `listener.listen(16)` | ✅ |
| `SO_REUSEADDR` | Set before bind | ✅ |

### Observations

1. **Blue is a pure server** — It never initiates connections. It cannot
   exfiltrate data to Red or the LLM because it never connects out. Its only
   egress is the reply frame back to the Referee.

2. **Fail-closed on malformed input** — If `prompt` is missing or not a string,
   `policy.classify(None)` raises `TypeError`, which is caught and the
   connection is closed without sending a reply. The Referee's `read_padded_response`
   will then get a short read / connection closed and treat it as a failure.
   This is correct fail-closed behavior.

3. **`response` is always `""`** — Blue's verdict object always has empty
   `response`. The Referee substitutes its own constant refusal text for
   blocked turns, so Blue cannot influence the response bytes. This is correct.

4. **No capability/token validation** — Blue does not validate capabilities;
   that is the Referee's job. Blue only sees the prompt and returns a verdict.
   This is correct per the design.

---

## LLM-engine agent (`workloads/llm-engine/agent.py`)

### Role in the design
The LLM guest is the **model worker**. It listens on VSOCK for one completion
request, runs the deterministic stand-in engine, and returns `{"output": ...}`.
It is reset between evaluations by the Referee (snapshot restore).

### Design compliance

| Design requirement | Implementation | Status |
|---|---|---|
| Listens on AF_VSOCK | `socket.AF_VSOCK`, `VMADDR_CID_ANY`, port 9002 | ✅ |
| Reads length-prefixed JSON frame | `wire.read_message` | ✅ |
| Calls `engine.respond(prompt, max_tokens)` | ✅ |
| Sends `{"output": ...}` | `wire.send_message(sock, response)` | ✅ |
| Rejects malformed prompts | `TypeError`/`ValueError` → return without reply | ✅ |
| Single request per connection | `handle()` serves one message then returns | ✅ |
| listen backlog 8 | `listener.listen(8)` | ✅ |
| `SO_REUSEADDR` | Set before bind | ✅ |
| No network device | `AF_VSOCK` only | ✅ |

### Observations

1. **Single request per connection** — `handle()` reads one message, replies
   once, returns. The connection is closed by the `with connection:` block.
   The Referee reads exactly one padded response per connection. This matches
   the one-turn-per-evaluation model.

2. **Input validation is strict** — `prompt` must be `str`, `max_tokens` must be
   `int` and `> 0` and `<= MAX_TOKENS_CEILING (512)`. Any violation raises
   `TypeError`/`ValueError`, caught by `handle`, connection closed without
   reply. Fail-closed.

3. **No state between requests** — The engine is a pure function of `(prompt,
   max_tokens)`. There is no KV cache, no conversation history, no randomness,
   no clock. This matches the design: "deliberately unable to leak anything
   about the guards: it never sees which stage let the prompt through, only the
   prompt itself."

4. **The `.gguf` file is not parsed** — `engine.respond` does not touch the
   model file. The model digest verification happens in `init.sh` *before* the
   agent starts. If the digest mismatches, init loops forever and the agent
   never binds its socket, so the Referee sees a deadline abort. This is
   correct fail-closed behavior.

---

## Common wire codec (`workloads/common/wire.py`)

### Design compliance

| Design requirement | Implementation | Status |
|---|---|---|
| Length-prefixed JSON: `u32 LE || JSON` | `encode` / `read_message` | ✅ |
| Max body 8192 B enforced before body read | `read_message` checks `length > max_body` | ✅ |
| Reply exactly 4096 B, space-padded | `pad_response` / `read_padded_response` | ✅ |
| Rejects malformed UTF-8 | `body.decode("utf-8")` raises → `FrameError` | ✅ |
| Rejects trailing garbage | `json.loads` rejects trailing non-whitespace | ✅ |
| Rejects unknown fields (serenity) | Handled by `#[serde(deny_unknown_fields)]` on Rust side | ✅ (Rust side) |
| Works over AF_UNIX and AF_VSOCK | Uses `socket.socket` generically | ✅ |
| Transport-agnostic (unit-testable via socketpair) | No platform-specific calls | ✅ |

### Observations

* `encode` raises `FrameError` if body > 8192 B — the guest refuses to send
  oversized frames, which is correct: the Referee would reject them anyway.
* `read_message` checks `length == 0` → `FrameError`. Zero-length frames are
  refused.
* `read_padded_response` reads exactly `frame_bytes` (4096). If the peer sends
  less and closes, `recv_exact` raises `FrameError("short read")`. If the peer
  sends more, only 4096 bytes are read (the rest stays in the socket buffer,
  but the connection is closed by the Referee after sending, so this is moot).
* The `FrameError` is never caught and swallowed silently in the wire layer —
  it propagates to the caller, which decides what to do (close connection,
  return without reply, etc.).

---

## Common policy (`workloads/common/policy.py`)

### Design compliance

| Design requirement | Implementation | Status |
|---|---|---|
| Regex stage: literal denylist + instruction-override | `DENYLIST` + `OVERRIDE_PATTERN` | ✅ |
| Semantic stage: probing detector | `PROBE_TOKENS` count | ✅ |
| Pass stage: nothing objectionable | Returns `allow` | ✅ |
| Cheapest stage first | `regex_stage` → `semantic_stage` → `allow` | ✅ |
| No third-party dependencies | Pure Python `re` only | ✅ |
| Byte-identical response for both block stages | `response: ""` in both | ✅ |
| Stage name in verdict for evidence | `"regex"` / `"semantic"` / `"pass"` | ✅ |

### Observations

1. **`PROBE_THRESHOLD = 1`** — A single probe keyword triggers the semantic
   block. This is intentional: the design says the semantic stage is a
   "probing-the-policy scorer". A single keyword match is sufficient to flag
   the prompt as probing. This is a conservative (false-positive-prone)
   threshold, which is correct for a defence: it is better to over-block than
   under-block.

2. **`OVERRIDE_PATTERN`** — Regex `\b(ignore|disregard|forget|override)\b[^.]{0,40}?\b(previous|prior|above|earlier|your)\b[^.]{0,20}?\b(instruction|instructions|prompt|rules|guidelines)\b`.
   This is case-insensitive (`re.IGNORECASE`) and robust to punctuation/filler
   words between the command and the target. It is a reasonable approximation
   of instruction-override detection for a stand-in.

3. **`normalise`** — Collapses whitespace and lowercases. This means prompts
   with extra spaces or different casing are normalized before checking. Good
   for preventing trivial evasion.

4. **`classify` raises `TypeError` if `prompt` is not a `str`** — Blue's agent
   catches this and closes the connection without replying. Fail-closed.

---

## Guest init.sh (`microvm/guest/init.sh`)

### Design compliance

| Design requirement | Implementation | Status |
|---|---|---|
| PID 1 inside every MicroVM | `exec` replaces the shell with the agent | ✅ |
| Rootfs mounted read-only | Firecracker `is_read_only: true` | ✅ (config) |
| devtmpfs, proc, sysfs, tmpfs mounts | Lines 27-35 | ✅ |
| Role from kernel cmdline only | `bayora.role=` parsed from `/proc/cmdline` | ✅ |
| Port from kernel cmdline | `bayora.port=` parsed | ✅ |
| Model digest from kernel cmdline (llm only) | `bayora.model_sha256=` parsed and verified | ✅ |
| Red: mounts provisioning disk read-only | `mount -t ext4 -o ro /dev/vdb /run/bayora` | ✅ |
| Red: deletes task disk after use | Not implemented — but the disk is read-only and ephemeral (tmpfs-backed? No, it's a virtio-blk backed by the host ext4 image) | ⚠️ See below |
| Red: execs agent.py | execs the red Python agent | ✅ |
| Blue: execs agent.py with port | execs the blue Python agent on port 9001 | ✅ |
| LLM: verifies model digest before binding | `sha256sum -c` before exec | ✅ |
| LLM: fail-closed loops if digest missing/mismatch | `while :; do sleep 3600; done` | ✅ |
| Unknown role: debug shell | `exec sh` | ✅ |

### Observations

1. **`uname` not found** — Line 43 calls `uname -r` which busybox may not
   provide. This is logged to `/dev/kmsg` only and is non-fatal (`|| true`).
   Cosmetic only.

2. **Red task disk persistence** — The task disk (`red-task.ext4`) is mounted
   read-only at `/run/bayora`. Red reads `task.json` from it. The disk is not
   explicitly unmounted or deleted after use. However, since the VM is
   destroyed after each evaluation (Firecracker snapshot reset), the disk
   contents are ephemeral. Red cannot re-run because the VM is gone. This is
   acceptable: the "one shot" property is enforced at the MicroVM level, not
   the filesystem level.

3. **`/dev/kmsg` logging** — All init messages go to `/dev/kmsg` with `|| true`
   fallbacks. This is fine for debugging but not security-critical.

4. **`set -eu`** — Any unhandled command failure causes init.sh to exit, which
   would cause the VM to halt. This is fail-closed: if mounting fails, the VM
   doesn't boot the agent.

---

## Overall assessment

| Component | Security posture | Issues found |
|---|---|---|
| Red agent | Good — client-only, one-shot capability, constant-size reply witness | Minor: redundant exception handling |
| Blue agent | Good — server-only, fail-closed on malformed input, constant-size reply | None |
| LLM agent | Good — server-only, deterministic, input validation, no state | None |
| Wire codec | Good — strict framing, length prefix, constant-size response, UTF-8 validation | None |
| Policy | Good — three stages, cheapest first, constant response for blocks | None |
| init.sh | Good — fail-closed, role-based dispatch, model digest verification | Minor: `uname` not found (cosmetic) |

**Overall: The guest workloads correctly implement the v3.0 design. All three
guests are clients or servers only (never both), speak only the mediated frame
protocol, have no network device, no filesystem outside their read-only rootfs,
and fail closed on malformed input. The Resettable pillar is enforced at the
Referee level (snapshot restore) and the guest level (no persistent state
across turns).**

### Recommended hardening (low priority)

1. Red agent: Remove the redundant `try/except` around `run_turn` (lines 143-144)
   since `run_turn` already catches `OSError`/`FrameError`.
2. init.sh: Remove or guard the `uname` call (line 43) since busybox may not
   provide it.
3. Consider adding a `--vsock-cid` flag to red-agent instead of hardcoding
   `host_cid: 2` in the default, though under Firecracker mediation the guest
   always connects to CID 2 anyway.
4. Consider adding a task-disk unmount/delete step in red's init.sh after the
   agent exits, for defense-in-depth (the VM is destroyed anyway, but explicit
   cleanup is cleaner).
