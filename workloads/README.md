# Guest workloads

The three untrusted parties, one directory each. Every guest is a single Python
3 file with no third-party dependencies, because a MicroVM rootfs built from
these directories has no package index and no network.

```
common/
  wire.py      the VSOCK frame codec (u32 LE length || JSON)
  policy.py    Blue's staged defence: regex -> semantic -> pass
  engine.py    the deterministic LLM stand-in
red-team/agent.py    the adversary: speaks the frame protocol to the Referee
blue-team/agent.py   the defence stages: answers the Referee with a verdict
llm-engine/agent.py  the model: answers the Referee with a completion
tests/test_workloads.py  24 tests, runnable anywhere (no AF_VSOCK needed)
```

## Who may talk to whom

Nothing here chooses its peer. The topology does:

```
Red  --frame-->  Referee  --BlueRequest-->  Blue
                    |     <--BlueVerdict--
                    |
                    +---LlmRequest----->  LLM    (only when Blue allows)
                        <--LlmResponse--
```

Blue never sees the prompt's origin and never talks to the LLM: the Referee
calls the LLM itself, so the decision to spend model time is made in the TCB,
not in the defence VM. Red sees only a constant-size response envelope with no
stage field, so it cannot tell a `regex_block` from a `semantic_block` — the
demo asserts the two are byte-identical from Red's side and that the evidence
log records the same response digest for both.

## The frame protocol

```
request   u32 LE length || JSON body            length <= 8192
response  exactly 4096 bytes of JSON, ASCII-space padded
```

`wire.py` is strict on purpose: the length prefix is checked before the body is
allocated, the body must be valid UTF-8, the JSON must have no trailing garbage,
and the top level must be an object. A guest that tolerates a sloppy frame is a
guest that can be driven off its protocol, so the tests pin every one of those
rejections.

## Running the tests

```bash
python3 workloads/tests/test_workloads.py
```

They cover the codec over `socket.socketpair()`, Blue's three stages, the LLM
stand-in's bounds and determinism, and the exact field sets the Referee
deserializes with `deny_unknown_fields`. The two ends of the wire are written in
different languages, so the tests exist to stop them drifting apart.

## Running the guests for real

Inside the MicroVMs, `microvm/guest/init.sh` starts them from the kernel command
line. On a Linux box without Firecracker, start them as ordinary processes and
point the Referee's VSOCK transport at `VMADDR_CID_LOCAL`:

```bash
python3 workloads/blue-team/agent.py 9001 &
python3 workloads/llm-engine/agent.py 9002 &
cargo run -p bayora-referee -- --transport vsock \
    --blue-cid 1 --blue-port 9001 --llm-cid 1 --llm-port 9002 \
    --vsock-port 5000 --signer unix:/tmp/bayora-signer.sock \
    --policy config/policy.yaml --images config/images.json \
    --evidence-log evidence/evidence_log.ndjson
```

`scripts/demo-vsock.py` does all of that, then provisions Red, runs it, and
verifies the resulting log — end to end, in one command.

## Status

`policy.py` is a real (if small) staged defence: a literal denylist, an
instruction-override pattern, and a probing scorer. Production replaces the
scorer with a classifier model; the verdict shape stays exactly the same, which
is why the Referee's `deny_unknown_fields` parser pins it.

`engine.py` is a deterministic stand-in for llama.cpp so that evidence is
replayable on a machine with no GPU. It never learns which stage admitted the
prompt, so it cannot leak that distinction even if it is fully compromised.
