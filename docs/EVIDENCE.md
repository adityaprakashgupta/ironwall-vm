# Evidence plane specification (byte-for-byte)

Everything the Referee asserts about an evaluation ends up in this log, and
everything the log claims is re-derived by the Independent Verifier. This
document is the contract between the two.

## Canonicalization: RFC 8785 JCS

Every hashed document passes through `bayora_common::jcs::to_bytes` before it is
hashed or written:

* object keys sorted by UTF-16 code unit;
* no insignificant whitespace;
* strings escaped per `serde_json` (no non-ASCII escapes);
* **floating point is rejected** — timings are recorded as integer microseconds
  (`held_us`), so both sides always hash identical bytes.

Consequence: the NDJSON line, the PostgreSQL row, and the verifier's
re-serialization are the same bytes. The verifier treats any line that is *not*
its own re-serialization as tampering (`NonCanonicalLine`), which catches key
reordering, injected fields, and whitespace reformatting in one check.

## Record shapes

Records are an internally tagged enum — `{"record_type": ...}` — with
`deny_unknown_fields`, so an injected field is a hard parse error.

### `evaluation` — one finalized evaluation

```json
{
  "record_type": "evaluation",
  "seq": 0,
  "manifest": { "evaluation_id": "…", "red_image_digest": "sha256:…", … },
  "manifest_hash": "<64 hex>",
  "manifest_signature": "<128 hex>",
  "events": [ { "event_type": "evaluation_started", … }, … ],
  "event_hash": "<64 hex>",
  "prev_chain_hash": "<64 hex>",
  "chain_hash": "<64 hex>"
}
```

JCS sorts keys, so the tag is **not** first — expect `{"chain_hash"…` on disk.

* `manifest` — the Evaluation Manifest: image digests, model digest, referee and
  Firecracker versions, kernel digest, timing/reset/resource policy, start time
  and a per-run nonce. This is what the Trust Anchor signs.
* `manifest_hash = sha256(JCS(manifest))`.
* `manifest_signature` — Ed25519 over the **raw 32 bytes** of `manifest_hash`.
* `events` — the ordered, canonically-hashed narrative (see below).
* `event_hash = sha256(JCS(events))`.
* `prev_chain_hash` — the previous chain hash (genesis = 32 zero bytes).
* `chain_hash` — see the chain formula below.

### `batch_seal` — a Merkle commitment over a run of chain hashes

```json
{
  "record_type": "batch_seal",
  "batch_id": "batch_9",
  "seq_start": 0,
  "seq_end": 8,
  "leaves": ["<64 hex>", …],
  "merkle_root": "<64 hex>",
  "signature": "<128 hex>",
  "sealed_at": "2026-09-26T16:05:00.000Z"
}
```

* leaves are the per-evaluation `chain_hash` values for `seq_start ..= seq_end`;
* `merkle_root = merkle_root(leaves)`;
* `signature` — Ed25519 over the raw 32 bytes of `merkle_root`.

## The event array

Exactly one `prompt_routed` and one `response_released` per evaluation; the
first event must be `evaluation_started` carrying this record's manifest hash.

| `event_type` | fields |
|---|---|
| `evaluation_started` | `evaluation_id`, `manifest_hash` |
| `state_reset` | `evaluation_id`, `mode`, `duration_us` |
| `prompt_routed` | `evaluation_id`, `path` (`regex_block` \| `semantic_block` \| `llm`) |
| `response_released` | `evaluation_id`, `held_us`, `frame_bytes`, `truncated`, `response_digest` |
| `deadline_abort` | `evaluation_id`, `elapsed_us` |

Completion is signalled by the **record** itself (its presence in the log), not
by an `evaluation_completed` event — otherwise the chain hash would depend on an
event that depends on the chain hash.

Every event's `evaluation_id` must equal the manifest's `evaluation_id`.

## The hash chain

```text
EventHash_i  = sha256( JCS(events_i) )
ManifestHash = sha256( JCS(manifest_i) )
ChainHash_i  = sha256( ChainHash_{i-1} || ManifestHash_i || EventHash_i )
ChainHash_-1 = 0x00 × 32                         (genesis)
```

`seq` is the index in the chain and must be strictly sequential from 0.

Removing, reordering, or editing any record breaks every subsequent link, and
because the links cover *both* the manifest and the events, an attacker cannot
substitute a compatible manifest either.

## Merkle batches

```text
level₀ = [ ChainHash_seq_start , … , ChainHash_seq_end ]
levelₖ = [ sha256(l || r) for each adjacent pair, or the lone node itself ]
root   = the single node at the top
```

* An **odd node is promoted unchanged** — never duplicated (duplication would
  make a leaf verifiable in two different positions).
* An empty leaf set is rejected.
* The default batch size is `audit.batch_size` in `config/policy.yaml`
  (default 8); `POST /v1/evaluations/seal` forces one.
* Seals must not overlap; the verifier enforces `seq_start > previous seq_end`.

## Dual sink

`EvidenceEmitter` fans each canonical record out to every configured sink:

| Sink | Purpose | Failure policy |
|---|---|---|
| `NDJsonSink` | append-only `evidence_log.ndjson` — the **audit-trusted** copy | always on |
| `PostgresSink` | fast query path for the dashboard | opt-in (`--features postgres`) |

Both receive the identical canonical bytes. If the two ever diverge, the run is
tampered — `bayora-verifier --postgres-url …` compares them record for record
(`SinkDivergence`) and names the first differing index.

Schema used by the verifier's comparison:

```sql
CREATE TABLE evidence_records (
  id           BIGSERIAL PRIMARY KEY,   -- preserves append order
  record_bytes BYTEA NOT NULL
);
```

## What the verifier recomputes

For each `evaluation` record, in log order:

1. `sha256(JCS(manifest))` == `manifest_hash`;
2. Ed25519 verify over the raw 32 bytes of `manifest_hash`;
3. `sha256(JCS(events))` == `event_hash`;
4. events bound to the manifest (ids match; first event carries the hash);
5. environment digests identical across the whole log (no mid-run drift);
6. timing policy identical across the whole log;
7. exactly one `prompt_routed` and one `response_released`;
8. `frame_bytes` constant across the whole log (constant-size egress);
9. `prev_chain_hash` == previous head, `chain_hash` recomputes, `seq` sequential;
10. evaluation id and manifest nonce are each unique.

For each `batch_seal`: recompute the Merkle root from the recorded leaves,
verify the root signature, check the range is contiguous and inside the log,
check no overlap with a previous seal, and check every leaf equals the chain
hash at that `seq`.

Finally the verifier **independently measures the timing side channel** from
`response_released.held_us` values: distinct held times, sample standard
deviation, whether the band sits inside the declared bucket window, and
attacker inference accuracy (1-D k-means, k=3, majority-voted labels) against the
defence-stage label.

Two guards stop that measurement from flattering itself:

* the accuracy is only *stated* with at least nine samples across at least two
  distinct stage labels — below that, `k=3` degenerates to one cluster per point
  and would report a meaningless `1.00`, so the verifier prints
  `not measurable` instead;
* `bounded` requires the declared mode, a single band (relative spread < 5 %),
  and every released frame inside the declared bucket window
  (`bucket − 2 ms .. bucket + 30 ms`).

Under `--strict-timing`, a run declared `EVAL_*` whose measurable accuracy makes
the stage recoverable is reported invalid; a run with too few samples to decide
is reported **inconclusive**, not invalid.

## Reading the log

```bash
# full report
bayora-verifier --log evidence.ndjson --pubkey keys/trust_anchor.pk

# trimmed to your published expectations
bayora-verifier --log evidence.ndjson --pubkey keys/trust_anchor.pk \
    --expect-evaluations 12 --expect-seals 2 \
    --expect-chain-head 4ab2… --require-all-sealed --strict-timing

# machine-readable
bayora-verifier --log evidence.ndjson --pubkey keys/trust_anchor.pk --json
```

Sample success output:

```text
VALID
  evaluations   : 9
  batch seals   : 1
  unsealed      : 0
  chain head    : 4ab2c0…
  trust anchor  : 1f0e…
  timing        : EVAL_500 - 9 sample(s), held 500918..501742us, stddev 301us (0.0602% of mean), inference accuracy 0.33 (bounded)
```

Sample failure output (pinpointed, exit 1):

```text
INVALID
line 7: event hash mismatch for eval_0195f2a4: recorded 3c1a…, recomputed 9be4…
```
