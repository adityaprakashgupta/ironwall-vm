//! Evidence emission: the dual-sink append log + hash chain + Merkle seals.
//!
//! Every finalized evaluation becomes an [`EvidenceRecord::Evaluation`]
//! appended to every registered [`EvidenceSink`]:
//!
//! * `evidence/evidence_log.ndjson` — append-only, canonical (JCS) bytes;
//! * PostgreSQL — the same bytes in a column, for fast querying.
//!
//! The verifier re-reads the append log and proves divergence between the two
//! sinks (Stage 4B), which is why the log is the audit-trusted copy and the
//! database is the fast one.
//!
//! Trust anchor interaction: the manifest is signed when the evaluation is
//! *created* (before any prompt), and each batch of chain hashes is signed via
//! a Merkle root when sealed. This module only transports those signatures —
//! it never holds a key.

use crate::trust_anchor::{SignerError, TrustAnchorSigner};
use bayora_common::chain::{merkle_root, ChainState};
use bayora_common::digest::Digest;
use bayora_common::events::{hash_events, EvaluationEvent};
use bayora_common::manifest::EvaluationManifest;
use bayora_common::records::EvidenceRecord;
use bayora_common::timeutil::now_rfc3339_ms;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("sink write failed: {0}")]
    Io(String),
    #[error("sink rejected record: {0}")]
    Rejected(String),
    #[error("sink is not configured")]
    Unconfigured,
}

#[async_trait::async_trait]
pub trait EvidenceSink: Send + Sync {
    /// Append the canonical bytes of one record.
    async fn append(&self, canonical: &[u8]) -> Result<(), SinkError>;
    /// Human-readable sink identity for the HUD / logs.
    fn describe(&self) -> String;
}

/// Append-only NDJSON file. Canonical bytes plus a trailing newline.
pub struct NDJsonSink {
    path: PathBuf,
    file: tokio::sync::Mutex<tokio::fs::File>,
}

impl NDJsonSink {
    pub async fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await?;
        Ok(NDJsonSink {
            path,
            file: tokio::sync::Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait::async_trait]
impl EvidenceSink for NDJsonSink {
    async fn append(&self, canonical: &[u8]) -> Result<(), SinkError> {
        let mut file = self
            .file
            .lock()
            .await;
        file.write_all(canonical)
            .await
            .map_err(|e| SinkError::Io(e.to_string()))?;
        file.write_all(b"\n")
            .await
            .map_err(|e| SinkError::Io(e.to_string()))?;
        file.flush()
            .await
            .map_err(|e| SinkError::Io(e.to_string()))?;
        Ok(())
    }

    fn describe(&self) -> String {
        format!("ndjson:{}", self.path.display())
    }
}

/// In-memory sink for tests.
pub struct MemorySink {
    lines: Mutex<Vec<Vec<u8>>>,
}

impl MemorySink {
    pub fn new() -> Self {
        MemorySink {
            lines: Mutex::new(Vec::new()),
        }
    }

    pub fn lines(&self) -> Vec<Vec<u8>> {
        self.lines.lock().unwrap().clone()
    }

    pub fn len(&self) -> usize {
        self.lines.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for MemorySink {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl EvidenceSink for MemorySink {
    async fn append(&self, canonical: &[u8]) -> Result<(), SinkError> {
        self.lines
            .lock()
            .unwrap()
            .push(canonical.to_vec());
        Ok(())
    }

    fn describe(&self) -> String {
        "memory".into()
    }
}

/// PostgreSQL dual-sink (fast query path). Enabled with `--features postgres`.
#[cfg(feature = "postgres")]
pub struct PostgresSink {
    client: tokio::sync::Mutex<tokio_postgres::Client>,
}

#[cfg(feature = "postgres")]
impl PostgresSink {
    pub async fn connect(url: &str) -> Result<Self, SinkError> {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .map_err(|e| SinkError::Io(e.to_string()))?;
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                tracing::error!(error = %e, "postgres connection closed");
            }
        });
        Ok(PostgresSink {
            client: tokio::sync::Mutex::new(client),
        })
    }
}

#[cfg(feature = "postgres")]
#[async_trait::async_trait]
impl EvidenceSink for PostgresSink {
    async fn append(&self, canonical: &[u8]) -> Result<(), SinkError> {
        let mut client = self.client.lock().await;
        client
            .execute(
                "INSERT INTO evidence_records (record_bytes) VALUES ($1)",
                &[&canonical],
            )
            .await
            .map_err(|e| SinkError::Rejected(e.to_string()))?;
        Ok(())
    }

    fn describe(&self) -> String {
        "postgres".into()
    }
}

/// Fans out one canonical record to every sink.
pub struct DualSink {
    sinks: Vec<std::sync::Arc<dyn EvidenceSink>>,
}

impl DualSink {
    pub fn new(sinks: Vec<std::sync::Arc<dyn EvidenceSink>>) -> Self {
        DualSink { sinks }
    }

    pub fn len(&self) -> usize {
        self.sinks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sinks.is_empty()
    }

    pub fn descriptions(&self) -> Vec<String> {
        self.sinks.iter().map(|s| s.describe()).collect()
    }

    /// Append to every sink. Fails closed: a sink failure is an error the
    /// caller must surface, never a silently dropped record.
    async fn append_all(&self, canonical: &[u8]) -> Result<(), SinkError> {
        for sink in &self.sinks {
            sink.append(canonical).await?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EmitterError {
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error("sink failure: {0}")]
    Sink(#[from] SinkError),
    #[error("canonicalization failed: {0}")]
    Canonical(String),
    #[error("merkle construction failed: {0}")]
    Merkle(String),
}

/// Builds and appends evidence records.
pub struct EvidenceEmitter {
    chain: Mutex<ChainState>,
    pending_leaves: Mutex<Vec<Digest>>,
    sink: DualSink,
    signer: std::sync::Arc<dyn TrustAnchorSigner>,
    require_manifest_signature: bool,
    batch_size: usize,
}

impl EvidenceEmitter {
    pub fn new(
        sink: DualSink,
        signer: std::sync::Arc<dyn TrustAnchorSigner>,
        require_manifest_signature: bool,
        batch_size: usize,
    ) -> Self {
        EvidenceEmitter {
            chain: Mutex::new(ChainState::genesis()),
            pending_leaves: Mutex::new(Vec::new()),
            sink,
            signer,
            require_manifest_signature,
            batch_size: batch_size.max(1),
        }
    }

    pub fn sink(&self) -> &DualSink {
        &self.sink
    }

    pub fn chain_head(&self) -> Digest {
        self.chain.lock().unwrap().prev_hash()
    }

    pub fn chain_len(&self) -> u64 {
        self.chain.lock().unwrap().len()
    }

    pub fn pending_leaves(&self) -> usize {
        self.pending_leaves.lock().unwrap().len()
    }

    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    pub fn trust_anchor_public_key_hex(&self) -> String {
        self.signer.public_key_hex()
    }

    /// Append one evaluation record: link it into the hash chain, then write
    /// the canonical bytes to every sink.
    ///
    /// The returned record carries the chain hash and sequence number so the
    /// caller can finish the turn response and (if a batch is due) seal it.
    pub async fn emit_evaluation(
        &self,
        manifest: &EvaluationManifest,
        manifest_signature: String,
        events: &[EvaluationEvent],
    ) -> Result<EvidenceRecord, EmitterError> {
        if self.require_manifest_signature && manifest_signature.is_empty() {
            return Err(EmitterError::Sink(SinkError::Rejected(
                "manifest signature missing but required by policy".into(),
            )));
        }

        let manifest_hash = manifest
            .hash()
            .map_err(|e| EmitterError::Canonical(e.to_string()))?;
        let event_digest = Digest(hash_events(events).map_err(|e| EmitterError::Canonical(e.to_string()))?);

        // Link into the chain, capturing the previous head first so the
        // record is self-describing (verifier needs it to re-derive the link).
        let (seq, chain_hash, prev_chain_hash) = {
            let mut chain = self.chain.lock().unwrap();
            let prev = chain.prev_hash();
            let (seq, hash) = chain.link(&manifest_hash, &event_digest);
            (seq, hash, prev)
        };

        // Queue the chain hash as the next Merkle leaf.
        self.pending_leaves
            .lock()
            .unwrap()
            .push(chain_hash);

        let record = EvidenceRecord::Evaluation {
            seq,
            manifest: manifest.clone(),
            manifest_hash: manifest_hash.to_hex(),
            manifest_signature,
            events: events.to_vec(),
            event_hash: event_digest.to_hex(),
            prev_chain_hash: prev_chain_hash.to_hex(),
            chain_hash: chain_hash.to_hex(),
        };

        // Dual sink: canonical bytes to every registered sink. A sink failure
        // is an error the caller must surface, never a silent drop.
        let canonical = record
            .canonical_bytes()
            .map_err(|e| EmitterError::Canonical(e.to_string()))?;
        self.sink.append_all(&canonical).await?;

        Ok(record)
    }

    /// Seal the pending chain hashes into a Merkle batch (or `None` if there
    /// is nothing to seal). The batch root is signed by the trust anchor.
    ///
    /// `auto_seal` is used after each evaluation; explicit sealing is also
    /// exposed via the control plane (`POST /v1/evaluations/seal`).
    pub async fn seal_batch(
        &self,
        batch_id: &str,
    ) -> Result<Option<EvidenceRecord>, EmitterError> {
        let leaves: Vec<Digest> = {
            let mut pending = self.pending_leaves.lock().unwrap();
            if pending.is_empty() {
                return Ok(None);
            }
            pending.drain(..).collect()
        };
        let seq_start = self.chain.lock().unwrap().len().saturating_sub(leaves.len() as u64);
        let seq_end = self.chain.lock().unwrap().len().saturating_sub(1);
        let root = merkle_root(&leaves).map_err(|e| EmitterError::Merkle(e.to_string()))?;

        // Sign the root via the isolated signer (32 raw bytes in, 64 out).
        let signature = self
            .signer
            .sign_digest(root.as_bytes())
            .await
            .map_err(SignerError::from)?;

        let record = EvidenceRecord::BatchSeal {
            batch_id: batch_id.to_string(),
            seq_start,
            seq_end,
            leaves: leaves.iter().map(|d| d.to_hex()).collect(),
            merkle_root: root.to_hex(),
            signature: hex::encode(signature),
            sealed_at: now_rfc3339_ms(),
        };

        let canonical = record
            .canonical_bytes()
            .map_err(|e| EmitterError::Canonical(e.to_string()))?;
        self.sink.append_all(&canonical).await?;
        Ok(Some(record))
    }

    /// Seal automatically once `batch_size` evaluations are pending.
    pub async fn maybe_seal(&self) -> Result<Option<EvidenceRecord>, EmitterError> {
        if self.pending_leaves() >= self.batch_size {
            self.seal_batch(&format!("batch_{}", self.chain_len())).await
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ndjson_sink_appends_newline_terminated_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence/evidence_log.ndjson");
        let sink = NDJsonSink::open(&path).await.unwrap();
        sink.append(b"{\"a\":1}").await.unwrap();
        sink.append(b"{\"b\":2}").await.unwrap();
        let raw = tokio::fs::read_to_string(&path).await.unwrap();
        assert_eq!(raw, "{\"a\":1}\n{\"b\":2}\n");
    }

    #[tokio::test]
    async fn dual_sink_fans_out_to_every_sink() {
        let mem_a = std::sync::Arc::new(MemorySink::new());
        let mem_b = std::sync::Arc::new(MemorySink::new());
        let sink = DualSink::new(vec![mem_a.clone(), mem_b.clone()]);
        assert_eq!(sink.len(), 2);
        assert!(!sink.is_empty());
        assert!(sink.descriptions().contains(&"memory".to_string()));
        sink.append_all(b"{\"x\":1}").await.unwrap();
        assert_eq!(mem_a.len(), 1);
        assert_eq!(mem_b.len(), 1);
    }

    /// Deterministic signer stand-in: returns a fixed 64-byte value so the
    /// emitter's bookkeeping can be tested without a live signer daemon.
    struct StaticSigner;
    #[async_trait::async_trait]
    impl TrustAnchorSigner for StaticSigner {
        async fn sign_digest(&self, digest: &[u8; 32]) -> Result<[u8; 64], SignerError> {
            let mut out = [0u8; 64];
            out[..32].copy_from_slice(digest);
            Ok(out)
        }
        fn public_key_hex(&self) -> String {
            hex::encode([9u8; 32])
        }
    }

    fn manifest(id: &str) -> EvaluationManifest {
        EvaluationManifest::new(
            id,
            &bayora_common::testutil::registry(),
            &bayora_common::testutil::policy(),
            "2026-09-26T16:00:00.000Z",
            "94a8f102c4d9e812",
        )
    }

    #[tokio::test]
    async fn emit_links_chain_and_dual_writes() {
        let mem = std::sync::Arc::new(MemorySink::new());
        let sink = DualSink::new(vec![mem.clone()]);
        let emitter = EvidenceEmitter::new(sink, std::sync::Arc::new(StaticSigner), true, 4);

        let events = vec![EvaluationEvent::EvaluationStarted {
            evaluation_id: "eval_1".into(),
            manifest_hash: "aa".into(),
        }];
        let record = emitter
            .emit_evaluation(&manifest("eval_1"), "sig-1".to_string(), &events)
            .await
            .unwrap();
        match &record {
            EvidenceRecord::Evaluation { seq, prev_chain_hash, .. } => {
                assert_eq!(*seq, 0);
                // Genesis prev is 32 zero bytes.
                assert_eq!(*prev_chain_hash, bayora_common::chain::ChainState::genesis().prev_hash().to_hex());
            }
            other => panic!("expected Evaluation record, got {other:?}"),
        }
        assert_eq!(emitter.chain_len(), 1);
        assert_eq!(emitter.pending_leaves(), 1);
        assert_eq!(mem.len(), 1);
        // The stored line is canonical and reparses to the same record.
        let stored = EvidenceRecord::from_bytes(&mem.lines()[0]).unwrap();
        assert_eq!(stored, record);
    }

    #[tokio::test]
    async fn emit_refuses_missing_signature_when_required() {
        let sink = DualSink::new(vec![std::sync::Arc::new(MemorySink::new())]);
        let emitter = EvidenceEmitter::new(sink, std::sync::Arc::new(StaticSigner), true, 4);
        let err = emitter
            .emit_evaluation(&manifest("eval_1"), String::new(), &[])
            .await
            .unwrap_err();
        assert!(matches!(err, EmitterError::Sink(SinkError::Rejected(_))));
        assert_eq!(emitter.chain_len(), 0, "nothing must be chained on refusal");
    }

    #[tokio::test]
    async fn seals_form_a_verifiable_merkle_batch() {
        let mem = std::sync::Arc::new(MemorySink::new());
        let sink = DualSink::new(vec![mem.clone()]);
        let emitter = EvidenceEmitter::new(sink, std::sync::Arc::new(StaticSigner), true, 3);
        for i in 0..3 {
            let id = format!("eval_{i}");
            let events = vec![EvaluationEvent::EvaluationStarted {
                evaluation_id: id.clone(),
                manifest_hash: "aa".into(),
            }];
            emitter
                .emit_evaluation(&manifest(&id), "sig".into(), &events)
                .await
                .unwrap();
        }
        assert_eq!(emitter.pending_leaves(), 3);
        let seal = emitter.seal_batch("batch_1").await.unwrap().expect("seal");
        match &seal {
            EvidenceRecord::BatchSeal {
                seq_start,
                seq_end,
                leaves,
                merkle_root,
                ..
            } => {
                assert_eq!((*seq_start, *seq_end), (0, 2));
                assert_eq!(leaves.len(), 3);
                let recomputed =
                    bayora_common::records::recomputed_merkle_root(leaves).unwrap();
                assert_eq!(recomputed.to_hex(), *merkle_root);
            }
            other => panic!("expected BatchSeal, got {other:?}"),
        }
        assert_eq!(emitter.pending_leaves(), 0, "leaves consumed by seal");
        // The seal is appended to the log after the three evaluation records.
        assert_eq!(mem.len(), 4);
        assert!(emitter.seal_batch("batch_2").await.unwrap().is_none());

        // And the log is fully parseable end to end.
        let parsed: Vec<EvidenceRecord> = mem
            .lines()
            .iter()
            .map(|l| EvidenceRecord::from_bytes(l).unwrap())
            .collect();
        assert_eq!(parsed.len(), 4);
    }

    #[tokio::test]
    async fn maybe_seal_waits_for_batch_size() {
        let mem = std::sync::Arc::new(MemorySink::new());
        let emitter = EvidenceEmitter::new(
            DualSink::new(vec![mem]),
            std::sync::Arc::new(StaticSigner),
            false,
            2,
        );
        for i in 0..2 {
            let id = format!("eval_{i}");
            emitter
                .emit_evaluation(&manifest(&id), "sig".into(), &[])
                .await
                .unwrap();
        }
        assert!(emitter.maybe_seal().await.unwrap().is_some());
        assert!(emitter.maybe_seal().await.unwrap().is_none());
    }
}
