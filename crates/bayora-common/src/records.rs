//! The evidence records written to both sinks (PostgreSQL + append-only log).
//!
//! Every record is serialized through RFC 8785 JCS before being written, so
//! the line stored in the file, the row stored in PostgreSQL, and the bytes
//! re-hashed by the Independent Verifier are always identical.

use crate::chain::merkle_root;
use crate::digest::Digest;
use crate::events::EvaluationEvent;
use crate::jcs;
use crate::manifest::EvaluationManifest;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceRecord {
    /// One finalized evaluation: manifest + ordered events + chain link.
    Evaluation {
        /// Position in the global hash chain.
        seq: u64,
        manifest: EvaluationManifest,
        /// `sha256(JCS(manifest))`, hex.
        manifest_hash: String,
        /// Trust Anchor signature over the raw 32-byte manifest hash, hex.
        manifest_signature: String,
        /// Ordered event array for this evaluation.
        events: Vec<EvaluationEvent>,
        /// `sha256(JCS(events))`, hex.
        event_hash: String,
        /// `ChainHash_{i-1}`, hex (genesis = 32 zero bytes).
        prev_chain_hash: String,
        /// `sha256(prev || manifest_hash || event_hash)`, hex.
        chain_hash: String,
    },
    /// Merkle batch seal over the chain hashes of `seq_start..=seq_end`.
    BatchSeal {
        batch_id: String,
        seq_start: u64,
        seq_end: u64,
        /// Leaf chain hashes in sequence order, hex.
        leaves: Vec<String>,
        /// `merkle_root(leaves)`, hex.
        merkle_root: String,
        /// Trust Anchor signature over the raw 32-byte root, hex.
        signature: String,
        sealed_at: String,
    },
}

use serde::{Deserialize, Serialize};

impl EvidenceRecord {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, jcs::JcsError> {
        jcs::to_bytes(self)
    }

    pub fn evaluation_id(&self) -> Option<&str> {
        match self {
            EvidenceRecord::Evaluation { manifest, .. } => Some(&manifest.evaluation_id),
            EvidenceRecord::BatchSeal { .. } => None,
        }
    }

    pub fn seq(&self) -> Option<u64> {
        match self {
            EvidenceRecord::Evaluation { seq, .. } => Some(*seq),
            EvidenceRecord::BatchSeal { .. } => None,
        }
    }

    pub fn record_type(&self) -> &'static str {
        match self {
            EvidenceRecord::Evaluation { .. } => "evaluation",
            EvidenceRecord::BatchSeal { .. } => "batch_seal",
        }
    }

    /// Parse a canonical line/row back into a record.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        serde_json::from_slice(bytes).map_err(|e| e.to_string())
    }
}

/// Re-derive the Merkle root of a batch seal's leaves (verifier-side check).
pub fn recomputed_merkle_root(seal_leaves: &[String]) -> Result<Digest, String> {
    let leaves: Vec<Digest> = seal_leaves
        .iter()
        .map(|l| Digest::from_hex(l))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    merkle_root(&leaves).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EvaluationEvent;

    fn sample_eval(seq: u64) -> EvidenceRecord {
        EvidenceRecord::Evaluation {
            seq,
            manifest: EvaluationManifest::new(
                format!("eval_{seq}"),
                &crate::testutil::registry(),
                &crate::testutil::policy(),
                "2026-09-26T16:00:00.000Z",
                "94a8f102c4d9e812",
            ),
            manifest_hash: Digest::of(b"m").to_hex(),
            manifest_signature: hex::encode([1u8; 64]),
            events: vec![EvaluationEvent::EvaluationStarted {
                evaluation_id: format!("eval_{seq}"),
                manifest_hash: Digest::of(b"m").to_hex(),
            }],
            event_hash: Digest::of(b"e").to_hex(),
            prev_chain_hash: Digest::ZERO.to_hex(),
            chain_hash: Digest::of(b"c").to_hex(),
        }
    }

    #[test]
    fn canonical_line_roundtrip() {
        let rec = sample_eval(0);
        let line = rec.canonical_bytes().unwrap();
        let back = EvidenceRecord::from_bytes(&line).unwrap();
        assert_eq!(back, rec);
        // Deterministic.
        assert_eq!(rec.canonical_bytes().unwrap(), line);
        // No whitespace in canonical form.
        assert!(!line.contains(&b' '));
    }

    #[test]
    fn tagged_record_type_survives_roundtrip() {
        let rec = sample_eval(3);
        let line = String::from_utf8(rec.canonical_bytes().unwrap()).unwrap();
        // JCS sorts keys, so the tag is not necessarily first.
        assert!(line.contains(r#""record_type":"evaluation""#));
        assert!(line.starts_with(r#"{"chain_hash""#));
        let seal = EvidenceRecord::BatchSeal {
            batch_id: "b1".into(),
            seq_start: 0,
            seq_end: 2,
            leaves: vec![Digest::of(b"1").to_hex()],
            merkle_root: Digest::of(b"r").to_hex(),
            signature: hex::encode([2u8; 64]),
            sealed_at: "2026-09-26T16:00:00.000Z".into(),
        };
        let line = String::from_utf8(seal.canonical_bytes().unwrap()).unwrap();
        assert!(line.contains(r#""record_type":"batch_seal""#));
        assert_eq!(seal.record_type(), "batch_seal");
        assert!(seal.evaluation_id().is_none());
    }

    #[test]
    fn injected_record_fields_are_rejected() {
        let rec = sample_eval(0);
        let mut v: serde_json::Value = serde_json::from_slice(&rec.canonical_bytes().unwrap()).unwrap();
        v["injected"] = serde_json::json!("tamper");
        let bytes = serde_json::to_vec(&v).unwrap();
        assert!(EvidenceRecord::from_bytes(&bytes).is_err());
    }

    #[test]
    fn merkle_recompute_matches_chain_helper() {
        use crate::chain::merkle_root;
        let leaves = vec![Digest::of(b"a"), Digest::of(b"b"), Digest::of(b"c")];
        let leaf_hex: Vec<String> = leaves.iter().map(|d| d.to_hex()).collect();
        assert_eq!(
            recomputed_merkle_root(&leaf_hex).unwrap(),
            merkle_root(&leaves).unwrap()
        );
    }
}
