//! Hash chain + binary Merkle tree definitions shared by Referee and Verifier.
//!
//! ```text
//! ChainHash_i = sha256( ChainHash_{i-1} || ManifestHash_i || EventHash_i )
//! ```
//! `ChainHash_{-1}` (genesis) is 32 zero bytes.
//!
//! Merkle: leaves are the per-evaluation `ChainHash_i` values, internal nodes
//! are `sha256(left || right)`, and an odd node at any level is *promoted
//! unchanged* (no duplication). Empty leaf sets are rejected.

use crate::digest::Digest;
use sha2::{Digest as _, Sha256};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MerkleError {
    #[error("cannot build a Merkle root from zero leaves")]
    EmptyLeafSet,
}

/// Sequential hash-chain state.
#[derive(Debug, Clone)]
pub struct ChainState {
    prev: Digest,
    index: u64,
}

impl Default for ChainState {
    fn default() -> Self {
        Self::genesis()
    }
}

impl ChainState {
    pub fn genesis() -> Self {
        ChainState {
            prev: Digest::ZERO,
            index: 0,
        }
    }

    pub fn prev_hash(&self) -> Digest {
        self.prev
    }

    pub fn len(&self) -> u64 {
        self.index
    }

    pub fn is_empty(&self) -> bool {
        self.index == 0
    }

    /// Link one evaluation into the chain, returning `(seq, chain_hash)`.
    pub fn link(&mut self, manifest_hash: &Digest, event_hash: &Digest) -> (u64, Digest) {
        let mut h = Sha256::new();
        h.update(self.prev.0);
        h.update(manifest_hash.0);
        h.update(event_hash.0);
        let chain_hash = Digest(h.finalize().into());
        let seq = self.index;
        self.prev = chain_hash;
        self.index += 1;
        (seq, chain_hash)
    }
}

/// Binary SHA-256 Merkle root over already-hashed leaves.
/// Odd nodes are promoted unchanged.
pub fn merkle_root(leaves: &[Digest]) -> Result<Digest, MerkleError> {
    if leaves.is_empty() {
        return Err(MerkleError::EmptyLeafSet);
    }
    let mut level: Vec<Digest> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            if pair.len() == 2 {
                let mut h = Sha256::new();
                h.update(pair[0].0);
                h.update(pair[1].0);
                next.push(Digest(h.finalize().into()));
            } else {
                // Odd node promoted unchanged.
                next.push(pair[0]);
            }
        }
        level = next;
    }
    Ok(level[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(s: &str) -> Digest {
        Digest::of(s.as_bytes())
    }

    #[test]
    fn chain_link_matches_spec_formula() {
        use sha2::Sha256;
        let mut chain = ChainState::genesis();
        let mh = d("manifest");
        let eh = d("events");

        let mut expected = Sha256::new();
        expected.update([0u8; 32]); // genesis prev
        expected.update(mh.0);
        expected.update(eh.0);
        let expected = Digest(expected.finalize().into());

        let (seq, hash) = chain.link(&mh, &eh);
        assert_eq!(seq, 0);
        assert_eq!(hash, expected);
        assert_eq!(chain.prev_hash(), hash);
        assert_eq!(chain.len(), 1);
    }

    #[test]
    fn chain_is_sequential() {
        let mut chain = ChainState::genesis();
        let (_, h0) = chain.link(&d("m0"), &d("e0"));
        let (_, h1) = chain.link(&d("m1"), &d("e1"));
        assert_ne!(h0, h1);
        // h1 commits to h0.
        assert_eq!(chain.len(), 2);
    }

    #[test]
    fn merkle_single_leaf_is_the_leaf() {
        let leaf = d("only");
        assert_eq!(merkle_root(&[leaf]).unwrap(), leaf);
    }

    #[test]
    fn merkle_odd_promotes_last() {
        let a = d("a");
        let b = d("b");
        let c = d("c");
        use sha2::Sha256;
        let mut h = Sha256::new();
        h.update(a.0);
        h.update(b.0);
        let ab = Digest(h.finalize().into());
        // level = [ab, c] -> [sha256(ab||c)]
        let mut h2 = Sha256::new();
        h2.update(ab.0);
        h2.update(c.0);
        let expected = Digest(h2.finalize().into());
        assert_eq!(merkle_root(&[a, b, c]).unwrap(), expected);
    }

    #[test]
    fn merkle_rejects_empty() {
        assert_eq!(merkle_root(&[]), Err(MerkleError::EmptyLeafSet));
    }
}
