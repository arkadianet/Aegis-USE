//! E4 — canonical-Ergo anchor binding (the on-chain lever).
//!
//! The PegVault sits ON the chain hn is merge-mined against, so its own
//! execution context is a canonical view of the anchor chain. The contract
//! splices `ergo_ref = CONTEXT.headers(j).id` (a recent canonical Ergo header)
//! into the reconstructed journal; byte-exact `verifyStark` then forces the
//! guest to have committed that exact id. The guest proves here:
//!
//! - some Ergo header `H_anchor` **extension-commits** `id(B_a)` for a suffix
//!   block `B_a` (the §2.3-step-4 batch-merkle inclusion — same as E2), and
//! - `H_anchor` is an **ancestor of `ergo_ref`** by hash linkage: recompute each
//!   header's id (`serialize_header` → blake2b256) and follow `parent_id` from
//!   `ergo_ref` back to `H_anchor`.
//!
//! **No PoW verification for this chain** — canonicality of `ergo_ref` is
//! supplied by Ergo consensus itself via `CONTEXT.headers`. Linkage costs ~2–3
//! blake2b compressions per header (~2–4 M cycles at depth ≤ 72). This is the
//! cheap trick the whole hybrid rests on: the contract contributes the one fact
//! a proof cannot (a canonical chain view); the proof contributes the rest.
//!
//! What it buys (mainnet): a fabricated suffix must additionally get its fake
//! tip committed INTO the canonical Ergo chain — only a real Ergo-block miner
//! can, and it is a public, watchable act. On the difficulty-1 STARK devnet,
//! Ergo blocks are free, so E4 is mechanism-demonstration only there (§6.5).
//!
//! Gated behind `aux-pow` (shares E2's Ergo primitives).

use ergo_ser::batch_merkle_proof::BatchMerkleProof;
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{serialize_header, Header as ErgoHeader};
use ergo_validation::popow::verify_batch_merkle_proof;

use super::share::{mm_leaf_digest, AEGIS_MM_KEY as MM_KEY, MM_COMMITMENT_VERSION as MM_VERSION};

/// The anchor-linkage witness: a parent-linked chain of Ergo headers from
/// `ergo_ref` (index 0) back to `H_anchor` (last), plus the extension-inclusion
/// proof that `H_anchor` commits the anchored hn block id.
#[derive(Debug, Clone)]
pub struct AnchorWitness {
    /// `[ergo_ref, …, H_anchor]` — each header's `parent_id` == id of the next.
    pub headers: Vec<ErgoHeader>,
    /// The `AEGIS_MM_KEY` field in `H_anchor`'s extension carrying `id(B_a)`.
    pub anchor_field: ExtensionField,
    /// Batch-merkle proof binding `anchor_field` to `H_anchor.extension_root`.
    pub anchor_proof: BatchMerkleProof,
}

/// Why anchor linkage failed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnchorError {
    #[error("anchor witness has no headers")]
    EmptyChain,
    #[error("header[0] id does not equal the contract-spliced ergo_ref_id")]
    RefMismatch,
    #[error("header[{i}].parent_id does not equal id(header[{j}]) — chain broken")]
    ChainBroken { i: usize, j: usize },
    #[error("H_anchor extension proof must prove exactly one leaf (got {got})")]
    ProofShape { got: usize },
    #[error("H_anchor extension field key/version/value is not the MM commitment")]
    BadCommitment,
    #[error("H_anchor extension proof leaf digest does not match the claimed field")]
    ProofLeafMismatch,
    #[error("H_anchor extension proof does not reduce to its extension_root")]
    ProofInvalid,
    #[error("H_anchor does not commit the claimed anchored hn block id")]
    AnchoredIdMismatch,
    #[error("header serialize failed: {0}")]
    HeaderEncode(String),
}

fn ergo_header_id(h: &ErgoHeader) -> Result<[u8; 32], AnchorError> {
    let (_, id) = serialize_header(h).map_err(|e| AnchorError::HeaderEncode(e.to_string()))?;
    Ok(*id.as_bytes())
}

/// Verify the suffix tip region is committed under an ancestor of the canonical
/// `ergo_ref_id`, and that ancestor commits `anchored_hn_id` (the id of some
/// suffix block `B_a`). Returns the anchor depth (headers from ref to anchor).
pub fn verify_anchor_linkage(
    w: &AnchorWitness,
    ergo_ref_id: &[u8; 32],
    anchored_hn_id: &[u8; 32],
) -> Result<usize, AnchorError> {
    if w.headers.is_empty() {
        return Err(AnchorError::EmptyChain);
    }
    // ergo_ref (index 0) must be the exact contract-spliced canonical id.
    if &ergo_header_id(&w.headers[0])? != ergo_ref_id {
        return Err(AnchorError::RefMismatch);
    }
    // Hash-linkage: each header's parent is the next header's id.
    for i in 0..w.headers.len() - 1 {
        let parent = *w.headers[i].parent_id.as_bytes();
        if parent != ergo_header_id(&w.headers[i + 1])? {
            return Err(AnchorError::ChainBroken { i, j: i + 1 });
        }
    }

    // H_anchor commits id(B_a) via extension-merkle inclusion (no PoW needed).
    let anchor = w.headers.last().expect("non-empty");
    if w.anchor_proof.indices.len() != 1 {
        return Err(AnchorError::ProofShape {
            got: w.anchor_proof.indices.len(),
        });
    }
    if w.anchor_field.key != MM_KEY
        || w.anchor_field.value.len() != 1 + 32
        || w.anchor_field.value[0] != MM_VERSION
    {
        return Err(AnchorError::BadCommitment);
    }
    if w.anchor_proof.indices[0].1 != mm_leaf_digest(&w.anchor_field) {
        return Err(AnchorError::ProofLeafMismatch);
    }
    if !verify_batch_merkle_proof(&w.anchor_proof, anchor.extension_root.as_bytes()) {
        return Err(AnchorError::ProofInvalid);
    }
    if w.anchor_field.value[1..] != anchored_hn_id[..] {
        return Err(AnchorError::AnchoredIdMismatch);
    }

    Ok(w.headers.len() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_crypto::merkle::{extension_root, merkle_proof_by_indices};
    use ergo_ser::batch_merkle_proof::{ProofEntry, Side};

    /// Decode a real testnet header as a template.
    fn template_header() -> ErgoHeader {
        let path = format!(
            "{}/../test-vectors/testnet/blocks/scala_block_442815.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).unwrap();
        let sblock: ergo_rest_json::types::ScalaFullBlock = serde_json::from_str(&raw).unwrap();
        ergo_rest_json::decode_scala_header_struct(&sblock.header).unwrap()
    }

    /// Build `H_anchor` committing `hn_id` in its extension; return (header,
    /// field, proof).
    fn anchor_header(hn_id: [u8; 32]) -> (ErgoHeader, ExtensionField, BatchMerkleProof) {
        let mut eh = template_header();
        let mut value = Vec::with_capacity(33);
        value.push(MM_VERSION);
        value.extend_from_slice(&hn_id);
        let field = ExtensionField { key: MM_KEY, value };
        let fields: Vec<([u8; 2], Vec<u8>)> = vec![(field.key, field.value.clone())];
        let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        eh.extension_root = extension_root(&pairs).into();
        let leaves: Vec<Vec<u8>> = fields
            .iter()
            .map(|(k, v)| {
                let mut leaf = vec![2u8];
                leaf.extend_from_slice(k);
                leaf.extend_from_slice(v);
                leaf
            })
            .collect();
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let (indices, raw) = merkle_proof_by_indices(&refs, &[0]).unwrap();
        let proof = BatchMerkleProof {
            indices,
            proofs: raw
                .into_iter()
                .map(|e| ProofEntry {
                    digest: e.digest,
                    side: Side::from_byte(e.side),
                })
                .collect(),
        };
        (eh, field, proof)
    }

    /// Chain `depth` headers from a fresh ergo_ref down to `anchor`, each
    /// parent-linked to the next.
    fn linked_chain(anchor: ErgoHeader, depth: usize) -> Vec<ErgoHeader> {
        let mut chain = vec![anchor];
        for i in 0..depth {
            let child_id = ergo_header_id(&chain[0]).unwrap();
            let mut parent = template_header();
            parent.parent_id = ergo_primitives::digest::ModifierId::from(child_id);
            // Perturb height so successive headers differ (distinct ids).
            parent.height = 1000 + i as u32;
            chain.insert(0, parent);
        }
        chain
    }

    // ----- happy path -----

    #[test]
    fn honest_anchor_links_to_ergo_ref() {
        let hn_id = [0x42u8; 32];
        let (anchor, field, proof) = anchor_header(hn_id);
        let headers = linked_chain(anchor, 3);
        let ergo_ref = ergo_header_id(&headers[0]).unwrap();
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        let depth = verify_anchor_linkage(&w, &ergo_ref, &hn_id).expect("anchor links");
        assert_eq!(depth, 3);
    }

    // ----- error paths -----

    #[test]
    fn wrong_ergo_ref_is_rejected() {
        let hn_id = [0x42u8; 32];
        let (anchor, field, proof) = anchor_header(hn_id);
        let headers = linked_chain(anchor, 2);
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        assert_eq!(
            verify_anchor_linkage(&w, &[0u8; 32], &hn_id),
            Err(AnchorError::RefMismatch),
            "ergo_ref must be the contract-spliced canonical id"
        );
    }

    #[test]
    fn broken_parent_link_is_rejected() {
        let hn_id = [0x42u8; 32];
        let (anchor, field, proof) = anchor_header(hn_id);
        let mut headers = linked_chain(anchor, 2);
        // Snap the link: repoint the middle header's parent.
        headers[0].parent_id = ergo_primitives::digest::ModifierId::from([9u8; 32]);
        let ergo_ref = ergo_header_id(&headers[0]).unwrap();
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        match verify_anchor_linkage(&w, &ergo_ref, &hn_id) {
            Err(AnchorError::ChainBroken { .. }) => {}
            other => panic!("expected ChainBroken, got {other:?}"),
        }
    }

    #[test]
    fn wrong_anchored_id_is_rejected() {
        let hn_id = [0x42u8; 32];
        let (anchor, field, proof) = anchor_header(hn_id);
        let headers = linked_chain(anchor, 1);
        let ergo_ref = ergo_header_id(&headers[0]).unwrap();
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        assert_eq!(
            verify_anchor_linkage(&w, &ergo_ref, &[0xAAu8; 32]),
            Err(AnchorError::AnchoredIdMismatch),
            "the anchored hn id must match what H_anchor commits"
        );
    }
}
