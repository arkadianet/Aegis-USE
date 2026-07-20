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

use super::batch_merkle::verify_batch_merkle_proof;
use super::share::{mm_leaf_digest, AEGIS_MM_KEY as MM_KEY, MM_COMMITMENT_VERSION as MM_VERSION};

/// F5 / D-F5 (`epoch-validity-f1-f3-design.md` §6 cond. 2, §8): the minimum
/// number of canonical Ergo blocks the suffix tip's anchor (`H_anchor`) must be
/// buried under `ergo_ref`. Depth 0 still forces one Ergo block (the §6
/// Ergo-hashrate floor), but a single-block anchor is reorg-able; requiring a
/// few *settled* Ergo blocks converts "one Ergo block" into "`A_MIN` buried
/// Ergo blocks" and defeats a private single-block equivocation the attacker
/// reorgs away after the release confirms. Pinned image constant; the exact
/// production value is an operator/params decision (D-F5 recommends "several").
pub const A_MIN: usize = 3;

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
    #[error("anchor buried at depth {depth} < A_min {min} (F5)")]
    InsufficientDepth { depth: usize, min: usize },
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

/// Verify anchor linkage AND enforce F5 burial depth (`depth >= a_min`). This is
/// what the mainnet guest calls: the suffix tip is not merely committed in *some*
/// canonical-Ergo ancestor of `ergo_ref`, but one buried under at least `a_min`
/// Ergo blocks (§6 cond. 2). Returns the verified anchor depth.
pub fn verify_anchor_linkage_min_depth(
    w: &AnchorWitness,
    ergo_ref_id: &[u8; 32],
    anchored_hn_id: &[u8; 32],
    a_min: usize,
) -> Result<usize, AnchorError> {
    let depth = verify_anchor_linkage(w, ergo_ref_id, anchored_hn_id)?;
    if depth < a_min {
        return Err(AnchorError::InsufficientDepth { depth, min: a_min });
    }
    Ok(depth)
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

    // ----- F5 burial depth -----

    #[test]
    fn anchor_buried_below_a_min_is_rejected() {
        // A tip anchored at depth < A_MIN is a single (or too-shallow), reorg-able
        // Ergo commitment — F5 rejects it.
        let hn_id = [0x42u8; 32];
        let (anchor, field, proof) = anchor_header(hn_id);
        let headers = linked_chain(anchor, A_MIN - 1); // depth A_MIN-1 < A_MIN
        let ergo_ref = ergo_header_id(&headers[0]).unwrap();
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        // Pure linkage still succeeds…
        assert_eq!(verify_anchor_linkage(&w, &ergo_ref, &hn_id), Ok(A_MIN - 1));
        // …but the depth-enforcing entry point rejects the shallow burial.
        assert_eq!(
            verify_anchor_linkage_min_depth(&w, &ergo_ref, &hn_id, A_MIN),
            Err(AnchorError::InsufficientDepth {
                depth: A_MIN - 1,
                min: A_MIN
            }),
            "the tip anchor must be buried >= A_MIN Ergo blocks (F5)"
        );
    }

    #[test]
    fn anchor_buried_at_a_min_is_accepted() {
        let hn_id = [0x42u8; 32];
        let (anchor, field, proof) = anchor_header(hn_id);
        let headers = linked_chain(anchor, A_MIN); // depth == A_MIN
        let ergo_ref = ergo_header_id(&headers[0]).unwrap();
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        assert_eq!(
            verify_anchor_linkage_min_depth(&w, &ergo_ref, &hn_id, A_MIN),
            Ok(A_MIN),
            "burial exactly at A_MIN is sufficient"
        );
    }

    // ----- §6 caveat: no honest Ergo commitment coincides with a fake tip -----

    #[test]
    fn an_honest_tip_commitment_cannot_be_passed_off_as_a_fake_tip() {
        // §6 caveat asserted: an Ergo block that honestly commits the real hn tip
        // id carries a DIFFERENT id from any fabricator-reachable fake tip (whose
        // body / chain_id differ), by Poseidon2 collision-resistance of the hn
        // header id + chain_id binding. So E4 cannot be satisfied by free-riding
        // an honest Ergo block: the fabricator must mine their OWN Ergo block
        // committing THEIR fake tip.
        use super::super::header_id::header_id;
        use super::super::types::SuffixBlock;
        use crate::poseidon::F;
        use p3_field::PrimeCharacteristicRing;

        let honest = SuffixBlock {
            height: 42,
            prev_header_id: [1u8; 32],
            prev_root: core::array::from_fn(|i| F::from_u32(i as u32 + 1)),
            state_root: core::array::from_fn(|i| F::from_u32(i as u32 + 9)),
            timestamp_ms: 1_760_000_000_000,
            sc_nbits: 0x2000_0100,
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: core::array::from_fn(|i| F::from_u32(i as u32 + 3)),
            coinbase_amount: 5,
            coinbase_cm: core::array::from_fn(|i| F::from_u32(i as u32 + 7)),
            coinbase_is_reward: true,
            pot_after: 1000,
        };
        // A "fake" tip differing only in a body/coinbase field.
        let mut fake = honest.clone();
        fake.coinbase_amount = 6;

        let honest_id = header_id(0x484E_0005, &honest);
        let fake_id = header_id(0x484E_0005, &fake);
        assert_ne!(honest_id, fake_id, "distinct bodies => distinct tip ids");
        // Different chain_id also separates the commitment (cross-chain replay).
        assert_ne!(
            honest_id,
            header_id(0x484E_0006, &honest),
            "chain_id binds the tip id"
        );

        // An Ergo header honestly committing `honest_id` does NOT verify as an
        // anchor for `fake_id` — the pass-off is infeasible.
        let (anchor, field, proof) = anchor_header(honest_id);
        let headers = linked_chain(anchor, A_MIN);
        let ergo_ref = ergo_header_id(&headers[0]).unwrap();
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        assert_eq!(
            verify_anchor_linkage_min_depth(&w, &ergo_ref, &fake_id, A_MIN),
            Err(AnchorError::AnchoredIdMismatch),
            "an honest tip commitment cannot anchor a fabricator's fake tip"
        );
        // Sanity: it DOES anchor the honest tip it actually commits.
        assert!(verify_anchor_linkage_min_depth(&w, &ergo_ref, &honest_id, A_MIN).is_ok());
    }

    // ----- round-trips -----

    /// The E4 wire round-trip (`aux_wire`) preserves an anchor witness: an honest
    /// linkage still links after `from_witness` → serde → `into_witness` (the
    /// guest reads the wire form, so the header/proof codecs must be faithful).
    #[test]
    fn anchor_wire_roundtrip_still_links() {
        use crate::epoch::aux_wire::AnchorWitnessWire;
        let hn_id = [0x42u8; 32];
        let (anchor, field, proof) = anchor_header(hn_id);
        let headers = linked_chain(anchor, 3);
        let ergo_ref = ergo_header_id(&headers[0]).unwrap();
        let w = AnchorWitness {
            headers,
            anchor_field: field,
            anchor_proof: proof,
        };
        verify_anchor_linkage(&w, &ergo_ref, &hn_id).expect("baseline links");

        let wire = AnchorWitnessWire::from_witness(&w);
        let bytes = postcard::to_allocvec(&wire).expect("wire serializes");
        let back: AnchorWitnessWire = postcard::from_bytes(&bytes).expect("wire deserializes");
        let w2 = back.into_witness();
        // ergo_ref must be recomputed from the round-tripped header (the wire
        // carries bytes, not the id) — it must equal the original.
        let ergo_ref2 = ergo_header_id(&w2.headers[0]).unwrap();
        assert_eq!(ergo_ref2, ergo_ref, "round-tripped ergo_ref id is stable");
        let depth = verify_anchor_linkage(&w2, &ergo_ref2, &hn_id).expect("round-tripped links");
        assert_eq!(depth, 3);
    }
}
