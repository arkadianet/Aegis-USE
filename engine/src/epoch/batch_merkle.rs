//! Vendored batch-Merkle proof verification — the guest-safe copy of
//! `ergo-validation::popow::merkle::verify_batch_merkle_proof`.
//!
//! **Why vendored (M-E1 packaging fix, `epoch-validity-design.md` §4):** E2/E4
//! need only this ONE function from `ergo-validation`, but pulling it in drags
//! the whole `ergo-validation → ergo-sigma` edge, and `ergo-sigma` carries a
//! `#[cfg(panic = "abort")] compile_error!` (its AVL verifier isolates malformed
//! proofs with `catch_unwind`, a no-op under `panic = "abort"`). RISC0 guests
//! build `panic = "abort"`, so the aux-PoW guest could not cross-compile to
//! `riscv32im-risc0-zkvm-elf`. This module reproduces the batch-Merkle verify
//! **byte-for-byte** over the panic-abort-safe primitives it actually uses
//! (`ergo_crypto::blake2b256`, `ergo_ser::batch_merkle_proof`), dropping the
//! `ergo-sigma` dependency from the guest path entirely.
//!
//! **Consensus-critical — do not "clean up".** This is a verbatim port of the
//! reviewed scrypto-parity implementation (`scorex.crypto.authds.merkle.
//! BatchMerkleProof.valid`, compact Merkle multiproofs per Lum Ramabaja). The
//! extension-inclusion checks in E2 (`share.rs`) and E4 (`anchor.rs`) reduce to
//! it, so any drift from the Scala/Curve-Trees definition is a consensus break.
//! The parity round-trip tests below (constructed proofs verify; wrong roots and
//! insufficient proofs fail) are the guard.

use ergo_crypto::autolykos::common::blake2b256;
use ergo_ser::batch_merkle_proof::{BatchMerkleProof, ProofEntry, Side};

/// Internal-node prefix byte. Matches scrypto `MerkleTree.InternalNodePrefix
/// = 1` and `ergo-crypto::merkle`'s constant.
const INTERNAL_NODE_PREFIX: u8 = 0x01;

/// Verify a `BatchMerkleProof` against an expected root digest.
/// Returns `true` iff replaying the bottom-up reduction produces
/// exactly the supplied `expected_root`.
///
/// Scala parity: `scrypto BatchMerkleProof.valid`.
///
/// Empty proof (no indices, no proof entries) verifies against any
/// root — used by the genesis case in `PoPowHeader.checkInterlinksProof`
/// (`PoPowHeader.scala:57-60`). Returns `true` in that case to
/// match Scala behavior.
pub fn verify_batch_merkle_proof(proof: &BatchMerkleProof, expected_root: &[u8; 32]) -> bool {
    if proof.indices.is_empty() && proof.proofs.is_empty() {
        return true;
    }

    let mut e: Vec<(u32, [u8; 32])> = proof.indices.clone();
    e.sort_by_key(|(i, _)| *i);
    let a: Vec<u32> = e.iter().map(|(i, _)| *i).collect();

    let result = loop_reduce(&a, &e, &proof.proofs);
    result.len() == 1 && result[0] == *expected_root
}

/// Recursive bottom-up reduction. Returns the digest(s) produced at
/// the topmost level — should be a single-element vector containing
/// the merkle root on success.
fn loop_reduce(a: &[u32], e: &[(u32, [u8; 32])], m: &[ProofEntry]) -> Vec<[u8; 32]> {
    // Step 1: pair each index with its immediate neighbor.
    // For an even index i, pair = (i, i + 1). For odd, pair = (i - 1, i).
    let b: Vec<(u32, u32)> = a
        .iter()
        .map(|i| {
            if i.is_multiple_of(2) {
                (*i, *i + 1)
            } else {
                (*i - 1, *i)
            }
        })
        .collect();

    debug_assert_eq!(b.len(), e.len(), "b and e must be equal-length");

    let mut e_new: Vec<[u8; 32]> = Vec::new();
    let mut m_pos = 0usize;
    let mut i = 0usize;

    while i < b.len() {
        // Check for duplicate pair (i, i+1) — i.e. both indices of
        // this pair are in our proven set. If so, combine the two
        // leaves directly without consuming a proof entry. Need to
        // peek at b[i+1] which only exists when i + 1 < b.len().
        let duplicate_pair = b.len() > 1 && i + 1 < b.len() && b[i] == b[i + 1];

        if duplicate_pair {
            // Hash the corresponding values in e together.
            let parent = internal_hash_pair(&e[i].1, &e[i + 1].1);
            e_new.push(parent);
            i += 2;
        } else {
            // Hash with the next proof entry, respecting its side.
            let entry = match m.get(m_pos) {
                Some(p) => p,
                None => {
                    // Insufficient proof entries — invalid.
                    return Vec::new();
                }
            };
            let parent = combine_with_proof_entry(entry, &e[i].1);
            e_new.push(parent);
            m_pos += 1;
            i += 1;
        }
    }

    // Build a_new = unique(b).map(|(p, _)| p / 2).
    // Scala uses `b.distinct.map(_._1 / 2)`. We iterate b in order,
    // de-duplicating consecutive duplicate pairs (which match the
    // duplicate_pair branch above).
    let mut a_new: Vec<u32> = Vec::new();
    let mut prev: Option<(u32, u32)> = None;
    for pair in &b {
        if prev != Some(*pair) {
            a_new.push(pair.0 / 2);
            prev = Some(*pair);
        }
    }

    let m_remaining = &m[m_pos..];
    if (!m_remaining.is_empty() || e_new.len() > 1) && !a_new.is_empty() {
        let e_new_pairs: Vec<(u32, [u8; 32])> = a_new
            .iter()
            .zip(e_new.iter())
            .map(|(idx, hash)| (*idx, *hash))
            .collect();
        return loop_reduce(&a_new, &e_new_pairs, m_remaining);
    }

    e_new
}

/// `Blake2b256(0x01 || left || right)`.
fn internal_hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 32 + 32);
    buf.push(INTERNAL_NODE_PREFIX);
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    blake2b256(&buf)
}

/// `Blake2b256(0x01 || left)` — the empty-right-sibling case.
fn internal_hash_left_only(left: &[u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + 32);
    buf.push(INTERNAL_NODE_PREFIX);
    buf.extend_from_slice(left);
    blake2b256(&buf)
}

/// Combine a leaf digest with a proof entry's sibling. Handles the
/// `None` (empty-sibling) case by falling through to the left-only
/// hash regardless of `side` — matches scrypto's behavior where
/// `EmptyByteArray ++ leaf == leaf == leaf ++ EmptyByteArray`.
fn combine_with_proof_entry(entry: &ProofEntry, leaf: &[u8; 32]) -> [u8; 32] {
    match entry.digest {
        None => internal_hash_left_only(leaf),
        Some(sibling) => match entry.side {
            Side::Left => internal_hash_pair(&sibling, leaf),
            Side::Right => internal_hash_pair(leaf, &sibling),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ergo_crypto::merkle::merkle_tree_root;

    // ----- helpers -----

    fn leaf_hash(data: &[u8]) -> [u8; 32] {
        let mut input = Vec::with_capacity(1 + data.len());
        input.push(0x00);
        input.extend_from_slice(data);
        blake2b256(&input)
    }

    // ----- happy path -----

    #[test]
    fn empty_proof_verifies_against_any_root() {
        let bmp = BatchMerkleProof {
            indices: vec![],
            proofs: vec![],
        };
        assert!(verify_batch_merkle_proof(&bmp, &[0xAA; 32]));
        assert!(verify_batch_merkle_proof(&bmp, &[0xBB; 32]));
    }

    #[test]
    fn two_leaf_pair_with_no_proofs_when_both_indices_proven() {
        let l0 = vec![0xAA; 8];
        let l1 = vec![0xBB; 8];
        let lh0 = leaf_hash(&l0);
        let lh1 = leaf_hash(&l1);
        let root = merkle_tree_root(&[&l0, &l1]);
        let bmp = BatchMerkleProof {
            indices: vec![(0u32, lh0), (1u32, lh1)],
            proofs: vec![],
        };
        assert!(verify_batch_merkle_proof(&bmp, &root));
    }

    // ----- error paths -----

    #[test]
    fn wrong_root_fails() {
        let l0 = vec![0xAA; 8];
        let l1 = vec![0xBB; 8];
        let lh0 = leaf_hash(&l0);
        let lh1 = leaf_hash(&l1);
        let bmp = BatchMerkleProof {
            indices: vec![(0u32, lh0), (1u32, lh1)],
            proofs: vec![],
        };
        assert!(!verify_batch_merkle_proof(&bmp, &[0xFF; 32]));
    }

    // ----- construct + verify round-trip (scrypto-parity guard) -----

    /// Build a batch proof via `ergo_crypto::merkle::merkle_proof_by_indices`,
    /// convert it to the wire `BatchMerkleProof` shape, and verify it against
    /// the tree's root — round-trips the serve-side construction through this
    /// consume-side verify. If either drifts from scrypto's definition, this
    /// catches it (the reason the vendored copy stays byte-identical).
    fn build_and_verify_batch(elements: &[&[u8]], indices: &[u32]) -> bool {
        use ergo_crypto::merkle::{merkle_proof_by_indices, merkle_tree_root};

        let (idx_with_hashes, proofs) =
            merkle_proof_by_indices(elements, indices).expect("indices valid");
        let proof_entries: Vec<ProofEntry> = proofs
            .into_iter()
            .map(|e| ProofEntry {
                digest: e.digest,
                side: if e.side == 0 { Side::Left } else { Side::Right },
            })
            .collect();
        let bmp = BatchMerkleProof {
            indices: idx_with_hashes,
            proofs: proof_entries,
        };
        let root = merkle_tree_root(elements);
        verify_batch_merkle_proof(&bmp, &root)
    }

    #[test]
    fn constructed_proof_verifies_single_leaf() {
        let l0 = vec![0xAA; 8];
        let leaves: Vec<&[u8]> = vec![&l0];
        assert!(build_and_verify_batch(&leaves, &[0]));
    }

    #[test]
    fn constructed_proof_verifies_two_leaves_both_proven() {
        let l0 = vec![0xAA; 8];
        let l1 = vec![0xBB; 8];
        let leaves: Vec<&[u8]> = vec![&l0, &l1];
        assert!(build_and_verify_batch(&leaves, &[0, 1]));
    }

    #[test]
    fn constructed_proof_verifies_two_leaves_one_proven() {
        let l0 = vec![0xAA; 8];
        let l1 = vec![0xBB; 8];
        let leaves: Vec<&[u8]> = vec![&l0, &l1];
        assert!(build_and_verify_batch(&leaves, &[0]));
        assert!(build_and_verify_batch(&leaves, &[1]));
    }

    #[test]
    fn constructed_proof_verifies_seven_leaves_sparse_subset() {
        // Odd-trailing at multiple levels — the empty-sibling reduction.
        let leaves_owned: Vec<Vec<u8>> = (0u8..7).map(|i| vec![i, i + 0x10, i + 0x20]).collect();
        let leaves: Vec<&[u8]> = leaves_owned.iter().map(|v| v.as_slice()).collect();
        assert!(build_and_verify_batch(&leaves, &[0, 3, 5]));
        assert!(build_and_verify_batch(&leaves, &[1, 4, 6]));
        assert!(build_and_verify_batch(&leaves, &[6]));
    }

    #[test]
    fn constructed_proof_verifies_all_leaves_in_tree() {
        let leaves_owned: Vec<Vec<u8>> = (0u8..16).map(|i| vec![i; 8]).collect();
        let leaves: Vec<&[u8]> = leaves_owned.iter().map(|v| v.as_slice()).collect();
        let all_indices: Vec<u32> = (0u32..16).collect();
        assert!(build_and_verify_batch(&leaves, &all_indices));
    }
}
