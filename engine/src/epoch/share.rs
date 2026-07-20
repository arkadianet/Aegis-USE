//! E2 — in-guest aux-PoW share verification (the fabrication pricer).
//!
//! For each suffix reward block the guest verifies a share witness binding the
//! block's [`header_id`](super::header_id::header_id) to real Autolykos v2 work
//! at the block's `sc_nbits` target. This is what turns fabrication from *free*
//! into *priced in real PoW*: a fabricator must actually mine every block of
//! their fake suffix (design §2.1-E2, §6). Verified in-guest — the host is the
//! untrusted settler, so a host-only check would be toothless.
//!
//! Ported verbatim from the reviewed node verifier
//! (`aegis-node/src/hn/auxpow.rs::HnAuxPow::verify`, itself the reviewed
//! Curve-Trees share verifier `crate::auxpow::verify_share`), re-pointed from
//! the node's `hn_header_id` to this crate's `header_id` (the guest-recomputable
//! one). The block-committed, replay-safe subset only (the node-subjective C2
//! height window and the deterministically-enforced DAA equality are out of
//! scope in-proof, exactly as in the node port — see `hn/auxpow.rs` header doc).
//!
//! **Gated behind the `aux-pow` feature.** It pulls the reviewed Ergo primitives
//! (blake2b256, Autolykos v2, batch-merkle inclusion). Whether that crate graph
//! cross-compiles to the RISC0 guest target (`riscv32im-risc0-zkvm-elf`) is the
//! design's flagged make-or-break measurement (M-E1); the logic here is the same
//! pure-over-bytes function either way, native-tested below.

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::batch_merkle_proof::BatchMerkleProof;
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{serialize_header_without_pow, Header as ErgoHeader};
use num_bigint::BigUint;
use std::collections::HashSet;

use super::batch_merkle::verify_batch_merkle_proof;
use super::header_id::header_id;
use super::types::SuffixBlock;

// The MM commitment constants (pinned; mirror `aegis-spec`) — the extension
// field key/version/length the miner splices to carry the hn header id. Shared
// with the E4 anchor verifier (`super::anchor`).
pub(crate) const AEGIS_MM_KEY: [u8; 2] = [0xAE, 0x00];
pub(crate) const MM_COMMITMENT_VERSION: u8 = 0x01;
const MM_FIELD_VALUE_LEN: usize = 33;
/// Scala `Extension` leaf node prefix (`0x00` for a data leaf).
const LEAF_NODE_PREFIX: u8 = 0x00;

/// An hn block's aux-PoW share witness (guest form) — the Ergo candidate header
/// that solved the PoW, the `AEGIS_MM_KEY` extension field carrying the hn
/// header id, and the batch-merkle proof binding that field to the header's
/// `extension_root`.
#[derive(Debug, Clone)]
pub struct ShareWitness {
    pub ergo_header: ErgoHeader,
    pub field: ExtensionField,
    pub proof: BatchMerkleProof,
}

/// Why a share was rejected — fail-fast in verifier-step order (mirror of
/// `hn/auxpow.rs::HnAuxPowError`, minus the codec variants).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ShareError {
    #[error("share Ergo header carries a v1 solution; only Autolykos v2 accepted")]
    NotAutolykosV2,
    #[error("share Ergo header bytes-without-pow serialize failed: {0}")]
    HeaderEncode(String),
    #[error("share extension proof must prove exactly one leaf (got {got})")]
    ProofShape { got: usize },
    #[error("share extension proof leaf digest does not match the claimed field")]
    ProofLeafMismatch,
    #[error("share extension proof does not reduce to the header's extension_root")]
    ProofInvalid,
    #[error("share extension field key is not AEGIS_MM_KEY")]
    WrongKey,
    #[error("share commitment value has the wrong length or version")]
    BadValue,
    #[error("share commitment does not equal this block's hn header id")]
    HeaderIdMismatch,
    #[error("share target from sc_nbits {nbits:#010x} is zero")]
    ZeroTarget { nbits: u32 },
    #[error("share Autolykos hit does not clear the block's sc_nbits target")]
    PowNotCleared,
    #[error("suffix has {blocks} blocks but {shares} shares (one share per block)")]
    ShareCountMismatch { blocks: usize, shares: usize },
    #[error("two suffix shares carry the same PoW message (one solve, many blocks — F6b)")]
    SharedPowMessage,
}

/// The Autolykos PoW message of a share: `blake2b256` over the header bytes
/// WITHOUT the solution (it includes `extension_root`, binding the work to the
/// hn-id commitment). Surfaced so the suffix verifier can enforce F6b —
/// distinct message ⟺ distinct solve.
pub(crate) fn share_pow_message(witness: &ShareWitness) -> Result<[u8; 32], ShareError> {
    let header_bytes = serialize_header_without_pow(&witness.ergo_header)
        .map_err(|e| ShareError::HeaderEncode(e.to_string()))?;
    Ok(blake2b256(&header_bytes))
}

/// Extension-merkle leaf digest of a field: `blake2b256(0x00 ‖ kvToLeaf(field))`
/// where `kvToLeaf = [key.len() as u8] ‖ key ‖ value` (Scala `Extension`).
/// Shared with the E4 anchor verifier (`super::anchor`).
pub(crate) fn mm_leaf_digest(field: &ExtensionField) -> [u8; 32] {
    let mut leaf = Vec::with_capacity(1 + field.key.len() + field.value.len());
    leaf.push(field.key.len() as u8);
    leaf.extend_from_slice(&field.key);
    leaf.extend_from_slice(&field.value);
    let mut pre = Vec::with_capacity(1 + leaf.len());
    pre.push(LEAF_NODE_PREFIX);
    pre.extend_from_slice(&leaf);
    blake2b256(&pre)
}

/// Verify `witness` binds `header_id` to real Autolykos work at `sc_nbits`.
/// Pure over the presented bytes — the committed id is RECOMPUTED by the caller
/// (the guest, via `header_id(chain_id, block)`) and passed in, never trusted
/// from the witness. Returns the block's real-work weight on success.
pub fn verify_share(
    witness: &ShareWitness,
    header_id: &[u8; 32],
    sc_nbits: u32,
) -> Result<BigUint, ShareError> {
    // Step 1 — Autolykos v2 only.
    let nonce = match &witness.ergo_header.solution {
        AutolykosSolution::V2 { nonce, .. } => *nonce,
        AutolykosSolution::V1 { .. } => return Err(ShareError::NotAutolykosV2),
    };

    // Step 3 — PoW message = blake2b256 of the header bytes WITHOUT the solution
    // (includes extension_root, binding the work to the commitment).
    let msg = share_pow_message(witness)?;

    // Step 4 — extension inclusion under the PoW-committed extension_root.
    if witness.proof.indices.len() != 1 {
        return Err(ShareError::ProofShape {
            got: witness.proof.indices.len(),
        });
    }
    if witness.proof.indices[0].1 != mm_leaf_digest(&witness.field) {
        return Err(ShareError::ProofLeafMismatch);
    }
    if !verify_batch_merkle_proof(
        &witness.proof,
        witness.ergo_header.extension_root.as_bytes(),
    ) {
        return Err(ShareError::ProofInvalid);
    }

    // Step 5 — field decode + id binding (id RECOMPUTED by the caller).
    if witness.field.key != AEGIS_MM_KEY {
        return Err(ShareError::WrongKey);
    }
    if witness.field.value.len() != MM_FIELD_VALUE_LEN
        || witness.field.value[0] != MM_COMMITMENT_VERSION
    {
        return Err(ShareError::BadValue);
    }
    if witness.field.value[1..] != header_id[..] {
        return Err(ShareError::HeaderIdMismatch);
    }

    // Step 6 — threshold: the SAME hit Ergo computes, vs the block's target.
    let target = get_target(sc_nbits);
    if target == BigUint::ZERO {
        return Err(ShareError::ZeroTarget { nbits: sc_nbits });
    }
    if !check_pow_v2(
        &msg,
        &nonce,
        witness.ergo_header.height,
        witness.ergo_header.version,
        &target,
    ) {
        return Err(ShareError::PowNotCleared);
    }

    Ok(decode_compact_bits(sc_nbits))
}

/// Verify every suffix block's aux-PoW share **and** enforce F6b: all shares
/// carry pairwise-distinct PoW messages, so one Autolykos solve cannot be
/// amplified into `k` "blocks" (dropping the fabrication price from `k·D` to
/// `D`). The node kills amplification with extension-key uniqueness (rule 405,
/// `block.rs:642`); in-guest the equivalent is that distinct `msg` ⟺ distinct
/// solve (re-binding a hit to a different message voids it), which needs only
/// the already-computed message — no extension replay. Honest chains build one
/// candidate per hn block, so their messages differ trivially.
///
/// The block-committed hn id is RECOMPUTED per block (`header_id`) and never
/// trusted from the share. Returns each block's real-work weight on success.
pub fn verify_suffix_shares(
    chain_id: u32,
    blocks: &[SuffixBlock],
    shares: &[ShareWitness],
) -> Result<Vec<BigUint>, ShareError> {
    if blocks.len() != shares.len() {
        return Err(ShareError::ShareCountMismatch {
            blocks: blocks.len(),
            shares: shares.len(),
        });
    }
    let mut seen: HashSet<[u8; 32]> = HashSet::with_capacity(blocks.len());
    let mut works = Vec::with_capacity(blocks.len());
    for (block, share) in blocks.iter().zip(shares) {
        let hid = header_id(chain_id, block);
        let work = verify_share(share, &hid, block.sc_nbits)?;
        if !seen.insert(share_pow_message(share)?) {
            return Err(ShareError::SharedPowMessage);
        }
        works.push(work);
    }
    Ok(works)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::header_id::header_id;
    use crate::epoch::types::SuffixBlock;
    use crate::poseidon::{Digest, F};
    use ergo_crypto::merkle::{extension_root, merkle_proof_by_indices};
    use ergo_ser::batch_merkle_proof::{ProofEntry, Side};
    use p3_field::PrimeCharacteristicRing;

    const CHAIN_ID: u32 = 0x484E_0005;

    fn digest(base: u32) -> Digest {
        core::array::from_fn(|i| F::from_u32(base + i as u32))
    }

    fn diff1_block() -> SuffixBlock {
        SuffixBlock {
            height: 5,
            prev_header_id: [0u8; 32],
            prev_root: digest(7),
            state_root: digest(8),
            timestamp_ms: 1_760_000_000_000,
            sc_nbits: ergo_ser::difficulty::encode_compact_bits(&BigUint::from(1u8)),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: digest(3),
            coinbase_amount: 1,
            coinbase_cm: digest(4),
            coinbase_is_reward: true,
            pot_after: 10,
            shielded_after: 11,
        }
    }

    /// Mine a valid difficulty-1 share committing `header_id` — the same test
    /// construction as `hn/auxpow.rs::build_hn_aux_pow`, re-pointed at the engine
    /// header id.
    fn mine_share(block: &SuffixBlock, grind: bool) -> ShareWitness {
        let hid = header_id(CHAIN_ID, block);
        let path = format!(
            "{}/../test-vectors/testnet/blocks/scala_block_442815.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
        let sblock: ergo_rest_json::types::ScalaFullBlock =
            serde_json::from_str(&raw).expect("block JSON parses");
        let mut eh =
            ergo_rest_json::decode_scala_header_struct(&sblock.header).expect("header decodes");
        let mut fields: Vec<([u8; 2], Vec<u8>)> = sblock
            .extension
            .fields
            .iter()
            .map(|kv| {
                let key: [u8; 2] = hex::decode(&kv[0]).unwrap().try_into().unwrap();
                (key, hex::decode(&kv[1]).unwrap())
            })
            .collect();

        let mut value = Vec::with_capacity(MM_FIELD_VALUE_LEN);
        value.push(MM_COMMITMENT_VERSION);
        value.extend_from_slice(&hid);
        let commitment = ExtensionField {
            key: AEGIS_MM_KEY,
            value,
        };
        fields.push((commitment.key, commitment.value.clone()));

        let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|(k, v)| (&k[..], &v[..])).collect();
        eh.extension_root = extension_root(&pairs).into();

        let leaves: Vec<Vec<u8>> = fields
            .iter()
            .map(|(k, v)| {
                let mut leaf = Vec::with_capacity(1 + 2 + v.len());
                leaf.push(2u8);
                leaf.extend_from_slice(k);
                leaf.extend_from_slice(v);
                leaf
            })
            .collect();
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let idx = (fields.len() - 1) as u32;
        let (indices, raw_proof) = merkle_proof_by_indices(&refs, &[idx]).expect("proof builds");
        let proof = BatchMerkleProof {
            indices,
            proofs: raw_proof
                .into_iter()
                .map(|e| ProofEntry {
                    digest: e.digest,
                    side: Side::from_byte(e.side),
                })
                .collect(),
        };

        if grind {
            let target = get_target(block.sc_nbits);
            let msg = blake2b256(&serialize_header_without_pow(&eh).expect("serializes"));
            let pk = *eh.solution.pk();
            let nonce = (0u64..8192)
                .map(|i| i.to_be_bytes())
                .find(|n| check_pow_v2(&msg, n, eh.height, eh.version, &target))
                .expect("a nonce clears difficulty-1 within 8192 tries");
            eh.solution = AutolykosSolution::V2 { pk, nonce };
        }

        ShareWitness {
            ergo_header: eh,
            field: commitment,
            proof,
        }
    }

    // ----- happy path -----

    #[test]
    fn mined_share_binds_block_and_verifies() {
        let block = diff1_block();
        let w = mine_share(&block, true);
        let hid = header_id(CHAIN_ID, &block);
        let work = verify_share(&w, &hid, block.sc_nbits).expect("valid share verifies");
        assert_eq!(work, BigUint::from(1u8));
    }

    // ----- error paths -----

    #[test]
    fn share_for_a_different_block_fails_id_binding() {
        let block = diff1_block();
        let w = mine_share(&block, true);
        let mut other = block.clone();
        other.state_root[0] += F::ONE;
        let other_id = header_id(CHAIN_ID, &other);
        assert_eq!(
            verify_share(&w, &other_id, block.sc_nbits),
            Err(ShareError::HeaderIdMismatch),
            "the share commits exactly one header id"
        );
    }

    #[test]
    fn insufficient_work_is_rejected() {
        let mut block = diff1_block();
        block.sc_nbits = ergo_ser::difficulty::encode_compact_bits(&(BigUint::from(1u8) << 200));
        let w = mine_share(&block, false);
        let hid = header_id(CHAIN_ID, &block);
        assert_eq!(
            verify_share(&w, &hid, block.sc_nbits),
            Err(ShareError::PowNotCleared),
            "a hit that does not clear the target is priced out"
        );
    }

    // ----- F6b: one solve cannot become many blocks -----

    #[test]
    fn amplified_shares_sharing_one_solve_are_rejected() {
        // The amplification attack: one solved Ergo candidate presented as k
        // "distinct" shares. Here the same solve backs two suffix entries — the
        // second carries the identical PoW message, so the dedup fires.
        let block = diff1_block();
        let share = mine_share(&block, true);
        let blocks = vec![block.clone(), block];
        let shares = vec![share.clone(), share];
        assert_eq!(
            verify_suffix_shares(CHAIN_ID, &blocks, &shares),
            Err(ShareError::SharedPowMessage),
            "one Autolykos solve must not be amplified into k blocks"
        );
    }

    #[test]
    fn distinct_honest_shares_pass_the_dedup() {
        // Two genuinely different hn blocks ⇒ different id commitments ⇒ different
        // extension_roots ⇒ different PoW messages: honest suffixes are unaffected.
        let b0 = diff1_block();
        let mut b1 = diff1_block();
        b1.state_root[0] += F::ONE;
        let s0 = mine_share(&b0, true);
        let s1 = mine_share(&b1, true);
        let works =
            verify_suffix_shares(CHAIN_ID, &[b0, b1], &[s0, s1]).expect("distinct solves verify");
        assert_eq!(works.len(), 2);
    }

    #[test]
    fn share_count_must_match_block_count() {
        let block = diff1_block();
        assert_eq!(
            verify_suffix_shares(CHAIN_ID, &[block], &[]),
            Err(ShareError::ShareCountMismatch {
                blocks: 1,
                shares: 0
            }),
        );
    }

    // ----- round-trips -----

    /// The E2 wire round-trip (`aux_wire`) preserves a share: a mined share that
    /// verifies typed still verifies after `from_witness` → serde → `into_witness`
    /// (the guest reads the wire form, so the codec must be faithful).
    #[test]
    fn share_wire_roundtrip_still_verifies() {
        use crate::epoch::aux_wire::ShareWitnessWire;
        let block = diff1_block();
        let w = mine_share(&block, true);
        let hid = header_id(CHAIN_ID, &block);
        verify_share(&w, &hid, block.sc_nbits).expect("baseline share verifies");

        let wire = ShareWitnessWire::from_witness(&w);
        let bytes = postcard::to_allocvec(&wire).expect("wire serializes");
        let back: ShareWitnessWire = postcard::from_bytes(&bytes).expect("wire deserializes");
        let w2 = back.into_witness();
        verify_share(&w2, &hid, block.sc_nbits).expect("round-tripped share still verifies");
    }
}
