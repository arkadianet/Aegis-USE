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
use ergo_validation::popow::verify_batch_merkle_proof;
use num_bigint::BigUint;

// The MM commitment constants (pinned; mirror `aegis-spec`) — the extension
// field key/version/length the miner splices to carry the hn header id.
const AEGIS_MM_KEY: [u8; 2] = [0xAE, 0x00];
const MM_COMMITMENT_VERSION: u8 = 0x01;
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
}

/// Extension-merkle leaf digest of a field: `blake2b256(0x00 ‖ kvToLeaf(field))`
/// where `kvToLeaf = [key.len() as u8] ‖ key ‖ value` (Scala `Extension`).
fn leaf_digest(field: &ExtensionField) -> [u8; 32] {
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
    let header_bytes = serialize_header_without_pow(&witness.ergo_header)
        .map_err(|e| ShareError::HeaderEncode(e.to_string()))?;
    let msg = blake2b256(&header_bytes);

    // Step 4 — extension inclusion under the PoW-committed extension_root.
    if witness.proof.indices.len() != 1 {
        return Err(ShareError::ProofShape {
            got: witness.proof.indices.len(),
        });
    }
    if witness.proof.indices[0].1 != leaf_digest(&witness.field) {
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
}
