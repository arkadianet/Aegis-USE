//! Merge-mining: binding an hn block to real Autolykos work (E0).
//!
//! The Aegis miner solves the devnet's Autolykos PoW with the hn block's
//! [`hn_header_id`](super::header::hn_header_id) committed in the Ergo
//! candidate's extension section. This module holds:
//!
//! - [`fetch_devnet_anchor`] — the liveness scaffold (API consumer only): the
//!   devnet best header as an [`AuxAnchor`].
//! - [`HnAuxPow`] + [`HnAuxPow::verify`] — the PoW BINDING (E0): a share
//!   witness (Ergo candidate header + the `AEGIS_MM_KEY` extension field + a
//!   `BatchMerkleProof`) verified to (a) commit exactly this hn block's header
//!   id and (b) carry Autolykos v2 work clearing the block's `sc_nbits`
//!   target. This is a port of the reviewed Curve-Trees share verifier
//!   ([`crate::auxpow::verify_share`], merge-mining.md §2.3), re-pointed from
//!   the Curve-Trees header id to the hn header id and reusing the exact same
//!   leaf/merkle/PoW primitives (both pinned by
//!   `tests/auxpow_real_extension_oracle.rs`).
//!
//! **Adaptations from the reviewed verifier, and their risk:**
//! - The committed object is [`hn_header_id`](super::header::hn_header_id)
//!   (Poseidon2, packed to 32 opaque bytes) instead of the Curve-Trees
//!   blake2b header id. Risk: low — the Ergo extension value is opaque bytes
//!   either way (merge-mining.md §2.2); the binding logic is identical.
//! - The subjective **C2 height window** (step 2) and the **`sc_nbits`-vs-DAA
//!   equality** (§3) are NOT re-checked here: the window is node-view-dependent
//!   (not committed by the block, so not replay-safe — `epoch-validity-design.md`
//!   §6.7), and the DAA equality is already enforced deterministically in
//!   [`HnState::apply_block`](super::state::HnState::apply_block). What remains
//!   here is exactly the block-committed, replay-safe subset.

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_primitives::reader::VlqReader;
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::batch_merkle_proof::{
    deserialize_batch_merkle_proof, serialize_batch_merkle_proof, BatchMerkleProof,
};
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{
    read_header, serialize_header_without_pow, write_header, Header as ErgoHeader,
};
use ergo_validation::popow::verify_batch_merkle_proof;
use num_bigint::BigUint;

use aegis_spec::{AEGIS_MM_KEY, MM_COMMITMENT_VERSION, MM_FIELD_VALUE_LEN};

use super::header::hn_header_id;
use super::state::{AuxAnchor, HnBlock};
use crate::auxpow::leaf_digest;

/// An hn block's aux-PoW binding: the Ergo candidate header that solved the
/// PoW, the `AEGIS_MM_KEY` extension field carrying the committed hn header id,
/// and the batch-merkle proof binding that field to the header's
/// `extension_root`. Stored in [`HnBlock::aux_pow`] as [`Self::to_bytes`] (the
/// Ergo header has no serde impl — it uses the same manual codec as the
/// reviewed [`crate::auxpow::ShareWitness`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HnAuxPow {
    pub ergo_header: ErgoHeader,
    pub field: ExtensionField,
    pub proof: BatchMerkleProof,
}

/// Why an hn aux-PoW witness was rejected — one variant per verifier step,
/// fail-fast in step order (merge-mining.md §2.3, minus the node-subjective
/// window and the separately-enforced DAA equality).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HnAuxPowError {
    #[error("aux-PoW Ergo header carries a v1 solution; only Autolykos v2 is accepted")]
    NotAutolykosV2,
    #[error("aux-PoW Ergo header bytes-without-pow serialize failed: {0}")]
    HeaderEncode(String),
    #[error("aux-PoW extension proof must prove exactly one leaf (got {got})")]
    ProofShape { got: usize },
    #[error("aux-PoW extension proof leaf digest does not match the claimed field")]
    ProofLeafMismatch,
    #[error("aux-PoW extension proof does not reduce to the header's extension_root")]
    ProofInvalid,
    #[error("aux-PoW extension field key is not AEGIS_MM_KEY")]
    WrongKey,
    #[error("aux-PoW commitment value has the wrong length or version")]
    BadValue,
    #[error("aux-PoW commitment does not equal this block's hn header id")]
    HeaderIdMismatch,
    #[error("aux-PoW target from sc_nbits {nbits:#010x} is zero")]
    ZeroTarget { nbits: u32 },
    #[error("aux-PoW Autolykos hit does not clear the block's sc_nbits target")]
    PowNotCleared,
}

/// Witness codec failure.
#[derive(Debug, thiserror::Error)]
pub enum HnAuxPowDecodeError {
    #[error("aux-PoW witness read failed: {0}")]
    Read(#[from] ergo_primitives::reader::ReadError),
    #[error("aux-PoW witness proof decode failed: {0}")]
    Proof(ergo_ser::error::WriteError),
    #[error("trailing bytes after aux-PoW witness ({0} left)")]
    TrailingBytes(usize),
}

impl HnAuxPow {
    /// Canonical wire form: Ergo header, then `key(2) ‖ value_len(u8) ‖ value`,
    /// then the length-prefixed `BatchMerkleProof` (the reviewed
    /// `ShareWitness` codec, minus the aegis-block bytes — here the committed
    /// object is the hn block's own header id).
    pub fn to_bytes(&self) -> Result<Vec<u8>, ergo_ser::error::WriteError> {
        if self.field.value.len() > u8::MAX as usize {
            return Err(ergo_ser::error::WriteError::InvalidData(format!(
                "aux-PoW field value too long for extension wire format: {} bytes (max 255)",
                self.field.value.len()
            )));
        }
        let mut w = VlqWriter::with_capacity(256);
        write_header(&mut w, &self.ergo_header)?;
        w.put_bytes(&self.field.key);
        w.put_u8(self.field.value.len() as u8);
        w.put_bytes(&self.field.value);
        let proof_bytes = serialize_batch_merkle_proof(&self.proof);
        w.put_u64(proof_bytes.len() as u64);
        w.put_bytes(&proof_bytes);
        Ok(w.result())
    }

    /// Decode exactly one witness — trailing bytes are an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HnAuxPowDecodeError> {
        let mut r = VlqReader::new(bytes);
        let ergo_header = read_header(&mut r)?;
        let key = r.get_array::<2>()?;
        let value_len = r.get_u8()? as usize;
        let value = r.get_bytes(value_len)?.to_vec();
        let proof_len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
        let proof = deserialize_batch_merkle_proof(r.get_bytes(proof_len)?)
            .map_err(HnAuxPowDecodeError::Proof)?;
        if !r.is_empty() {
            return Err(HnAuxPowDecodeError::TrailingBytes(r.remaining()));
        }
        Ok(HnAuxPow {
            ergo_header,
            field: ExtensionField { key, value },
            proof,
        })
    }

    /// Verify this witness binds `block` to real Autolykos work at
    /// `block.sc_nbits`. Pure over the presented bytes: the committed id is
    /// RECOMPUTED as `hn_header_id(chain_id, block)`, never trusted. Returns
    /// the block's real-work weight (`decode_compact_bits(sc_nbits)`) on
    /// success.
    pub fn verify(&self, chain_id: u32, block: &HnBlock) -> Result<BigUint, HnAuxPowError> {
        // Step 1 — solution type: Autolykos v2 only.
        let nonce = match &self.ergo_header.solution {
            AutolykosSolution::V2 { nonce, .. } => *nonce,
            AutolykosSolution::V1 { .. } => return Err(HnAuxPowError::NotAutolykosV2),
        };

        // Step 3 — PoW message = blake2b256 of the Ergo header bytes WITHOUT
        // the solution; those bytes include `extension_root`, which binds the
        // work to the commitment.
        let header_bytes = serialize_header_without_pow(&self.ergo_header)
            .map_err(|e| HnAuxPowError::HeaderEncode(e.to_string()))?;
        let msg = blake2b256(&header_bytes);

        // Step 4 — extension inclusion: the leaf digest rebuilt from the
        // CLAIMED field must be the single proven leaf, reduced against the
        // header's PoW-committed extension_root.
        if self.proof.indices.len() != 1 {
            return Err(HnAuxPowError::ProofShape {
                got: self.proof.indices.len(),
            });
        }
        if self.proof.indices[0].1 != leaf_digest(&self.field) {
            return Err(HnAuxPowError::ProofLeafMismatch);
        }
        if !verify_batch_merkle_proof(&self.proof, self.ergo_header.extension_root.as_bytes()) {
            return Err(HnAuxPowError::ProofInvalid);
        }

        // Step 5 — field decode + id binding. The committed id is RECOMPUTED
        // from the presented block, never read from the witness.
        if self.field.key != AEGIS_MM_KEY {
            return Err(HnAuxPowError::WrongKey);
        }
        if self.field.value.len() != MM_FIELD_VALUE_LEN
            || self.field.value[0] != MM_COMMITMENT_VERSION
        {
            return Err(HnAuxPowError::BadValue);
        }
        if self.field.value[1..] != hn_header_id(chain_id, block)[..] {
            return Err(HnAuxPowError::HeaderIdMismatch);
        }

        // Step 6 — aux-PoW threshold: the SAME hit Ergo computes for this
        // candidate, checked against the hn block's `sc_nbits` target.
        let target = get_target(block.sc_nbits);
        if target == BigUint::ZERO {
            return Err(HnAuxPowError::ZeroTarget {
                nbits: block.sc_nbits,
            });
        }
        if !check_pow_v2(
            &msg,
            &nonce,
            self.ergo_header.height,
            self.ergo_header.version,
            &target,
        ) {
            return Err(HnAuxPowError::PowNotCleared);
        }

        Ok(decode_compact_bits(block.sc_nbits))
    }
}

/// Fetch the devnet's current best header as an [`AuxAnchor`]. `None` if the
/// devnet is unreachable or the response is missing the expected fields.
pub fn fetch_devnet_anchor(api_url: &str, api_key: &str) -> Option<AuxAnchor> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .ok()?;
    let text = client
        .get(format!("{api_url}/info"))
        .header("api_key", api_key)
        .send()
        .ok()?
        .text()
        .ok()?;
    let json: serde_json::Value = serde_json::from_str(&text).ok()?;
    let id_hex = json.get("bestHeaderId")?.as_str()?;
    let height = json
        .get("fullHeight")
        .and_then(|v| v.as_u64())
        .or_else(|| json.get("headersHeight").and_then(|v| v.as_u64()))?;
    let id: [u8; 32] = hex::decode(id_hex).ok()?.try_into().ok()?;
    Some(AuxAnchor {
        devnet_header_id: id,
        devnet_height: height,
    })
}

/// Mine a VALID hn aux-PoW witness binding `block`'s header id — a crate-test
/// helper (used by [`crate::hn::state`]'s Strict apply-block tests too). Ports
/// the reviewed `crate::auxpow` test construction: take a real Ergo testnet
/// header, splice the `AEGIS_MM_KEY` commitment for `hn_header_id(chain_id,
/// block)` into its extension, re-root, build the batch proof, and grind a
/// nonce that clears `get_target(block.sc_nbits)` (difficulty-1 ⇒ ~1 try).
#[cfg(test)]
pub(crate) fn mine_hn_aux_pow(chain_id: u32, block: &HnBlock) -> HnAuxPow {
    build_hn_aux_pow(chain_id, block, true)
}

/// As [`mine_hn_aux_pow`] but with `grind` controlling whether the nonce is
/// ground to clear `block.sc_nbits`. `grind == false` keeps the real testnet
/// header's original nonce — used to test a hard target the hit cannot clear.
#[cfg(test)]
pub(crate) fn build_hn_aux_pow(chain_id: u32, block: &HnBlock, grind: bool) -> HnAuxPow {
    use crate::auxpow::{aegis_mm_extension_field, kv_to_leaf};
    use ergo_crypto::merkle::{extension_root, merkle_proof_by_indices};
    use ergo_ser::batch_merkle_proof::{ProofEntry, Side};

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

    let commitment = aegis_mm_extension_field(hn_header_id(chain_id, block));
    fields.push((commitment.key, commitment.value.clone()));

    let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|(k, v)| (&k[..], &v[..])).collect();
    eh.extension_root = extension_root(&pairs).into();

    let leaves: Vec<Vec<u8>> = fields
        .iter()
        .map(|(k, v)| {
            kv_to_leaf(&ExtensionField {
                key: *k,
                value: v.clone(),
            })
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
            .expect("a nonce must clear the difficulty-1 target within 8192 tries");
        eh.solution = AutolykosSolution::V2 { pk, nonce };
    }

    HnAuxPow {
        ergo_header: eh,
        field: commitment,
        proof,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hn::state::AuxAnchor;

    const CHAIN_ID: u32 = 0x484E_0005;

    // ----- helpers -----

    /// A difficulty-1 hn block skeleton for binding tests (only the header-id
    /// fields matter to the verifier).
    fn diff1_block() -> HnBlock {
        HnBlock {
            height: 5,
            prev_root: [7u32; 8],
            prev_header_id: [0u8; 32],
            state_root: [8u32; 8],
            timestamp_ms: 1_760_000_000_000,
            sc_nbits: ergo_ser::difficulty::encode_compact_bits(&BigUint::from(1u8)),
            txs: vec![],
            pegouts: vec![],
            pegins: vec![],
            miner_owner: [3u32; 8],
            coinbase_amount: 1,
            coinbase_cm: [4u32; 8],
            coinbase_ct: vec![],
            coinbase_is_reward: true,
            pot_after: 10,
            anchor: AuxAnchor::genesis(),
            aux_pow: None,
        }
    }

    // ----- happy path -----

    #[test]
    fn mined_witness_binds_block_and_verifies() {
        let block = diff1_block();
        let aux = mine_hn_aux_pow(CHAIN_ID, &block);
        let work = aux
            .verify(CHAIN_ID, &block)
            .expect("valid witness verifies");
        assert_eq!(work, BigUint::from(1u8), "difficulty-1 weight");
    }

    // ----- round-trips -----

    #[test]
    fn witness_bytes_roundtrip_and_still_verify() {
        let block = diff1_block();
        let aux = mine_hn_aux_pow(CHAIN_ID, &block);
        let bytes = aux.to_bytes().expect("serializes");
        let decoded = HnAuxPow::from_bytes(&bytes).expect("decodes");
        assert_eq!(decoded, aux);
        decoded
            .verify(CHAIN_ID, &block)
            .expect("round-tripped witness still verifies");
    }

    // ----- error paths -----

    #[test]
    fn witness_for_a_different_block_fails_header_id_binding() {
        // A witness mined for `block` must not verify a block with any changed
        // committed field (the id is recomputed, never trusted).
        let block = diff1_block();
        let aux = mine_hn_aux_pow(CHAIN_ID, &block);
        let mut other = block.clone();
        other.state_root[0] ^= 1;
        assert_eq!(
            aux.verify(CHAIN_ID, &other),
            Err(HnAuxPowError::HeaderIdMismatch)
        );
        // Same block, different chain id → different committed id.
        assert_eq!(
            aux.verify(CHAIN_ID + 1, &block),
            Err(HnAuxPowError::HeaderIdMismatch)
        );
    }

    #[test]
    fn hard_target_hit_does_not_clear() {
        // A block at difficulty 2^200 (target ~2^56): the real testnet
        // header's un-ground hit cannot clear it. The commitment binds
        // correctly (the id includes the hard sc_nbits), so the failure
        // isolates to the PoW threshold — insufficient work is rejected.
        let mut block = diff1_block();
        block.sc_nbits = ergo_ser::difficulty::encode_compact_bits(&(BigUint::from(1u8) << 200));
        let aux = build_hn_aux_pow(CHAIN_ID, &block, false);
        assert_eq!(
            aux.verify(CHAIN_ID, &block),
            Err(HnAuxPowError::PowNotCleared)
        );
    }

    #[test]
    fn wrong_key_field_rejected() {
        let block = diff1_block();
        let mut aux = mine_hn_aux_pow(CHAIN_ID, &block);
        aux.field.key = [0x00, 0x77];
        // Leaf digest now mismatches the proven leaf (fails earlier, at step 4).
        assert_eq!(
            aux.verify(CHAIN_ID, &block),
            Err(HnAuxPowError::ProofLeafMismatch)
        );
    }
}
