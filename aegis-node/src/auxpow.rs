//! Aux-PoW share verification + extension-commitment construction
//! (merge-mining.md §2 — M2a).
//!
//! One hash, two targets: the Aegis block id sits in the Ergo block
//! candidate's extension section, so `msg =
//! blake2b256(bytes_without_pow(ergo_header))` commits to it through
//! `extension_root`. The same Autolykos v2 hit Ergo checks against its
//! own target is checked here against the (easier) Aegis target from
//! the Aegis header's `sc_nbits` — the hit computation is
//! target-independent, exactly like Namecoin/Dogecoin aux-PoW.
//!
//! This module is the pure consensus primitive: commitment field
//! construction ([`aegis_mm_extension_field`]), the share witness
//! codec ([`ShareWitness`]), and the fail-fast verifier
//! ([`verify_share`], merge-mining.md §2.3 steps 1–6 plus the
//! `sc_nbits`-vs-DAA equality). Everything is re-derived from the
//! presented bytes; nothing carried in the witness is trusted.
//!
//! M2a intentionally stops at "this witness proves real Autolykos
//! work bound to this Aegis id". Body validation (§2.3 step 7,
//! `Chain::try_extend`), share ingestion, weight bookkeeping and fork
//! choice live in [`crate::mm_forkchoice`] (M2b); the running loop
//! that feeds them is [`crate::node`] (M6c).

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_primitives::reader::{ReadError, VlqReader};
use ergo_primitives::writer::VlqWriter;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::batch_merkle_proof::{
    deserialize_batch_merkle_proof, serialize_batch_merkle_proof, BatchMerkleProof,
};
use ergo_ser::difficulty::decode_compact_bits;
use ergo_ser::error::WriteError;
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{
    read_header, serialize_header_without_pow, write_header, Header as ErgoHeader,
};
use ergo_validation::popow::verify_batch_merkle_proof;
use num_bigint::BigUint;

use aegis_spec::{AEGIS_MM_KEY, MM_COMMITMENT_VERSION, MM_FIELD_VALUE_LEN};

use crate::block::{Block, BlockDecodeError};
use crate::daa::{next_nbits, DaaParams};
use crate::header::Header as AegisHeader;

/// Merkle leaf-node prefix byte. Matches scrypto
/// `MerkleTree.LeafPrefix = 0` and `ergo-crypto::merkle`'s private
/// `leaf_hash` (the popow verifier keeps the same local copy of the
/// internal-node prefix for the identical reason).
const LEAF_NODE_PREFIX: u8 = 0x00;

/// Build the extension field a merge-miner embeds in an Ergo block
/// candidate: `key = AEGIS_MM_KEY`, `value = MM_COMMITMENT_VERSION ‖
/// aegis_block_id` (33 bytes — inside Ergo's 64-byte rule-404 cap).
pub fn aegis_mm_extension_field(aegis_block_id: [u8; 32]) -> ExtensionField {
    let mut value = Vec::with_capacity(MM_FIELD_VALUE_LEN);
    value.push(MM_COMMITMENT_VERSION);
    value.extend_from_slice(&aegis_block_id);
    ExtensionField {
        key: AEGIS_MM_KEY,
        value,
    }
}

/// Extension-merkle leaf bytes for a field — Scala `Extension.kvToLeaf`:
/// `[key.len() as u8 = 2] ‖ key ‖ value`. Must stay byte-identical to
/// the leaf construction inside `ergo_crypto::merkle::extension_root`
/// (oracle-pinned against a real block's PoW-committed
/// `extension_root` in `tests/auxpow_real_extension_oracle.rs`).
pub fn kv_to_leaf(field: &ExtensionField) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(1 + field.key.len() + field.value.len());
    leaf.push(field.key.len() as u8);
    leaf.extend_from_slice(&field.key);
    leaf.extend_from_slice(&field.value);
    leaf
}

/// Merkle leaf digest of a field: `blake2b256(0x00 ‖ kvToLeaf(field))`
/// — the digest a `BatchMerkleProof` carries for a proven leaf. Public
/// so the hn aux-PoW verifier ([`crate::hn::auxpow`], E0) reuses the
/// exact same leaf construction instead of re-deriving it (both are
/// pinned by `tests/auxpow_real_extension_oracle.rs`).
pub fn leaf_digest(field: &ExtensionField) -> [u8; 32] {
    let leaf = kv_to_leaf(field);
    let mut pre = Vec::with_capacity(1 + leaf.len());
    pre.push(LEAF_NODE_PREFIX);
    pre.extend_from_slice(&leaf);
    blake2b256(&pre)
}

/// Verifier-side chain view for share checks: the Ergo follower tip
/// (C2 height window) and the Aegis DAA expectation (§3).
#[derive(Debug, Clone)]
pub struct ShareContext<'a> {
    /// Height of this node's own `ergo_follow::Follower` tip.
    pub follower_tip_height: u32,
    /// C2 window half-width (`aegis_spec::K_LAG` in production).
    pub k_lag: u32,
    /// Aegis DAA parameters.
    pub daa: &'a DaaParams,
    /// `(timestamp_ms, sc_nbits)` of the Aegis parent chain, oldest
    /// first — exactly the [`next_nbits`] input view.
    pub daa_view: &'a [(u64, u32)],
}

/// A verified share (merge-mining.md §2.3 steps 1–6 passed): real
/// Autolykos work bound to exactly this Aegis block id. Body validity
/// (`Chain::try_extend`) is M2b's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidShare {
    /// Recomputed id of the presented Aegis header.
    pub aegis_id: [u8; 32],
    /// Expected work: `decode_compact_bits(sc_nbits)` — the fork-choice
    /// weight input (§5).
    pub work: BigUint,
    /// Height of the Ergo candidate that carried the commitment.
    pub ergo_height: u32,
}

/// Share rejection — one variant per verifier step, fail-fast in step
/// order (merge-mining.md §2.3).
#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    /// Step 1: only `AutolykosSolution::V2` shares are accepted.
    #[error("share Ergo header carries an Autolykos v1 solution; only v2 is accepted")]
    NotAutolykosV2,
    /// Step 2: C2 height window (anti `calc_n` grinding / stockpiling).
    #[error("ergo candidate height {got} outside share window [{low}, {high}]")]
    HeightOutOfWindow { got: u32, low: u32, high: u32 },
    /// Step 3: the header cannot be serialized to its PoW preimage
    /// (mirrors `PowError::HeaderEncode`).
    #[error("ergo header bytes-without-pow serialize: {0}")]
    HeaderEncode(String),
    /// Step 4: the proof must prove exactly one leaf. Also rejects the
    /// empty `BatchMerkleProof`, which `verify_batch_merkle_proof`
    /// vacuously accepts against ANY root (Scala genesis-interlinks
    /// parity) — consensus-critical to exclude here.
    #[error("extension proof must prove exactly one leaf (got {got})")]
    ProofShape { got: usize },
    /// Step 4: the proof's leaf digest is not the digest of the
    /// claimed field bytes — a proof for different key/value.
    #[error("extension proof leaf digest does not match the claimed field")]
    ProofLeafMismatch,
    /// Step 4: the proof does not reduce to the header's
    /// PoW-committed `extension_root`.
    #[error("extension merkle proof does not reduce to the header's extension_root")]
    ProofInvalid,
    /// Step 5: only `AEGIS_MM_KEY` fields are commitments.
    #[error("extension field key {got:02x?} is not AEGIS_MM_KEY")]
    WrongKey { got: [u8; 2] },
    /// Step 5: commitment value must be exactly version ‖ 32-byte id.
    #[error("commitment value length {got} != {MM_FIELD_VALUE_LEN}")]
    ValueLen { got: usize },
    /// Step 5: unknown commitment-era version byte.
    #[error("commitment version byte {got:#04x} != MM_COMMITMENT_VERSION")]
    ValueVersion { got: u8 },
    /// Step 5: the committed id is not the recomputed id of the
    /// presented Aegis header (ids are never trusted, only recomputed).
    #[error("committed aegis id does not match the presented Aegis header")]
    AegisIdMismatch,
    /// Step 6: `sc_nbits` decodes to a zero target (mirrors
    /// `verify_pow_solution`'s zero-target guard).
    #[error("aegis target from sc_nbits {nbits:#010x} is zero")]
    ZeroTarget { nbits: u32 },
    /// Step 6: the Autolykos hit does not clear the Aegis target.
    #[error("Autolykos hit does not clear the Aegis target (sc_nbits {nbits:#010x})")]
    PowNotCleared { nbits: u32 },
    /// Self-declared-easy-target defense (§3): `sc_nbits` must equal
    /// the DAA-expected value for this chain position.
    #[error("sc_nbits {got:#010x} != DAA-expected {want:#010x}")]
    NbitsMismatch { got: u32, want: u32 },
}

/// Verify an aux-PoW share (merge-mining.md §2.3 steps 1–6 + the
/// `sc_nbits` DAA equality from §3). Pure function over the witness
/// pieces and the verifier's own chain view; every value is re-derived
/// from presented bytes. Returns the validated share on success —
/// body validation (`Chain::try_extend`) is deliberately NOT here (M2b).
pub fn verify_share(
    ergo_header: &ErgoHeader,
    field: &ExtensionField,
    proof: &BatchMerkleProof,
    aegis_header: &AegisHeader,
    ctx: &ShareContext<'_>,
) -> Result<ValidShare, ShareError> {
    // Step 1 — solution type: v2 only (mainnet is v2 since 417,792;
    // one code path, one analysis).
    let nonce = match &ergo_header.solution {
        AutolykosSolution::V2 { nonce, .. } => *nonce,
        AutolykosSolution::V1 { .. } => return Err(ShareError::NotAutolykosV2),
    };

    // Step 2 — C2 height window against our own follower view.
    let low = ctx.follower_tip_height.saturating_sub(ctx.k_lag);
    let high = ctx.follower_tip_height.saturating_add(1);
    if ergo_header.height < low || ergo_header.height > high {
        return Err(ShareError::HeightOutOfWindow {
            got: ergo_header.height,
            low,
            high,
        });
    }

    // Step 3 — PoW message: blake2b256 of the header bytes WITHOUT the
    // solution; those bytes include `extension_root`, which is what
    // binds the work to the commitment.
    let header_bytes = serialize_header_without_pow(ergo_header)
        .map_err(|e| ShareError::HeaderEncode(e.to_string()))?;
    let msg = blake2b256(&header_bytes);

    // Step 4 — extension inclusion. The leaf digest is rebuilt from
    // the CLAIMED field bytes and must be the (single) leaf the proof
    // proves; only then is the proof reduced against the header's
    // PoW-committed extension_root.
    if proof.indices.len() != 1 {
        return Err(ShareError::ProofShape {
            got: proof.indices.len(),
        });
    }
    if proof.indices[0].1 != leaf_digest(field) {
        return Err(ShareError::ProofLeafMismatch);
    }
    if !verify_batch_merkle_proof(proof, ergo_header.extension_root.as_bytes()) {
        return Err(ShareError::ProofInvalid);
    }

    // Step 5 — field decode + id binding. The id is RECOMPUTED from
    // the presented Aegis header, never read from the witness.
    if field.key != AEGIS_MM_KEY {
        return Err(ShareError::WrongKey { got: field.key });
    }
    if field.value.len() != MM_FIELD_VALUE_LEN {
        return Err(ShareError::ValueLen {
            got: field.value.len(),
        });
    }
    if field.value[0] != MM_COMMITMENT_VERSION {
        return Err(ShareError::ValueVersion {
            got: field.value[0],
        });
    }
    let aegis_id = aegis_header.id();
    if field.value[1..] != aegis_id[..] {
        return Err(ShareError::AegisIdMismatch);
    }

    // Step 6 — aux-PoW threshold: the SAME hit Ergo would compute for
    // this candidate (same msg/nonce/height/version → same `calc_n`),
    // checked against the Aegis target.
    let aegis_target = get_target(aegis_header.sc_nbits);
    if aegis_target == BigUint::ZERO {
        return Err(ShareError::ZeroTarget {
            nbits: aegis_header.sc_nbits,
        });
    }
    if !check_pow_v2(
        &msg,
        &nonce,
        ergo_header.height,
        ergo_header.version,
        &aegis_target,
    ) {
        return Err(ShareError::PowNotCleared {
            nbits: aegis_header.sc_nbits,
        });
    }

    // §3 — the target itself is consensus: a miner cannot self-declare
    // an easy `sc_nbits`.
    let want = next_nbits(ctx.daa, ctx.daa_view);
    if aegis_header.sc_nbits != want {
        return Err(ShareError::NbitsMismatch {
            got: aegis_header.sc_nbits,
            want,
        });
    }

    Ok(ValidShare {
        aegis_id,
        work: decode_compact_bits(aegis_header.sc_nbits),
        ergo_height: ergo_header.height,
    })
}

/// The share witness Aegis gossip carries per block (merge-mining.md
/// §2.3 inputs): the full Ergo candidate header (with its Autolykos
/// solution), the commitment field, the batch-merkle proof binding the
/// field to `extension_root`, and the full Aegis block bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareWitness {
    /// Full Ergo candidate header, including the PoW solution.
    pub ergo_header: ErgoHeader,
    /// The claimed `AEGIS_MM_KEY` extension field.
    pub field: ExtensionField,
    /// Batch-merkle proof: field leaf → `ergo_header.extension_root`.
    pub proof: BatchMerkleProof,
    /// Canonical Aegis [`Block`] bytes (opaque at codec level; decoded
    /// and hashed — never trusted — at verification time).
    pub aegis_block_bytes: Vec<u8>,
}

/// Witness decode failure.
#[derive(Debug, thiserror::Error)]
pub enum WitnessDecodeError {
    #[error("witness read failed: {0}")]
    Read(#[from] ReadError),
    #[error("witness proof decode failed: {0}")]
    Proof(WriteError),
    #[error("trailing bytes after witness ({0} left)")]
    TrailingBytes(usize),
}

/// Witness verification failure: the Aegis block bytes must decode
/// before the share checks can bind the commitment to their header.
#[derive(Debug, thiserror::Error)]
pub enum WitnessError {
    #[error("aegis block decode failed: {0}")]
    Block(#[from] BlockDecodeError),
    #[error(transparent)]
    Share(#[from] ShareError),
}

impl ShareWitness {
    /// Canonical wire serialization: full Ergo header, then the field
    /// as `key(2) ‖ value_len(u8) ‖ value` (the extension wire shape,
    /// same ≤255 cap), then the length-prefixed scrypto
    /// `BatchMerkleProof` encoding, then the length-prefixed Aegis
    /// block bytes.
    pub fn bytes(&self) -> Result<Vec<u8>, WriteError> {
        if self.field.value.len() > u8::MAX as usize {
            return Err(WriteError::InvalidData(format!(
                "witness field value too long for extension wire format: {} bytes (max 255)",
                self.field.value.len()
            )));
        }
        let mut w = VlqWriter::with_capacity(256 + self.aegis_block_bytes.len());
        write_header(&mut w, &self.ergo_header)?;
        w.put_bytes(&self.field.key);
        w.put_u8(self.field.value.len() as u8);
        w.put_bytes(&self.field.value);
        let proof_bytes = serialize_batch_merkle_proof(&self.proof);
        w.put_u64(proof_bytes.len() as u64);
        w.put_bytes(&proof_bytes);
        w.put_u64(self.aegis_block_bytes.len() as u64);
        w.put_bytes(&self.aegis_block_bytes);
        Ok(w.result())
    }

    /// Decode exactly one witness — trailing bytes are an error.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WitnessDecodeError> {
        let mut r = VlqReader::new(bytes);
        let ergo_header = read_header(&mut r)?;
        let key = r.get_array::<2>()?;
        let value_len = r.get_u8()? as usize;
        let value = r.get_bytes(value_len)?.to_vec();
        let proof_len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
        let proof = deserialize_batch_merkle_proof(r.get_bytes(proof_len)?)
            .map_err(WitnessDecodeError::Proof)?;
        let block_len = usize::try_from(r.get_u64()?).unwrap_or(usize::MAX);
        let aegis_block_bytes = r.get_bytes(block_len)?.to_vec();
        if !r.is_empty() {
            return Err(WitnessDecodeError::TrailingBytes(r.remaining()));
        }
        Ok(ShareWitness {
            ergo_header,
            field: ExtensionField { key, value },
            proof,
            aegis_block_bytes,
        })
    }

    /// Decode the carried Aegis block and run [`verify_share`] against
    /// its header (the id is recomputed from these presented bytes —
    /// merge-mining.md §2.3 step 5).
    pub fn verify(&self, ctx: &ShareContext<'_>) -> Result<ValidShare, WitnessError> {
        let block = Block::from_bytes(&self.aegis_block_bytes)?;
        Ok(verify_share(
            &self.ergo_header,
            &self.field,
            &self.proof,
            &block.header,
            ctx,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::BlockBody;
    use crate::daa::difficulty_to_nbits;
    use aegis_spec::K_LAG;
    use ergo_crypto::merkle::{extension_root, merkle_proof_by_indices};
    use ergo_rest_json::types::ScalaFullBlock;
    use ergo_ser::batch_merkle_proof::{ProofEntry, Side};

    // ----- helpers -----
    //
    // The Ergo-header base for the structural tests is REAL testnet
    // block 442815 (v4, Autolykos v2; same capture the pegmint e2e
    // pins). No real Ergo block carries an AEGIS_MM_KEY field yet, so
    // the commitment path re-roots that header's extension over
    // (real fields + the commitment) and grinds a nonce against a
    // difficulty-1 Aegis target — every hash/merkle/pow primitive used
    // here is the SAME code that `tests/auxpow_real_extension_oracle.rs`
    // pins against the real block's PoW-committed values.

    fn vector(rel: &str) -> String {
        let path = format!("{}/../test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
    }

    /// Extension key-value pairs as decoded from the capture JSON.
    type KvFields = Vec<([u8; 2], Vec<u8>)>;

    /// Real testnet block 442815: decoded header + verbatim extension
    /// key-value fields.
    fn real_block_parts() -> (ErgoHeader, KvFields) {
        let block: ScalaFullBlock =
            serde_json::from_str(&vector("testnet/blocks/scala_block_442815.json"))
                .expect("block JSON parses");
        let header =
            ergo_rest_json::decode_scala_header_struct(&block.header).expect("header decodes");
        let fields = block
            .extension
            .fields
            .iter()
            .map(|kv| {
                let key: [u8; 2] = hex::decode(&kv[0])
                    .expect("key hex")
                    .try_into()
                    .expect("2-byte key");
                (key, hex::decode(&kv[1]).expect("value hex"))
            })
            .collect();
        (header, fields)
    }

    fn sample_aegis_header(sc_nbits: u32) -> AegisHeader {
        AegisHeader {
            version: 1,
            prev_id: [0x11; 32],
            height: 7,
            timestamp_ms: 1_760_000_000_123,
            tx_root: [0x22; 32],
            cm_tree_root: [0x33; 32],
            nullifier_digest: [0x44; 32],
            pot_balance: 5_000,
            sc_nbits,
            reward_claim: [0x55; 33],
        }
    }

    fn easy_nbits() -> u32 {
        difficulty_to_nbits(&BigUint::from(1u8))
    }

    fn daa_with_min(min_difficulty_nbits: u32) -> DaaParams {
        DaaParams {
            target_secs: 15,
            window: 90,
            min_difficulty_nbits,
        }
    }

    /// Re-root the real header's extension over (real fields ‖ `field`)
    /// and build the batch proof for `field`'s leaf. When `mine_nbits`
    /// is set, grind the nonce until the hit clears that target (with
    /// difficulty 1 the first nonce all but surely clears).
    fn share_with_field(
        field: &ExtensionField,
        mine_nbits: Option<u32>,
    ) -> (ErgoHeader, BatchMerkleProof) {
        let (mut eh, mut fields) = real_block_parts();
        fields.push((field.key, field.value.clone()));
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
        let (indices, raw) = merkle_proof_by_indices(&refs, &[idx]).expect("proof builds");
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

        if let Some(nbits) = mine_nbits {
            let msg = blake2b256(&serialize_header_without_pow(&eh).expect("serializes"));
            let target = get_target(nbits);
            let pk = *eh.solution.pk();
            let nonce = (0u64..4096)
                .map(|i| i.to_be_bytes())
                .find(|n| check_pow_v2(&msg, n, eh.height, eh.version, &target))
                .expect("a nonce must clear a difficulty-1 target within 4096 tries");
            eh.solution = AutolykosSolution::V2 { pk, nonce };
        }
        (eh, proof)
    }

    /// Fully valid mined share for a fresh Aegis header at difficulty 1.
    fn valid_share() -> (ErgoHeader, ExtensionField, BatchMerkleProof, AegisHeader) {
        let ah = sample_aegis_header(easy_nbits());
        let field = aegis_mm_extension_field(ah.id());
        let (eh, proof) = share_with_field(&field, Some(ah.sc_nbits));
        (eh, field, proof, ah)
    }

    // ----- happy path -----

    #[test]
    fn mm_extension_field_layout_matches_spec() {
        let id = [0xCD; 32];
        let field = aegis_mm_extension_field(id);
        assert_eq!(field.key, AEGIS_MM_KEY);
        assert_eq!(field.value.len(), MM_FIELD_VALUE_LEN);
        assert_eq!(field.value[0], MM_COMMITMENT_VERSION);
        assert_eq!(&field.value[1..], &id[..]);
        // kvToLeaf: [2] ‖ key ‖ value.
        let leaf = kv_to_leaf(&field);
        assert_eq!(leaf[0], 2);
        assert_eq!(&leaf[1..3], &AEGIS_MM_KEY[..]);
        assert_eq!(&leaf[3..], &field.value[..]);
    }

    #[test]
    fn mined_share_verifies_and_returns_recomputed_share() {
        let (eh, field, proof, ah) = valid_share();
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        let share = verify_share(&eh, &field, &proof, &ah, &ctx).expect("valid share verifies");
        assert_eq!(share.aegis_id, ah.id());
        assert_eq!(share.work, BigUint::from(1u8));
        assert_eq!(share.ergo_height, eh.height);
    }

    #[test]
    fn witness_verify_decodes_block_and_verifies() {
        let (eh, field, proof, ah) = valid_share();
        let block = Block {
            header: ah,
            body: BlockBody::default(),
            coinbase: None,
        };
        let witness = ShareWitness {
            ergo_header: eh,
            field,
            proof,
            aegis_block_bytes: block.bytes(),
        };
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: witness.ergo_header.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        let share = witness.verify(&ctx).expect("witness verifies");
        assert_eq!(share.aegis_id, block.id());
    }

    // ----- round-trips -----

    #[test]
    fn share_witness_bytes_roundtrips() {
        let (eh, field, proof, ah) = valid_share();
        let block = Block {
            header: ah,
            body: BlockBody::default(),
            coinbase: None,
        };
        let witness = ShareWitness {
            ergo_header: eh,
            field,
            proof,
            aegis_block_bytes: block.bytes(),
        };
        let bytes = witness.bytes().expect("witness serializes");
        let decoded = ShareWitness::from_bytes(&bytes).expect("witness decodes");
        assert_eq!(decoded, witness);
    }

    // ----- error paths -----

    #[test]
    fn v1_solution_share_rejected() {
        let (mut eh, field, proof, ah) = valid_share();
        let pk = *eh.solution.pk();
        eh.solution = AutolykosSolution::V1 {
            pk,
            w: pk,
            nonce: [0u8; 8],
            d: Vec::new(),
        };
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::NotAutolykosV2)
        ));
    }

    #[test]
    fn share_height_below_window_errors() {
        let (eh, field, proof, ah) = valid_share();
        let daa = daa_with_min(easy_nbits());
        // Follower tip so far ahead that low = tip - K_LAG > header.height.
        let ctx = ShareContext {
            follower_tip_height: eh.height + K_LAG + 1,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::HeightOutOfWindow { .. })
        ));
    }

    #[test]
    fn share_height_above_tip_plus_one_errors() {
        let (eh, field, proof, ah) = valid_share();
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height - 2,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::HeightOutOfWindow { .. })
        ));
    }

    #[test]
    fn unserializable_ergo_header_errors() {
        let (mut eh, field, proof, ah) = valid_share();
        // v4 headers must have empty unparsed_bytes; a non-empty vector
        // makes serialize_header_without_pow fail (PowError::HeaderEncode
        // mirror).
        eh.unparsed_bytes = vec![0x01];
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::HeaderEncode(_))
        ));
    }

    #[test]
    fn empty_proof_vacuous_accept_rejected() {
        // verify_batch_merkle_proof returns TRUE for the empty proof
        // against ANY root (Scala genesis-interlinks parity) — the
        // one-leaf shape check is what makes that unexploitable here.
        let (eh, field, _proof, ah) = valid_share();
        let empty = BatchMerkleProof {
            indices: Vec::new(),
            proofs: Vec::new(),
        };
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &empty, &ah, &ctx),
            Err(ShareError::ProofShape { got: 0 })
        ));
    }

    #[test]
    fn tampered_aegis_id_fails_leaf_binding() {
        // Claimed field re-bound to a different Aegis id while the
        // proof still carries the original leaf digest.
        let (eh, _field, proof, ah) = valid_share();
        let tampered = aegis_mm_extension_field([0xEE; 32]);
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &tampered, &proof, &ah, &ctx),
            Err(ShareError::ProofLeafMismatch)
        ));
    }

    #[test]
    fn forged_proof_over_different_tree_fails_merkle() {
        // Internally consistent field+proof pair, but over a DIFFERENT
        // extension tree than the one the header's PoW committed to.
        let (eh, _field, _proof, _ah) = valid_share();
        let mut other = sample_aegis_header(easy_nbits());
        other.timestamp_ms += 1;
        let forged_field = aegis_mm_extension_field(other.id());
        let (_eh2, forged_proof) = share_with_field(&forged_field, None);
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &forged_field, &forged_proof, &other, &ctx),
            Err(ShareError::ProofInvalid)
        ));
    }

    #[test]
    fn wrong_key_field_rejected() {
        // Correctly proven field (steps 1-4 pass) whose key is not
        // AEGIS_MM_KEY — by definition not a commitment.
        let ah = sample_aegis_header(easy_nbits());
        let mut field = aegis_mm_extension_field(ah.id());
        field.key = [0x00, 0x77];
        let (eh, proof) = share_with_field(&field, None);
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::WrongKey { got: [0x00, 0x77] })
        ));
    }

    #[test]
    fn wrong_value_version_byte_rejected() {
        let ah = sample_aegis_header(easy_nbits());
        let mut field = aegis_mm_extension_field(ah.id());
        field.value[0] = 0x02;
        let (eh, proof) = share_with_field(&field, None);
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::ValueVersion { got: 0x02 })
        ));
    }

    #[test]
    fn wrong_value_length_rejected() {
        let ah = sample_aegis_header(easy_nbits());
        let mut field = aegis_mm_extension_field(ah.id());
        field.value.pop();
        let (eh, proof) = share_with_field(&field, None);
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::ValueLen { got: 32 })
        ));
    }

    #[test]
    fn presented_aegis_header_id_mismatch_rejected() {
        // Valid commitment for header A, but header B presented — the
        // id is recomputed from presented bytes, never trusted.
        let (eh, field, proof, ah) = valid_share();
        let mut other = ah;
        other.timestamp_ms += 1;
        let daa = daa_with_min(easy_nbits());
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &other, &ctx),
            Err(ShareError::AegisIdMismatch)
        ));
    }

    #[test]
    fn hard_target_share_pow_not_cleared() {
        // Aegis difficulty 2^200 → target ~2^56; the (unmined) real
        // nonce's hit cannot clear it. The DAA expects the same hard
        // value, so the failure isolates to step 6.
        let hard = difficulty_to_nbits(&(BigUint::from(1u8) << 200));
        let ah = sample_aegis_header(hard);
        let field = aegis_mm_extension_field(ah.id());
        let (eh, proof) = share_with_field(&field, None);
        let daa = daa_with_min(hard);
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::PowNotCleared { .. })
        ));
    }

    #[test]
    fn self_declared_easy_nbits_daa_mismatch_rejected() {
        // Share declares (and clears) difficulty 1, but the DAA expects
        // difficulty 2 — the self-declared-easy-target defense (§3).
        let (eh, field, proof, ah) = valid_share();
        let daa = daa_with_min(difficulty_to_nbits(&BigUint::from(2u8)));
        let ctx = ShareContext {
            follower_tip_height: eh.height,
            k_lag: K_LAG,
            daa: &daa,
            daa_view: &[],
        };
        assert!(matches!(
            verify_share(&eh, &field, &proof, &ah, &ctx),
            Err(ShareError::NbitsMismatch { .. })
        ));
    }

    #[test]
    fn witness_from_truncated_bytes_errors() {
        let (eh, field, proof, ah) = valid_share();
        let block = Block {
            header: ah,
            body: BlockBody::default(),
            coinbase: None,
        };
        let witness = ShareWitness {
            ergo_header: eh,
            field,
            proof,
            aegis_block_bytes: block.bytes(),
        };
        let bytes = witness.bytes().expect("witness serializes");
        assert!(ShareWitness::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn witness_with_trailing_garbage_errors() {
        let (eh, field, proof, ah) = valid_share();
        let block = Block {
            header: ah,
            body: BlockBody::default(),
            coinbase: None,
        };
        let witness = ShareWitness {
            ergo_header: eh,
            field,
            proof,
            aegis_block_bytes: block.bytes(),
        };
        let mut bytes = witness.bytes().expect("witness serializes");
        bytes.push(0x00);
        assert!(matches!(
            ShareWitness::from_bytes(&bytes),
            Err(WitnessDecodeError::TrailingBytes(1))
        ));
    }
}
