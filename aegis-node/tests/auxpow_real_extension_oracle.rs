//! Real-Ergo-block oracle for the aux-PoW machinery (merge-mining.md
//! §2.3 / M2a): every primitive the share verifier composes —
//! extension leaf encoding, extension merkle tree, batch-merkle proof
//! reduction, PoW message, Autolykos v2 threshold — is pinned against
//! a REAL testnet block whose commitments were produced by the Scala
//! reference node and sealed by real proof-of-work.
//!
//! ## Vector (verbatim node output, nothing hand-edited)
//!
//! `test-vectors/testnet/blocks/scala_block_442815.json` — the full
//! `GET /blocks/{id}` response for testnet block 442815 (header id
//! `26cb1be1…5471`, v4, Autolykos v2, 14 interlink extension fields),
//! Scala testnet node (`arks-testnet-node` 6.0.3, `127.0.0.1:9062`),
//! captured 2026-07-13 — the same capture the pegmint e2e pins.
//!
//! ## Oracle discipline
//!
//! Expected values are the real header's PoW-committed digests
//! (`extension_root`, `n_bits`) and the node's own field bytes — never
//! `expected = my_fn(input)`. What IS my_fn-vs-my_fn (the
//! leaf-digest equality inside `real_field_batch_proofs…`) is labeled
//! as the self-consistency half of an assertion whose other half is
//! root-anchored.
//!
//! ## Honest scope
//!
//! No real Ergo block carries an `AEGIS_MM_KEY` field yet, so the
//! commitment-specific path (key/value decode, id binding, DAA check)
//! is exercised structurally in `src/auxpow.rs` tests over this same
//! real header; here the real-data composition is driven as far as
//! reality allows — through steps 1–4 on wholly real bytes
//! (`real_interlink_field_rejects…`).

use aegis_node::auxpow::{kv_to_leaf, verify_share, ShareContext, ShareError};
use aegis_node::daa::{difficulty_to_nbits, DaaParams};
use aegis_node::Header as AegisHeader;
use aegis_spec::K_LAG;
use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_crypto::merkle::{extension_root, merkle_proof_by_indices};
use ergo_crypto::pow::verify_pow_solution;
use ergo_rest_json::types::ScalaFullBlock;
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::batch_merkle_proof::{BatchMerkleProof, ProofEntry, Side};
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::{serialize_header_without_pow, Header};
use ergo_validation::popow::verify_batch_merkle_proof;
use num_bigint::BigUint;

// ----- helpers -----

/// Pinned capture identity — a silently re-captured vector fails
/// loudly instead of shifting every assertion.
const H_REF: u32 = 442_815;
const FIELD_COUNT: usize = 14;

fn vector(rel: &str) -> String {
    let path = format!("{}/../test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

/// Real header + verbatim extension fields from the capture.
fn real_block_parts() -> (Header, Vec<ExtensionField>) {
    let block: ScalaFullBlock =
        serde_json::from_str(&vector("testnet/blocks/scala_block_442815.json"))
            .expect("block JSON parses");
    let header = ergo_rest_json::decode_scala_header_struct(&block.header).expect("header decodes");
    let fields = block
        .extension
        .fields
        .iter()
        .map(|kv| ExtensionField {
            key: hex::decode(&kv[0])
                .expect("key hex")
                .try_into()
                .expect("2-byte key"),
            value: hex::decode(&kv[1]).expect("value hex"),
        })
        .collect();
    (header, fields)
}

/// Batch proof for field `idx` over the real extension's kvToLeaf tree.
fn proof_for(fields: &[ExtensionField], idx: u32) -> BatchMerkleProof {
    let leaves: Vec<Vec<u8>> = fields.iter().map(kv_to_leaf).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let (indices, raw) = merkle_proof_by_indices(&refs, &[idx]).expect("proof builds");
    BatchMerkleProof {
        indices,
        proofs: raw
            .into_iter()
            .map(|e| ProofEntry {
                digest: e.digest,
                side: Side::from_byte(e.side),
            })
            .collect(),
    }
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

// ----- oracle parity -----

#[test]
fn real_extension_root_recomputes_to_pow_committed_root() {
    // THE leaf-encoding oracle: rebuild the extension merkle root from
    // the node's verbatim key-value fields using kvToLeaf =
    // [2] ‖ key ‖ value; it must equal the real header's
    // extension_root, which the block's real PoW sealed. A wrong leaf
    // encoding, tree shape, or prefix byte cannot pass this.
    let (header, fields) = real_block_parts();
    assert_eq!(header.height, H_REF);
    assert_eq!(fields.len(), FIELD_COUNT, "pinned capture: 14 fields");
    let pairs: Vec<(&[u8], &[u8])> = fields.iter().map(|f| (&f.key[..], &f.value[..])).collect();
    assert_eq!(
        extension_root(&pairs),
        *header.extension_root.as_bytes(),
        "recomputed extension root must equal the PoW-committed root"
    );
}

#[test]
fn real_field_batch_proofs_verify_against_pow_committed_root() {
    // Every real field's single-leaf batch proof must reduce to the
    // real (PoW-committed) extension_root — the exact reduction the
    // share verifier's step 4 runs. The leaf-digest equality below is
    // the self-consistency half (kv_to_leaf + 0x00 prefix vs the proof
    // builder); its correctness is anchored by the root equality, whose
    // expected value is the node's.
    let (header, fields) = real_block_parts();
    let root = header.extension_root.as_bytes();
    for idx in 0..fields.len() as u32 {
        let proof = proof_for(&fields, idx);
        assert_eq!(proof.indices.len(), 1);
        let leaf = kv_to_leaf(&fields[idx as usize]);
        let mut pre = vec![0x00];
        pre.extend_from_slice(&leaf);
        assert_eq!(
            proof.indices[0].1,
            blake2b256(&pre),
            "field {idx}: proof leaf digest == blake2b256(0x00 ‖ kvToLeaf)"
        );
        assert!(
            verify_batch_merkle_proof(&proof, root),
            "field {idx}: proof must reduce to the PoW-committed root"
        );
    }
}

#[test]
fn real_header_pow_verifies_own_easier_and_not_harder_targets() {
    // Dual-threshold soundness on a REAL solution: the same
    // (msg, nonce) pair that cleared Ergo's own target must clear any
    // easier target and fail an impossibly hard one — the hit is
    // target-independent, which is what makes one hash serve two
    // chains.
    let (header, _fields) = real_block_parts();
    verify_pow_solution(&header).expect("real header PoW verifies against its own nBits");

    let msg = blake2b256(&serialize_header_without_pow(&header).expect("serializes"));
    let nonce = match &header.solution {
        AutolykosSolution::V2 { nonce, .. } => *nonce,
        other => panic!("capture must be Autolykos v2, got {other:?}"),
    };
    let own_target = get_target(header.n_bits);
    assert!(
        check_pow_v2(&msg, &nonce, header.height, header.version, &own_target),
        "explicit check against own target"
    );
    let easier = &own_target * BigUint::from(1024u32);
    assert!(
        check_pow_v2(&msg, &nonce, header.height, header.version, &easier),
        "same hit must clear an easier (larger) target"
    );
    let impossibly_hard = BigUint::from(1u8);
    assert!(
        !check_pow_v2(
            &msg,
            &nonce,
            header.height,
            header.version,
            &impossibly_hard
        ),
        "same hit must fail an impossibly hard target"
    );
}

// ----- error paths -----

#[test]
fn real_interlink_field_rejects_as_commitment_at_key_check() {
    // Drive verify_share as far as wholly-real data allows: real
    // header, real interlinks field, real proof against the real
    // PoW-committed root. Steps 1-4 must PASS; step 5 must reject the
    // field because its key is not AEGIS_MM_KEY — reaching exactly
    // WrongKey proves the whole real-data prefix of the pipeline.
    let (header, fields) = real_block_parts();
    let proof = proof_for(&fields, 0);
    let daa = DaaParams {
        target_secs: 15,
        window: 90,
        min_difficulty_nbits: difficulty_to_nbits(&BigUint::from(1u8)),
    };
    let ah = sample_aegis_header(daa.min_difficulty_nbits);
    let ctx = ShareContext {
        follower_tip_height: header.height,
        k_lag: K_LAG,
        daa: &daa,
        daa_view: &[],
    };
    let got = verify_share(&header, &fields[0], &proof, &ah, &ctx);
    assert!(
        matches!(got, Err(ShareError::WrongKey { got }) if got == fields[0].key),
        "must fail at the key check (steps 1-4 passed on real bytes), got {got:?}"
    );
}

#[test]
fn tampered_real_field_value_fails_leaf_binding() {
    // Flip one byte of the claimed field: the proof (still carrying
    // the real leaf digest) can no longer be bound to it.
    let (header, fields) = real_block_parts();
    let proof = proof_for(&fields, 0);
    let mut tampered = fields[0].clone();
    tampered.value[0] ^= 0x01;
    let daa = DaaParams {
        target_secs: 15,
        window: 90,
        min_difficulty_nbits: difficulty_to_nbits(&BigUint::from(1u8)),
    };
    let ah = sample_aegis_header(daa.min_difficulty_nbits);
    let ctx = ShareContext {
        follower_tip_height: header.height,
        k_lag: K_LAG,
        daa: &daa,
        daa_view: &[],
    };
    assert!(matches!(
        verify_share(&header, &tampered, &proof, &ah, &ctx),
        Err(ShareError::ProofLeafMismatch)
    ));
}
