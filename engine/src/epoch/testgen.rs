//! Measurement / test scaffolding (behind `aux-pow`): build real aux-PoW
//! artifacts for the M-E1 guest measurement — a mined difficulty-1 share
//! committing a block's header id (E2), and a parent-linked Ergo header chain
//! committing a tip id (E4).
//!
//! This lives in the lib (not `#[cfg(test)]`) so the recursion crate's M-E1 dump
//! harness (a separate crate) can build a real epoch without re-plumbing the
//! Ergo primitives. It reads a real testnet header from `test-vectors/` as a
//! template, so it is scaffolding only — never linked into consensus or the
//! default build.

use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::autolykos::v2::check_pow_v2;
use ergo_crypto::difficulty::get_target;
use ergo_crypto::merkle::{extension_root, merkle_proof_by_indices};
use ergo_ser::autolykos::AutolykosSolution;
use ergo_ser::batch_merkle_proof::{BatchMerkleProof, ProofEntry, Side};
use ergo_ser::extension::ExtensionField;
use ergo_ser::header::serialize_header_without_pow;

use super::anchor::AnchorWitness;
use super::header_id::header_id;
use super::share::{ShareWitness, AEGIS_MM_KEY, MM_COMMITMENT_VERSION};
use super::types::SuffixBlock;

const MM_FIELD_VALUE_LEN: usize = 33;

/// The compact `sc_nbits` encoding of difficulty 1 — the target every M-E1
/// measurement block is mined at (so grinding finds a nonce cheaply).
pub fn diff1_nbits() -> u32 {
    ergo_ser::difficulty::encode_compact_bits(&num_bigint::BigUint::from(1u8))
}

fn template_header() -> ergo_ser::header::Header {
    let path = format!(
        "{}/../test-vectors/testnet/blocks/scala_block_442815.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let sblock: ergo_rest_json::types::ScalaFullBlock =
        serde_json::from_str(&raw).expect("block JSON parses");
    ergo_rest_json::decode_scala_header_struct(&sblock.header).expect("header decodes")
}

/// Build an Ergo candidate header whose extension commits `hn_id` under
/// `AEGIS_MM_KEY`, returning `(header, field, inclusion_proof)`.
fn commit_header(hn_id: [u8; 32]) -> (ergo_ser::header::Header, ExtensionField, BatchMerkleProof) {
    let mut eh = template_header();
    let mut value = Vec::with_capacity(MM_FIELD_VALUE_LEN);
    value.push(MM_COMMITMENT_VERSION);
    value.extend_from_slice(&hn_id);
    let field = ExtensionField {
        key: AEGIS_MM_KEY,
        value,
    };
    let fields: Vec<([u8; 2], Vec<u8>)> = vec![(field.key, field.value.clone())];
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
    let (indices, raw_proof) = merkle_proof_by_indices(&refs, &[0]).expect("proof builds");
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
    (eh, field, proof)
}

/// Mine a valid difficulty-1 aux-PoW share committing `header_id(chain_id,
/// block)` at `block.sc_nbits` — the E2 witness for one suffix reward block.
/// The block's `sc_nbits` MUST decode to difficulty 1 (else grinding may not
/// find a nonce in the bounded search).
pub fn mine_diff1_share(chain_id: u32, block: &SuffixBlock) -> ShareWitness {
    let hid = header_id(chain_id, block);
    let (mut eh, field, proof) = commit_header(hid);

    let target = get_target(block.sc_nbits);
    let msg = blake2b256(&serialize_header_without_pow(&eh).expect("serializes"));
    let pk = *eh.solution.pk();
    let nonce = (0u64..100_000)
        .map(|i| i.to_be_bytes())
        .find(|n| check_pow_v2(&msg, n, eh.height, eh.version, &target))
        .expect("a nonce clears difficulty-1");
    eh.solution = AutolykosSolution::V2 { pk, nonce };

    ShareWitness {
        ergo_header: eh,
        field,
        proof,
    }
}

/// Build a parent-linked Ergo header chain `[ergo_ref, …, H_anchor]` of length
/// `depth + 1`, where `H_anchor` (the last) extension-commits `anchored_hn_id`.
/// Returns `(witness, ergo_ref_id)` — the E4 anchor witness + the id the
/// PegVault would splice from `CONTEXT.headers`.
pub fn build_anchor_chain(anchored_hn_id: [u8; 32], depth: usize) -> (AnchorWitness, [u8; 32]) {
    let (anchor, anchor_field, anchor_proof) = commit_header(anchored_hn_id);
    let mut headers = vec![anchor];
    for i in 0..depth {
        let child_id = {
            let (_, id) = ergo_ser::header::serialize_header(&headers[0]).expect("serializes");
            *id.as_bytes()
        };
        let mut parent = template_header();
        parent.parent_id = ergo_primitives::digest::ModifierId::from(child_id);
        parent.height = 1000 + i as u32;
        headers.insert(0, parent);
    }
    let ergo_ref_id = {
        let (_, id) = ergo_ser::header::serialize_header(&headers[0]).expect("serializes");
        *id.as_bytes()
    };
    (
        AnchorWitness {
            headers,
            anchor_field,
            anchor_proof,
        },
        ergo_ref_id,
    )
}
