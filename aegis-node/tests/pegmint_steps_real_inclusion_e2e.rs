//! PegMint steps 5–9 e2e over ONLY real testnet data — the two
//! tx-inclusion claims of `verify_pegmint` run through the REAL
//! steps-1–4 `ComparativeAnchor` (real NiPoPoW proof + real dense
//! checkpoint-rooted follower), with every hash oracled against the
//! live Scala node's own output.
//!
//! ## Vectors (all VERBATIM node output, nothing hand-edited)
//!
//! - `test-vectors/testnet/nipopow/proof_m6_k10.json` +
//!   `scala_headers_442813_442815.json` — the existing steps-1–4 e2e
//!   captures (tip 442825, `h_ref = 442815`).
//! - `test-vectors/testnet/blocks/scala_block_442815.json` — the full
//!   `GET /blocks/{id}` response for the block AT `h_ref` (height
//!   442815, header id `26cb1be1…5471`, v4, one tx), Scala testnet
//!   node (`arks-testnet-node` 6.0.3, `127.0.0.1:9062`), captured
//!   2026-07-13.
//! - `test-vectors/testnet/blocks/scala_proof_for_tx_442815.json` —
//!   the node's own `GET /blocks/{id}/proofFor/{txId}` for that tx:
//!   the node-authored merkle inclusion proof (leaf preimage + sibling
//!   levels), same capture.
//!
//! ## Oracle discipline
//!
//! Every quantity the verifier recomputes is pinned against the node:
//! the tx id (node-reported `id`), the leaf preimage (node `proofFor
//! .leafData`), the witness-leaf sibling (node `proofFor.levels[0]`),
//! and the tree root (the PoW-committed `transactionsRoot` of the real
//! header). No `expected = my_fn(input)` assertions — expectations are
//! node-produced bytes.
//!
//! ## Honest scope
//!
//! The testnet has no USE token (params.md stand-in TBD), so no real
//! lock→consolidation pair exists yet: the steps 6b–9 receipt content
//! path is exercised by the synthetic-but-real-algorithm unit suite in
//! `pegmint_steps.rs`. Here, `verify_pegmint` reaching
//! `ReceiptNotConsumed` on the real pair proves steps 0, 5a, 5b and 6a
//! all passed on real bytes through the real settled view.

use aegis_node::ergo_follow::Follower;
use aegis_node::pegmint::{
    ergo_testnet_anchor, verify_ergo_chain_comparative, ComparativeAnchor, DifficultyParams,
    InclusionRole, PegMintError,
};
use aegis_node::pegmint_steps::{
    read_pegmint_proof, serialize_pegmint_proof, verify_pegmint, PegMintProof, PegMintUsedSet,
    PegParams, TxInclusion, MAX_NIPOPOW_PROOF_BYTES,
};
use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::merkle::{merkle_proof_by_indices, merkle_tree_root, tx_leaf_digest};
use ergo_primitives::reader::VlqReader;
use ergo_rest_json::decode::{decode_scala_transaction_with_mode, DecodeMode};
use ergo_rest_json::types::{ScalaFullBlock, ScalaHeader, ScalaOutputInput, ScalaTransactionInput};
use ergo_ser::batch_merkle_proof::{BatchMerkleProof, ProofEntry, Side};
use ergo_ser::header::Header;
use ergo_ser::popow_proof::NipopowProof;
use ergo_ser::transaction::{read_transaction, transaction_id, Transaction};

// ----- helpers -----

/// Pinned capture identities — a silently re-captured vector fails
/// loudly instead of shifting every assertion.
const H_REF: u32 = 442_815;
const N_MINT: u64 = 10;
const BLOCK_ID: &str = "26cb1be1c7bb654ab013d3a87d7dd997f04b6f82aa4f233f2af550135e545471";
const TX_ID: &str = "383059cf7b65313cbf7b75e5f25606f9ed7a4a305cc28e6de6e15278b46470d6";

fn vector(rel: &str) -> String {
    let path = format!("{}/../test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn real_proof() -> NipopowProof {
    ergo_rest_json::decode_nipopow_proof_json(&vector("testnet/nipopow/proof_m6_k10.json"))
        .expect("captured Scala proof JSON decodes")
}

/// The dense checkpoint-rooted follower over the verbatim chainSlice
/// capture (heights 442813..=442815) — same construction as the
/// steps-1–4 e2e (root pinned to the proof's last prefix superblock).
fn dense_follower() -> Follower {
    let dtos: Vec<ScalaHeader> =
        serde_json::from_str(&vector("testnet/nipopow/scala_headers_442813_442815.json"))
            .expect("chainSlice array parses");
    let headers: Vec<Header> = dtos
        .iter()
        .map(|dto| {
            ergo_rest_json::decode_scala_header_struct(dto).expect("captured header decodes")
        })
        .collect();
    let (_bytes, root_id) =
        ergo_ser::header::serialize_header(&headers[0]).expect("root serializes");
    let mut f = Follower::with_root(N_MINT, *root_id.as_bytes());
    for h in &headers {
        f.apply_header(h).expect("real header follows");
    }
    f
}

/// Real steps-1–4 verdict: the captured proof against the pinned
/// testnet anchor and the real follower.
fn real_anchor() -> ComparativeAnchor {
    verify_ergo_chain_comparative(
        &real_proof(),
        &ergo_testnet_anchor(),
        &DifficultyParams::testnet(),
        N_MINT,
        &dense_follower(),
    )
    .expect("real continuous proof accepts")
}

/// `(header, txs)` decoded from the verbatim full-block capture; each
/// tx is `(node_reported_id_hex, wire_bytes)`.
fn real_block() -> (Header, Vec<(String, Vec<u8>)>) {
    let block: ScalaFullBlock =
        serde_json::from_str(&vector("testnet/blocks/scala_block_442815.json"))
            .expect("block JSON parses");
    let header = ergo_rest_json::decode_scala_header_struct(&block.header).expect("header decodes");
    let txs = block
        .block_transactions
        .transactions
        .iter()
        .map(|tx| {
            // Same read-shape → input-shape bridge the repo's own
            // block decode path uses; Preserve keeps on-chain bytes
            // verbatim (byte-fidelity oracle).
            let tx_input = ScalaTransactionInput {
                inputs: tx.inputs.clone(),
                data_inputs: tx.data_inputs.clone(),
                outputs: tx
                    .outputs
                    .iter()
                    .map(|o| ScalaOutputInput {
                        value: o.value,
                        ergo_tree: o.ergo_tree.clone(),
                        assets: o.assets.clone(),
                        creation_height: o.creation_height,
                        additional_registers: o.additional_registers.clone(),
                    })
                    .collect(),
            };
            let bytes = decode_scala_transaction_with_mode(&tx_input, DecodeMode::Preserve)
                .expect("captured tx decodes to wire bytes");
            (tx.id.clone(), bytes)
        })
        .collect();
    (header, txs)
}

fn parse_tx(bytes: &[u8]) -> Transaction {
    let mut r = VlqReader::new(bytes);
    let tx = read_transaction(&mut r).expect("tx wire bytes parse");
    assert!(r.is_empty(), "no trailing bytes");
    tx
}

/// v2+ witness leaf: `blake2b256(concat input proofs)[1..]` (31 bytes).
fn witness_leaf(tx: &Transaction) -> Vec<u8> {
    let mut all = Vec::new();
    for i in &tx.inputs {
        all.extend_from_slice(&i.spending_proof.proof);
    }
    blake2b256(&all)[1..].to_vec()
}

/// The real block's leaves under the v2+ rule (tx ids ++ witness ids)
/// and the real batch inclusion proof for tx `i`.
fn real_inclusion(header: &Header, txs: &[(String, Vec<u8>)], i: usize) -> TxInclusion {
    let parsed: Vec<Transaction> = txs.iter().map(|(_, b)| parse_tx(b)).collect();
    let mut leaves: Vec<Vec<u8>> = parsed
        .iter()
        .map(|t| transaction_id(t).expect("txid").as_bytes().to_vec())
        .collect();
    leaves.extend(parsed.iter().map(witness_leaf));
    let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
    let (indices, proofs) = merkle_proof_by_indices(&refs, &[i as u32]).expect("index in range");
    TxInclusion {
        header: header.clone(),
        tx_bytes: txs[i].1.clone(),
        proof: BatchMerkleProof {
            indices,
            proofs: proofs
                .into_iter()
                .map(|e| ProofEntry {
                    digest: e.digest,
                    side: Side::from_byte(e.side),
                })
                .collect(),
        },
    }
}

/// Placeholder deploy pins — the testnet has no USE token yet, so no
/// real tx can satisfy steps 6b–7; these values only need to be
/// *defined* for the composed calls below (which are expected to stop
/// at `ReceiptNotConsumed`).
fn placeholder_params() -> PegParams {
    PegParams {
        use_token_id: [0xAA; 32],
        peg_vault_nft: [0xBB; 32],
        deposit_receipt_script_hash: [0xCC; 32],
        fee_pot_script_hash: [0xDD; 32],
        peg_fee_floor: 100,
        peg_fee_rate_bps: 100,
    }
}

fn real_pegmint_proof() -> PegMintProof {
    let (header, txs) = real_block();
    let incl = real_inclusion(&header, &txs, 0);
    PegMintProof {
        work: real_proof(),
        lock: incl.clone(),
        receipt_output_index: 0,
        consolidation: incl,
        receipt_input_index: 0,
    }
}

// ----- oracle parity -----

#[test]
fn real_block_txid_and_root_match_node_and_pow_header() {
    let (header, txs) = real_block();
    assert_eq!(header.height, H_REF);
    // Re-derived header id == the pinned capture id (never trust a
    // carried id — same discipline as the verifier).
    let (_bytes, hid) = ergo_ser::header::serialize_header(&header).expect("header serializes");
    assert_eq!(hex::encode(hid.as_bytes()), BLOCK_ID);
    assert_eq!(txs.len(), 1, "pinned capture: one tx at 442815");
    assert_eq!(txs[0].0, TX_ID);
    // Recomputed txid == node-reported id.
    let tx = parse_tx(&txs[0].1);
    let txid = transaction_id(&tx).expect("txid");
    assert_eq!(hex::encode(txid.as_bytes()), TX_ID);
    // v4 block: root over (tx ids ++ witness ids) == the PoW-committed
    // transactionsRoot of the real header.
    assert_eq!(header.version, 4);
    let wid = witness_leaf(&tx);
    let root = merkle_tree_root(&[txid.as_bytes(), &wid]);
    assert_eq!(&root, header.transactions_root.as_bytes());
}

#[test]
fn node_proof_for_tx_oracles_leaf_rule_and_witness_sibling() {
    // The node's own inclusion proof for this tx pins BOTH rules the
    // verifier relies on: the leaf preimage is the txid (§5.2.5), and
    // the single sibling is the hashed witness leaf (witness-leaf
    // non-confusion, §5.2 note).
    let v: serde_json::Value =
        serde_json::from_str(&vector("testnet/blocks/scala_proof_for_tx_442815.json"))
            .expect("proofFor parses");
    assert_eq!(v["leafData"].as_str().expect("leafData"), TX_ID);
    let (_, txs) = real_block();
    let tx = parse_tx(&txs[0].1);
    let mut wid32 = [0u8; 32];
    // tx_leaf_digest takes the 32-byte tx id; the witness sibling is a
    // LEAF over the 31-byte witness id, so hash it via the same scorex
    // rule reconstructed explicitly (0x00 ‖ preimage).
    let wid = witness_leaf(&tx);
    let mut pre = vec![0x00];
    pre.extend_from_slice(&wid);
    wid32.copy_from_slice(&blake2b256(&pre));
    assert_eq!(
        v["levels"][0][0].as_str().expect("sibling hex"),
        hex::encode(wid32),
        "node's sibling == leaf-hash of the recomputed witness id"
    );
    assert_eq!(
        v["levels"][0][1].as_u64(),
        Some(0),
        "computed hash on the left"
    );
    // And the verifier-side leaf digest rule on the tx side matches the
    // node's leaf preimage.
    let txid = transaction_id(&tx).expect("txid");
    let mut pre = vec![0x00];
    pre.extend_from_slice(txid.as_bytes());
    assert_eq!(tx_leaf_digest(txid.as_bytes()), blake2b256(&pre));
}

// ----- happy path -----

#[test]
fn real_inclusions_pass_through_real_comparative_anchor() {
    // Fully real composition: real NiPoPoW work → real ComparativeAnchor
    // (h_ref = 442815) → both inclusion claims (real header AT h_ref,
    // real tx bytes, real merkle proof) verify; the first tx-content
    // check (6b consumption) then correctly rejects because the real
    // coinbase does not spend its own output. Reaching EXACTLY
    // ReceiptNotConsumed proves steps 0, 5a, 5b, 6a all passed on real
    // bytes.
    let anchor = real_anchor();
    assert_eq!(anchor.h_ref, H_REF);
    let proof = real_pegmint_proof();
    assert!(matches!(
        verify_pegmint(
            &proof,
            &anchor,
            &PegMintUsedSet::new(),
            &placeholder_params()
        ),
        Err(PegMintError::ReceiptNotConsumed)
    ));
}

#[test]
fn verify_pegmint_full_composes_steps_1_9_on_real_data() {
    // The composed entry point (review P2): steps 1–4 are derived from
    // `proof.work` INTERNALLY (not a caller-supplied anchor), then steps
    // 5–9 run against exactly that anchor. On the real pair this must
    // reach the SAME boundary as the split call above — proving the
    // structural binding threads through identically. A follower NOT
    // caught up to H_ref would instead defer (NotCaughtUp); here the
    // dense follower is caught up, so we reach 6b's ReceiptNotConsumed.
    let proof = real_pegmint_proof();
    let follower = dense_follower();
    let result = aegis_node::pegmint_steps::verify_pegmint_full(
        &proof,
        &ergo_testnet_anchor(),
        &DifficultyParams::testnet(),
        N_MINT,
        &follower,
        &PegMintUsedSet::new(),
        &placeholder_params(),
    );
    assert!(
        matches!(result, Err(PegMintError::ReceiptNotConsumed)),
        "composed full verifier must reach the same real-data boundary as the split path, got {result:?}"
    );
}

// ----- round-trips -----

#[test]
fn real_pegmint_proof_envelope_roundtrips_within_caps() {
    let proof = real_pegmint_proof();
    let bytes = serialize_pegmint_proof(&proof).expect("real proof serializes under §5.6 caps");
    // §5.6 note: measure the real continuous proof against the frozen
    // NiPoPoW cap.
    let work_bytes = ergo_ser::popow_proof::serialize_nipopow_proof(&proof.work).expect("work");
    assert!(
        work_bytes.len() <= MAX_NIPOPOW_PROOF_BYTES,
        "real proof {} B must fit the 1 MiB cap",
        work_bytes.len()
    );
    let parsed = read_pegmint_proof(&bytes).expect("envelope parses");
    assert_eq!(parsed, proof);
}

// ----- error paths -----

#[test]
fn real_suffix_smuggle_rejects_at_h_ref_boundary() {
    // P1-A on real data: with N_mint = 11 the settled boundary moves to
    // 442814, so the SAME real block-442815 inclusion is now above
    // h_ref → InclusionNotSettled. This is the exact anti-suffix-
    // smuggle contract steps 5–9 must enforce.
    let anchor = verify_ergo_chain_comparative(
        &real_proof(),
        &ergo_testnet_anchor(),
        &DifficultyParams::testnet(),
        N_MINT + 1,
        &dense_follower(),
    )
    .expect("comparative path accepts at deeper n_mint");
    assert_eq!(anchor.h_ref, H_REF - 1);
    let proof = real_pegmint_proof();
    assert!(matches!(
        verify_pegmint(
            &proof,
            &anchor,
            &PegMintUsedSet::new(),
            &placeholder_params()
        ),
        Err(PegMintError::InclusionNotSettled {
            role: InclusionRole::Lock,
            height: H_REF
        })
    ));
}
