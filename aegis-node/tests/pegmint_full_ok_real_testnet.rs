//! THE peg-in capstone: `verify_pegmint` (and the composed
//! `verify_pegmint_full`) driven to a full **`Ok(PegMintEffect)`** on
//! 100% real Ergo-testnet chain data — the first green end-to-end
//! peg-in verification against a real lock→consolidation pair.
//!
//! The steps-5–9 e2e (`pegmint_steps_real_inclusion_e2e.rs`) stops at
//! `ReceiptNotConsumed` because at capture time the testnet had no
//! deployed peg. It does now (`test-vectors/testnet/peg/README.md`):
//!
//! - **LOCK#1** `bc7245…90eb` @ 443396 — DepositReceipt box at
//!   OUTPUTS(0): 100_000 tUSE base units, R4 = 33-byte sc_dest,
//!   node-reported boxId `b7fde1…6d13`.
//! - **CONSOLIDATION** `81015c…aa93` @ 443406 — spends that boxId at
//!   INPUTS(2) with the PegVault NFT at OUTPUTS(0).tokens(0) (the §5.4
//!   merge-vs-refund discriminator).
//!
//! ## Vectors (`test-vectors/testnet/peg-inclusion/`, all VERBATIM
//! node output from the Scala testnet node `127.0.0.1:9062`,
//! appVersion 6.0.3, captured 2026-07-13, nothing hand-edited)
//!
//! - `proof_m6_k10.json` — `GET /nipopow/proof/6/10` at tip 443665
//!   (`h_ref = 443665 − 10 = 443655 ≥ 443406`: both inclusions settle).
//! - `scala_headers_443396_443655.json` — dense
//!   `GET /blocks/chainSlice?fromHeight=443395&toHeight=443655`, the
//!   gap-free best-chain run rooting the follower AT the lock height
//!   and catching it up through `h_ref`.
//! - `scala_block_443396.json` / `scala_block_443406.json` — full
//!   `GET /blocks/{id}` for both inclusion blocks (v4, 3 txs each).
//! - `scala_proof_for_lock_443396.json` /
//!   `scala_proof_for_cons_443406.json` — the node's own
//!   `GET /blocks/{id}/proofFor/{txId}` merkle proofs.
//!
//! ## Oracle discipline
//!
//! No `expected = my_fn(input)`: every asserted quantity is a
//! node-produced byte string — tx ids from the block capture, the
//! receipt boxId from the node's own `outputs[0].boxId`, sc_dest from
//! the on-chain R4, roots from the PoW-committed `transactionsRoot`
//! (whose headers chain to the pinned testnet genesis through real
//! Autolykos PoW — the anti-fabrication oracle).
//!
//! ## Scala `proofFor` quirk on multi-tx blocks (honest note)
//!
//! On these 3-tx blocks the node's `proofFor/{txId}` does NOT return
//! the queried tx's own leaf: for the lock tx it does (leafData = the
//! lock txid), but for the consolidation tx it returns a proof for a
//! *witness* leaf (leafData = `blake2b256("")[1..]`, the shared
//! witness id of the block's all-empty-`proofBytes` txs). Both
//! responses are still genuine node-authored proofs over the same tree
//! — each reduces to its header's PoW-committed root — so they oracle
//! the two leaf rules the verifier relies on (§5.2.5 txid leaf,
//! witness-leaf non-confusion). The verifier never consumes them; it
//! builds its own single-leaf batch proof from the full block.

use aegis_node::ergo_follow::Follower;
use aegis_node::pegmint::{
    ergo_testnet_anchor, verify_ergo_chain_comparative, ComparativeAnchor, DifficultyParams,
    PegMintError,
};
use aegis_node::pegmint_steps::{
    read_pegmint_proof, serialize_pegmint_proof, verify_pegmint, verify_pegmint_full, PegMintProof,
    PegMintUsedSet, PegParams, TxInclusion, MAX_NIPOPOW_PROOF_BYTES,
};
use ergo_crypto::autolykos::common::blake2b256;
use ergo_crypto::merkle::merkle_proof_by_indices;
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
const PROOF_TIP: u32 = 443_665;
const N_MINT: u64 = 10;
const H_REF: u32 = PROOF_TIP - N_MINT as u32; // 443_655
const LOCK_HEIGHT: u32 = 443_396;
const CONS_HEIGHT: u32 = 443_406;
const LOCK_BLOCK_ID: &str = "c8dfdd69d3d4f14014a01219d1024d92a7277a00b85e2295fa83ab3e12d27ecc";
const CONS_BLOCK_ID: &str = "3bc2bd285a214216ceb07ca0001647099b917778019aac0c6c032e8331b46cca";
const LOCK_TX_ID: &str = "bc7245647bee2f242b118dae0094f594692afb7d7333967bf8d62884a07790eb";
const CONS_TX_ID: &str = "81015c1be5e50f3a4ac34f733b9bf70ba84488ca04a7c5e2f4b068e7fe8eaa93";
/// Index of the peg tx inside each captured block's tx list.
const LOCK_TX_INDEX: usize = 1;
const CONS_TX_INDEX: usize = 1;
/// The node-reported boxId of the lock's OUTPUTS(0) DepositReceipt
/// (`scala_block_443396.json` `outputs[0].boxId` — the used-set key
/// and rho seed the verifier must re-derive).
const RECEIPT_BOX_ID: &str = "b7fde121261d67cf8522013f2c8e131a5e41ae902132d52273331f9c73756d13";
/// The receipt's on-chain R4 payload (33-byte sc_dest; the register is
/// `0e21` ‖ this — secp256k1 G compressed, per the deploy README).
const SC_DEST: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const NOTE_VALUE: u64 = 100_000;
const RECEIPT_OUTPUT_INDEX: u16 = 0;
const RECEIPT_INPUT_INDEX: u16 = 2;

/// Real testnet deploy pins (`test-vectors/testnet/peg/README.md` +
/// `PegVault.injected.es`): tUSE stand-in token, PegVault singleton
/// NFT, blake2b256 of the deployed DepositReceipt tree, and the
/// vault's injected dummy FeePot hash + fee params (floor 1000 = 1
/// tUSE, 100 bps).
fn testnet_peg_params() -> PegParams {
    PegParams {
        use_token_id: hex32("006a33af9b295c830b1fe19422ede003da35a1c3a5f6ac56618e99ef2eaa2bab"),
        peg_vault_nft: hex32("006ad21fd48bc6676dab0e7b32df80b0d29119912bf9e9022f60eed844067307"),
        deposit_receipt_script_hash: hex32(
            "312466e0ed5660f4e36b182b6e754dd6db3f68edc000baf8a7512eab5a17f804",
        ),
        fee_pot_script_hash: hex32(
            "a09058ec9f7df6c4e79c8dc07640ff2e3ec7874577bb41ce0b0b23d0ed8a314d",
        ),
        peg_fee_floor: 1000,
        peg_fee_rate_bps: 100,
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hex::decode(s).expect("valid hex"));
    out
}

fn vector(rel: &str) -> String {
    let path = format!("{}/../test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path}: {e}"))
}

fn real_proof() -> NipopowProof {
    ergo_rest_json::decode_nipopow_proof_json(&vector("testnet/peg-inclusion/proof_m6_k10.json"))
        .expect("captured Scala proof JSON decodes")
}

/// The dense follower over the verbatim chainSlice capture (heights
/// 443396..=443655): rooted AT the lock height so the settled view
/// contains both inclusion headers, caught up through `h_ref`.
fn dense_follower() -> Follower {
    let dtos: Vec<ScalaHeader> = serde_json::from_str(&vector(
        "testnet/peg-inclusion/scala_headers_443396_443655.json",
    ))
    .expect("chainSlice array parses");
    let headers: Vec<Header> = dtos
        .iter()
        .map(|dto| {
            ergo_rest_json::decode_scala_header_struct(dto).expect("captured header decodes")
        })
        .collect();
    assert_eq!(headers.first().expect("nonempty").height, LOCK_HEIGHT);
    assert_eq!(headers.last().expect("nonempty").height, H_REF);
    let (_bytes, root_id) =
        ergo_ser::header::serialize_header(&headers[0]).expect("root serializes");
    let mut f = Follower::with_root(N_MINT, *root_id.as_bytes());
    for h in &headers {
        f.apply_header(h).expect("real header follows");
    }
    f
}

/// Real steps-1–4 verdict: the captured continuous proof against the
/// pinned testnet anchor and the real follower.
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

/// `(header, txs)` decoded from a verbatim full-block capture; each tx
/// is `(node_reported_id_hex, wire_bytes)` — the same read-shape →
/// input-shape bridge as the steps-5–9 e2e (Preserve keeps on-chain
/// bytes verbatim, the byte-fidelity oracle).
fn real_block(rel: &str) -> (Header, Vec<(String, Vec<u8>)>) {
    let block: ScalaFullBlock = serde_json::from_str(&vector(rel)).expect("block JSON parses");
    let header = ergo_rest_json::decode_scala_header_struct(&block.header).expect("header decodes");
    let txs = block
        .block_transactions
        .transactions
        .iter()
        .map(|tx| {
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

fn lock_block() -> (Header, Vec<(String, Vec<u8>)>) {
    real_block("testnet/peg-inclusion/scala_block_443396.json")
}

fn cons_block() -> (Header, Vec<(String, Vec<u8>)>) {
    real_block("testnet/peg-inclusion/scala_block_443406.json")
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

/// The block's leaves under the v2+ rule (tx ids ++ witness ids) and
/// the real batch inclusion proof for tx `i`.
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

/// The real, fully-populated peg-in proof for LOCK#1 → CONSOLIDATION.
fn real_pegmint_proof() -> PegMintProof {
    let (lh, ltxs) = lock_block();
    let (ch, ctxs) = cons_block();
    PegMintProof {
        work: real_proof(),
        lock: real_inclusion(&lh, &ltxs, LOCK_TX_INDEX),
        receipt_output_index: RECEIPT_OUTPUT_INDEX,
        consolidation: real_inclusion(&ch, &ctxs, CONS_TX_INDEX),
        receipt_input_index: RECEIPT_INPUT_INDEX,
    }
}

fn assert_capstone_effect(effect: &aegis_node::pegmint_steps::PegMintEffect) {
    assert_eq!(effect.note_value, NOTE_VALUE, "N = 100.000 tUSE");
    assert_eq!(hex::encode(effect.sc_dest), SC_DEST, "R4 sc_dest");
    assert_eq!(
        hex::encode(effect.box_id),
        RECEIPT_BOX_ID,
        "re-derived receipt boxId == the node-reported boxId"
    );
    assert_eq!(effect.rho_seed, effect.box_id, "rho seeds from the boxId");
    // §5.5/F2 min(): the lock paid nothing to a FeePot-scripted output,
    // so pot_credit = min(0, peg_fee(100_000) = max(1000, 1000)) = 0 —
    // and the mint still goes through.
    assert_eq!(effect.pot_credit, 0, "fee-less lock credits 0, still mints");
}

// ----- happy path -----

#[test]
fn pegmint_real_lock_and_consolidation_reach_full_ok() {
    // THE capstone: steps 1–9 all green on real chain data. h_ref
    // arithmetic: proof tip 443665 − N_mint 10 = 443655, and both
    // inclusions (443396, 443406) are ≤ h_ref, i.e. settled.
    let anchor = real_anchor();
    assert_eq!(anchor.h_ref, H_REF);
    // LOCK_HEIGHT < CONS_HEIGHT, so this settles BOTH inclusions.
    assert!(CONS_HEIGHT <= anchor.h_ref);
    let proof = real_pegmint_proof();
    let effect = verify_pegmint(
        &proof,
        &anchor,
        &PegMintUsedSet::new(),
        &testnet_peg_params(),
    )
    .expect("real testnet lock+consolidation pair mints");
    assert_capstone_effect(&effect);
}

#[test]
fn verify_pegmint_full_reaches_full_ok_on_real_pair() {
    // The composed steps-1–9 entry point (review P2): the anchor is
    // derived from proof.work INTERNALLY. Must emit the identical
    // effect as the split path above.
    let proof = real_pegmint_proof();
    let effect = verify_pegmint_full(
        &proof,
        &ergo_testnet_anchor(),
        &DifficultyParams::testnet(),
        N_MINT,
        &dense_follower(),
        &PegMintUsedSet::new(),
        &testnet_peg_params(),
    )
    .expect("composed full verifier mints on the real pair");
    assert_capstone_effect(&effect);
    let split = verify_pegmint(
        &proof,
        &real_anchor(),
        &PegMintUsedSet::new(),
        &testnet_peg_params(),
    )
    .expect("split path mints");
    assert_eq!(effect, split, "composed and split paths agree exactly");
}

// ----- round-trips -----

#[test]
fn real_full_ok_proof_envelope_roundtrips_within_caps() {
    // The first REAL fully-mintable proof also exercises the §5.1 wire
    // envelope: multi-tx-block inclusion proofs (3 sibling levels), a
    // ~real-size NiPoPoW part under the frozen 1 MiB cap.
    let proof = real_pegmint_proof();
    let work_bytes = ergo_ser::popow_proof::serialize_nipopow_proof(&proof.work).expect("work");
    assert!(
        work_bytes.len() <= MAX_NIPOPOW_PROOF_BYTES,
        "real proof {} B must fit the 1 MiB cap",
        work_bytes.len()
    );
    let bytes = serialize_pegmint_proof(&proof).expect("serializes under §5.6 caps");
    let parsed = read_pegmint_proof(&bytes).expect("envelope parses");
    assert_eq!(parsed, proof);
}

// ----- error paths -----

#[test]
fn pegmint_real_receipt_replay_rejects_already_minted() {
    // I2 on real data: after the first mint the receipt boxId is in
    // the used set — the same real proof must then reject.
    let anchor = real_anchor();
    let proof = real_pegmint_proof();
    let mut used = PegMintUsedSet::new();
    let effect = verify_pegmint(&proof, &anchor, &used, &testnet_peg_params()).expect("mints");
    assert!(used.insert(effect.box_id), "first insert is fresh");
    assert!(matches!(
        verify_pegmint(&proof, &anchor, &used, &testnet_peg_params()),
        Err(PegMintError::AlreadyMinted)
    ));
}

// ----- oracle parity -----

#[test]
fn real_blocks_txids_and_roots_match_node_and_pow_headers() {
    for ((header, txs), (block_id, height, peg_txid, peg_index)) in
        [lock_block(), cons_block()].into_iter().zip([
            (LOCK_BLOCK_ID, LOCK_HEIGHT, LOCK_TX_ID, LOCK_TX_INDEX),
            (CONS_BLOCK_ID, CONS_HEIGHT, CONS_TX_ID, CONS_TX_INDEX),
        ])
    {
        assert_eq!(header.height, height);
        assert_eq!(header.version, 4);
        // Re-derived header id == the pinned capture id (never trust a
        // carried id — same discipline as the verifier).
        let (_bytes, hid) = ergo_ser::header::serialize_header(&header).expect("serializes");
        assert_eq!(hex::encode(hid.as_bytes()), block_id);
        assert_eq!(txs.len(), 3, "pinned capture: three txs per block");
        assert_eq!(txs[peg_index].0, peg_txid, "node-reported peg txid");
        // Every recomputed txid == the node-reported id, and the v4
        // root over (tx ids ++ witness ids) == the PoW-committed
        // transactionsRoot.
        let parsed: Vec<Transaction> = txs.iter().map(|(_, b)| parse_tx(b)).collect();
        let mut leaves: Vec<Vec<u8>> = Vec::new();
        for (tx, (node_id, _)) in parsed.iter().zip(txs.iter()) {
            let txid = transaction_id(tx).expect("txid");
            assert_eq!(&hex::encode(txid.as_bytes()), node_id);
            leaves.push(txid.as_bytes().to_vec());
        }
        leaves.extend(parsed.iter().map(witness_leaf));
        let refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let root = ergo_crypto::merkle::merkle_tree_root(&refs);
        assert_eq!(&root, header.transactions_root.as_bytes());
    }
}

/// Fold a node `proofFor` response (leafData + `[digest, side]`
/// levels) to a root with the scorex rules (leaf = `H(0x00‖data)`,
/// node = `H(0x01‖l‖r)`, side 0 = computed hash on the left).
fn reduce_node_proof(v: &serde_json::Value) -> [u8; 32] {
    let leaf = hex::decode(v["leafData"].as_str().expect("leafData")).expect("hex");
    let mut pre = vec![0x00];
    pre.extend_from_slice(&leaf);
    let mut cur = blake2b256(&pre);
    for level in v["levels"].as_array().expect("levels") {
        let sibling = hex::decode(level[0].as_str().expect("digest hex")).expect("hex");
        let mut pre = vec![0x01];
        if level[1].as_u64() == Some(0) {
            pre.extend_from_slice(&cur);
            pre.extend_from_slice(&sibling);
        } else {
            pre.extend_from_slice(&sibling);
            pre.extend_from_slice(&cur);
        }
        cur = blake2b256(&pre);
    }
    cur
}

#[test]
fn node_proof_for_lock_oracles_txid_leaf_rule() {
    // The node's own inclusion proof for the LOCK tx pins the §5.2.5
    // leaf rule on a REAL multi-tx block: the leaf preimage is exactly
    // the txid, and the node's sibling path reduces to the
    // PoW-committed root.
    let v: serde_json::Value = serde_json::from_str(&vector(
        "testnet/peg-inclusion/scala_proof_for_lock_443396.json",
    ))
    .expect("proofFor parses");
    assert_eq!(v["leafData"].as_str().expect("leafData"), LOCK_TX_ID);
    let (header, _) = lock_block();
    assert_eq!(&reduce_node_proof(&v), header.transactions_root.as_bytes());
}

#[test]
fn node_proof_for_cons_returns_witness_leaf_but_oracles_the_tree() {
    // Scala quirk (module docs): querying proofFor for the
    // consolidation txid returns a proof for a WITNESS leaf instead —
    // leafData is the 31-byte `blake2b256("")[1..]` shared by this
    // block's all-empty-proofBytes txs. Still a genuine node-authored
    // proof over the same tree: it reduces to the PoW-committed root,
    // oracle-ing the witness-leaf rule the verifier's leaf-binding
    // relies on (a 31-byte preimage can never equal a 32-byte txid
    // leaf without a Blake2b256 collision).
    let v: serde_json::Value = serde_json::from_str(&vector(
        "testnet/peg-inclusion/scala_proof_for_cons_443406.json",
    ))
    .expect("proofFor parses");
    let leaf = v["leafData"].as_str().expect("leafData");
    assert_eq!(leaf.len(), 62, "31-byte witness preimage");
    assert_eq!(leaf, hex::encode(&blake2b256(&[])[1..]));
    let (header, ctxs) = cons_block();
    let cons = parse_tx(&ctxs[CONS_TX_INDEX].1);
    assert_eq!(
        leaf,
        hex::encode(witness_leaf(&cons)),
        "the consolidation's own witness id (all proofs empty)"
    );
    assert_eq!(&reduce_node_proof(&v), header.transactions_root.as_bytes());
}
