//! Integration tests for the wallet's node client + scan + self-transfer,
//! driven against a REAL node: its `Chain`, `ShieldedState`, `SeedCore`,
//! mempool, and the loopback `ApiServer`. These node crates are
//! dev-dependencies only — the shipped wallet never links them.
//!
//! Two scenes:
//! - `produced_chain_*`: authentic node-produced coinbase blocks; the
//!   wallet's tree rebuild is cross-checked against the node's own root.
//! - `self_transfer_*`: the wallet's own notes are placed on a served
//!   block, scanned, consolidated into a real proof, submitted, and the
//!   spend confirmed via the nullifier endpoint.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use aegis_crypto::note::{note_cm_bytes, EvenScalar};
use aegis_node::{
    AdmissionView, ApiServer, ApiState, Block, BlockBody, Chain, Mempool, NodeStatus, PowMode,
    ProofMode, RewardMode, SeedCore, ShieldedState,
};
use aegis_types::{Header, ShieldedOutput, ShieldedTransfer};
use aegis_wallet::{consolidate, NodeClient, SpendingKey, WalletState};
use num_bigint::BigUint;
use rand::SeedableRng;

const FEE: u64 = 10; // Network::Dev sc_tx_fee

fn dev_params() -> &'static aegis_spec::NetworkParams {
    aegis_spec::Network::Dev.params()
}

/// A `NodeStatus` reflecting the real shielded state (the fields the
/// wallet reads: height, root, leaf count, nullifiers), the rest filled
/// plausibly.
fn status_from(height: u64, tip: [u8; 32], timestamp_ms: u64, state: &ShieldedState) -> NodeStatus {
    NodeStatus {
        network_name: "aegis-dev",
        canonical_tip: tip,
        canonical_height: height,
        tip_timestamp_ms: timestamp_ms,
        next_sc_nbits: 0x0100_0000,
        median_time_past: timestamp_ms,
        cumulative_work: BigUint::from(height + 1),
        pending_hostile_work: BigUint::ZERO,
        ergo_tip_height: None,
        tip_is_final: false,
        l_final: 0,
        pot: state.pot(),
        nullifier_digest: state.nullifier_digest(),
        cm_tree_root: state.cm_tree_root(),
        leaf_count: state.leaf_count(),
        nullifiers: Arc::new(state.nullifiers().clone()),
        mempool_size: 0,
        mempool_txs: Arc::new(Vec::new()),
    }
}

// ----- produced-chain scene: real node blocks, tree-rebuild parity -----

#[test]
fn produced_chain_client_reads_and_scan_matches_node_root() {
    // Produce a handful of authentic coinbase blocks so the chain has
    // real note-commitment leaves.
    let mut chain = Chain::new(
        aegis_spec::Network::Dev,
        PowMode::DevStub,
        ProofMode::DevStub,
    );
    let mut core = SeedCore::new(aegis_spec::Network::Dev);
    for h in 0..4u64 {
        let ts = chain.tip().timestamp_ms + 15_000;
        let tag = EvenScalar::from(0x100 + h);
        let blinding = EvenScalar::from(0x200 + h);
        let block = chain
            .produce_next_with_coinbase(BlockBody::default(), ts, tag, blinding)
            .expect("produce coinbase block");
        chain.try_extend(block.clone(), ts).expect("extend");
        core.record_canonical(&block);
    }
    let height = chain.tip().height;
    let status = status_from(
        height,
        chain.tip().id(),
        chain.tip().timestamp_ms,
        chain.state(),
    );
    let node_root = chain.state().cm_tree_root();
    let node_leaves = chain.state().leaf_count();

    let state = ApiState::new(
        status,
        Arc::new(RwLock::new(core)),
        Arc::new(RwLock::new(Mempool::new())),
        AdmissionView::new(Arc::new(Vec::new()), Arc::new(BTreeSet::new()), FEE),
    );
    let server = ApiServer::spawn("127.0.0.1:0", state).expect("spawn");
    let client = NodeClient::new(server.base_url()).expect("client");

    // Client endpoints decode correctly.
    let tip = client.tip().expect("tip");
    assert_eq!(tip.height, height);
    assert_eq!(tip.id, chain.tip().id());
    let chain_state = client.state().expect("state");
    assert_eq!(chain_state.leaf_count, node_leaves as u64);
    assert_eq!(chain_state.cm_tree_root, node_root);

    let page = client.blocks(1, 100).expect("blocks");
    assert_eq!(page.tip_height, height);
    assert_eq!(page.blocks.len(), height as usize);
    // block(id) and block_at(height) both decode.
    let by_id = client.block(&page.blocks[0].id).expect("block by id");
    assert_eq!(by_id.header.height, page.blocks[0].height);
    assert!(client.block_at(height).expect("block_at").is_some());
    assert!(client.block_at(height + 1).expect("past tip").is_none());

    // The wallet rebuilds the SAME tree the node did: scan's internal
    // parity check would error on any divergence, and the leaf count and
    // computed root must match the node's authoritative values.
    let sk = SpendingKey::from_bytes([0x55; 32]);
    let mut wallet = WalletState::new();
    let report = wallet.scan(&sk, &client).expect("scan matches node root");
    assert_eq!(report.leaf_count, node_leaves);
    assert_eq!(
        aegis_wallet::state::node_cm_tree_root(wallet.leaves()),
        node_root,
        "wallet's rebuilt root equals the node's"
    );
}

// ----- self-transfer scene: scan my notes, consolidate, submit, confirm -----

/// Build a block at height 1 whose single transfer's outputs are the two
/// given note commitments (nullifiers/proof are irrelevant to scan).
fn block_with_output_notes(cm0: [u8; 33], cm1: [u8; 33]) -> (Block, ShieldedTransfer) {
    let out = |cm: [u8; 33]| ShieldedOutput {
        note_cm: cm,
        epk: [0u8; 33],
        ct: [0u8; 152],
        out_ct: [0u8; 80],
    };
    let tx = ShieldedTransfer {
        nullifiers: [[0x01; 32], [0x02; 32]],
        outputs: [out(cm0), out(cm1)],
        proof: vec![0u8; 8],
    };
    let header = Header {
        version: 1,
        prev_id: [0u8; 32],
        height: 1,
        timestamp_ms: 1_760_000_015_000,
        tx_root: [0x22; 32],
        cm_tree_root: [0x33; 32],
        nullifier_digest: [0x44; 32],
        pot_balance: 0,
        sc_nbits: 0x0100_0000,
        reward_claim: [0u8; 33],
    };
    let block = Block {
        header,
        body: BlockBody {
            transfers: vec![tx.clone()],
            ..Default::default()
        },
        coinbase: None,
    };
    (block, tx)
}

#[test]
fn self_transfer_scan_consolidate_submit_and_confirm() {
    let sk = SpendingKey::from_bytes([0x66; 32]);

    // The wallet journals two self-notes it "created" (1000, 500). Their
    // commitments are what will appear on-chain as leaves.
    let mut wallet = WalletState::new();
    let n0 = wallet.add_note(1_000);
    let n1 = wallet.add_note(500);
    let leaves = vec![n0.commitment(&sk), n1.commitment(&sk)];

    // Serve a block carrying those two notes as outputs, and derive the
    // node's authoritative root by applying that block to a real
    // ShieldedState (the node's own tree math is the oracle).
    let (block, tx) = block_with_output_notes(note_cm_bytes(&leaves[0]), note_cm_bytes(&leaves[1]));
    let mut oracle = ShieldedState::new();
    oracle
        .apply_block(&[tx], &[], dev_params(), RewardMode::DevStub, None)
        .expect("apply");
    assert_eq!(oracle.leaf_count(), 2);

    let mut core = SeedCore::new(aegis_spec::Network::Dev);
    core.record_canonical(&block);
    let status = status_from(1, block.id(), block.header.timestamp_ms, &oracle);

    let admission = AdmissionView::new(Arc::new(leaves.clone()), Arc::new(BTreeSet::new()), FEE);
    let api = ApiState::new(
        status,
        Arc::new(RwLock::new(core)),
        Arc::new(RwLock::new(Mempool::new())),
        admission,
    );
    let server = ApiServer::spawn("127.0.0.1:0", api.clone()).expect("spawn");
    let client = NodeClient::new(server.base_url()).expect("client");

    // Scan resolves both notes → balance is their sum.
    let report = wallet.scan(&sk, &client).expect("scan");
    assert_eq!(report.notes_resolved, 2);
    assert_eq!(report.notes_spent, 0);
    assert_eq!(wallet.balance(), 1_500);

    // Build the self-transfer and submit it: the node's mempool verifies
    // the REAL proof against the same anchor and admits it.
    let mut rng = rand::rngs::StdRng::from_seed([7u8; 32]);
    let consolidation = consolidate(&sk, &wallet, FEE, &mut rng).expect("consolidate");
    let outcome = client.submit(&consolidation.transfer).expect("submit");
    assert!(outcome.is_new(), "first submit is new");
    assert_eq!(outcome.id, consolidation.transfer.id());

    // A resubmit is idempotent.
    assert!(!client
        .submit(&consolidation.transfer)
        .expect("resubmit")
        .is_new());

    // Confirm-a-spend: not yet mined ⇒ nullifier unspent. After the node
    // records the nullifiers (mining), the same query reports spent.
    let nf = &consolidation.nullifiers[0];
    assert!(!client.nullifier(nf).expect("nullifier pre-mine"));
    let mut mined = status_from(1, block.id(), block.header.timestamp_ms, &oracle);
    let mut spent = BTreeSet::new();
    spent.insert(consolidation.nullifiers[0]);
    spent.insert(consolidation.nullifiers[1]);
    mined.nullifiers = Arc::new(spent);
    api.publish(mined);
    assert!(client.nullifier(nf).expect("nullifier post-mine"));

    // Commit locally: inputs marked spent ⇒ balance drops to zero (the
    // journalled change/reserve need a rescan to resolve).
    consolidation.commit(&mut wallet);
    assert_eq!(wallet.balance(), 0);
}
