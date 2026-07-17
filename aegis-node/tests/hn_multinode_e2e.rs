//! Two-node hash-native testnet e2e: node A produces (mining) with the genesis
//! allocation; node B syncs from A over P2P (IBD from genesis), both serve the
//! wallet HTTP API. A remote wallet against EACH node sees a consistent chain
//! (same root), and a tx submitted to B propagates to A, gets mined, and lands
//! on both; node B is restarted, re-syncs, and a wallet rescan stays consistent.

use std::sync::{Arc, Mutex};

use aegis_engine::address::{Address, HRP_TEST};
use aegis_hn_wallet::{ChainView, SpendCircuit, Wallet};
use aegis_node::hn::params::FAUCET_SEED;
use aegis_node::hn::{HnApiServer, HnApiState, HnChain, HnChainParams, HttpChain};

fn addr_of(w: &Wallet) -> Address {
    Address::decode(&w.address_string(HRP_TEST), HRP_TEST).unwrap()
}

fn serve(chain: &Arc<Mutex<HnChain>>, miner: Address) -> HnApiServer {
    HnApiServer::spawn(
        "127.0.0.1:0",
        HnApiState {
            chain: Arc::clone(chain),
            miner,
        },
    )
    .unwrap()
}

#[test]
fn two_node_hash_native_testnet() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let params = HnChainParams::testnet();

    let miner = Wallet::from_seed(b"mn-miner");
    let mut faucet = Wallet::from_seed(FAUCET_SEED); // holds the genesis allocation
    let mut r = Wallet::from_seed(b"mn-recipient");
    let addr_m = addr_of(&miner);
    let addr_r = addr_of(&r);

    // ---- node A: genesis allocation + mining ----
    let chain_a = Arc::new(Mutex::new(
        HnChain::create_with_params(dir_a.path(), SpendCircuit::new(), params).unwrap(),
    ));
    let server_a = serve(&chain_a, addr_m);
    let net_a = HttpChain::new(server_a.base_url());

    // ---- node B: empty, syncs from A over P2P (IBD from genesis) ----
    let chain_b = Arc::new(Mutex::new(
        HnChain::create(dir_b.path(), SpendCircuit::new()).unwrap(),
    ));
    let server_b = serve(&chain_b, addr_of(&miner));
    let net_b = HttpChain::new(server_b.base_url());

    let synced = chain_b.lock().unwrap().sync_from(&net_a);
    assert!(synced >= 2, "B syncs A's genesis blocks over P2P");
    assert_eq!(
        net_a.current_root(),
        net_b.current_root(),
        "both nodes agree on the accumulator root after sync"
    );

    // ---- the faucet wallet (scanning via node A) funds a stranger ----
    let circuit = SpendCircuit::new();
    faucet.scan(&net_a);
    assert_eq!(faucet.balance(), 1_000_000_000);

    // Faucet pays R 1000; the tx is submitted to NODE B.
    let tx = faucet.pay(&net_a, &circuit, &addr_r, 1_000, 10).unwrap();
    net_b.submit(&tx).expect("node B admits the tx");

    // Gossip: A pulls B's mempool, then A mines the block.
    let pulled = chain_a.lock().unwrap().pull_mempool(&net_b);
    assert_eq!(pulled, 1, "A picks up the tx gossiped from B");
    net_a.mine().expect("A mines a block");

    // B syncs the new block from A.
    chain_b.lock().unwrap().sync_from(&net_a);
    assert_eq!(
        net_a.current_root(),
        net_b.current_root(),
        "the mined block propagated B→A→mined→B; both roots agree"
    );

    // ---- cross-node consistency: R finds the payment via EITHER node ----
    let mut r_via_a = Wallet::from_seed(b"mn-recipient");
    r_via_a.scan(&net_a);
    r.scan(&net_b);
    assert_eq!(r.balance(), 1_000, "R finds the 1000 payment via node B");
    assert_eq!(
        r_via_a.balance(),
        1_000,
        "R finds the same payment via node A (cross-node consistency)"
    );

    // ---- double-spend rejected on BOTH nodes ----
    assert!(net_b.submit(&tx).is_err(), "replay rejected by node B");
    assert!(net_a.submit(&tx).is_err(), "replay rejected by node A");

    // ---- restart node B: reopen from disk, re-sync, rescan consistent ----
    let b_height = { chain_b.lock().unwrap().height() };
    drop(server_b);
    drop(net_b);
    let chain_b2 = Arc::new(Mutex::new(
        HnChain::open(dir_b.path(), SpendCircuit::new()).unwrap(),
    ));
    assert_eq!(
        chain_b2.lock().unwrap().height(),
        b_height,
        "node B persisted its synced chain across restart"
    );
    let server_b2 = serve(&chain_b2, addr_of(&miner));
    let net_b2 = HttpChain::new(server_b2.base_url());
    // catch up anything mined while B was down (none here, but the path runs).
    chain_b2.lock().unwrap().sync_from(&net_a);

    let mut r_after = Wallet::from_seed(b"mn-recipient");
    r_after.scan(&net_b2);
    assert_eq!(
        r_after.balance(),
        1_000,
        "wallet rescan of the restarted, re-synced node B is consistent"
    );
    assert_eq!(
        net_a.current_root(),
        net_b2.current_root(),
        "roots still agree"
    );
}
