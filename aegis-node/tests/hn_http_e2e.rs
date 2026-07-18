//! The promoted e2e: a REMOTE wallet drives the full flow over the node's HTTP
//! API (not in-process). Wallet ↔ node is only a URL: scan/paths/root/nullifier
//! over GET, tx submit + mine over POST. Then a node restart (reopen from disk,
//! respawn the server) and a wallet rescan.

use std::sync::{Arc, Mutex};

use aegis_engine::address::{Address, HRP_TEST};
use aegis_hn_wallet::{SpendCircuit, Wallet};
use aegis_node::hn::{HnApiServer, HnApiState, HnChain, HnChainParams, HttpChain};

fn addr_of(w: &Wallet) -> Address {
    Address::decode(&w.address_string(HRP_TEST), HRP_TEST).unwrap()
}

#[test]
fn remote_wallet_over_http_end_to_end() {
    let dir = tempfile::tempdir().unwrap();

    let mut a = Wallet::from_seed(b"http-A");
    let mut b = Wallet::from_seed(b"http-B");
    let miner = Wallet::from_seed(b"http-M");
    let (addr_a, addr_b, addr_m) = (addr_of(&a), addr_of(&b), addr_of(&miner));

    // ---- boot the node with a PINNED genesis (allocation + pot are params) ----
    let params = HnChainParams::testnet().with_genesis(
        vec![
            (addr_a, 1_000),
            (addr_a, 500),
            (addr_a, 200), // a third note so A can spend again later
            (addr_b, 20),
        ],
        10_000,
    );
    let fee = params.flat_fee;
    let chain = HnChain::create_genesis(dir.path(), SpendCircuit::new(), params.clone()).unwrap();

    // ---- serve the HTTP surface over the shared chain ----
    let shared = Arc::new(Mutex::new(chain));
    let server = HnApiServer::spawn(
        "127.0.0.1:0",
        HnApiState {
            chain: Arc::clone(&shared),
            miner: addr_m,
        },
    )
    .unwrap();
    let url = server.base_url();

    // The wallet holds ONLY its keys + the node URL + its own circuit keys
    // (same stable vk as the node's via SpendCircuit::new()).
    let net = HttpChain::new(&url);
    let circuit = SpendCircuit::new();

    // ---- scan over HTTP ----
    a.scan(&net);
    b.scan(&net);
    assert_eq!(a.balance(), 1_700);
    assert_eq!(b.balance(), 20);

    // ---- A pays B 800 (flat fee) — proof built against HTTP-served paths/root ----
    let tx1 = a.pay(&net, &circuit, &addr_b, 800, fee).unwrap();
    net.submit(&tx1).expect("node mempool admits over HTTP");
    net.mine().expect("node mines a block over HTTP");
    a.scan(&net);
    b.scan(&net);
    assert_eq!(a.balance(), 897); // spent 1000+500, change 697, kept 200
    assert_eq!(b.balance(), 820);

    // ---- double-spend: a replayed (already-spent) tx is rejected over HTTP ----
    assert!(
        net.submit(&tx1).is_err(),
        "a replayed already-spent tx is rejected by the node over HTTP"
    );

    let height_before = { shared.lock().unwrap().height() };
    let a_balance_before = a.balance();

    // ---- RESTART: stop server, reopen the chain from disk, respawn ----
    drop(server);
    drop(net);
    let reopened = HnChain::open(dir.path(), SpendCircuit::new(), params).unwrap();
    assert_eq!(reopened.height(), height_before, "persisted across restart");
    let shared2 = Arc::new(Mutex::new(reopened));
    let server2 = HnApiServer::spawn(
        "127.0.0.1:0",
        HnApiState {
            chain: Arc::clone(&shared2),
            miner: addr_of(&miner),
        },
    )
    .unwrap();
    let net2 = HttpChain::new(server2.base_url());

    // ---- wallet rescan over the restarted node's HTTP ----
    let mut a_restored = Wallet::from_seed(b"http-A");
    a_restored.scan(&net2);
    assert_eq!(
        a_restored.balance(),
        a_balance_before,
        "remote rescan of a restarted node recovers the balance"
    );

    // The restarted node still accepts a fresh spend over HTTP (stable vk).
    let tx2 = a_restored.pay(&net2, &circuit, &addr_b, 50, fee).unwrap();
    net2.submit(&tx2)
        .expect("restarted node accepts a fresh spend over HTTP");
}
