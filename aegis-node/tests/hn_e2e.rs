//! Real-node hash-native e2e: the wallet rehearsal promoted onto a persisted
//! aegis-node `HnChain`. Coinbase/faucet mint → A pays B by address → B finds +
//! spends → double-spend rejected at the REAL mempool → node restart (reload
//! from disk) → wallet rescan recovers state.

use aegis_engine::address::{Address, HRP_TEST};
use aegis_hn_wallet::{SpendCircuit, Wallet};
use aegis_node::hn::state::HnError;
use aegis_node::hn::HnChain;

/// Fixed circuit-key seed so the published vk is stable across the restart.
const CIRCUIT_SEED: u64 = 0xA315_C0DE_5EED_0001;

fn addr_of(w: &Wallet) -> Address {
    // Senders know only the encoded string.
    Address::decode(&w.address_string(HRP_TEST), HRP_TEST).unwrap()
}

#[test]
fn real_node_hash_native_end_to_end() {
    let dir = tempfile::tempdir().unwrap();

    let mut a = Wallet::from_seed(b"node-e2e-A");
    let mut b = Wallet::from_seed(b"node-e2e-B");
    let mut c = Wallet::from_seed(b"node-e2e-C");
    let miner = Wallet::from_seed(b"node-e2e-M"); // coinbase sink (value 0)
    let (addr_a, addr_b, addr_c) = (addr_of(&a), addr_of(&b), addr_of(&c));

    // ---- boot the node ----
    let mut chain = HnChain::create(dir.path(), SpendCircuit::deterministic(CIRCUIT_SEED)).unwrap();

    // ---- faucet: coinbase mints (each its own block) ----
    chain.produce_block(&addr_a, 1_000).unwrap();
    chain.produce_block(&addr_a, 500).unwrap();
    chain.produce_block(&addr_b, 50).unwrap();
    chain.produce_block(&addr_c, 5).unwrap();

    a.scan(&chain);
    b.scan(&chain);
    c.scan(&chain);
    assert_eq!(a.balance(), 1_500);
    assert_eq!(b.balance(), 50);
    assert_eq!(c.balance(), 5);

    // A stale instance of A (scanned pre-spend) for the double-spend attempt.
    let mut a_stale = Wallet::from_seed(b"node-e2e-A");
    a_stale.scan(&chain);

    // ---- A pays B 800 (fee 10), submitted to the real mempool ----
    let tx1 = a.pay(&chain, chain.circuit(), &addr_b, 800, 10).unwrap();
    chain.submit(tx1).expect("mempool admits A→B");
    chain.produce_block(&addr_of(&miner), 0).unwrap(); // seal the block
    a.scan(&chain);
    b.scan(&chain);
    assert_eq!(a.balance(), 690); // change
    assert_eq!(b.balance(), 850);

    // ---- double-spend from the stale instance: rejected at the mempool ----
    let tx_ds = a_stale
        .pay(&chain, chain.circuit(), &addr_c, 700, 10)
        .expect("stale wallet still builds a (membership-valid) proof");
    assert_eq!(
        chain.submit(tx_ds),
        Err(HnError::DoubleSpend),
        "the real mempool must reject a spend of already-spent notes"
    );

    // ---- B pays C 300, C pays A back 100 ----
    let tx2 = b.pay(&chain, chain.circuit(), &addr_c, 300, 10).unwrap();
    chain.submit(tx2).unwrap();
    chain.produce_block(&addr_of(&miner), 0).unwrap();
    b.scan(&chain);
    c.scan(&chain);
    assert_eq!(b.balance(), 540);
    assert_eq!(c.balance(), 305);

    let tx3 = c.pay(&chain, chain.circuit(), &addr_a, 100, 5).unwrap();
    chain.submit(tx3).unwrap();
    chain.produce_block(&addr_of(&miner), 0).unwrap();
    a.scan(&chain);
    c.scan(&chain);
    assert_eq!(a.balance(), 790);
    assert_eq!(c.balance(), 200);

    // ---- exact reconciliation (fees burn) ----
    let minted = 1_000 + 500 + 50 + 5;
    let fees = 10 + 10 + 5;
    assert_eq!(a.balance() + b.balance() + c.balance(), minted - fees);

    let height_before = chain.height();
    let a_balance_before = a.balance();

    // ---- RESTART: drop the node, reopen from disk (replays the block log) ----
    drop(chain);
    let reopened = HnChain::open(dir.path(), SpendCircuit::deterministic(CIRCUIT_SEED)).unwrap();
    assert_eq!(
        reopened.height(),
        height_before,
        "state persisted across restart"
    );

    // A fresh wallet from A's seed rescans the reopened node and recovers state.
    let mut a_restored = Wallet::from_seed(b"node-e2e-A");
    a_restored.scan(&reopened);
    assert_eq!(
        a_restored.balance(),
        a_balance_before,
        "wallet rescan of a restarted node recovers the exact balance"
    );

    // The reopened node still accepts a fresh spend (the vk is stable).
    let mut chain2 = reopened;
    let tx4 = a_restored
        .pay(&chain2, chain2.circuit(), &addr_b, 50, 5)
        .unwrap();
    chain2
        .submit(tx4)
        .expect("reopened node accepts a spend against its stable vk");
}
