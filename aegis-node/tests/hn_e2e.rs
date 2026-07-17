//! Real-node hash-native e2e: the wallet flow over a persisted aegis-node
//! `HnChain` producing blocks through the real production step, with emission,
//! fee-to-miner, and coinbase maturity.
//!
//! genesis fund → A pays B by address → B finds+spends → double-spend rejected
//! at the REAL mempool → balances reconcile (genesis + emission; fees move to
//! the miner, not burned) → the miner's coinbase is immature immediately, then
//! spendable after maturity → node restart (reload from disk) → wallet rescan.

use aegis_engine::address::{Address, HRP_TEST};
use aegis_hn_wallet::chain::COINBASE_MATURITY;
use aegis_hn_wallet::{ChainView, SpendCircuit, Wallet};
use aegis_node::hn::chain::EMISSION_PER_BLOCK;
use aegis_node::hn::state::HnError;
use aegis_node::hn::HnChain;

fn addr_of(w: &Wallet) -> Address {
    Address::decode(&w.address_string(HRP_TEST), HRP_TEST).unwrap()
}

#[test]
fn real_node_hash_native_end_to_end() {
    let dir = tempfile::tempdir().unwrap();

    let mut a = Wallet::from_seed(b"node-e2e-A");
    let mut b = Wallet::from_seed(b"node-e2e-B");
    let mut c = Wallet::from_seed(b"node-e2e-C");
    let mut m = Wallet::from_seed(b"node-e2e-M"); // the miner
    let (addr_a, addr_b, addr_c, addr_m) = (addr_of(&a), addr_of(&b), addr_of(&c), addr_of(&m));

    let mut chain = HnChain::create(dir.path(), SpendCircuit::new()).unwrap();

    // ---- genesis funding (immediately spendable, non-coinbase) ----
    chain.fund(&addr_a, 1_000).unwrap();
    chain.fund(&addr_a, 500).unwrap();
    chain.fund(&addr_b, 50).unwrap();
    chain.fund(&addr_c, 5).unwrap();
    for w in [&mut a, &mut b, &mut c] {
        w.scan(&chain);
    }
    assert_eq!(a.balance(), 1_500);
    assert_eq!(b.balance(), 50);
    assert_eq!(c.balance(), 5);

    // A stale instance of A (scanned pre-spend) for the double-spend attempt.
    let mut a_stale = Wallet::from_seed(b"node-e2e-A");
    a_stale.scan(&chain);

    // ---- A pays B 800 (fee 10); M mines the block ----
    let tx1 = a.pay(&chain, chain.circuit(), &addr_b, 800, 10).unwrap();
    chain.submit(tx1).expect("mempool admits A→B");
    chain.produce_block(&addr_m).unwrap(); // M earns emission + 10 fee
    a.scan(&chain);
    b.scan(&chain);
    assert_eq!(a.balance(), 690);
    assert_eq!(b.balance(), 850);

    // ---- double-spend from the stale instance: rejected at the mempool ----
    let tx_ds = a_stale
        .pay(&chain, chain.circuit(), &addr_c, 700, 10)
        .expect("stale wallet still builds a (membership-valid) proof");
    assert_eq!(chain.submit(tx_ds), Err(HnError::DoubleSpend));

    // ---- B pays C 300, C pays A back 100 (M mines each) ----
    let tx2 = b.pay(&chain, chain.circuit(), &addr_c, 300, 10).unwrap();
    chain.submit(tx2).unwrap();
    chain.produce_block(&addr_m).unwrap();
    b.scan(&chain);
    c.scan(&chain);

    let tx3 = c.pay(&chain, chain.circuit(), &addr_a, 100, 5).unwrap();
    chain.submit(tx3).unwrap();
    chain.produce_block(&addr_m).unwrap();
    a.scan(&chain);
    c.scan(&chain);
    m.scan(&chain);

    // ---- conservation: genesis + emission; fees moved to the miner ----
    let genesis = 1_000 + 500 + 50 + 5;
    let n_mined = 3u64; // three payment blocks
    let total = a.balance() + b.balance() + c.balance() + m.balance();
    assert_eq!(
        total,
        genesis + n_mined * EMISSION_PER_BLOCK,
        "value is conserved: genesis + emission (fees redistributed, not burned)"
    );
    // The miner earned emission + fees (3×50 + 10+10+5 = 175).
    assert_eq!(m.balance(), n_mined * EMISSION_PER_BLOCK + (10 + 10 + 5));

    // ---- coinbase maturity: the miner's reward is not spendable yet ----
    assert_eq!(
        m.spendable_balance(chain.tip_height()),
        0,
        "freshly-mined coinbase is immature"
    );

    // Mine enough empty blocks for the miner's earliest coinbase notes to mature.
    for _ in 0..COINBASE_MATURITY {
        chain.produce_block(&addr_m).unwrap();
    }
    m.scan(&chain);
    assert!(
        m.spendable_balance(chain.tip_height()) > 0,
        "coinbase (fees + emission) is spendable after maturity"
    );

    // The miner spends matured coinbase → proves fees + emission actually land
    // and are spendable: A receives the miner's payment.
    let a_before = a.balance();
    let tx_m = m
        .pay(&chain, chain.circuit(), &addr_a, 40, 5)
        .expect("miner spends matured coinbase (fees + emission)");
    chain
        .submit(tx_m)
        .expect("miner's coinbase spend is admitted");
    chain.produce_block(&addr_m).unwrap();
    a.scan(&chain);
    m.scan(&chain);
    assert_eq!(
        a.balance(),
        a_before + 40,
        "the miner's matured-coinbase payment reaches A"
    );

    // ---- min-fee floor: a zero-fee tx is rejected cheaply (before verify) ----
    // Use a throwaway instance so the rejected attempt does not perturb `a`'s
    // local spent-state before the restart comparison below.
    {
        let mut a_fee = Wallet::from_seed(b"node-e2e-A");
        a_fee.scan(&chain);
        if let Ok(t) = a_fee.pay(&chain, chain.circuit(), &addr_b, 10, 0) {
            assert_eq!(chain.submit(t), Err(HnError::FeeTooLow), "min-fee floor");
        }
    }

    let height_before = chain.height();
    let a_balance_before = a.balance();

    // ---- RESTART: reopen from disk (replays the block log) ----
    drop(chain);
    let reopened = HnChain::open(dir.path(), SpendCircuit::new()).unwrap();
    assert_eq!(
        reopened.height(),
        height_before,
        "state persisted across restart"
    );

    let mut a_restored = Wallet::from_seed(b"node-e2e-A");
    a_restored.scan(&reopened);
    assert_eq!(
        a_restored.balance(),
        a_balance_before,
        "wallet rescan of a restarted node recovers the exact balance"
    );

    // The reopened node still accepts a fresh spend (stable vk).
    let mut chain2 = reopened;
    let tx4 = a_restored
        .pay(&chain2, chain2.circuit(), &addr_b, 50, 5)
        .unwrap();
    chain2
        .submit(tx4)
        .expect("reopened node accepts a spend against its stable vk");
}
