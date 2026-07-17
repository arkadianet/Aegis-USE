//! Real-node hash-native e2e under the SPEC economics: pinned genesis, the
//! flat 0.03 USE fee (exact — 0/0.02/0.04 all rejected), fees → pot,
//! pot-funded coinbase `min(pot, base + per_tx × txs)`, coinbase maturity, and
//! the conservation invariant (shielded total + pot constant) checked at every
//! stage of a multi-block multi-tx run.
//!
//! genesis → A pays B by address → B finds+spends → double-spend rejected at
//! the REAL mempool → pot + conservation reconcile → the miner's coinbase is
//! immature immediately, then spendable after maturity → wrong-fee txs rejected
//! → node restart (reload from disk) → wallet rescan.

use aegis_engine::address::{Address, HRP_TEST};
use aegis_hn_wallet::{ChainView, SpendCircuit, Wallet};
use aegis_node::hn::state::HnError;
use aegis_node::hn::{HnChain, HnChainParams};

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

    // ---- pinned genesis: allocation + pot are chain params, not free funding ----
    const GENESIS_POT: u64 = 1_000_000;
    let genesis = vec![(addr_a, 1_000), (addr_a, 500), (addr_b, 50), (addr_c, 5)];
    let genesis_sum: u64 = genesis.iter().map(|(_, v)| v).sum();
    let params = HnChainParams::testnet().with_genesis(genesis.clone(), GENESIS_POT);
    let fee = params.flat_fee;
    let maturity = params.coinbase_maturity;

    let mut chain = HnChain::create_genesis(dir.path(), SpendCircuit::new(), params).unwrap();
    for w in [&mut a, &mut b, &mut c] {
        w.scan(&chain);
    }
    assert_eq!(a.balance(), 1_500);
    assert_eq!(b.balance(), 50);
    assert_eq!(c.balance(), 5);
    assert_eq!(
        chain.pot(),
        GENESIS_POT,
        "genesis issuance leaves the pot at its pinned value"
    );

    // The conservation invariant, checked after every block below.
    let conserved = GENESIS_POT + genesis_sum;
    let assert_conserved = |chain: &HnChain| {
        assert_eq!(
            chain.pot() + chain.shielded_total(),
            conserved,
            "I1-extended: shielded total + pot is conserved"
        );
    };
    assert_conserved(&chain);

    // A stale instance of A (scanned pre-spend) for the double-spend attempt.
    let mut a_stale = Wallet::from_seed(b"node-e2e-A");
    a_stale.scan(&chain);

    // ---- A pays B 800 (flat fee); M mines the block ----
    let tx1 = a.pay(&chain, chain.circuit(), &addr_b, 800, fee).unwrap();
    chain.submit(tx1).expect("mempool admits A→B");
    chain.produce_block(&addr_m).unwrap(); // coinbase = base + 1 tx bonus = 2
    assert_conserved(&chain);
    a.scan(&chain);
    b.scan(&chain);
    assert_eq!(a.balance(), 697); // 1500 − 800 − 3
    assert_eq!(b.balance(), 850);

    // ---- double-spend from the stale instance: rejected at the mempool ----
    let tx_ds = a_stale
        .pay(&chain, chain.circuit(), &addr_c, 690, fee)
        .expect("stale wallet still builds a (membership-valid) proof");
    assert_eq!(chain.submit(tx_ds), Err(HnError::DoubleSpend));

    // ---- B pays C 300, C pays A back 100 (M mines each) ----
    let tx2 = b.pay(&chain, chain.circuit(), &addr_c, 300, fee).unwrap();
    chain.submit(tx2).unwrap();
    chain.produce_block(&addr_m).unwrap();
    assert_conserved(&chain);
    b.scan(&chain);
    c.scan(&chain);

    let tx3 = c.pay(&chain, chain.circuit(), &addr_a, 100, fee).unwrap();
    chain.submit(tx3).unwrap();
    chain.produce_block(&addr_m).unwrap();
    assert_conserved(&chain);
    a.scan(&chain);
    c.scan(&chain);
    m.scan(&chain);

    // ---- pot accounting, exact: 3 txs × fee in, 3 coinbases × 2 out ----
    let fees_paid = 3 * fee;
    let coinbases = 3 * 2; // each block: base 1 + 1 inclusion bonus
    assert_eq!(
        chain.pot(),
        GENESIS_POT + fees_paid - coinbases,
        "pot = genesis + fees − coinbases, exactly"
    );
    // The miner earned ONLY the pot draws — never the fees directly.
    assert_eq!(m.balance(), coinbases);
    // Wallet-side totals agree with the tracked shielded total.
    assert_eq!(
        a.balance() + b.balance() + c.balance() + m.balance(),
        chain.shielded_total(),
        "the sum of wallet balances is the shielded pool total"
    );

    // ---- coinbase maturity: the miner's reward is not spendable yet ----
    assert_eq!(
        m.spendable_balance(chain.tip_height()),
        0,
        "freshly-mined coinbase is immature"
    );

    // Mine enough empty blocks (base draw only) for the miner's earliest
    // coinbase notes to mature.
    for _ in 0..maturity {
        chain.produce_block(&addr_m).unwrap();
    }
    assert_conserved(&chain);
    m.scan(&chain);
    assert!(
        m.spendable_balance(chain.tip_height()) > 0,
        "coinbase is spendable after maturity"
    );

    // The miner spends matured coinbase → proves the pot draws actually land
    // and are spendable: A receives the miner's payment.
    let a_before = a.balance();
    let tx_m = m
        .pay(&chain, chain.circuit(), &addr_a, 1, fee)
        .expect("miner spends matured coinbase");
    chain
        .submit(tx_m)
        .expect("miner's coinbase spend is admitted");
    chain.produce_block(&addr_m).unwrap();
    assert_conserved(&chain);
    a.scan(&chain);
    m.scan(&chain);
    assert_eq!(
        a.balance(),
        a_before + 1,
        "the miner's matured-coinbase payment reaches A"
    );

    // ---- the flat fee is EXACT: 0, fee−1, fee+1 are all rejected cheaply ----
    for wrong_fee in [0, fee - 1, fee + 1] {
        let mut a_fee = Wallet::from_seed(b"node-e2e-A");
        a_fee.scan(&chain);
        let t = a_fee
            .pay(&chain, chain.circuit(), &addr_b, 10, wrong_fee)
            .expect("the wallet can build the proof; the CHAIN rejects the fee");
        assert_eq!(
            chain.submit(t),
            Err(HnError::BadFee),
            "fee {wrong_fee} != flat fee {fee} is consensus-invalid"
        );
    }

    let height_before = chain.height();
    let pot_before = chain.pot();
    let a_balance_before = a.balance();

    // ---- RESTART: reopen from disk (replays the block log) ----
    drop(chain);
    let reopened = HnChain::open(
        dir.path(),
        SpendCircuit::new(),
        HnChainParams::testnet().with_genesis(genesis, GENESIS_POT),
    )
    .unwrap();
    assert_eq!(
        reopened.height(),
        height_before,
        "state persisted across restart"
    );
    assert_eq!(
        reopened.pot(),
        pot_before,
        "the pot balance replays exactly from the block log"
    );
    assert_conserved(&reopened);

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
        .pay(&chain2, chain2.circuit(), &addr_b, 50, fee)
        .unwrap();
    chain2
        .submit(tx4)
        .expect("reopened node accepts a spend against its stable vk");
}
