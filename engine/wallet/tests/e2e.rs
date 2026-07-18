//! Multi-wallet end-to-end rehearsal: three wallets on an in-memory chain,
//! paying each other by ADDRESS STRING only (the stranger flow), with real
//! HIDING monolith proofs verified by the node accept path.
//!
//! The script: faucet → A pays B → B pays C → C pays A back; change is found
//! by each sender's own scan; balances reconcile exactly (fees burn); a
//! double-spend from a stale wallet instance is rejected by the nullifier set;
//! a watch-only viewing key sees B's payment but holds no spend authority.

use aegis_engine::address::{Address, HRP_TEST};
use aegis_engine::commit::note_commitment;
use aegis_engine::note_encryption::{encrypt_note, NotePlaintext, MEMO_BYTES, NOTE_CT_BYTES};
use aegis_engine::poseidon::{Digest, F};
use aegis_hn_wallet::{InMemoryChain, SpendCircuit, SubmitError, Wallet};
use p3_field::PrimeCharacteristicRing;

// ----- helpers -----

fn digest(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

/// Faucet: mint a note straight into the accumulator, encrypted to `addr`
/// exactly like a payment output (so the recipient finds it by scanning).
fn faucet(chain: &mut InMemoryChain, addr: &Address, value: u64, tag: u32) {
    let (rho, r) = (digest(10_000 + tag), digest(20_000 + tag));
    let cm = note_commitment(value, &addr.owner, &rho, &r);
    let pt = NotePlaintext {
        value,
        rho,
        r,
        memo: [0u8; MEMO_BYTES],
    };
    let ct = encrypt_note(addr, &cm, &pt).expect("faucet address is valid");
    chain.append_output(cm, ct);
}

// ----- the rehearsal -----

#[test]
fn three_wallet_stranger_flow_reconciles() {
    let circuit = SpendCircuit::new();
    let mut chain = InMemoryChain::new();

    let mut a = Wallet::from_seed(b"wallet-a-seed");
    let mut b = Wallet::from_seed(b"wallet-b-seed");
    let mut c = Wallet::from_seed(b"wallet-c-seed");

    // Senders know each other ONLY as encoded address strings.
    let addr_b = Address::decode(&b.address_string(HRP_TEST), HRP_TEST).unwrap();
    let addr_c = Address::decode(&c.address_string(HRP_TEST), HRP_TEST).unwrap();
    let addr_a = Address::decode(&a.address_string(HRP_TEST), HRP_TEST).unwrap();

    // Bootstrap: A gets 1000 + 500; B and C get dust (the 2-in shape needs two
    // inputs; zero/dust change notes play this role organically later).
    faucet(&mut chain, &a.address(), 1_000, 1);
    faucet(&mut chain, &a.address(), 500, 2);
    faucet(&mut chain, &b.address(), 50, 3);
    faucet(&mut chain, &c.address(), 5, 4);

    a.scan(&chain);
    b.scan(&chain);
    c.scan(&chain);
    assert_eq!(a.balance(), 1_500);
    assert_eq!(b.balance(), 50);
    assert_eq!(c.balance(), 5);

    // A stale second instance of A (same seed, scanned pre-spend) for the
    // double-spend attempt below.
    let mut a_stale = Wallet::from_seed(b"wallet-a-seed");
    a_stale.scan(&chain);

    // ---- A pays B 800 (fee 10) ----
    let tx1 = a
        .pay(&chain, &circuit, &addr_b, 800, 10)
        .expect("A can pay");
    assert_eq!(tx1.out_ciphertexts[0].len(), NOTE_CT_BYTES);
    assert_eq!(tx1.out_ciphertexts[1].len(), NOTE_CT_BYTES);
    chain.submit(&tx1, &circuit).expect("node accepts A→B");

    a.scan(&chain);
    b.scan(&chain);
    // change (1500 − 810 = 690) found by A's own scanner; B found the payment.
    assert_eq!(a.balance(), 690);
    assert_eq!(b.balance(), 850);

    // ---- double-spend from the stale instance: rejected by the node ----
    let tx_ds = a_stale
        .pay(&chain, &circuit, &addr_c, 700, 10)
        .expect("stale wallet can still BUILD a proof (its notes look unspent)");
    assert_eq!(
        chain.submit(&tx_ds, &circuit),
        Err(SubmitError::DoubleSpend),
        "the nullifier set must reject a spend of already-spent notes"
    );

    // ---- B pays C 300 (fee 10) ----
    let tx2 = b
        .pay(&chain, &circuit, &addr_c, 300, 10)
        .expect("B can pay");
    chain.submit(&tx2, &circuit).expect("node accepts B→C");
    b.scan(&chain);
    c.scan(&chain);
    assert_eq!(b.balance(), 540); // 850 − 310
    assert_eq!(c.balance(), 305);

    // ---- C pays A back 100 (fee 5) ----
    let tx3 = c.pay(&chain, &circuit, &addr_a, 100, 5).expect("C can pay");
    chain.submit(&tx3, &circuit).expect("node accepts C→A");
    a.scan(&chain);
    c.scan(&chain);
    assert_eq!(c.balance(), 200); // 305 − 105
    assert_eq!(a.balance(), 790); // 690 + 100

    // ---- exact reconciliation: totals minus burned fees ----
    let total_start = 1_000 + 500 + 50 + 5;
    let fees = 10 + 10 + 5;
    assert_eq!(
        a.balance() + b.balance() + c.balance(),
        total_start - fees,
        "balances must reconcile exactly (fees burn)"
    );

    // ---- watch-only: sees B's payments, holds no spend authority ----
    let vk = b.viewing_key();
    let seen = vk.detect(&chain, 0);
    assert!(
        seen.iter().any(|&(_, value, _)| value == 800),
        "the viewing key must detect B's incoming 800 payment"
    );
    assert!(
        seen.iter().any(|&(_, value, _)| value == 50),
        "the viewing key must detect B's faucet note"
    );
    // Spend authority is structural: `ViewingKey` carries only (enc_sk, owner)
    // — no nk exists in the type, so no nullifier or spend witness can be
    // derived from it (enforced at compile time; nothing to call).

    // ---- a replayed tx is also a double-spend ----
    assert_eq!(chain.submit(&tx1, &circuit), Err(SubmitError::DoubleSpend));
}
