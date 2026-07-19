//! Peg consensus e2e over the real hn chain (devnet mocked at the PegInCheck
//! boundary): a confirmed vault deposit mints the deterministic pegmint note
//! minus the 1% pot fee → the recipient finds and spends it (shielded hop) →
//! a peg-out burns shielded value to a PUBLIC withdrawal (burn-note binding
//! enforced) with its 1% fee to the pot → the withdrawal is recorded for
//! settlement. Adversarial: duplicate deposit mint, unconfirmed-claim
//! deferral on a follower, tampered burn binding (wrong amount / recipient),
//! and exact bridge-flow conservation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aegis_engine::address::{Address, HRP_TEST};
use aegis_hn_wallet::{SpendCircuit, Wallet};
use aegis_node::hn::state::{HnError, PegInClaim, PegOutTx};
use aegis_node::hn::{HnChain, HnChainParams, PegInCheck};

fn addr_of(w: &Wallet) -> Address {
    Address::decode(&w.address_string(HRP_TEST), HRP_TEST).unwrap()
}

/// A mock devnet-vault view: confirms everything while `on` is true.
struct MockVault {
    on: Arc<AtomicBool>,
}
impl PegInCheck for MockVault {
    fn confirmed(&self, _claim: &PegInClaim) -> bool {
        self.on.load(Ordering::SeqCst)
    }
}

fn claim_for(dest: &Address, amount: u64, box_id: [u8; 32], params: &HnChainParams) -> PegInClaim {
    use aegis_node::hn::mint::pegmint_note;
    use aegis_node::hn::state::digest_to_limbs;
    let minted = amount - params.peg_fee(amount);
    let mint = pegmint_note(dest, minted, &box_id);
    let _ = mint.cm;
    PegInClaim {
        box_id,
        dest_owner: digest_to_limbs(&dest.owner),
        dest_enc_pk: dest.enc_pk,
        amount,
        ciphertext: mint.ciphertext,
    }
}

#[test]
fn peg_in_and_peg_out_consensus_end_to_end() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();

    let mut alice = Wallet::from_seed(b"peg-alice"); // deposits on the devnet
    let mut bob = Wallet::from_seed(b"peg-bob"); // receives the shielded hop
    let miner = Wallet::from_seed(b"peg-miner");
    let (addr_a, addr_b, addr_m) = (addr_of(&alice), addr_of(&bob), addr_of(&miner));

    const GENESIS_POT: u64 = 1_000_000;
    let params = HnChainParams::testnet().with_genesis(vec![], GENESIS_POT);
    let fee = params.flat_fee;

    let mut chain = HnChain::create(dir_a.path(), SpendCircuit::new(), params.clone()).unwrap();
    let on = Arc::new(AtomicBool::new(true));
    chain.set_pegin_check(Box::new(MockVault {
        on: Arc::clone(&on),
    }));

    // ---- peg-in: a confirmed 10_000 deposit to Alice mints 9_900 ----
    let deposit = 10_000u64;
    let peg_fee_in = params.peg_fee(deposit); // 100
    let claim = claim_for(&addr_a, deposit, [0x11; 32], &params);
    chain.queue_pegin(claim.clone());
    chain.produce_block(&addr_m).unwrap();
    alice.scan(&chain);
    assert_eq!(alice.balance(), deposit - peg_fee_in, "mint = deposit − 1%");
    assert_eq!(
        chain.pot(),
        GENESIS_POT + peg_fee_in - 1, // +fee −coinbase(base 1, no spends)
        "the peg-in fee landed in the pot"
    );
    // Conservation with bridge inflow: shielded+pot grew by exactly the deposit.
    assert_eq!(
        chain.pot() + chain.shielded_total(),
        GENESIS_POT + deposit,
        "system total grew by exactly the deposited amount"
    );

    // ---- adversarial: the same deposit can never mint twice ----
    chain.queue_pegin(claim.clone()); // silently dropped (used)
                                      // Force it into a block anyway via a hand-built follower path:
                                      // (queue_pegin drops it, so produce a block and check no second mint)
    chain.produce_block(&addr_m).unwrap();
    alice.scan(&chain);
    assert_eq!(alice.balance(), deposit - peg_fee_in, "no double mint");

    // A second deposit to Alice (so she holds TWO notes for 2-in spends).
    let claim2 = claim_for(&addr_a, 5_000, [0x22; 32], &params);
    chain.queue_pegin(claim2);
    chain.produce_block(&addr_m).unwrap();
    alice.scan(&chain);
    let fee2 = params.peg_fee(5_000); // 50
    assert_eq!(alice.balance(), 9_900 + 5_000 - fee2);

    // ---- shielded hop: Alice pays Bob 2_000 on Aegis ----
    let tx = alice
        .pay(&chain, chain.circuit(), &addr_b, 2_000, fee)
        .unwrap();
    chain.submit(tx).unwrap();
    chain.produce_block(&addr_m).unwrap();
    bob.scan(&chain);
    assert_eq!(bob.balance(), 2_000, "Bob received the shielded hop");

    // ---- peg-out: Bob withdraws 990 to an Ergo recipient ----
    // Bob needs TWO notes for the 2-in burn spend; a third deposit refills
    // Alice (she only holds one change note after the hop) so she can send
    // Bob a second note.
    let claim3 = claim_for(&addr_a, 1_000, [0x33; 32], &params);
    chain.queue_pegin(claim3);
    chain.produce_block(&addr_m).unwrap();
    alice.scan(&chain);
    let tx2 = alice
        .pay(&chain, chain.circuit(), &addr_b, 100, fee)
        .unwrap();
    chain.submit(tx2).unwrap();
    chain.produce_block(&addr_m).unwrap();
    bob.scan(&chain);

    let withdrawal = 990u64;
    let peg_fee_out = params.peg_fee(withdrawal); // 9
    let recipient_prop = vec![0xAA; 36]; // stand-in Ergo ErgoTree bytes
    let pot_before = chain.pot();
    let sys_before = chain.pot() + chain.shielded_total();

    let burn_tx = bob
        .burn_spend(
            &chain,
            chain.circuit(),
            withdrawal,
            peg_fee_out,
            &recipient_prop,
            fee,
        )
        .unwrap();

    // ---- adversarial FIRST: tampered withdrawal amount / recipient ----
    let wrong_amount = PegOutTx {
        tx: burn_tx.clone(),
        amount: withdrawal + 1, // claims more than was burned
        recipient_prop: recipient_prop.clone(),
    };
    assert_eq!(
        chain.submit_pegout(wrong_amount),
        Err(HnError::BadPegOut),
        "a withdrawal claiming more than the burn is rejected"
    );
    let zero = PegOutTx {
        tx: burn_tx.clone(),
        amount: 0,
        recipient_prop: recipient_prop.clone(),
    };
    assert_eq!(chain.submit_pegout(zero), Err(HnError::BadPegOut));
    // D1 redirect: the SAME real burn (victim's pending withdrawal) claimed
    // with the ATTACKER's recipient — everything else identical. Pre-D1 the
    // burn did not bind the recipient and this was ACCEPTED (the theft
    // vector); the recipient-bound derivation must reject it.
    let attacker_prop = vec![0xEE; 36];
    assert_ne!(attacker_prop, recipient_prop);
    let redirect = PegOutTx {
        tx: burn_tx.clone(),
        amount: withdrawal,
        recipient_prop: attacker_prop,
    };
    assert_eq!(
        chain.submit_pegout(redirect),
        Err(HnError::BadPegOut),
        "D1: a withdrawal redirected to a different recipient is rejected"
    );

    // The honest peg-out is admitted and mined.
    let po = PegOutTx {
        tx: burn_tx,
        amount: withdrawal,
        recipient_prop: recipient_prop.clone(),
    };
    chain.submit_pegout(po).expect("honest peg-out admitted");
    chain.produce_block(&addr_m).unwrap();

    // Withdrawal recorded exactly once, with the right binding.
    let ws = chain.withdrawals();
    assert_eq!(ws.len(), 1);
    assert_eq!(ws[0].amount, withdrawal);
    assert_eq!(ws[0].recipient_prop, recipient_prop);

    // Pot: +flat fee +peg fee −coinbase(1 base + 1 spend bonus = 2).
    assert_eq!(
        chain.pot(),
        pot_before + fee + peg_fee_out - 2,
        "peg-out fees (flat + 1%) landed in the pot"
    );
    // Conservation with bridge outflow: system total shrank by exactly W.
    assert_eq!(
        chain.pot() + chain.shielded_total(),
        sys_before - withdrawal,
        "system total shrank by exactly the withdrawal"
    );

    // ---- follower deferral: an unconfirmed claim defers, then applies ----
    let mut follower = HnChain::create(dir_b.path(), SpendCircuit::new(), params.clone()).unwrap();
    let off = Arc::new(AtomicBool::new(false));
    follower.set_pegin_check(Box::new(MockVault {
        on: Arc::clone(&off),
    }));
    // Sync all of A's blocks: stops (defers) at the first peg-in block.
    let blocks = chain.blocks_since(0);
    let mut applied = 0;
    let mut deferred = false;
    for b in blocks.clone() {
        match follower.ingest_block(b) {
            Ok(true) => applied += 1,
            Ok(false) => {}
            Err(HnError::PegInNotConfirmed) => {
                deferred = true;
                break;
            }
            Err(e) => panic!("unexpected: {e}"),
        }
    }
    assert!(deferred, "an unconfirmed peg-in claim DEFERS the sync");
    assert_eq!(applied, 0, "nothing applied before the deferral point");

    // The follower's devnet view catches up → the same blocks now apply.
    off.store(true, Ordering::SeqCst);
    for b in blocks {
        if b.height >= follower.height() {
            follower
                .ingest_block(b)
                .expect("applies after confirmation");
        }
    }
    assert_eq!(follower.height(), chain.height(), "follower fully synced");
    assert_eq!(
        follower.pot(),
        chain.pot(),
        "pot identical across nodes after peg flows"
    );
    assert_eq!(follower.withdrawals(), chain.withdrawals());

    // ---- D1 at BLOCK validation: a peer relays the pegout block with its
    // withdrawal record redirected to the attacker's recipient. The burn note
    // in the (unchanged, validly-proven) spend binds the victim's recipient,
    // so recomputing the burn commitment mismatches and the block is rejected
    // — a redirected withdrawal can never be RECORDED by any honest node. ----
    let dir_c = tempfile::tempdir().unwrap();
    let mut node_c = HnChain::create(dir_c.path(), SpendCircuit::new(), params.clone()).unwrap();
    let on_c = Arc::new(AtomicBool::new(true));
    node_c.set_pegin_check(Box::new(MockVault {
        on: Arc::clone(&on_c),
    }));
    let blocks = chain.blocks_since(0);
    let pegout_height = blocks
        .iter()
        .find(|b| !b.pegouts.is_empty())
        .expect("pegout block")
        .height;
    for b in blocks.iter().filter(|b| b.height < pegout_height) {
        node_c
            .ingest_block(b.clone())
            .expect("honest prefix applies");
    }
    let honest_block = blocks
        .iter()
        .find(|b| b.height == pegout_height)
        .unwrap()
        .clone();
    let mut tampered = honest_block.clone();
    tampered.pegouts[0].recipient_prop = vec![0xEE; 36];
    assert_eq!(
        node_c.ingest_block(tampered),
        Err(HnError::BadPegOut),
        "D1: a block whose withdrawal record redirects the recipient is rejected"
    );
    // The untampered block still applies — the rejection was the redirect.
    node_c
        .ingest_block(honest_block)
        .expect("honest pegout block applies");
    assert_eq!(node_c.withdrawals().len(), 1);
    assert_eq!(node_c.withdrawals()[0].recipient_prop, recipient_prop);
}
