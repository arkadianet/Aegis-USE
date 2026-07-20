//! Stage-T epoch-validity end-to-end (E1 + E3): the honest happy path settles,
//! and a fabricated (non-canonical private-tree) epoch CANNOT — it dies at the
//! structural re-derivation / digest bind / anchor / header-chain / maturity /
//! replay checks. This is the design's §"Stage T" headline deliverable, run at
//! the engine level (exactly what the guest executes; the recursion digest
//! channel is parity-tested separately in `aegis-recursion`).

use aegis_engine::burn::burn_cm_expected;
use aegis_engine::epoch::digest::epoch_spend_root;
use aegis_engine::epoch::header_id::header_id;
use aegis_engine::epoch::types::{coinbase_amount, peg_fee, FLAT_FEE, PEGOUT_DELAY};
use aegis_engine::epoch::verify::{verify_epoch, EpochError, EpochWitness};
use aegis_engine::epoch::{epoch_journal, PegIn, PegOut, SpendPublics, SuffixBlock};
use aegis_engine::merkle::Frontier;
use aegis_engine::mint::coinbase_cm_expected;
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::settled::{empty_settled_root, SettledSet, SETTLED_DEPTH};
use p3_field::PrimeCharacteristicRing;

const CHAIN_ID: u32 = 0x484E_0005;

fn digest(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base.wrapping_mul(131) + i as u32 + 1))
}

/// A host-side honest-suffix builder — mirrors `apply_block` so honest blocks
/// pass `verify_epoch` by construction. Non-consensus test tooling.
struct Builder {
    chain_id: u32,
    frontier: Frontier,
    pot: u64,
    shielded: u64,
    height: u64,
    prev_header_id: [u8; 32],
    miner_owner: Digest,
    blocks: Vec<SuffixBlock>,
    all_spends: Vec<SpendPublics>,
    counter: u32,
    tip_id_prev: [u8; 32],
    pot_before: u64,
    shielded_before: u64,
}

/// A peg-out to add: (amount, recipient).
struct PegSpec {
    amount: u64,
    recipient: Vec<u8>,
}

impl Builder {
    fn new(pot: u64, shielded: u64, start_height: u64) -> Self {
        let frontier = Frontier::new();
        Self {
            chain_id: CHAIN_ID,
            frontier,
            pot,
            shielded,
            height: start_height,
            prev_header_id: [0u8; 32],
            miner_owner: digest(7),
            blocks: Vec::new(),
            all_spends: Vec::new(),
            counter: 1000,
            tip_id_prev: [0u8; 32],
            pot_before: pot,
            shielded_before: shielded,
        }
    }

    fn fresh(&mut self) -> u32 {
        self.counter += 1;
        self.counter
    }

    /// A plain 2-in/2-out tx anchored at the current tip root.
    fn plain_tx(&mut self, prev_root: Digest) -> SpendPublics {
        SpendPublics {
            root: prev_root,
            nf0: digest(self.fresh()),
            nf1: digest(self.fresh()),
            cm0: digest(self.fresh()),
            cm1: digest(self.fresh()),
            fee: FLAT_FEE,
        }
    }

    /// A peg-out spend whose cm0 is the bound burn note.
    fn pegout(&mut self, prev_root: Digest, amount: u64, recipient: Vec<u8>) -> PegOut {
        let nf0 = digest(self.fresh());
        let fee = peg_fee(amount);
        let cm0 = burn_cm_expected(amount + fee, &nf0, &recipient, amount);
        PegOut {
            spend: SpendPublics {
                root: prev_root,
                nf0,
                nf1: digest(self.fresh()),
                cm0,
                cm1: digest(self.fresh()),
                fee: FLAT_FEE,
            },
            amount,
            recipient_prop: recipient,
        }
    }

    fn add_block(&mut self, n_tx: usize, pegouts: Vec<PegSpec>, pegins: Vec<(u64, Digest)>) {
        let prev_root = self.frontier.root();
        let txs: Vec<SpendPublics> = (0..n_tx).map(|_| self.plain_tx(prev_root)).collect();
        let pos: Vec<PegOut> = pegouts
            .into_iter()
            .map(|p| self.pegout(prev_root, p.amount, p.recipient))
            .collect();
        let pins: Vec<PegIn> = pegins
            .into_iter()
            .enumerate()
            .map(|(i, (amount, owner))| PegIn {
                box_id: [(self.height as u8).wrapping_add(i as u8); 32],
                dest_owner: owner,
                amount,
            })
            .collect();

        let n_spends = txs.len() + pos.len();
        let fees = FLAT_FEE * n_spends as u64;
        let cb = coinbase_amount(self.pot, n_spends);
        let mut pegout_fees = 0u64;
        for p in &pos {
            pegout_fees += peg_fee(p.amount);
        }
        let mut pegin_fees = 0u64;
        let mut pegin_inflow = 0u64;
        for pi in &pins {
            pegin_fees += peg_fee(pi.amount);
            pegin_inflow += pi.amount;
        }
        let mut burn_total = 0u64;
        for p in &pos {
            burn_total += p.amount + peg_fee(p.amount);
        }
        let pot_after = self.pot + fees + pegout_fees + pegin_fees - cb;
        // Conservation replay (mirror of `verify_epoch`): shielded pool grows by
        // the coinbase + net peg-in, shrinks by fees + burned value.
        let shielded_after = self.shielded + cb + (pegin_inflow - pegin_fees) - fees - burn_total;

        let bid = aegis_engine::epoch::header_id::block_id(self.height, &prev_root);
        let coinbase_cm = coinbase_cm_expected(&self.miner_owner, cb, &bid);

        // Re-derive leaves in consensus order and advance the frontier.
        for s in txs.iter().chain(pos.iter().map(|p| &p.spend)) {
            let _ = self.frontier.append(s.cm0);
            let _ = self.frontier.append(s.cm1);
        }
        for pi in &pins {
            let minted = pi.amount - peg_fee(pi.amount);
            let cm = aegis_engine::mint::pegmint_cm_expected(&pi.dest_owner, minted, &pi.box_id);
            let _ = self.frontier.append(cm);
        }
        let _ = self.frontier.append(coinbase_cm);
        let state_root = self.frontier.root();

        for s in txs.iter().chain(pos.iter().map(|p| &p.spend)) {
            self.all_spends.push(s.clone());
        }

        let block = SuffixBlock {
            height: self.height,
            prev_header_id: self.prev_header_id,
            prev_root,
            state_root,
            timestamp_ms: 1_760_000_000_000 + self.height * 15_000,
            sc_nbits: 0x2000_0100,
            txs,
            pegouts: pos,
            pegins: pins,
            miner_owner: self.miner_owner,
            coinbase_amount: cb,
            coinbase_cm,
            coinbase_is_reward: true,
            pot_after,
            shielded_after,
        };
        self.prev_header_id = header_id(self.chain_id, &block);
        self.blocks.push(block);
        self.pot = pot_after;
        self.shielded = shielded_after;
        self.height += 1;
    }

    /// Finish into a witness with honest E3 paths + the honest recursion digest.
    fn finish(&self, counter_next: u64) -> EpochWitness {
        // Honest settled-set witnesses in peg-out order.
        let mut set = SettledSet::new();
        let mut paths: Vec<[Digest; SETTLED_DEPTH]> = Vec::new();
        for b in &self.blocks {
            for po in &b.pegouts {
                paths.push(set.witness(&po.spend.nf0));
                set.insert(&po.spend.nf0);
            }
        }
        EpochWitness {
            chain_id: self.chain_id,
            blocks: self.blocks.clone(),
            frontier_bytes: postcard::to_allocvec(&Frontier::new()).unwrap(),
            tip_id_prev: self.tip_id_prev,
            pot_before: self.pot_before,
            shielded_before: self.shielded_before,
            seam_roots: vec![],
            settled_root_in: empty_settled_root(),
            settled_paths: paths,
            spend_root_digest: epoch_spend_root(&self.all_spends),
            ergo_ref_id: [0xEE; 32],
            counter_next,
        }
    }
}

/// Build an honest suffix: block 0 carries a tx + a peg-out; then `PEGOUT_DELAY`
/// maturing blocks so the burn is settleable at the tip.
fn honest_builder() -> Builder {
    let mut b = Builder::new(1_000_000, 1_000_000, 100);
    b.add_block(
        1,
        vec![PegSpec {
            amount: 5000,
            recipient: b"\x00\x08\xcd recipient-ergotree".to_vec(),
        }],
        vec![(2000, digest(999))],
    );
    for _ in 0..PEGOUT_DELAY {
        b.add_block(0, vec![], vec![]);
    }
    b
}

// ----- happy path -----

#[test]
fn honest_epoch_settles() {
    let b = honest_builder();
    let w = b.finish(1);
    let r = verify_epoch(&w).expect("an honest canonical epoch settles");
    assert_eq!(r.prev_root, Frontier::new().root());
    assert_eq!(r.new_root, b.blocks.last().unwrap().state_root);
    assert_eq!(r.withdrawals.len(), 1);
    assert_eq!(r.withdrawals[0].amount, 5000);
    assert_ne!(r.settled_root_out, empty_settled_root());
    // The journal reconstructs cleanly at fixed offsets.
    let j = epoch_journal(
        &r,
        &w.settled_root_in,
        &w.tip_id_prev,
        &w.ergo_ref_id,
        w.counter_next,
    );
    assert_eq!(&j[0..8], aegis_engine::epoch::EPOCH_JOURNAL_TAG);
    assert_eq!(
        j.len(),
        8 + 32 * 7 + 8 + (8 + 8 + w.blocks[0].pegouts[0].recipient_prop.len())
    );
}

// ----- the fabrication headline: it dies at four distinct checks -----

#[test]
fn fabricated_private_tree_note_dies_at_the_digest_bind() {
    // The core attack: a settler mints a fake note into a private tree, produces
    // a "valid" burn against it, and appends it. The burn binding + arithmetic
    // are all internally consistent — but the fake spend is NOT one the recursion
    // tree verified, so the re-derived suffix digest != the bound root digest.
    let b = honest_builder();
    let mut w = b.finish(1);

    // Inject a fabricated peg-out into block 0 (a note from nowhere), rebuilding
    // block 0's state_root/pot so the block is internally consistent — the ONLY
    // thing the fabricator cannot fake is the recursion digest.
    let mut fab = Builder::new(1_000_000, 1_000_000, 100);
    let extra = PegSpec {
        amount: 90_000,
        recipient: b"\x00\x08\xcd attacker".to_vec(),
    };
    fab.add_block(
        1,
        vec![
            PegSpec {
                amount: 5000,
                recipient: b"\x00\x08\xcd recipient-ergotree".to_vec(),
            },
            extra,
        ],
        vec![(2000, digest(999))],
    );
    for _ in 0..PEGOUT_DELAY {
        fab.add_block(0, vec![], vec![]);
    }
    let fab_w = fab.finish(1);

    // The fabricator presents the honest recursion digest (they only have proofs
    // for the real spends) but a suffix containing the extra fake spend.
    w.blocks = fab_w.blocks.clone();
    w.settled_paths = fab_w.settled_paths.clone();
    // spend_root_digest stays the HONEST one (real proofs only).
    let honest_digest = epoch_spend_root(&b.all_spends);
    w.spend_root_digest = honest_digest;

    assert_eq!(
        verify_epoch(&w),
        Err(EpochError::SpendDigestMismatch),
        "a fabricated private-tree note has no real spend proof — the bind dies"
    );
}

#[test]
fn spend_anchored_to_a_private_root_dies_at_the_anchor_window() {
    let b = honest_builder();
    let mut w = b.finish(1);
    // Repoint block 0's first tx to a private (never-real) anchor root.
    w.blocks[0].txs[0].root = digest(0xDEAD);
    // Keep the digest bind consistent with the tampered suffix so the anchor
    // check is what fires (not the bind).
    let mut spends = Vec::new();
    for blk in &w.blocks {
        for s in blk.txs.iter().chain(blk.pegouts.iter().map(|p| &p.spend)) {
            spends.push(s.clone());
        }
    }
    w.spend_root_digest = epoch_spend_root(&spends);
    assert_eq!(
        verify_epoch(&w),
        Err(EpochError::AnchorOutOfWindow { i: 0, j: 0 }),
        "a spend can only anchor to a real recent state-root, never a private tree"
    );
}

#[test]
fn broken_header_chain_dies() {
    let b = honest_builder();
    let mut w = b.finish(1);
    // Snap the link between block 0 and block 1.
    w.blocks[1].prev_header_id[0] ^= 0xFF;
    assert_eq!(
        verify_epoch(&w),
        Err(EpochError::HeaderChainBroken { i: 1 }),
        "the suffix must be a real header-id chain from the sealed tip"
    );
}

#[test]
fn wrong_sealed_tip_dies() {
    let b = honest_builder();
    let mut w = b.finish(1);
    w.tip_id_prev[0] ^= 1;
    assert_eq!(
        verify_epoch(&w),
        Err(EpochError::HeaderChainBroken { i: 0 })
    );
}

#[test]
fn immature_burn_dies_at_pegout_delay() {
    // A suffix that settles a burn younger than pegout_delay is rejected — this
    // is what forces a fabricator to mine a >= pegout_delay+1-block suffix.
    let mut b = Builder::new(1_000_000, 1_000_000, 100);
    b.add_block(
        0,
        vec![PegSpec {
            amount: 5000,
            recipient: b"r".to_vec(),
        }],
        vec![],
    );
    // Only a couple maturing blocks (< PEGOUT_DELAY).
    for _ in 0..3 {
        b.add_block(0, vec![], vec![]);
    }
    let w = b.finish(1);
    match verify_epoch(&w) {
        Err(EpochError::NotMatured { .. }) => {}
        other => panic!("expected NotMatured, got {other:?}"),
    }
}

#[test]
fn tampered_state_root_dies() {
    let b = honest_builder();
    let mut w = b.finish(1);
    w.blocks[0].state_root[0] += F::ONE;
    // Rebuild header chain from the tamper so the header check passes and the
    // state-root weld is what fires.
    let mut prev = w.tip_id_prev;
    for blk in w.blocks.iter_mut() {
        blk.prev_header_id = prev;
        prev = header_id(CHAIN_ID, blk);
    }
    assert_eq!(
        verify_epoch(&w),
        Err(EpochError::StateRootMismatch { i: 0 }),
        "state_root must equal the frontier root over the re-derived leaves"
    );
}

// ----- D1 recipient binding -----

#[test]
fn redirected_recipient_dies_at_the_burn_binding() {
    // THE D1 theft vector at the settlement layer: a permissionless settler
    // takes the victim's real matured burn (real spend, real cm0, built for the
    // honest recipient) and re-labels the recorded withdrawal to pay THEIR OWN
    // address. Because the burn nonces bind (recipient_prop, amount) (D1), the
    // guest's recomputed burn commitment no longer reproduces the spend's out0,
    // so the redirect dies at the burn binding — before it can ever be journaled
    // and paid. Block 0's peg-out burn binding is checked ahead of the following
    // block's header link, so this is the check that fires.
    let b = honest_builder();
    let mut w = b.finish(1);
    // cm0 stays the honestly-built burn note; only the recorded recipient moves.
    w.blocks[0].pegouts[0].recipient_prop = b"\x00\x08\xcd attacker".to_vec();
    assert_eq!(
        verify_epoch(&w),
        Err(EpochError::BadBurnBinding { i: 0, j: 0 }),
        "a burn note is only reproducible with the recipient it was built for (D1)"
    );
}

// ----- E3 replay-close -----

#[test]
fn re_settling_a_burn_dies_at_the_settled_set() {
    // Settle once, then attempt to settle the SAME burn again against the
    // resulting R6 — the non-membership proof cannot reproduce it.
    let b = honest_builder();
    let w1 = b.finish(1);
    let r1 = verify_epoch(&w1).expect("first settlement");

    // A second (synthetic non-canonical) epoch re-appending the same burn nf0.
    let nf0 = b.blocks[0].pegouts[0].spend.nf0;
    let mut set = SettledSet::new();
    set.insert(&nf0); // it was settled in r1
    let path = set.witness(&nf0);

    // Build a fresh single-block-ish witness re-presenting the burn against R6_out.
    let mut w2 = b.finish(2);
    w2.settled_root_in = r1.settled_root_out;
    w2.settled_paths = vec![path];
    // (Only the first peg-out's path is under attack; give the honest set state.)
    // Force just the E3 check: keep everything else valid but re-present nf0.
    // The suffix already contains the burn with this nf0; its path now proves a
    // MEMBER, so verify_insert fails.
    match verify_epoch(&w2) {
        Err(EpochError::AlreadySettled { .. }) => {}
        other => panic!("expected AlreadySettled, got {other:?}"),
    }
}
