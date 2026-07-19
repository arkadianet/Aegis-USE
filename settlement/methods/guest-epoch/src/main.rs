// Stage-T epoch-validity settlement guest (v7, AEGISPV1).
//
// Extends the v6 batch guest with the epoch-validity statement that closes the
// fabrication vector: the settler can no longer supply epoch leaves — the guest
// RE-DERIVES them from proven suffix blocks and proves the suffix is a
// consensus-valid, real-value hn extension of the sealed tip.
//
// Statement (design 2.2, `dev-docs/sidechain/epoch-validity-design.md`):
//   1. verify the ONE aggregation ROOT proof (constant in N) — it recursively
//      attests EVERY suffix spend proof; its surfaced digest is the epoch
//      spend-root over (root ‖ nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ fee) per suffix spend;
//   2. E1: `verify_epoch` — header-id chain T_prev→T_new (R7), leaves re-derived
//      from the proven blocks (the anti-fabrication bind against the §1 digest),
//      new_root == B_k.state_root, anchor-window, economics replay, pegout_delay;
//   3. E3: chain the settled-burn set R6_in → R6_out (non-membership then insert);
//   4. (aux-pow feature) E2: per suffix reward block, verify its aux-PoW share
//      binds the block's header id to real Autolykos work (the fabrication pricer);
//   5. (aux-pow feature) E4: the suffix tip is committed under an ancestor of the
//      contract-spliced canonical `ergo_ref` (CONTEXT.headers);
//   6. journal the exact AEGISPV1 bytes the PegVault reconstructs.
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use aegis_engine::epoch::wire::EpochWitnessWire;
use aegis_engine::epoch::{epoch_journal, verify_epoch};
use aegis_engine::poseidon::Digest;
use aegis_recursion::digest_agg::verify_root_bytes_sha;
use aegis_recursion::AggParams;
use risc0_zkvm::guest::env;

risc0_zkvm::guest::entry!(main);

fn main() {
    // ---- private inputs (env::read order; the host writes exactly this) ----
    let root_bytes: Vec<u8> = env::read();
    let witness_wire: EpochWitnessWire = env::read();

    let c0 = env::cycle_count();

    // ---- 1. verify the aggregation ROOT (ONE verify, constant in N) ----
    // The surfaced digest is the epoch spend-root the tree folded from every
    // suffix spend's public values — the object E1's leaf re-derivation binds to.
    let params = AggParams::default();
    let root_digest =
        verify_root_bytes_sha(&params, &root_bytes).expect("aggregate root must verify");
    let c_verify = env::cycle_count();
    env::log(&alloc::format!("CYCLES root_verify={}", c_verify - c0));

    // Bind the VERIFIED root's surfaced digest into the witness (never trust the
    // wire value): `verify_epoch` then requires the re-derived `epoch_spend_root`
    // to equal it, so a wrong root or a fabricated leaf can never pass.
    let mut witness = witness_wire.into_witness();
    witness.spend_root_digest = {
        let d: Digest = core::array::from_fn(|i| root_digest[i]);
        d
    };

    // ---- 2+3. E1 structural epoch validity + E3 settled-burn accumulator ----
    let settled_root_in = witness.settled_root_in;
    let tip_id_prev = witness.tip_id_prev;
    let ergo_ref_id = witness.ergo_ref_id;
    let counter_next = witness.counter_next;
    let result = verify_epoch(&witness).expect("epoch-validity statement must hold");
    let c_epoch = env::cycle_count();
    env::log(&alloc::format!("CYCLES epoch_validity={}", c_epoch - c_verify));

    // ---- 4+5. E2 aux-PoW share verify + E4 anchor linkage (priced fabrication) ----
    #[cfg(feature = "aux-pow")]
    {
        use aegis_engine::epoch::anchor::verify_anchor_linkage;
        use aegis_engine::epoch::aux_wire::{AnchorWitnessWire, ShareWitnessWire};
        use aegis_engine::epoch::header_id::header_id;
        use aegis_engine::epoch::share::verify_share;

        // Per suffix reward block: verify its aux-PoW share binds the block's
        // header id to real Autolykos work at its sc_nbits target. The wire form
        // carries each Ergo object as its canonical byte image (the typed Ergo
        // structs are not serde) — rebuild it here, in-guest.
        let share_wires: Vec<ShareWitnessWire> = env::read();
        assert_eq!(
            share_wires.len(),
            witness.blocks.len(),
            "one share per block"
        );
        for (block, share_wire) in witness.blocks.iter().zip(share_wires) {
            let hid = header_id(witness.chain_id, block);
            let share = share_wire.into_witness();
            verify_share(&share, &hid, block.sc_nbits).expect("aux-PoW share must verify");
        }
        let c_e2 = env::cycle_count();
        env::log(&alloc::format!("CYCLES aux_pow_e2={}", c_e2 - c_epoch));

        // E4: the suffix tip is committed under an ancestor of the canonical ref.
        let anchor_wire: AnchorWitnessWire = env::read();
        let anchor = anchor_wire.into_witness();
        let anchored_hn_id = header_id(witness.chain_id, witness.blocks.last().unwrap());
        verify_anchor_linkage(&anchor, &ergo_ref_id, &anchored_hn_id)
            .expect("canonical-Ergo anchor linkage must hold");
        env::log(&alloc::format!(
            "CYCLES anchor_e4={}",
            env::cycle_count() - c_e2
        ));
    }

    // ---- 6. commit the §2.2 AEGISPV1 journal (PegVault reconstructs it) ----
    let journal = epoch_journal(
        &result,
        &settled_root_in,
        &tip_id_prev,
        &ergo_ref_id,
        counter_next,
    );
    env::commit_slice(&journal);
}
