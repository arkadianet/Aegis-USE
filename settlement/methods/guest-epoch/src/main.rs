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

/// D-F5 §6 condition 1: whether E4 (canonical-Ergo anchor binding) is MANDATORY
/// on this image. The mainnet image pins it `true`; it is asserted
/// unconditionally in `main` (outside the `aux-pow` cfg), so an image built
/// without E4 cannot settle. A devnet mechanism-demonstration image (§6.5) may
/// set it `false`, but the mainnet floor argument (§6) requires E4 present.
const REQUIRE_E4: bool = true;

/// F3 pinned deposit-recognition image constants. These are **deployment-
/// specific** — the deployed vault address's `ergoTree` bytes and the USE token
/// id (derived from the `VaultSpec`, `bridge-tools/src/vault_epoch.rs`), the same
/// values the node's `VaultWatch` is configured with. They MUST be pinned at the
/// cut before any real peg-in can settle. F3 fails CLOSED against a wrong value
/// (a non-matching tree/token rejects every peg-in as unbacked), so a placeholder
/// is safe for a pre-cut / no-peg-in devnet image but blocks real mints until set.
// TODO(cut): replace with the deployed vault tree bytes and USE token id.
const PINNED_VAULT_TREE_BYTES: &[u8] = &[];
const PINNED_USE_TOKEN_ID: [u8; 32] = [0u8; 32];

fn main() {
    // §6 cond. 1: E4 is mandatory on the mainnet image — assert require_e4
    // unconditionally. Without the `aux-pow` feature the guest binds no anchor,
    // so a required-E4 image built that way must refuse to run.
    assert!(
        !REQUIRE_E4 || cfg!(feature = "aux-pow"),
        "require_e4: mainnet image must bind E4 (build with the `aux-pow` feature)"
    );

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
    let mut result = verify_epoch(&witness).expect("epoch-validity statement must hold");
    let c_epoch = env::cycle_count();
    env::log(&alloc::format!("CYCLES epoch_validity={}", c_epoch - c_verify));

    // ---- 4+5. E2 aux-PoW share verify + E4 anchor linkage (priced fabrication) ----
    #[cfg(feature = "aux-pow")]
    {
        use aegis_engine::epoch::anchor::{verify_anchor_linkage_min_depth, A_MIN};
        use aegis_engine::epoch::aux_wire::{AnchorWitnessWire, ShareWitnessWire};
        use aegis_engine::epoch::header_id::header_id;

        // Per suffix reward block: verify its aux-PoW share binds the block's
        // header id to real Autolykos work at its sc_nbits target. The wire form
        // carries each Ergo object as its canonical byte image (the typed Ergo
        // structs are not serde) — rebuild it here, in-guest.
        let share_wires: Vec<ShareWitnessWire> = env::read();
        let shares: Vec<_> = share_wires.into_iter().map(|w| w.into_witness()).collect();
        // F6b: verify_suffix_shares enforces one DISTINCT Autolykos solve per block
        // (rejecting share amplification — a single solve replayed as k inclusion
        // proofs), on top of the per-block share↔header-id↔sc_nbits work binding.
        // Without this the k·D fabrication price collapses to D.
        aegis_engine::epoch::share::verify_suffix_shares(
            witness.chain_id,
            &witness.blocks,
            &shares,
        )
        .expect("aux-PoW shares must verify and be non-amplified (F6b)");
        let c_e2 = env::cycle_count();
        env::log(&alloc::format!("CYCLES aux_pow_e2={}", c_e2 - c_epoch));

        // E4: the suffix tip is committed under an ancestor of the canonical ref.
        let anchor_wire: AnchorWitnessWire = env::read();
        let anchor = anchor_wire.into_witness();
        let anchored_hn_id = header_id(witness.chain_id, witness.blocks.last().unwrap());
        // F5: the tip's anchor must be buried >= A_MIN canonical Ergo blocks —
        // this is what turns "one Ergo block" into "A_MIN settled Ergo blocks"
        // and secures the §6 Ergo-hashrate fabrication floor.
        verify_anchor_linkage_min_depth(&anchor, &ergo_ref_id, &anchored_hn_id, A_MIN)
            .expect("canonical-Ergo anchor linkage at depth >= A_MIN must hold");
        let c_e4 = env::cycle_count();
        env::log(&alloc::format!("CYCLES anchor_e4={}", c_e4 - c_e2));

        // ---- F3: peg-in backing — every suffix peg-in mint is backed by a
        // real, >=PEGIN_CONFIRMATIONS-buried Ergo deposit on the SAME canonical
        // ergo_ref, minted at most once ever. Folds each deposit's
        // one-mint-ever key into R6 on top of the F6c nullifiers, so the journal
        // commits the peg-in-inclusive settled root.
        use aegis_engine::epoch::aux_wire::PegInBackingWitnessWire;
        use aegis_engine::epoch::pegin::{verify_pegin_backing, DepositParams, PEGIN_CONFIRMATIONS};
        let backing_wire: PegInBackingWitnessWire = env::read();
        let backing = backing_wire.into_witness();
        let deposit_params = DepositParams {
            vault_tree_bytes: PINNED_VAULT_TREE_BYTES.to_vec(),
            use_token_id: PINNED_USE_TOKEN_ID,
            pegin_confirmations: PEGIN_CONFIRMATIONS,
        };
        result.settled_root_out = verify_pegin_backing(
            &witness.blocks,
            &backing,
            &ergo_ref_id,
            result.settled_root_out,
            &deposit_params,
        )
        .expect("every peg-in must be backed by a real, buried, uniquely-minted deposit");
        env::log(&alloc::format!(
            "CYCLES pegin_backing_f3={}",
            env::cycle_count() - c_e4
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
