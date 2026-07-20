//! Parity: the engine's native `circuit_sponge` reproduces the recursion
//! library's in-circuit `add_hash_slice` (via the `sponge_digest` oracle). This
//! is the load-bearing guest-parity claim — the settlement guest recomputes the
//! withdrawals digest with `circuit_sponge`, never a circuit.
//!
//! `RUSTFLAGS="-Ctarget-cpu=native" cargo test --release --test sponge_parity`

use aegis_engine::epoch::digest::{epoch_spend_root, spend_leaf_digest};
use aegis_engine::epoch::types::{SpendPublics, FLAT_FEE};
use aegis_engine::poseidon::{Digest, F};
use aegis_engine::settlement_digest::{amount_limbs, circuit_sponge, identity_digest};
use aegis_recursion::digest_agg::sponge_digest;
use p3_field::PrimeCharacteristicRing;

fn seq(base: u32, n: usize) -> Vec<F> {
    (0..n).map(|i| F::from_u32(base + i as u32)).collect()
}

fn digest(base: u32) -> Digest {
    core::array::from_fn(|i| F::from_u32(base + i as u32))
}

fn spend(base: u32) -> SpendPublics {
    SpendPublics {
        root: digest(base),
        nf0: digest(base + 10),
        nf1: digest(base + 20),
        cm0: digest(base + 30),
        cm1: digest(base + 40),
        fee: FLAT_FEE,
    }
}

#[test]
fn native_circuit_sponge_matches_circuit_oracle() {
    // Cover the exact input widths the settlement digest uses: leaf (32),
    // fold (16), identity preimage (padded to 24/32), toy (4/8), AND the
    // 48-element epoch spend-leaf preimage.
    for n in [4usize, 8, 16, 24, 32, 48] {
        let x = seq(1000 + n as u32, n);
        assert_eq!(
            circuit_sponge(&x).as_slice(),
            sponge_digest(&x).as_slice(),
            "circuit_sponge != circuit oracle for n={n}"
        );
    }
}

/// The 6-field epoch spend-leaf digest (`root ‖ nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ fee`)
/// matches the in-circuit sponge oracle over the SAME 48-element preimage — the
/// exact preimage `layer1_epoch`'s leaf circuit folds. This is the native↔circuit
/// parity for the 6-field fold the epoch guest binds against (design §3 / gate 3).
#[test]
fn epoch_spend_leaf_digest_matches_circuit_oracle() {
    let s = spend(7);
    // Rebuild the 48-element preimage exactly as `spend_leaf_digest` folds it.
    let mut preimage: Vec<F> = Vec::with_capacity(48);
    preimage.extend_from_slice(&s.root);
    preimage.extend_from_slice(&s.nf0);
    preimage.extend_from_slice(&s.nf1);
    preimage.extend_from_slice(&s.cm0);
    preimage.extend_from_slice(&s.cm1);
    preimage.extend_from_slice(&amount_limbs(s.fee));
    assert_eq!(preimage.len(), 48);
    assert_eq!(
        spend_leaf_digest(&s).as_slice(),
        sponge_digest(&preimage).as_slice(),
        "epoch spend-leaf digest != circuit sponge oracle"
    );
}

/// The epoch spend-Merkle root folds the leaf digests exactly as the aggregation
/// tree does (`H(left ‖ right)` per node, identity padding), reproduced here via
/// the circuit sponge oracle. Confirms `epoch_spend_root` (what the guest
/// recomputes) equals the value the `layer1_epoch` tree would surface.
#[test]
fn epoch_spend_root_matches_circuit_tree_fold() {
    // Three spends → padded to four with the identity digest.
    let spends = [spend(1), spend(100), spend(250)];
    let mut leaves: Vec<Digest> = spends.iter().map(spend_leaf_digest).collect();
    leaves.push(identity_digest());
    // Fold the padded tree with the circuit oracle (H(left ‖ right) per node).
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut inputs: Vec<F> = Vec::with_capacity(16);
            inputs.extend_from_slice(&pair[0]);
            inputs.extend_from_slice(&pair[1]);
            let d = sponge_digest(&inputs);
            next.push(core::array::from_fn(|i| d[i]));
        }
        leaves = next;
    }
    assert_eq!(
        epoch_spend_root(&spends).as_slice(),
        leaves[0].as_slice(),
        "epoch_spend_root != circuit tree fold"
    );
}
