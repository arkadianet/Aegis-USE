//! The epoch **spend-digest bind** (E1's anti-fabrication core).
//!
//! For epoch-validity the recursion tree aggregates EVERY suffix spend proof
//! (not just the N withdrawals), and each leaf exposes the digest of its spend's
//! public values `(root ‖ nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ fee)`. The tree folds those to
//! one root digest, surfaced on the root proof's `aegis/digest` entry (the
//! option-A channel, `recursion-feasibility.md` §11). The guest recomputes the
//! SAME root here from the suffix it re-derives leaves from, and checks equality
//! (`crate::epoch::verify`). That equality is the bind: the `(cm0, cm1)` the
//! guest appends to the value tree are exactly the outputs of REAL, valid spend
//! proofs — a fabricator cannot inject a fake note commitment without a real
//! spend producing it. Combined with the anchor-window (`root` ∈ recent real
//! roots) this is what makes a private-tree epoch un-settleable.
//!
//! The fold mirrors `settlement_digest` (same `circuit_sponge`, same identity
//! padding, same left→right / bottom→top tree) — the recursion crate's
//! `layer1_epoch` exposes `spend_leaf_digest` exactly as `layer1_settlement`
//! exposes the withdrawal leaf digest, so the surfaced root equals
//! [`epoch_spend_root`] by construction.

use crate::poseidon::{Digest, F};
use crate::settlement_digest::{amount_limbs, circuit_sponge, identity_digest};

use super::types::SpendPublics;

/// The per-spend leaf digest the recursion tree exposes:
/// `H(root ‖ nf0 ‖ nf1 ‖ cm0 ‖ cm1 ‖ fee)` (48 field elements, rate-aligned),
/// folded by the circuit sponge — the exact value the leaf circuit surfaces.
pub fn spend_leaf_digest(s: &SpendPublics) -> Digest {
    let mut inputs: Vec<F> = Vec::with_capacity(48);
    inputs.extend_from_slice(&s.root);
    inputs.extend_from_slice(&s.nf0);
    inputs.extend_from_slice(&s.nf1);
    inputs.extend_from_slice(&s.cm0);
    inputs.extend_from_slice(&s.cm1);
    inputs.extend_from_slice(&amount_limbs(s.fee));
    circuit_sponge(&inputs)
}

/// Fold a power-of-two-padded slice of leaf digests into the root exactly as the
/// aggregation tree does: `H(left ‖ right)` per node, pairs left→right,
/// bottom→top.
fn fold_tree(mut leaves: Vec<Digest>) -> Digest {
    assert!(!leaves.is_empty(), "empty spend tree");
    assert!(leaves.len().is_power_of_two(), "power-of-two leaf count");
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len() / 2);
        for pair in leaves.chunks(2) {
            let mut inputs: Vec<F> = Vec::with_capacity(16);
            inputs.extend_from_slice(&pair[0]);
            inputs.extend_from_slice(&pair[1]);
            next.push(circuit_sponge(&inputs));
        }
        leaves = next;
    }
    leaves[0]
}

/// The suffix spend-Merkle-root over `spends` (in consensus order), padded to the
/// next power of two with the pinned identity digest — the value the guest
/// checks against the recursion root proof's surfaced digest. `>= 1` required.
pub fn epoch_spend_root(spends: &[SpendPublics]) -> Digest {
    assert!(!spends.is_empty(), "at least one suffix spend");
    let padded = spends.len().next_power_of_two();
    let mut leaves: Vec<Digest> = spends.iter().map(spend_leaf_digest).collect();
    leaves.resize(padded, identity_digest());
    fold_tree(leaves)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::types::FLAT_FEE;
    use p3_field::PrimeCharacteristicRing;

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

    // ----- happy path -----

    #[test]
    fn spend_root_single_is_the_leaf() {
        let s = spend(1);
        assert_eq!(
            epoch_spend_root(std::slice::from_ref(&s)),
            spend_leaf_digest(&s)
        );
    }

    // ----- error paths (the bind sensitivity) -----

    #[test]
    fn any_field_change_moves_the_root() {
        let base = [spend(1), spend(100)];
        let root = epoch_spend_root(&base);
        for mutate in [
            |s: &mut SpendPublics| s.root[0] += F::ONE,
            |s: &mut SpendPublics| s.nf0[0] += F::ONE,
            |s: &mut SpendPublics| s.nf1[0] += F::ONE,
            |s: &mut SpendPublics| s.cm0[0] += F::ONE,
            |s: &mut SpendPublics| s.cm1[0] += F::ONE,
            |s: &mut SpendPublics| s.fee += 1,
        ] {
            let mut m = base.clone();
            mutate(&mut m[0]);
            assert_ne!(
                epoch_spend_root(&m),
                root,
                "a changed spend field must move the root"
            );
        }
    }

    #[test]
    fn reorder_and_drop_change_the_root() {
        let a = [spend(1), spend(2)];
        let b = [spend(2), spend(1)];
        assert_ne!(
            epoch_spend_root(&a),
            epoch_spend_root(&b),
            "order-sensitive"
        );
        assert_ne!(
            epoch_spend_root(&a),
            epoch_spend_root(&[spend(1)]),
            "count-sensitive"
        );
    }
}
